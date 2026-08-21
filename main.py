from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

import docker
from dotenv import load_dotenv
from docker.errors import APIError as DockerAPIError
from docker.errors import DockerException
from docker.errors import NotFound as DockerNotFound
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, HttpUrl, ValidationError
from prometheus_client import Counter, Histogram, make_asgi_app

from google import genai
from google.genai import errors as genai_errors
from google.genai import types
from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from kubernetes.client.exceptions import ApiException as KubernetesApiException


class AnalyzeRequest(BaseModel):
    target_url: HttpUrl = Field(..., description="URL to inspect")


class SecurityReport(BaseModel):
    risk_level: Literal["LOW", "MEDIUM", "HIGH"]
    summary: str
    technical_findings: list[str]
    user_recommendation: str


class AnalyzeResponse(BaseModel):
    target_url: str
    telemetry_excerpt: str
    report: SecurityReport


class SandboxRuntimeError(RuntimeError):
    """Raised when the disposable sandbox container fails to execute safely."""


load_dotenv()  # Local-development fallback; Kubernetes injects this through a Secret.

app = FastAPI(title="NukeSandbox API", version="1.0.0")
app.mount("/metrics", make_asgi_app())


class JsonFormatter(logging.Formatter):
    """Emit machine-readable logs for collection by a container platform."""

    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {
                "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%SZ"),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            }
        )


logger = logging.getLogger("nukesandbox")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
logger.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())
logger.propagate = False

ANALYSIS_REQUESTS = Counter(
    "nukesandbox_analysis_requests_total",
    "URL analysis requests by outcome.",
    ["outcome"],
)
SANDBOX_DURATION = Histogram(
    "nukesandbox_sandbox_duration_seconds",
    "Time spent executing the disposable sandbox.",
)
SANDBOX_TEARDOWNS = Counter(
    "nukesandbox_sandbox_teardowns_total",
    "Sandbox cleanup attempts by outcome.",
    ["outcome"],
)

FRONTEND_DIST = Path("frontend/dist")
FRONTEND_ASSETS = FRONTEND_DIST / "assets"

if FRONTEND_ASSETS.exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_ASSETS)), name="assets")


MAX_TELEMETRY_CHARS = 12000
DOCKER_TIMEOUT_SECONDS = 10
KUBERNETES_NAMESPACE = os.getenv("SANDBOX_NAMESPACE", "nukesandbox")


def _redact_url_in_text(text: str, target_url: str) -> str:
    """Reduce prompt leakage by replacing repeated target URL mentions."""
    escaped = re.escape(target_url)
    return re.sub(escaped, "<TARGET_URL>", text, flags=re.IGNORECASE)


def _run_sandbox_telemetry(target_url: str) -> str:
    container = None
    started_at = time.monotonic()

    try:
        docker_client = docker.from_env()
        container = docker_client.containers.run(
            image="curlimages/curl:8.11.1",
            command=["curl", "-v", "-s", "-L", "--max-time", "8", target_url],
            detach=True,
            network_mode="bridge",
            cap_drop=["ALL"],
            read_only=True,
            mem_limit="128m",
            pids_limit=64,
            security_opt=["no-new-privileges:true"],
            user="65534:65534",
            auto_remove=False,
        )

        timed_out = False

        def _stop_if_running() -> None:
            nonlocal timed_out
            timed_out = True
            if container is not None:
                try:
                    container.kill()
                except DockerAPIError:
                    pass

        timeout_timer = threading.Timer(DOCKER_TIMEOUT_SECONDS, _stop_if_running)
        timeout_timer.start()
        try:
            result = container.wait()
        finally:
            timeout_timer.cancel()

        if timed_out:
            raise SandboxRuntimeError("Sandbox execution exceeded 10 seconds and was terminated.")

        logs = container.logs(stdout=True, stderr=True)
        telemetry_raw = logs.decode("utf-8", errors="replace")
        telemetry = telemetry_raw[:MAX_TELEMETRY_CHARS]

        status_code = int(result.get("StatusCode", 1))
        if status_code != 0 and not telemetry.strip():
            raise SandboxRuntimeError(
                f"Sandbox command failed with exit status {status_code} and no logs were captured."
            )

        return telemetry

    except DockerException as exc:
        raise SandboxRuntimeError(f"Docker runtime failure: {exc}") from exc
    finally:
        SANDBOX_DURATION.observe(time.monotonic() - started_at)
        if container is not None:
            try:
                container.remove(force=True)
                SANDBOX_TEARDOWNS.labels(outcome="removed").inc()
            except DockerNotFound:
                SANDBOX_TEARDOWNS.labels(outcome="already_removed").inc()
                pass
            except DockerAPIError:
                SANDBOX_TEARDOWNS.labels(outcome="error").inc()
                logger.warning("sandbox_cleanup_failed")
                pass


def _run_kubernetes_sandbox(target_url: str) -> str:
    """Run URL inspection as a tightly scoped, short-lived Kubernetes Pod."""
    started_at = time.monotonic()
    try:
        k8s_config.load_incluster_config()
        api = k8s_client.CoreV1Api()
        pod = api.create_namespaced_pod(
            namespace=KUBERNETES_NAMESPACE,
            body=k8s_client.V1Pod(
                metadata=k8s_client.V1ObjectMeta(generate_name="url-sandbox-", labels={"app": "nukesandbox-sandbox"}),
                spec=k8s_client.V1PodSpec(
                    restart_policy="Never",
                    automount_service_account_token=False,
                    active_deadline_seconds=DOCKER_TIMEOUT_SECONDS,
                    security_context=k8s_client.V1PodSecurityContext(run_as_non_root=True, run_as_user=65532),
                    containers=[
                        k8s_client.V1Container(
                            name="curl",
                            image="curlimages/curl:8.11.1",
                            args=["-v", "-s", "-L", "--max-time", "8", target_url],
                            resources=k8s_client.V1ResourceRequirements(
                                requests={"cpu": "50m", "memory": "64Mi"}, limits={"cpu": "250m", "memory": "128Mi"}
                            ),
                            security_context=k8s_client.V1SecurityContext(
                                allow_privilege_escalation=False,
                                read_only_root_filesystem=True,
                                capabilities=k8s_client.V1Capabilities(drop=["ALL"]),
                            ),
                        )
                    ],
                ),
            ),
        )
        pod_name = pod.metadata.name
        deadline = time.monotonic() + DOCKER_TIMEOUT_SECONDS + 2
        while time.monotonic() < deadline:
            status = api.read_namespaced_pod_status(pod_name, KUBERNETES_NAMESPACE).status.phase
            if status in {"Succeeded", "Failed"}:
                return api.read_namespaced_pod_log(pod_name, KUBERNETES_NAMESPACE)[:MAX_TELEMETRY_CHARS]
            time.sleep(0.5)
        raise SandboxRuntimeError("Kubernetes sandbox execution exceeded its deadline.")
    except KubernetesApiException as exc:
        raise SandboxRuntimeError(f"Kubernetes runtime failure: {exc.reason}") from exc
    finally:
        SANDBOX_DURATION.observe(time.monotonic() - started_at)
        if "api" in locals() and "pod_name" in locals():
            try:
                api.delete_namespaced_pod(pod_name, KUBERNETES_NAMESPACE, propagation_policy="Background")
                SANDBOX_TEARDOWNS.labels(outcome="removed").inc()
            except KubernetesApiException:
                SANDBOX_TEARDOWNS.labels(outcome="error").inc()


def _generate_security_report(target_url: str, telemetry: str) -> SecurityReport:
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        raise RuntimeError("GOOGLE_API_KEY is not set.")

    client = genai.Client(api_key=api_key)

    scrubbed_telemetry = _redact_url_in_text(telemetry, target_url)
    prompt = (
        "You are NukeSandbox, an empathetic security analyst for non-expert users. "
        "Analyze the HTTP/network telemetry below and produce a concise risk report.\n\n"
        "Rules:\n"
        "- Use plain language for summary and recommendation.\n"
        "- Highlight concrete indicators only (status codes, TLS hints, redirects, headers, failures).\n"
        "- If signals are mixed, choose MEDIUM.\n"
        "- Never include markdown.\n\n"
        f"Target URL: {target_url}\n"
        "Telemetry:\n"
        f"{scrubbed_telemetry}"
    )

    try:
        chosen_model = os.getenv("NUKESANDBOX_MODEL") or os.getenv("NOTIONGUARD_MODEL", "gemini-2.5-flash")

        response = client.models.generate_content(
            model=chosen_model,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=SecurityReport,
                temperature=0.2,
            ),
        )
    except genai_errors.APIError as exc:
        raise RuntimeError(f"GenAI API request failed: {exc}") from exc
    except Exception as exc:
        raise RuntimeError(f"Unexpected GenAI error: {exc}") from exc

    if response.parsed is not None:
        if isinstance(response.parsed, SecurityReport):
            return response.parsed
        try:
            return SecurityReport.model_validate(response.parsed)
        except ValidationError as exc:
            raise RuntimeError(f"Model returned invalid structured response: {exc}") from exc

    if response.text:
        try:
            data = json.loads(response.text)
            return SecurityReport.model_validate(data)
        except (json.JSONDecodeError, ValidationError) as exc:
            raise RuntimeError(f"Model output was not valid schema JSON: {exc}") from exc

    raise RuntimeError("Model returned no parsable content.")


@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze(payload: AnalyzeRequest) -> AnalyzeResponse:
    target_url = str(payload.target_url)

    parsed = urlparse(target_url)
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(status_code=400, detail="Only http and https URLs are supported.")

    try:
        telemetry = (
            _run_kubernetes_sandbox(target_url)
            if os.getenv("SANDBOX_EXECUTION_MODE", "docker") == "kubernetes"
            else _run_sandbox_telemetry(target_url)
        )
    except SandboxRuntimeError as exc:
        ANALYSIS_REQUESTS.labels(outcome="sandbox_error").inc()
        logger.warning("analysis_failed stage=sandbox")
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    if not telemetry.strip():
        ANALYSIS_REQUESTS.labels(outcome="empty_telemetry").inc()
        logger.info("analysis_failed stage=telemetry")
        raise HTTPException(status_code=422, detail="No telemetry captured from target URL.")

    try:
        report = _generate_security_report(target_url=target_url, telemetry=telemetry)
    except RuntimeError as exc:
        ANALYSIS_REQUESTS.labels(outcome="report_error").inc()
        logger.warning("analysis_failed stage=report")
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    ANALYSIS_REQUESTS.labels(outcome="success").inc()
    logger.info("analysis_completed risk_level=%s", report.risk_level)
    return AnalyzeResponse(
        target_url=target_url,
        telemetry_excerpt=telemetry,
        report=report,
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/ready")
def readiness() -> dict[str, str]:
    """Kubernetes readiness probe; no secret values are exposed."""
    if not os.getenv("GOOGLE_API_KEY"):
        raise HTTPException(status_code=503, detail="GOOGLE_API_KEY is not configured.")
    return {"status": "ready"}


@app.get("/", response_class=HTMLResponse, response_model=None)
def dashboard() -> HTMLResponse | FileResponse:
    frontend_index = FRONTEND_DIST / "index.html"
    if frontend_index.exists():
        return FileResponse(frontend_index)
    return HTMLResponse(
        "<h1>NukeSandbox frontend not built</h1>"
        "<p>Run npm install && npm run build in the frontend folder.</p>",
        status_code=503,
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
