from __future__ import annotations

import contextvars
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import socket
import threading
import time
import uuid
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
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, HttpUrl, ValidationError
from prometheus_client import Counter, Histogram, make_asgi_app
from redis import Redis
from redis.exceptions import RedisError

from opentelemetry import context as otel_context
from opentelemetry import propagate, trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

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

request_id_context: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")
identity_context: contextvars.ContextVar[str] = contextvars.ContextVar("identity", default="anonymous")


def _configure_tracing() -> None:
    """Export traces only when an OTLP collector endpoint is configured."""
    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        return
    provider = TracerProvider(resource=Resource.create({"service.name": "nukesandbox-api"}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint, insecure=True)))
    trace.set_tracer_provider(provider)


_configure_tracing()
tracer = trace.get_tracer("nukesandbox")


class JsonFormatter(logging.Formatter):
    """Emit machine-readable logs for collection by a container platform."""

    def format(self, record: logging.LogRecord) -> str:
        span_context = trace.get_current_span().get_span_context()
        return json.dumps(
            {
                "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%SZ"),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
                "request_id": request_id_context.get(),
                "trace_id": format(span_context.trace_id, "032x") if span_context.is_valid else None,
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
AUTH_FAILURES = Counter("nukesandbox_auth_failures_total", "Rejected API authentication attempts.")
SANDBOX_CAPACITY_REJECTIONS = Counter(
    "nukesandbox_sandbox_capacity_rejections_total", "Requests rejected because the global sandbox cap was reached."
)

FRONTEND_DIST = Path("frontend/dist")
FRONTEND_ASSETS = FRONTEND_DIST / "assets"

if FRONTEND_ASSETS.exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_ASSETS)), name="assets")


MAX_TELEMETRY_CHARS = 12000
DOCKER_TIMEOUT_SECONDS = 10
# Manifest-list digest so Docker and Kubernetes pull the same immutable curl image.
SANDBOX_IMAGE = (
    "curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69"
)
KUBERNETES_NAMESPACE = os.getenv("SANDBOX_NAMESPACE", "nukesandbox")
RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "false").lower() == "true"
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "10"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
API_AUTH_REQUIRED = os.getenv("API_AUTH_REQUIRED", "false").lower() == "true"
CONCURRENCY_LIMIT_ENABLED = os.getenv("CONCURRENCY_LIMIT_ENABLED", "false").lower() == "true"
MAX_CONCURRENT_SANDBOXES = int(os.getenv("MAX_CONCURRENT_SANDBOXES", "5"))
SANDBOX_SLOT_TTL_SECONDS = int(os.getenv("SANDBOX_SLOT_TTL_SECONDS", "30"))
SANDBOX_EGRESS_PROXY = os.getenv("SANDBOX_EGRESS_PROXY")
REQUIRE_EGRESS_PROXY = os.getenv("REQUIRE_EGRESS_PROXY", "false").lower() == "true"
_redis_client: Redis | None = None


def _get_redis_client() -> Redis:
    global _redis_client
    if _redis_client is None:
        redis_url = os.getenv("REDIS_URL")
        if not redis_url:
            raise RuntimeError("REDIS_URL must be configured when rate limiting is enabled.")
        _redis_client = Redis.from_url(redis_url, decode_responses=True, socket_connect_timeout=1)
    return _redis_client


def _authenticate_api_key(provided_key: str | None) -> str:
    """Authenticate an API key against SHA-256 digests stored in a runtime secret."""
    if not API_AUTH_REQUIRED:
        return "anonymous"
    try:
        key_hashes = json.loads(os.environ["API_KEY_HASHES"])
    except (KeyError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=503, detail="API authentication is not configured.") from exc
    if not isinstance(key_hashes, dict) or not provided_key:
        AUTH_FAILURES.inc()
        raise HTTPException(status_code=401, detail="A valid X-API-Key is required.")
    supplied_digest = hashlib.sha256(provided_key.encode()).hexdigest()
    for identity, expected_digest in key_hashes.items():
        if isinstance(identity, str) and isinstance(expected_digest, str) and hmac.compare_digest(supplied_digest, expected_digest):
            return identity
    AUTH_FAILURES.inc()
    raise HTTPException(status_code=401, detail="A valid X-API-Key is required.")


def _enforce_rate_limit(identity: str) -> None:
    """Use Redis as a shared fixed-window quota; fail closed to protect sandbox spend."""
    key = f"nukesandbox:rate-limit:{identity}:{int(time.time() // RATE_LIMIT_WINDOW_SECONDS)}"
    try:
        requests = _get_redis_client().incr(key)
        if requests == 1:
            _get_redis_client().expire(key, RATE_LIMIT_WINDOW_SECONDS)
    except (RedisError, RuntimeError) as exc:
        logger.error("rate_limit_unavailable error=%s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Rate limiter is unavailable.") from exc
    if requests > RATE_LIMIT_REQUESTS:
        raise HTTPException(status_code=429, detail="Analysis quota exceeded; retry shortly.")


def _acquire_sandbox_slot() -> None:
    """Atomically reserve shared Redis capacity so sandboxes cannot exhaust the cluster."""
    try:
        acquired = _get_redis_client().eval(
            "local active=tonumber(redis.call('GET', KEYS[1]) or '0'); "
            "if active >= tonumber(ARGV[1]) then return 0 end; "
            "redis.call('INCR', KEYS[1]); redis.call('EXPIRE', KEYS[1], ARGV[2]); return 1",
            1,
            "nukesandbox:active-sandboxes",
            MAX_CONCURRENT_SANDBOXES,
            SANDBOX_SLOT_TTL_SECONDS,
        )
    except (RedisError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail="Sandbox capacity controller is unavailable.") from exc
    if not acquired:
        SANDBOX_CAPACITY_REJECTIONS.inc()
        raise HTTPException(status_code=429, detail="Sandbox capacity is currently exhausted; retry shortly.")


def _release_sandbox_slot() -> None:
    try:
        _get_redis_client().eval(
            "local active=tonumber(redis.call('GET', KEYS[1]) or '0'); "
            "if active <= 1 then return redis.call('DEL', KEYS[1]) end; return redis.call('DECR', KEYS[1])",
            1,
            "nukesandbox:active-sandboxes",
        )
    except (RedisError, RuntimeError):
        logger.error("sandbox_slot_release_failed")


@app.middleware("http")
async def add_request_context_and_rate_limit(request, call_next):
    """Correlate API work end-to-end and enforce a shared analysis quota."""
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request_token = request_id_context.set(request_id)
    identity_token = None
    extracted_context = propagate.extract(request.headers)
    context_token = otel_context.attach(extracted_context)
    try:
        with tracer.start_as_current_span(f"http.{request.method.lower()}") as span:
            span.set_attribute("http.request.method", request.method)
            span.set_attribute("url.path", request.url.path)
            span.set_attribute("nukesandbox.request_id", request_id)
            if request.url.path == "/api/analyze":
                identity = _authenticate_api_key(request.headers.get("X-API-Key"))
                identity_token = identity_context.set(identity)
                if RATE_LIMIT_ENABLED:
                    _enforce_rate_limit(identity if API_AUTH_REQUIRED else (request.client.host if request.client else "unknown"))
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            span.set_attribute("http.response.status_code", response.status_code)
            return response
    except HTTPException as exc:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail}, headers=exc.headers)
    finally:
        otel_context.detach(context_token)
        if identity_token is not None:
            identity_context.reset(identity_token)
        request_id_context.reset(request_token)


def _redact_url_in_text(text: str, target_url: str) -> str:
    """Replace the submitted URL so Gemini never sees the original destination."""
    escaped = re.escape(target_url)
    redacted = re.sub(escaped, "<TARGET_URL>", text, flags=re.IGNORECASE)
    hostname = urlparse(target_url).hostname
    if hostname:
        redacted = re.sub(re.escape(hostname), "<TARGET_HOST>", redacted, flags=re.IGNORECASE)
    return redacted


def _build_security_report_prompt(target_url: str, telemetry: str) -> str:
    """Build a Gemini prompt that contains only redacted telemetry, never the raw URL."""
    return (
        "You are NukeSandbox, an empathetic security analyst for non-expert users. "
        "Analyze the HTTP/network telemetry below and produce a concise risk report.\n\n"
        "Rules:\n"
        "- Use plain language for summary and recommendation.\n"
        "- Highlight concrete indicators only (status codes, TLS hints, redirects, headers, failures).\n"
        "- If signals are mixed, choose MEDIUM.\n"
        "- Never include markdown.\n"
        "- Refer to the inspected destination as <TARGET_URL> or <TARGET_HOST> only. "
        "Never echo, reconstruct, or guess the original URL.\n\n"
        "Target: <TARGET_URL>\n"
        "Telemetry:\n"
        f"{_redact_url_in_text(telemetry, target_url)}"
    )


def _validate_public_target(target_url: str) -> None:
    """Block direct SSRF to non-public addresses before sandbox execution."""
    hostname = urlparse(target_url).hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Target URL must include a hostname.")
    try:
        addresses = {result[4][0] for result in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)}
    except socket.gaierror as exc:
        raise HTTPException(status_code=400, detail="Target hostname cannot be resolved.") from exc
    for address in addresses:
        if not ipaddress.ip_address(address).is_global:
            raise HTTPException(status_code=400, detail="Target URL must resolve only to public IP addresses.")


def _sandbox_command(target_url: str) -> list[str]:
    """Build a redirect-limited curl invocation, optionally forcing all egress through a proxy."""
    if REQUIRE_EGRESS_PROXY and not SANDBOX_EGRESS_PROXY:
        raise SandboxRuntimeError("SANDBOX_EGRESS_PROXY is required in this environment.")
    command = [
        "curl", "-v", "-s", "-L", "--max-time", "8", "--max-redirs", "5",
        "--proto", "=http,https", "--proto-redir", "=http,https",
    ]
    if SANDBOX_EGRESS_PROXY:
        command.extend(["--proxy", SANDBOX_EGRESS_PROXY, "--noproxy", ""])
    return [*command, target_url]


def _run_sandbox_telemetry(target_url: str) -> str:
    started_at = time.monotonic()

    try:
        with tracer.start_as_current_span("sandbox.docker") as span:
            span.set_attribute("sandbox.runtime", "docker")
            span.set_attribute("sandbox.timeout_seconds", DOCKER_TIMEOUT_SECONDS)
            return _run_docker_sandbox(target_url)
    finally:
        SANDBOX_DURATION.observe(time.monotonic() - started_at)


def _run_docker_sandbox(target_url: str) -> str:
    container = None
    try:
        docker_client = docker.from_env()
        container = docker_client.containers.run(
            image=SANDBOX_IMAGE,
            command=_sandbox_command(target_url),
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
        with tracer.start_as_current_span("sandbox.kubernetes") as span:
            span.set_attribute("sandbox.runtime", "kubernetes")
            span.set_attribute("k8s.namespace.name", KUBERNETES_NAMESPACE)
            return _run_kubernetes_pod(target_url)
    finally:
        SANDBOX_DURATION.observe(time.monotonic() - started_at)


def _kubernetes_sandbox_pod(target_url: str) -> k8s_client.V1Pod:
    """Disposable Pod with the same least-privilege controls as the Docker runner."""
    return k8s_client.V1Pod(
        metadata=k8s_client.V1ObjectMeta(
            generate_name="url-sandbox-",
            labels={"app.kubernetes.io/name": "nukesandbox-sandbox"},
        ),
        spec=k8s_client.V1PodSpec(
            restart_policy="Never",
            automount_service_account_token=False,
            enable_service_links=False,
            active_deadline_seconds=DOCKER_TIMEOUT_SECONDS,
            security_context=k8s_client.V1PodSecurityContext(
                run_as_non_root=True,
                run_as_user=65532,
                run_as_group=65532,
                seccomp_profile=k8s_client.V1SeccompProfile(type="RuntimeDefault"),
            ),
            containers=[
                k8s_client.V1Container(
                    name="curl",
                    image=SANDBOX_IMAGE,
                    image_pull_policy="IfNotPresent",
                    args=_sandbox_command(target_url)[1:],
                    resources=k8s_client.V1ResourceRequirements(
                        requests={"cpu": "50m", "memory": "64Mi"},
                        limits={"cpu": "250m", "memory": "128Mi"},
                    ),
                    security_context=k8s_client.V1SecurityContext(
                        allow_privilege_escalation=False,
                        read_only_root_filesystem=True,
                        privileged=False,
                        run_as_non_root=True,
                        run_as_user=65532,
                        run_as_group=65532,
                        capabilities=k8s_client.V1Capabilities(drop=["ALL"]),
                        seccomp_profile=k8s_client.V1SeccompProfile(type="RuntimeDefault"),
                    ),
                )
            ],
        ),
    )


def _run_kubernetes_pod(target_url: str) -> str:
    try:
        k8s_config.load_incluster_config()
        api = k8s_client.CoreV1Api()
        pod = api.create_namespaced_pod(
            namespace=KUBERNETES_NAMESPACE,
            body=_kubernetes_sandbox_pod(target_url),
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
    chosen_model = os.getenv("NUKESANDBOX_MODEL", "gemini-2.5-flash")
    prompt = _build_security_report_prompt(target_url, telemetry)

    try:
        with tracer.start_as_current_span("gemini.generate_report") as span:
            span.set_attribute("gen_ai.request.model", chosen_model)
            return _request_security_report(client, chosen_model, prompt)
    except genai_errors.APIError as exc:
        raise RuntimeError(f"GenAI API request failed: {exc}") from exc
    except Exception as exc:
        raise RuntimeError(f"Unexpected GenAI error: {exc}") from exc


def _request_security_report(client: genai.Client, chosen_model: str, prompt: str) -> SecurityReport:
    response = client.models.generate_content(
        model=chosen_model,
        contents=prompt,
        config=types.GenerateContentConfig(
            response_mime_type="application/json",
            response_schema=SecurityReport,
            temperature=0.2,
        ),
    )
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
    _validate_public_target(target_url)

    slot_acquired = False
    try:
        if CONCURRENCY_LIMIT_ENABLED:
            _acquire_sandbox_slot()
            slot_acquired = True
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
        return AnalyzeResponse(target_url=target_url, telemetry_excerpt=telemetry, report=report)
    finally:
        if slot_acquired:
            _release_sandbox_slot()


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

    # Pass the already-created application instance to avoid importing this module
    # a second time, which would register Prometheus metrics twice.
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
