from __future__ import annotations

import json
import os
import re
import threading
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

from google import genai
from google.genai import errors as genai_errors
from google.genai import types


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


load_dotenv()

app = FastAPI(title="NukeSandbox API", version="1.0.0")

FRONTEND_DIST = Path("frontend/dist")
FRONTEND_ASSETS = FRONTEND_DIST / "assets"

if FRONTEND_ASSETS.exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_ASSETS)), name="assets")


MAX_TELEMETRY_CHARS = 12000
DOCKER_TIMEOUT_SECONDS = 10


def _redact_url_in_text(text: str, target_url: str) -> str:
    """Reduce prompt leakage by replacing repeated target URL mentions."""
    escaped = re.escape(target_url)
    return re.sub(escaped, "<TARGET_URL>", text, flags=re.IGNORECASE)


def _run_sandbox_telemetry(target_url: str) -> str:
    container = None

    try:
        docker_client = docker.from_env()
        container = docker_client.containers.run(
            image="alpine:latest",
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
        if container is not None:
            try:
                container.remove(force=True)
            except DockerNotFound:
                pass
            except DockerAPIError:
                pass


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
        telemetry = _run_sandbox_telemetry(target_url)
    except SandboxRuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    if not telemetry.strip():
        raise HTTPException(status_code=422, detail="No telemetry captured from target URL.")

    try:
        report = _generate_security_report(target_url=target_url, telemetry=telemetry)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return AnalyzeResponse(
        target_url=target_url,
        telemetry_excerpt=telemetry,
        report=report,
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


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
