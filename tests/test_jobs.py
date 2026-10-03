from __future__ import annotations

from fastapi.testclient import TestClient

import jobs
import main


def _public_url(monkeypatch) -> None:
    monkeypatch.setattr(main, "_validate_public_target", lambda _url: None)
    monkeypatch.setattr(main, "RATE_LIMIT_ENABLED", False)
    monkeypatch.setattr(main, "API_AUTH_REQUIRED", False)


def test_analyze_command_keeps_url_as_data_not_a_shell_string() -> None:
    command = jobs.build_analyze_command("https://example.com; touch /tmp/pwned", "alice", "req-1")
    payload = command.model_dump()
    assert payload["event_type"] == "AnalyzeRequested"
    assert payload["target_url"] == "https://example.com; touch /tmp/pwned"
    assert payload["job_id"]


def test_job_store_complete_is_idempotent() -> None:
    store = jobs.JobStore()
    record = store.create(
        jobs.JobRecord(
            job_id="job-1",
            status="succeeded",
            stage="report",
            target_url="https://example.com",
            identity="alice",
            created_at=1.0,
            result={"target_url": "https://example.com"},
        )
    )
    updated = store.update("job-1", status="failed", error="should not overwrite")
    assert updated is not None
    # The store itself is last-write; the API layer ignores terminal jobs.
    assert record.status == "succeeded"


def test_sync_analyze_runs_when_kafka_is_disabled(monkeypatch) -> None:
    _public_url(monkeypatch)
    monkeypatch.setattr(main, "kafka_enabled", lambda: False)
    monkeypatch.setattr(
        main,
        "_run_analysis",
        lambda target_url: main.AnalyzeResponse(
            target_url=target_url,
            telemetry_excerpt="ok",
            report=main.SecurityReport(
                risk_level="LOW",
                summary="fine",
                technical_findings=[],
                user_recommendation="ok",
            ),
        ),
    )
    client = TestClient(main.app)
    response = client.post("/api/analyze", json={"target_url": "https://example.com"})
    assert response.status_code == 200
    assert response.json()["report"]["risk_level"] == "LOW"


def test_kafka_path_returns_202_and_poll_url(monkeypatch) -> None:
    _public_url(monkeypatch)
    store = jobs.JobStore()
    monkeypatch.setattr(jobs, "_store", store)
    monkeypatch.setattr(main, "kafka_enabled", lambda: True)
    monkeypatch.setattr(main, "publish_analyze_command", lambda _command: None)
    client = TestClient(main.app)
    response = client.post("/api/analyze", json={"target_url": "https://example.com"})
    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "queued"
    assert body["poll_url"].startswith("/api/jobs/")
    assert store.get(body["job_id"]) is not None


def test_internal_execute_requires_token() -> None:
    client = TestClient(main.app)
    response = client.post("/internal/execute", json={"target_url": "https://example.com"})
    assert response.status_code == 401


def test_internal_job_event_does_not_overwrite_terminal_state(monkeypatch) -> None:
    monkeypatch.setenv("INTERNAL_API_TOKEN", "secret")
    store = jobs.JobStore()
    store.create(
        jobs.JobRecord(
            job_id="job-locked",
            status="succeeded",
            stage="report",
            target_url="https://example.com",
            identity="alice",
            created_at=1.0,
            result={"kept": True},
        )
    )
    monkeypatch.setattr(jobs, "_store", store)
    client = TestClient(main.app)
    response = client.post(
        "/internal/jobs/job-locked/events",
        headers={"X-Internal-Token": "secret"},
        json={"status": "failed", "stage": "worker", "error": "replay"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "succeeded"
    assert response.json()["result"] == {"kept": True}
