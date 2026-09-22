from __future__ import annotations

import socket
import hashlib
import json

import pytest
from fastapi import HTTPException

import main


def _addresses(*addresses: str):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0)) for address in addresses]


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.9", "169.254.169.254", "::1"])
def test_ssrf_guard_blocks_non_public_addresses(monkeypatch: pytest.MonkeyPatch, address: str) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: _addresses(address))

    with pytest.raises(HTTPException, match="public IP"):
        main._validate_public_target("https://attacker.example")


def test_ssrf_guard_rejects_mixed_dns_answers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: _addresses("8.8.8.8", "10.0.0.9"))

    with pytest.raises(HTTPException, match="public IP"):
        main._validate_public_target("https://attacker.example")


def test_ssrf_guard_allows_public_address(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: _addresses("8.8.8.8"))

    main._validate_public_target("https://public.example")


def test_docker_runner_keeps_malicious_url_as_one_argument(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    class FakeContainer:
        def wait(self):
            return {"StatusCode": 0}

        def logs(self, **_kwargs):
            return b"telemetry"

        def remove(self, **_kwargs):
            return None

    class FakeContainers:
        def run(self, **kwargs):
            captured.update(kwargs)
            return FakeContainer()

    class FakeDocker:
        containers = FakeContainers()

    monkeypatch.setattr(main.docker, "from_env", lambda: FakeDocker())
    malicious_url = "https://example.com; touch /tmp/pwned"
    assert main._run_docker_sandbox(malicious_url) == "telemetry"
    assert captured["command"][-1] == malicious_url
    assert captured["command"][:6] == ["curl", "-v", "-s", "-L", "--max-time", "8"]
    assert captured["image"] == main.SANDBOX_IMAGE
    assert captured["cap_drop"] == ["ALL"]
    assert captured["read_only"] is True


def test_rate_limit_rejects_excess_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeRedis:
        requests = 0

        def incr(self, _key: str) -> int:
            self.requests += 1
            return self.requests

        def expire(self, _key: str, _seconds: int) -> None:
            return None

    monkeypatch.setattr(main, "_redis_client", FakeRedis())
    monkeypatch.setattr(main, "RATE_LIMIT_REQUESTS", 1)
    main._enforce_rate_limit("203.0.113.10")
    with pytest.raises(HTTPException) as exc_info:
        main._enforce_rate_limit("203.0.113.10")
    assert exc_info.value.status_code == 429


def test_api_key_authentication_returns_a_stable_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "API_AUTH_REQUIRED", True)
    monkeypatch.setenv("API_KEY_HASHES", json.dumps({"portfolio-user": hashlib.sha256(b"test-key").hexdigest()}))

    assert main._authenticate_api_key("test-key") == "portfolio-user"
    with pytest.raises(HTTPException) as exc_info:
        main._authenticate_api_key("incorrect")
    assert exc_info.value.status_code == 401


def test_proxy_is_required_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "REQUIRE_EGRESS_PROXY", True)
    monkeypatch.setattr(main, "SANDBOX_EGRESS_PROXY", None)

    with pytest.raises(main.SandboxRuntimeError, match="EGRESS_PROXY"):
        main._sandbox_command("https://example.com")


def test_proxy_command_forces_http_traffic_through_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "REQUIRE_EGRESS_PROXY", True)
    monkeypatch.setattr(main, "SANDBOX_EGRESS_PROXY", "http://egress-proxy:3128")

    command = main._sandbox_command("https://example.com")
    assert ["--proxy", "http://egress-proxy:3128", "--noproxy", ""] == command[-5:-1]
    assert "--proto-redir" in command


def test_global_sandbox_capacity_rejects_when_limit_is_reached(monkeypatch: pytest.MonkeyPatch) -> None:
    class FullRedis:
        def eval(self, *_args):
            return 0

    monkeypatch.setattr(main, "_redis_client", FullRedis())
    with pytest.raises(HTTPException) as exc_info:
        main._acquire_sandbox_slot()
    assert exc_info.value.status_code == 429


def test_gemini_prompt_never_includes_target_url_or_hostname() -> None:
    target_url = "https://secret-target.example/path?token=abc"
    telemetry = f"* Connected to secret-target.example\n> GET {target_url} HTTP/1.1\n< Location: {target_url}/next"

    prompt = main._build_security_report_prompt(target_url, telemetry)

    assert target_url not in prompt
    assert "secret-target.example" not in prompt
    assert "token=abc" not in prompt
    assert "<TARGET_URL>" in prompt
    assert "<TARGET_HOST>" in prompt


def test_azure_job_keeps_malicious_url_as_one_argument() -> None:
    malicious_url = "https://example.com; touch /tmp/pwned"
    body = main._azure_job_start_body(malicious_url)
    container = body["containers"][0]

    assert container["name"] == "curl"
    assert "image" not in container
    assert "command" not in container
    assert container["args"][-1] == malicious_url
    assert container["args"][:5] == ["-v", "-s", "-L", "--max-time", "8"]


def test_selected_sandbox_dispatches_azure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SANDBOX_EXECUTION_MODE", "azure")
    monkeypatch.setattr(main, "_run_azure_sandbox", lambda target: f"azure:{target}")

    assert main._run_selected_sandbox("https://example.com") == "azure:https://example.com"


def test_ready_requires_azure_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_API_KEY", "test-key")
    monkeypatch.setenv("SANDBOX_EXECUTION_MODE", "azure")
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    monkeypatch.delenv("AZURE_RESOURCE_GROUP", raising=False)

    with pytest.raises(HTTPException) as exc_info:
        main.readiness()
    assert exc_info.value.status_code == 503


def test_kubernetes_sandbox_matches_docker_hardening() -> None:
    pod = main._kubernetes_sandbox_pod("https://example.com")
    spec = pod.spec
    container = spec.containers[0]

    assert spec.automount_service_account_token is False
    assert spec.enable_service_links is False
    assert spec.security_context.run_as_non_root is True
    assert spec.security_context.run_as_user == 65532
    assert spec.security_context.seccomp_profile.type == "RuntimeDefault"
    assert container.image == main.SANDBOX_IMAGE
    assert "@sha256:" in container.image
    assert container.security_context.allow_privilege_escalation is False
    assert container.security_context.read_only_root_filesystem is True
    assert container.security_context.privileged is False
    assert container.security_context.capabilities.drop == ["ALL"]
    assert container.security_context.seccomp_profile.type == "RuntimeDefault"
    assert container.args[-1] == "https://example.com"
