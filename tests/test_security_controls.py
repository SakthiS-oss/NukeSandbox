from __future__ import annotations

import socket

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
