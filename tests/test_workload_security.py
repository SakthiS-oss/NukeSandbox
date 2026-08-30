from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_api_workload_drops_privileges_and_sets_limits() -> None:
    workload = next(yaml.safe_load_all((ROOT / "k8s" / "deployment.yaml").read_text()))
    container = workload["spec"]["template"]["spec"]["containers"][0]

    assert container["image"].endswith(":main")
    assert container["securityContext"]["allowPrivilegeEscalation"] is False
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]
    assert set(container["resources"]["limits"]) == {"cpu", "memory"}


def test_admission_policy_covers_forbidden_workload_settings() -> None:
    policy = (ROOT / "policies" / "kyverno-nukesandbox.yaml").read_text()

    assert "hostPath" in policy
    assert "privileged" in policy
    assert "!*:latest" in policy
    assert "verifyImages" in policy
