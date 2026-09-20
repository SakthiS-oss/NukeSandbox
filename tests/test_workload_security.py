from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_api_workload_drops_privileges_and_sets_limits() -> None:
    workload = next(yaml.safe_load_all((ROOT / "k8s" / "deployment.yaml").read_text()))
    container = workload["spec"]["template"]["spec"]["containers"][0]

    assert not container["image"].endswith(":latest")
    assert ":latest" not in container["image"]
    assert container["securityContext"]["allowPrivilegeEscalation"] is False
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]
    assert set(container["resources"]["limits"]) == {"cpu", "memory"}


def test_sandbox_and_proxy_images_are_digest_pinned() -> None:
    import main

    assert "@sha256:" in main.SANDBOX_IMAGE
    proxy_manifests = list(yaml.safe_load_all((ROOT / "k8s" / "egress-proxy.yaml").read_text()))
    squid = next(
        doc["spec"]["template"]["spec"]["containers"][0]
        for doc in proxy_manifests
        if doc and doc.get("kind") == "Deployment"
    )
    assert "@sha256:" in squid["image"]
    assert not squid["image"].endswith(":latest")


def test_ci_publishes_immutable_tags_not_latest() -> None:
    workflow = (ROOT / ".github" / "workflows" / "security-gated-deploy.yml").read_text()

    assert "ghcr.io/${{ github.repository }}:latest" not in workflow
    assert "cosign verify" in workflow
    assert "set image" in workflow


def test_admission_policy_covers_forbidden_workload_settings() -> None:
    policy = (ROOT / "policies" / "kyverno-nukesandbox.yaml").read_text()

    assert "hostPath" in policy
    assert "privileged" in policy
    assert "!*:latest" in policy
    assert "verifyImages" in policy
