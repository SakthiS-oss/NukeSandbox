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


def test_azure_terraform_provisions_acr_container_apps_and_key_vault() -> None:
    terraform_dir = ROOT / "terraform"
    sources = "".join(path.read_text() for path in terraform_dir.glob("*.tf"))

    assert "azurerm_container_registry" in sources
    assert "azurerm_container_app" in sources
    assert "azurerm_container_app_job" in sources
    assert "azurerm_key_vault" in sources
    assert "azurerm_federated_identity_credential" in sources
    assert 'SANDBOX_EXECUTION_MODE"' in sources or "SANDBOX_EXECUTION_MODE" in sources
    assert "nukesandbox-sandbox" in sources


def test_azure_ci_publishes_to_acr_not_latest() -> None:
    workflow = (ROOT / ".github" / "workflows" / "azure-security-gated-deploy.yml").read_text()

    assert "azure/login@v2" in workflow
    assert "az acr login" in workflow
    assert "az containerapp update" in workflow
    assert "nukesandbox@$DIGEST" in workflow
    assert ":latest" not in workflow


def test_admission_policy_covers_forbidden_workload_settings() -> None:
    policy = (ROOT / "policies" / "kyverno-nukesandbox.yaml").read_text()

    assert "hostPath" in policy
    assert "privileged" in policy
    assert "!*:latest" in policy
    assert "verifyImages" in policy
