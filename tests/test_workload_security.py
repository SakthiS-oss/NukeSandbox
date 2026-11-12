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
    assert "branches: [kubernetes]" in workflow


def test_azure_terraform_provisions_acr_container_apps_and_key_vault() -> None:
    terraform_dir = ROOT / "terraform"
    sources = "".join(path.read_text() for path in terraform_dir.glob("*.tf"))

    assert "azurerm_container_registry" in sources
    assert "azurerm_container_app" in sources
    assert "azurerm_container_app_job" in sources
    assert "azurerm_key_vault" in sources
    assert "azurerm_federated_identity_credential" in sources
    assert "SANDBOX_EXECUTION_MODE" in sources
    assert "nukesandbox-sandbox" in sources
    assert "azurerm_container_app_job.sandbox.id" in sources
    assert "REPLACE_ME" in sources
    assert "github_deployer" in sources
    assert "scale-to-zero" in sources
    assert "Contributor" not in sources


def test_sandbox_job_pulls_the_acr_mirror_of_the_pinned_curl_image() -> None:
    import main

    variables = (ROOT / "terraform" / "variables.tf").read_text()
    stack = (ROOT / "terraform" / "container-apps.tf").read_text()
    rbac = (ROOT / "terraform" / "rbac.tf").read_text()
    digest = main.SANDBOX_IMAGE.split("@", 1)[1]
    job = stack.split('resource "azurerm_container_app_job" "sandbox"', 1)[1]

    assert digest in variables
    assert "az acr import" in stack
    assert "docker.io/curlimages/curl@" in stack
    assert 'image   = "${azurerm_container_registry.main.login_server}/curl@${local.curl_image_digest}"' in job
    assert "azurerm_user_assigned_identity.sandbox" in job
    assert "curlimages/curl" not in job
    assert "azurerm_user_assigned_identity.sandbox.principal_id" in rbac
    assert "AcrPull" in rbac


def test_curl_image_pin_is_updated_on_a_schedule() -> None:
    workflow = (ROOT / ".github" / "workflows" / "curl-image-update.yml").read_text()
    script = (ROOT / ".github" / "scripts" / "update_curl_pin.py").read_text()

    assert "schedule:" in workflow
    assert "cron:" in workflow
    assert "curlimages/curl" in workflow
    assert "update_curl_pin.py" in workflow
    assert "workflow_dispatch:" in workflow
    assert ":latest" not in workflow
    assert "main.py" in script
    assert "terraform/variables.tf" in script
    assert "application/vnd.docker.distribution.manifest.list.v2+json" in script
    assert "application/vnd.oci.image.index.v1+json" in script


def test_azure_ci_publishes_to_acr_not_latest() -> None:
    workflow = (ROOT / ".github" / "workflows" / "azure-security-gated-deploy.yml").read_text()

    assert "azure/login@v2" in workflow
    assert "az acr login" in workflow
    assert "az containerapp update" in workflow
    assert "nukesandbox@$DIGEST" in workflow
    assert ":latest" not in workflow
    assert "branches: [main]" in workflow
    assert "refs/heads/Azure" not in workflow
    sign_at = workflow.index("cosign sign --yes")
    verify_at = workflow.index("cosign verify")
    deploy_at = workflow.index("az containerapp update")
    assert sign_at < verify_at < deploy_at
    assert "azure-security-gated-deploy.yml@refs/heads/main" in workflow
    assert "https://token.actions.githubusercontent.com" in workflow


def _playbook_tasks(name: str) -> list[dict]:
    play = yaml.safe_load((ROOT / "ansible" / "playbooks" / name).read_text())[0]
    return [*play.get("pre_tasks", []), *play.get("tasks", []), *play.get("handlers", [])]


def test_ansible_never_logs_secrets_or_passes_them_as_arguments() -> None:
    secret_markers = ("google_api_key", "api_key", "key_vault_secrets")
    for playbook in ("bootstrap.yml", "smoke-test.yml"):
        for task in _playbook_tasks(playbook):
            if any(marker in yaml.safe_dump(task) for marker in secret_markers):
                assert task.get("no_log") is True, f"{playbook}: '{task['name']}' handles a secret without no_log"
            for arg in task.get("ansible.builtin.command", {}).get("argv", []):
                templated_secret = "{{" in arg and any(marker in arg for marker in (*secret_markers, ".value"))
                assert not templated_secret, f"{playbook}: '{task['name']}' puts a secret in argv; use stdin"


def test_azure_ci_lints_ansible() -> None:
    workflow = (ROOT / ".github" / "workflows" / "azure-security-gated-deploy.yml").read_text()

    assert "ansible-lint" in workflow
    assert "--syntax-check" in workflow


def test_admission_policy_covers_forbidden_workload_settings() -> None:
    policy = (ROOT / "policies" / "kyverno-nukesandbox.yaml").read_text()

    assert "hostPath" in policy
    assert "privileged" in policy
    assert "!*:latest" in policy
    assert "verifyImages" in policy
