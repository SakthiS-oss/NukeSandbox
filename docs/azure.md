# Azure Container Apps deployment

This branch runs the same URL-triage service on Azure Container Apps. The API is a Container App. Each inspection is a manual Azure Container Apps Job that starts a digest-pinned `curl` container, then exits. Images are stored in Azure Container Registry. Secrets come from Azure Key Vault.

```text
GitHub Actions (OIDC) ── Semgrep + Trivy ──> ACR ──> Container App revision
                                                      │
Client ──> FastAPI ──> Container Apps Job (curl) ──> telemetry ──> Gemini
                 │
                 └── managed identity starts the job; Key Vault injects secrets
```

## Provision

Prerequisites: Azure CLI, Terraform >= 1.5, and an Azure subscription.

```bash
az login
cd terraform
cp terraform.tfvars.example terraform.tfvars
# set google_api_key and api_key_hashes in the apply command, not in git
terraform init
terraform apply \
  -var="google_api_key=$GOOGLE_API_KEY" \
  -var="api_key_hashes=$API_KEY_HASHES"
```

Terraform creates:

- Resource group, Log Analytics workspace, and a Container Apps environment
- Azure Container Registry (admin disabled; pull/push via managed identity)
- Key Vault with RBAC, holding `GOOGLE_API_KEY` and `API_KEY_HASHES`
- User-assigned identities for the API and for GitHub Actions
- The `nukesandbox-api` Container App and the `nukesandbox-sandbox` Job
- A custom role that can only start/read/stop sandbox jobs
- GitHub OIDC federated credentials for the `Azure` branch and the `production` environment

The first Container App revision uses the public quickstart image. CI replaces it with the scanned ACR digest.

## GitHub settings

Add these repository or `production` environment secrets from `terraform output`:

| Secret | Terraform output |
|---|---|
| `AZURE_CLIENT_ID` | `github_client_id` |
| `AZURE_TENANT_ID` | `azure_tenant_id` |
| `AZURE_SUBSCRIPTION_ID` | `azure_subscription_id` |
| `AZURE_RESOURCE_GROUP` | `resource_group_name` |
| `ACR_LOGIN_SERVER` | `acr_login_server` |

Protect the `Azure` branch so **Azure security-gated build and deploy** is required.

## Local development

Local mode is unchanged: Docker Desktop plus `SANDBOX_EXECUTION_MODE=docker`. Azure packages are imported only when the API actually starts a job.

## Residual risk

Container Apps Jobs do not expose the same seccomp/capability knobs as Kubernetes Pods. Isolation is the disposable job replica, the custom job-only RBAC, and the existing DNS preflight. For production egress control, place the Container Apps environment in a VNet and restrict outbound traffic with NSG or Azure Firewall.
