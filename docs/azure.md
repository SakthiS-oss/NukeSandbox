# Azure Container Apps deployment

The API is a Consumption Container App. Each inspection is a manual Container Apps Job that runs digest-pinned `curl`, then exits. Images live in Azure Container Registry. Secrets live in Key Vault and are set with Azure CLI so they do not enter Terraform state.

```text
GitHub Actions (OIDC) ── Semgrep + Trivy ──> ACR ──> Container App revision
                                                      │
Client ──> FastAPI ──> Container Apps Job (curl) ──> telemetry ──> Gemini
                 │
                 └── managed identity starts only that job
```

## Provision

Prerequisites: Azure CLI and Terraform >= 1.5.

```bash
az login
cd terraform
terraform init
terraform apply
```

Then set secrets (do not pass them as `terraform -var`):

```bash
az keyvault secret set --vault-name "$(terraform output -raw key_vault_name)" \
  --name google-api-key --value "$GOOGLE_API_KEY"
az keyvault secret set --vault-name "$(terraform output -raw key_vault_name)" \
  --name api-key-hashes --value "$API_KEY_HASHES"
```

Terraform creates:

- A uniquely named resource group, 7-day Log Analytics workspace, and Container Apps environment
- Azure Container Registry (admin disabled; pull/push via managed identity)
- Key Vault with RBAC and placeholder secrets
- User-assigned identities for the API and for GitHub Actions
- The `nukesandbox-api` Container App (scale-to-zero, max 1 replica) and the `nukesandbox-sandbox` Job
- A job-scoped custom role for the API and an image-update role for GitHub
- GitHub OIDC federated credentials for the `Azure` branch and the `production` environment

The first Container App revision uses the public quickstart image. CI replaces it with the scanned ACR digest. Until that happens, `/ready` will fail if the Gemini key is still `REPLACE_ME`.

## GitHub settings

| Secret | Terraform output |
|---|---|
| `AZURE_CLIENT_ID` | `github_client_id` |
| `AZURE_TENANT_ID` | `azure_tenant_id` |
| `AZURE_SUBSCRIPTION_ID` | `azure_subscription_id` |
| `AZURE_RESOURCE_GROUP` | `resource_group_name` |
| `ACR_LOGIN_SERVER` | `acr_login_server` |

Protect the `Azure` branch so **Azure security-gated build and deploy** is required.

## Keeping the bill low

- Do not set `min_replicas` above 0 unless you need to avoid cold starts.
- Do not add Azure Cache for Redis, Front Door, or a VNet-injected environment unless you are ready to pay for them.
- Run `terraform destroy` when the demo is over.

## Residual risk

- Container Apps Jobs do not expose the same seccomp/capability knobs as Kubernetes Pods.
- Job start still accepts an ARM template override. This API sends args only; a caller with the raw `jobs/start` permission could still supply another image.
- There is no Redis quota on this branch. API keys and the 15-second job timeout are the cost controls.
- Sandbox egress is not VNet-locked. The process-level DNS preflight still rejects non-public answers. Production egress lockdown needs a VNet or Azure Firewall.
- The curl image is pulled from Docker Hub by digest. Mirroring it into ACR is optional and adds a small storage charge.
