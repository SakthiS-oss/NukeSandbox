# NukeSandbox

NukeSandbox inspects a URL in a short-lived sandbox, then turns the HTTP telemetry into a plain-language risk report with Gemini.

This `main` branch runs that path on **Azure Container Apps** and **Azure Container Registry**. Each inspection is a disposable Container Apps Job. The API never mounts a Docker socket.

## What this branch demonstrates

- **Disposable Azure sandboxes:** `SANDBOX_EXECUTION_MODE=azure` starts a curl Job, waits for it, reads logs, and stops it on failure or timeout.
- **Least privilege:** the API identity can start/read/stop only the sandbox job and read the Container Apps environment. GitHub OIDC can push to ACR and update the API image. It cannot read Key Vault or start jobs.
- **Secrets stay out of Git and Terraform state:** Key Vault holds `GOOGLE_API_KEY` and `API_KEY_HASHES`. Terraform creates placeholder secrets; you set the real values with Azure CLI.
- **Cheap by default:** Consumption plan, API scale-to-zero, one replica max, 7-day Log Analytics retention, no Redis, no Front Door, no VNet.
- **Security gates:** GitHub Actions runs pytest, Semgrep, Trivy, and `terraform fmt` before publishing `nukesandbox:<sha>` to ACR and deploying that digest.
- **Distributed analysis (optional, local):** Kafka plus a Scala Pekko (Akka-model) worker turn `POST /api/analyze` into an async job with backpressure and at-least-once delivery. See `docs/distributed-systems.md`.

Local Docker still works. The Kubernetes path lives on the `kubernetes` branch and under `terraform/kubernetes/`.

## Architecture

```text
GitHub Actions (OIDC) ── pytest + Semgrep + Trivy ──> ACR digest ──> Container App
                                                              │
Client ── X-API-Key ──> FastAPI ──> Container Apps Job (curl) ──> Gemini
                 │                         │
                 └── Key Vault secrets     └── replica exits (stopped on failure)

Optional local path:
Client ── 202 job_id ──> Kafka (job_id key) ──> Pekko worker ──> /internal/execute
```

## Cost notes

The Terraform stack is meant to stay on the Azure free/near-free tier:

| Choice | Why |
|---|---|
| Container Apps Consumption, `min_replicas = 0` | No charge while idle. First request after idle is a cold start. |
| `max_replicas = 1` | Stops surprise scale-out. |
| Manual Job, 15s replica timeout | You pay only while a sandbox is running. |
| ACR Basic, Key Vault standard | No private endpoints or Premium SKUs. |
| Log Analytics, 7-day retention | Enough for debugging; not a long-term SIEM. |

You still pay a little for ACR storage, Key Vault operations, and any Job/API CPU time. Destroy the resource group when you are done: `terraform destroy`.

This branch does **not** provision Redis, Azure Front Door, or a VNet. Those would raise the bill. Abuse control is API-key auth plus the Job timeout. Egress is the DNS preflight already in the app; lock outbound traffic with a VNet later if you need it.

## Local development

Prerequisites: Python 3.10+, Node 18+, Docker Desktop.

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt

cd frontend && npm ci && npm run build && cd ..
cp .env.example .env   # put a local Gemini key here
python3 main.py
pytest
```

Open `http://localhost:8000`. Local mode uses Docker and a digest-pinned `curlimages/curl` image. Health and metrics are at `/health` and `/metrics`. If you set `API_AUTH_REQUIRED=true`, enter the raw API key in the dashboard field.

To demo Kafka + Pekko instead of the synchronous API:

```bash
docker compose up -d kafka
export KAFKA_BOOTSTRAP_SERVERS=localhost:9094 INTERNAL_API_TOKEN=dev-internal-token
python3 main.py
# other terminal
cd worker && INTERNAL_API_TOKEN=dev-internal-token sbt run
```

The dashboard polls `GET /api/jobs/{id}` after a `202`. Leave Kafka unset on Azure so you do not add Event Hubs or a VM to the bill.

## Azure deployment

1. Sign in and apply Terraform. Do not pass secrets as `-var` values.

   ```bash
   az login
   cd terraform
   cp terraform.tfvars.example terraform.tfvars   # optional; edit github_repository if needed
   terraform init
   terraform apply
   ```

2. Write secrets with Azure CLI so they never enter Terraform state:

   ```bash
   terraform output -raw key_vault_name
   az keyvault secret set --vault-name "$(terraform output -raw key_vault_name)" \
     --name google-api-key --value "$GOOGLE_API_KEY"
   az keyvault secret set --vault-name "$(terraform output -raw key_vault_name)" \
     --name api-key-hashes --value "$API_KEY_HASHES"
   ```

   `API_KEY_HASHES` is JSON, for example `{"portfolio-user":"<sha256-digest>"}`. Create a digest without keeping the raw key in shell history:

   ```bash
   read -rs API_KEY; echo
   printf %s "$API_KEY" | sha256sum
   unset API_KEY
   ```

3. Copy these Terraform outputs into the GitHub `production` environment as secrets:

   | GitHub secret | Terraform output |
   |---|---|
   | `AZURE_CLIENT_ID` | `github_client_id` |
   | `AZURE_TENANT_ID` | `azure_tenant_id` |
   | `AZURE_SUBSCRIPTION_ID` | `azure_subscription_id` |
   | `AZURE_RESOURCE_GROUP` | `resource_group_name` |
   | `ACR_LOGIN_SERVER` | `acr_login_server` |

4. Protect `main` so **Azure security-gated build and deploy** is required. Push to `main`. CI publishes the scanned digest and updates the Container App.

5. Open `https://$(terraform output -raw container_app_fqdn)`. Enter the raw API key in the dashboard. The first request after idle can take longer because the API scales from zero.

More detail, including residual risk, is in `docs/azure.md`.

## API

`POST /api/analyze`

```json
{ "target_url": "https://example.com" }
```

Send the raw API key in `X-API-Key` when authentication is enabled. With Kafka enabled, the same route returns `202` and `GET /api/jobs/{job_id}` is the poll endpoint. `GET /health` is liveness. `GET /ready` fails until `GOOGLE_API_KEY` and the Azure job settings are present. `GET /metrics` is Prometheus text.

## Kubernetes (optional)

The original cluster path lives on the [`kubernetes`](https://github.com/SakthiS-oss/NukeSandbox/tree/kubernetes) branch. Check it out and follow that README (`cd terraform && terraform apply`, then `kubectl apply -k k8s`). That path can still use an egress proxy, Redis quotas, Kyverno, and Cosign.
