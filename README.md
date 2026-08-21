# ☢️ NukeSandbox

NukeSandbox is a security-focused URL triage service. It runs a target URL in a short-lived, non-root sandbox, turns network telemetry into a plain-language assessment with Gemini, and demonstrates a production-minded DevSecOps delivery path.

## What this portfolio project demonstrates

- **Least-privilege sandboxing:** no Linux capabilities, no privilege escalation, read-only filesystems, CPU/memory/PID limits, and an execution deadline.
- **Kubernetes-native execution:** in-cluster mode creates a disposable restricted Pod for every inspection; the API service has namespace-scoped RBAC only for creating, reading logs from, and deleting those Pods.
- **Infrastructure as code:** Terraform provisions the namespace, restricted service account, Role/RoleBinding, and resource quota. It deliberately uses an existing cluster context so cloud credentials and cluster lifecycle remain separate from application state.
- **Secrets management:** production configuration uses External Secrets Operator (ESO) to materialize `GOOGLE_API_KEY` from a `ClusterSecretStore`; no secret is included in Git, the image, or a Kubernetes manifest.
- **Security gates:** the GitHub Actions workflow fails pull requests on Semgrep SAST or Trivy filesystem/image findings rated High or Critical. Only an image that passes those checks can reach the deploy job.
- **Operability:** JSON logs are friendly to Loki/ELK-style collectors. Prometheus metrics expose request outcomes, sandbox duration, and cleanup outcomes at `/metrics`; Kubernetes probes use `/health` and `/ready`.

## Architecture

```text
GitHub Actions ── Semgrep + Trivy ──> build/scan image ──> Kubernetes deployment
                                                        │
Client ──> FastAPI ──(least-privilege RBAC)──> temporary curl Pod ──> telemetry
              │                                             │
              ├── JSON logs                                └── removed on completion
              └── /metrics ──> Prometheus/Grafana

External Secrets Operator ──> Kubernetes Secret ──> GOOGLE_API_KEY
```

## Local development

Prerequisites: Python 3.10+, Node 18+, and Docker Desktop.

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cd frontend && npm ci && npm run build && cd ..
cp .env.example .env  # then replace the placeholder local-development key
python main.py
```

Local mode defaults to the Docker runner. It uses `curlimages/curl`, which contains curl, instead of assuming the base Alpine image includes it. Visit `http://localhost:8000`; health and metrics are at `/health` and `/metrics`.

## Kubernetes deployment

1. Point `kubectl` and Terraform at a cluster. For a local demo, create one with kind or minikube.
2. Provision the isolated application boundary:

   ```bash
   cd terraform
   terraform init
   terraform apply
   ```

3. Install External Secrets Operator and configure a `ClusterSecretStore` named `vault-backend` (the supplied manifest assumes Vault; adapt the store and `remoteRef` values for AWS/GCP/Doppler).
4. Build and publish an image, replace `ghcr.io/your-org/nukesandbox:latest` in `k8s/deployment.yaml`, then apply the workload:

   ```bash
   kubectl apply -k k8s
   ```

The workload uses `SANDBOX_EXECUTION_MODE=kubernetes`; it never mounts the host Docker socket. The network policy establishes a default ingress deny; add an ingress-controller policy appropriate to your environment. In production, additionally restrict egress at the CNI/firewall layer to DNS plus approved destinations—this matters because the product intentionally follows user-supplied URLs.

### Required GitHub repository settings

Add `KUBECONFIG_DATA` as a protected environment secret, containing base64-encoded kubeconfig for a least-privilege deployment identity. Update the image name in `k8s/deployment.yaml` to your GHCR organization. Protect `main` so the **Security-gated build and deploy** check is required before merge.

## Security notes

- `.env` is strictly a local-development convenience and is ignored by Git. Kubernetes obtains secrets at runtime via ESO.
- The API's service account has no cluster-wide permissions and cannot list secrets, exec into Pods, or modify Deployments.
- Container cleanup runs on normal completion, failure, and timeout. Dashboarding the `nukesandbox_sandbox_duration_seconds` histogram and `nukesandbox_sandbox_teardowns_total` counter makes cleanup failures visible.

## API

`POST /api/analyze`

```json
{ "target_url": "https://example.com" }
```

`GET /health` checks process liveness, `GET /ready` confirms required runtime configuration is present, and `GET /metrics` exposes Prometheus-format metrics.
