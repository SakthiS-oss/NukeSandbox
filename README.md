# ☢️ NukeSandbox

NukeSandbox is a security-focused URL triage service. It runs a target URL in a short-lived, non-root sandbox, turns network telemetry into a plain-language assessment with Gemini, and demonstrates a production-minded DevSecOps delivery path.

## What this portfolio project demonstrates

- **Least-privilege sandboxing:** no Linux capabilities, no privilege escalation, read-only filesystems, CPU/memory/PID limits, and an execution deadline.
- **Kubernetes-native execution:** in-cluster mode creates a disposable restricted Pod for every inspection; the API service has namespace-scoped RBAC only for creating, reading logs from, and deleting those Pods.
- **Infrastructure as code:** Terraform provisions the namespace, restricted service account, Role/RoleBinding, and resource quota. It deliberately uses an existing cluster context so cloud credentials and cluster lifecycle remain separate from application state.
- **Secrets management:** production configuration uses External Secrets Operator (ESO) to materialize `GOOGLE_API_KEY` from a `ClusterSecretStore`; no secret is included in Git, the image, or a Kubernetes manifest.
- **Security gates:** GitHub Actions runs endpoint/security tests, Semgrep, and Trivy before publishing; release images receive an SPDX SBOM, build provenance attestation, and GitHub OIDC/Cosign signature that CD verifies before deployment.
- **Operability:** request IDs and OpenTelemetry spans correlate API, sandbox, and Gemini work. JSON logs are friendly to Loki/ELK-style collectors; Prometheus metrics expose request outcomes, sandbox duration, and cleanup outcomes at `/metrics`.
- **Abuse resistance:** URL DNS preflight blocks non-public addresses, and optional Redis-backed per-client quotas fail closed when the rate limiter is unavailable.
- **Outbound containment:** production sandbox Pods are egress-isolated to a Squid proxy, which reevaluates redirect destinations and blocks non-public ranges.

## Architecture

```text
GitHub Actions ── Semgrep + Trivy ──> build/scan image ──> Kubernetes deployment
                                                        │
Client ──> FastAPI ──(request ID + rate limit)──> temporary curl Pod ──> telemetry
              │                                             │
              ├── JSON logs + OTEL traces                   └── removed on completion
              └── /metrics ──> Prometheus/Grafana/alerts

External Secrets Operator ──> Kubernetes Secret ──> GOOGLE_API_KEY
```

## Local development

Prerequisites: Python 3.10+, Node 18+, and Docker Desktop.

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt

cd frontend && npm ci && npm run build && cd ..
cp .env.example .env  # then replace the placeholder local-development key
python3 main.py
pytest
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
4. Build and publish an image, then deploy its immutable digest rather than a mutable tag:

   ```bash
   kubectl apply -k k8s
   kubectl -n nukesandbox set image deployment/nukesandbox-api \
     api=ghcr.io/sakthis-oss/nukesandbox@sha256:YOUR_SIGNED_DIGEST
   ```

The workload uses `SANDBOX_EXECUTION_MODE=kubernetes`; it never mounts the host Docker socket. The network policy establishes a default ingress deny; add an ingress-controller policy appropriate to your environment. In production, additionally restrict egress at the CNI/firewall layer to DNS plus approved destinations—this matters because the product intentionally follows user-supplied URLs.

## Production add-ons

These components are intentionally separate from the base app because each requires its own cluster controller:

- **Tracing:** set `OTEL_EXPORTER_OTLP_ENDPOINT` to an OpenTelemetry Collector. The sample collector configuration is in `observability/otel-collector-config.yaml` and exports to Tempo.
- **Rate limiting:** set `RATE_LIMIT_ENABLED=true` and provide `REDIS_URL`; the API permits `RATE_LIMIT_REQUESTS` requests per `RATE_LIMIT_WINDOW_SECONDS` for each source IP. Use a managed, TLS-protected Redis service in production.
- **Dashboards and alerts:** import `observability/grafana-dashboard.json` into Grafana and apply `observability/prometheus-rules.yaml` when Prometheus Operator is installed.
- **Admission policy:** install Kyverno, validate `policies/kyverno-nukesandbox.yaml` in audit mode, then enforce it. It blocks hostPath/Docker socket mounts, privileged containers, `latest` images, missing limits, and unsigned NukeSandbox images.
- **GitOps and canaries:** install Argo CD, Argo Rollouts, and Argo CD Image Updater, then apply `gitops/argocd-application.yaml`. `gitops/canary-rollout.yaml` is a staged 25% → 50% → 100% release example.

See `docs/threat-model.md` for trust boundaries, attack paths, mitigations, and residual risk.

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

## Public deployment controls

Before exposing `/api/analyze`, enable `API_AUTH_REQUIRED`, store SHA-256 API-key digests in `API_KEY_HASHES`, and enable both Redis rate and concurrency limits. Generate a digest without writing the raw key to a shell history file:

```bash
read -rs API_KEY; echo
printf %s "$API_KEY" | sha256sum
unset API_KEY
```

Set the resulting value in the External Secret `nukesandbox/api-key-hashes`, for example `{"portfolio-user":"<sha256-digest>"}`. The API accepts the raw key only in the `X-API-Key` request header and uses the mapped identity for quota enforcement.

Kubernetes mode sets `REQUIRE_EGRESS_PROXY=true`: sandbox Pods may reach only cluster DNS and `nukesandbox-egress-proxy`. The proxy denies non-public destination ranges on every connection, including redirected requests. The image tag in `k8s/egress-proxy.yaml` should be replaced with a tested digest before a production rollout.
