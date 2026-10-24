# NukeSandbox threat model

## Scope and assets

The API accepts an untrusted URL, executes `curl` in a disposable sandbox, sends scrubbed telemetry to Gemini, and returns a risk report. Protected assets are the host/cluster, cloud credentials, Gemini API key, internal network services, and the availability/cost budget for sandbox execution.

## Trust boundaries

1. Internet client to FastAPI API.
2. API to Docker daemon, Kubernetes API, or Azure Container Apps Job API.
3. Sandbox network to an arbitrary Internet destination.
4. API to Gemini.
5. CI to container registry and deployment controller.

## Threats and mitigations

| Threat | Mitigation | Residual risk |
|---|---|---|
| Command injection through URL input | `curl` receives an argument array; no shell is invoked. | Bugs in the image/runtime remain possible. |
| Container escape or privilege escalation | Non-root UID, dropped capabilities, no-new-privileges (`allowPrivilegeEscalation=false` in Kubernetes), read-only root filesystem, RuntimeDefault seccomp on both Docker and Kubernetes sandboxes, resource/deadline limits, and Kyverno enforcement. Azure mode uses a disposable Container Apps Job plus a job-only custom role. Sandbox images are digest-pinned. | Docker socket use is unsafe for production; use Kubernetes or Azure Container Apps mode. Container Apps Jobs expose fewer Linux securityContext knobs than Pods. |
| SSRF to localhost, RFC1918, or cloud metadata | DNS preflight rejects non-global addresses. curl is pinned to the validated address with `--resolve` and never follows redirects itself; the API re-validates and pins every redirect hop (max 5, http/https only). Tests cover loopback, private, metadata, mixed answers, pinning, blocked redirects, and loops. | Pinning does not apply when an egress proxy is configured; the proxy must enforce destination rules. Without a VNet, nothing below the application stops a compromised sandbox image from reaching private ranges. |
| Prompt injection through inspected content | The response body is discarded (`-o /dev/null`). Remaining telemetry is fenced with a random per-request boundary, sanitized (control characters, fence look-alikes, line length), and labeled as untrusted evidence in the prompt. curl result fields use a random marker so headers cannot forge them. | Header and TLS text still reaches the model inside the fence; a sufficiently persuasive string can still bias a report. Structured output limits the blast radius to the report itself. |
| Sandbox cost exhaustion | Every replica enforces an in-process per-identity window and a semaphore around each inspection. Kubernetes mode can also use Redis quotas and Pod quotas. Azure mode keeps cost down with API-key auth, those process limits, a 15-second Job timeout, scale-to-zero, and `max_replicas = 1`. | The process limits are not shared across replicas. Azure mode has no Redis or WAF. Several clients with valid keys can still start jobs, up to the per-key window. |
| Secret leakage | API key is injected from External Secrets Operator or Azure Key Vault. The raw target URL and hostname are stripped from the Gemini prompt; telemetry mentions are replaced with `<TARGET_URL>` / `<TARGET_HOST>`. | Telemetry can contain sensitive remote content; retention must be controlled in the log platform. |
| Compromised build/deployment | Semgrep, Trivy, and digest-only ACR deploys on `main`. The `kubernetes` branch can add Cosign, Kyverno, and GitOps. GitHub's Azure identity can update the API image only. | Azure CI does not yet verify a Cosign signature before `az containerapp update`. |

## Security verification

Run `pytest` to exercise SSRF blocking, command-array isolation, sandbox restrictions, and rate-limit enforcement. Apply Kyverno policies in a non-production cluster first using audit mode, then change to enforce after validating exemptions.
