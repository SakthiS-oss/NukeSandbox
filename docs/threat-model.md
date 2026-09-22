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
| SSRF to localhost, RFC1918, or cloud metadata | DNS preflight rejects non-global addresses; tests cover loopback, private, metadata, and mixed answers. | DNS rebinding after preflight requires CNI/egress-proxy enforcement. |
| Sandbox cost exhaustion | Kubernetes mode can use Redis quotas and Pod quotas. Azure mode keeps cost down with API-key auth, a 15-second Job timeout, scale-to-zero, and `max_replicas = 1`. | Azure mode has no Redis/WAF. Distributed clients with a valid key can still start jobs until you add a cache or Front Door. |
| Secret leakage | API key is injected from External Secrets Operator or Azure Key Vault. The raw target URL and hostname are stripped from the Gemini prompt; telemetry mentions are replaced with `<TARGET_URL>` / `<TARGET_HOST>`. | Telemetry can contain sensitive remote content; retention must be controlled in the log platform. |
| Compromised build/deployment | Semgrep, Trivy, and digest-only ACR deploys on the Azure branch. The Kubernetes path can add Cosign, Kyverno, and GitOps. GitHub's Azure identity can update the API image only. | Azure CI does not yet verify a Cosign signature before `az containerapp update`. |

## Security verification

Run `pytest` to exercise SSRF blocking, command-array isolation, sandbox restrictions, and rate-limit enforcement. Apply Kyverno policies in a non-production cluster first using audit mode, then change to enforce after validating exemptions.
