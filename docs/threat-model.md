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
| Sandbox cost exhaustion | Redis per-client fixed-window quota, Pod quotas, and Prometheus alerts. | Distributed clients can still consume capacity; add identity-based quotas/WAF in production. |
| Secret leakage | API key is injected from External Secrets Operator or Azure Key Vault. The raw target URL and hostname are stripped from the Gemini prompt; telemetry mentions are replaced with `<TARGET_URL>` / `<TARGET_HOST>`. | Telemetry can contain sensitive remote content; retention must be controlled in the log platform. |
| Compromised build/deployment | Semgrep, Trivy, signed image policy, GitOps reconciliation, and canary rollout. | Signing keys/identity and policy controller availability must be operated securely. |

## Security verification

Run `pytest` to exercise SSRF blocking, command-array isolation, sandbox restrictions, and rate-limit enforcement. Apply Kyverno policies in a non-production cluster first using audit mode, then change to enforce after validating exemptions.
