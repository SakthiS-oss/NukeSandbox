import { ShieldCheck, AlertTriangle, Radar } from "lucide-react";
import { FormEvent, useState } from "react";
import { Button } from "./components/ui/button";
import { Card } from "./components/ui/card";
import { Input } from "./components/ui/input";
import { RiskBadge } from "./components/ui/risk-badge";

type RiskLevel = "LOW" | "MEDIUM" | "HIGH";

type SecurityReport = {
  risk_level: RiskLevel;
  summary: string;
  technical_findings: string[];
  user_recommendation: string;
};

type AnalyzeResponse = {
  target_url: string;
  telemetry_excerpt: string;
  report: SecurityReport;
};

const API_KEY_STORAGE = "nukesandbox.api-key";

function readStoredApiKey(): string {
  try {
    return sessionStorage.getItem(API_KEY_STORAGE) ?? "";
  } catch {
    return "";
  }
}

function rememberApiKey(value: string): void {
  try {
    sessionStorage.setItem(API_KEY_STORAGE, value);
  } catch {
    // Private-mode or blocked storage should not break analysis.
  }
}

function formatApiError(detail: unknown, fallback: string): string {
  if (typeof detail === "string" && detail.trim()) {
    return detail;
  }
  if (Array.isArray(detail) && detail.length > 0) {
    const first = detail[0] as { msg?: string };
    if (typeof first?.msg === "string") {
      return first.msg;
    }
  }
  return fallback;
}

export function App(): JSX.Element {
  const [url, setUrl] = useState("");
  const [apiKey, setApiKey] = useState(readStoredApiKey);
  const [status, setStatus] = useState("Ready to run analysis.");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<AnalyzeResponse | null>(null);

  async function onSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!url.trim()) {
      setError("Enter a URL to begin.");
      return;
    }

    setLoading(true);
    setError(null);
    setStatus("Launching sandbox and collecting telemetry...");

    try {
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (apiKey.trim()) {
        headers["X-API-Key"] = apiKey.trim();
      }

      const response = await fetch("/api/analyze", {
        method: "POST",
        headers,
        body: JSON.stringify({ target_url: url.trim() }),
      });

      const payload = (await response.json()) as AnalyzeResponse | { detail?: unknown };
      if (!response.ok) {
        throw new Error(formatApiError((payload as { detail?: unknown }).detail, "Analysis failed."));
      }

      setData(payload as AnalyzeResponse);
      setStatus("Analysis complete.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unexpected error.");
      setStatus("Analysis failed.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="min-h-screen bg-background text-foreground">
      <div className="pointer-events-none fixed -left-20 top-20 h-80 w-80 rounded-full bg-cyan-400/20 blur-3xl" />
      <div className="pointer-events-none fixed right-0 top-0 h-96 w-96 rounded-full bg-emerald-400/20 blur-3xl" />

      <div className="mx-auto w-[min(1040px,92vw)] py-10 animate-rise">
        <header className="mb-6">
          <p className="mb-2 inline-flex items-center gap-2 text-xs uppercase tracking-[0.2em] text-cyan-300">
            <Radar size={14} /> AI-Native Disposable Security Sandbox
          </p>
          <h1 className="font-display text-4xl font-bold md:text-5xl">NukeSandbox</h1>
          <p className="mt-3 max-w-3xl text-muted">
            Analyze unknown links in a locked-down disposable environment and get a clear, supportive risk explanation.
          </p>
        </header>

        <Card className="p-5">
          <form className="space-y-3" onSubmit={onSubmit}>
            <label className="text-sm text-muted" htmlFor="target-url">
              Target URL
            </label>
            <div className="grid gap-3 md:grid-cols-[1fr_auto]">
              <Input
                id="target-url"
                type="url"
                placeholder="https://example.com"
                value={url}
                onChange={(event) => setUrl(event.target.value)}
                required
              />
              <Button disabled={loading} type="submit">
                {loading ? "Analyzing..." : "Analyze"}
              </Button>
            </div>
            <label className="text-sm text-muted" htmlFor="api-key">
              API key
            </label>
            <Input
              id="api-key"
              type="password"
              autoComplete="off"
              placeholder="Required when the server enforces X-API-Key"
              value={apiKey}
              onChange={(event) => {
                setApiKey(event.target.value);
                rememberApiKey(event.target.value);
              }}
            />
            <p className="text-sm text-muted">{status}</p>
            {error ? <p className="text-sm text-rose-300">{error}</p> : null}
          </form>
        </Card>

        {data ? (
          <section className="mt-4 grid gap-4 md:grid-cols-2">
            <Card className="p-5 md:col-span-2">
              <div className="mb-2 flex items-center gap-2 text-sm text-cyan-200">
                <ShieldCheck size={16} /> Risk Level
              </div>
              <RiskBadge risk={data.report.risk_level} />
              <p className="mt-3 leading-relaxed text-slate-100">{data.report.summary}</p>
            </Card>

            <Card className="p-5">
              <div className="mb-2 flex items-center gap-2 text-sm text-amber-200">
                <AlertTriangle size={16} /> Technical Findings
              </div>
              <ul className="list-disc space-y-2 pl-5 text-sm text-slate-200">
                {data.report.technical_findings.length > 0 ? (
                  data.report.technical_findings.map((item) => <li key={item}>{item}</li>)
                ) : (
                  <li>No technical findings reported.</li>
                )}
              </ul>
            </Card>

            <Card className="p-5">
              <h2 className="mb-2 text-sm text-emerald-200">Recommendation</h2>
              <p className="text-sm leading-relaxed text-slate-100">{data.report.user_recommendation}</p>
            </Card>

            <Card className="p-5 md:col-span-2">
              <h2 className="mb-2 text-sm text-cyan-200">Telemetry Excerpt</h2>
              <pre className="max-h-80 overflow-auto rounded-lg border border-border bg-slate-950/70 p-3 text-xs text-slate-200">
                {data.telemetry_excerpt}
              </pre>
            </Card>
          </section>
        ) : null}
      </div>
    </main>
  );
}
