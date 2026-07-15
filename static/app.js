const form = document.getElementById("analyze-form");
const btn = document.getElementById("analyze-btn");
const statusText = document.getElementById("status-text");
const result = document.getElementById("result");

const riskLevelEl = document.getElementById("risk-level");
const summaryEl = document.getElementById("summary");
const findingsEl = document.getElementById("findings");
const recommendationEl = document.getElementById("recommendation");
const telemetryEl = document.getElementById("telemetry");

function setStatus(message, isError = false) {
  statusText.textContent = message;
  statusText.style.color = isError ? "#ff9ca6" : "#9db6c8";
}

function renderReport(data) {
  const report = data.report;
  const risk = report.risk_level || "-";

  riskLevelEl.textContent = risk;
  riskLevelEl.className = "risk-badge";
  if (risk === "LOW") {
    riskLevelEl.classList.add("risk-low");
  } else if (risk === "MEDIUM") {
    riskLevelEl.classList.add("risk-medium");
  } else if (risk === "HIGH") {
    riskLevelEl.classList.add("risk-high");
  }

  summaryEl.textContent = report.summary || "No summary returned.";
  recommendationEl.textContent = report.user_recommendation || "No recommendation returned.";

  findingsEl.innerHTML = "";
  const findings = Array.isArray(report.technical_findings) ? report.technical_findings : [];
  if (findings.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No technical findings reported.";
    findingsEl.appendChild(li);
  } else {
    findings.forEach((item) => {
      const li = document.createElement("li");
      li.textContent = item;
      findingsEl.appendChild(li);
    });
  }

  telemetryEl.textContent = data.telemetry_excerpt || "No telemetry captured.";
  result.classList.remove("hidden");
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const targetInput = document.getElementById("target-url");
  const targetUrl = (targetInput.value || "").trim();
  if (!targetUrl) {
    setStatus("Please enter a URL before running analysis.", true);
    return;
  }

  btn.disabled = true;
  setStatus("Launching disposable sandbox and collecting telemetry...");

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_url: targetUrl }),
    });

    const payload = await response.json();

    if (!response.ok) {
      const detail = payload && payload.detail ? payload.detail : "Analysis failed.";
      throw new Error(String(detail));
    }

    renderReport(payload);
    setStatus("Analysis complete. Review findings below.");
  } catch (error) {
    setStatus(error instanceof Error ? error.message : "An unexpected error occurred.", true);
  } finally {
    btn.disabled = false;
  }
});
