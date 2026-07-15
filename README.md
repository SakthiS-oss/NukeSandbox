# ☢️ NukeSandbox

> *Formerly NotionGuard*

An AI-native, enterprise-grade security orchestration pipeline that programmatically provisions short-lived, heavily unprivileged Docker sandboxes to safely execute and triage untrusted URLs and scripts.

By wrapping system-level telemetry collection inside an automated container lifecycle, **NukeSandbox** intercepts raw network/console logs, structures the payload, and leverages the Google GenAI SDK (`gemini-2.5-flash`) to generate empathetic, jargon-free security assessments streamed directly to a high-fidelity Next.js user dashboard.

---

## 🏛️ Philosophy & Core Architecture

> *"The technology of the future should not just protect us; it should augment our ability to explore the digital world without fear."*
> — Inspired by computing pioneers Douglas Engelbart and Alan Kay.

In modern workflows, collaboration happens across endless apps, tabs, and shared links. A single malicious string shouldn't compromise an entire workspace or local machine. NukeSandbox follows the principle of **computational bootstrapping** — using isolated, highly specialized programmatic environments to protect and elevate human throughput.

Instead of traditional, resource-heavy VM sandboxing or risky local process-spawning, NukeSandbox leverages a strict web-to-system micro-orchestration loop:

```
[ Next.js Frontend ] ──(POST /api/analyze)──> [ FastAPI Backend ]
                                                       │
                                               (Pipes Docker Daemon)
                                                       ▼
                                          ┌────────────────────────┐
                                          │   Isolated Alpine Pod  │
                                          │   - cap_drop: ALL      │
                                          │   - read_only: True    │
                                          │   - mem_limit: 128m    │
                                          │   - curl execution     │
                                          └────────────────────────┘
                                                       │
                                          (Extracts Telemetry Log)
                                                       ▼
[ User Dashboard ] <──(Validates JSON)─── [ Gemini Flash API ]
```

### Engineered Safety Profiles

- **Zero Command Injection Vectors:** The target URL is injected directly as a decoupled token element inside a literal execution array (`["curl", "-v", ..., target_url]`). It completely bypasses shell parsing (`sh -lc`), rendering command chain attacks (e.g. `; rm -rf /`) entirely non-executable.

- **Kernel Capability Drops:** The container initializes with `cap_drop=["ALL"]` and `security_opt=["no-new-privileges:true"]`. Even if an attacker uncovers an execution exploit inside the sandbox's curl layer, the sub-process lacks the fundamental kernel capabilities needed to escalate privilege or affect the host system.

- **Strict Resource Caps & Read-Only Root:** The sandbox mounts a completely `read_only` root filesystem alongside a hard memory ceiling of `128m` and a `pids_limit=64`. This structurally prevents memory exhaustion (DoS) or filesystem-based persistence attacks.

- **Deterministic Garbage Collection:** Backed by a multithreaded watchdog `Timer` tracking a strict 10-second ceiling, the backend triggers an explicit `.remove(force=True)` routine on the container ID inside a native `finally` block, eliminating ghost container sprawl.

---

## 🛠️ Tech Stack

| Layer | Tools |
|---|---|
| **Frontend** | Next.js, React, TypeScript, TailwindCSS, Vercel AI SDK |
| **Backend** | Python 3.10+, FastAPI, Uvicorn |
| **DevOps / Orchestration** | Docker Engine, Docker SDK for Python |
| **AI & Validation** | Google GenAI SDK (`gemini-2.5-flash`), Pydantic |
| **Configuration** | Python-Dotenv |

---

## 📂 Repository Structure

```
nuke-sandbox/
│
├── main.py                 # Core FastAPI Orchestrator & GenAI Pipeline
├── .env                    # Local runtime variables (git-ignored)
├── .env.example            # Public reference blueprint for configuration
├── requirements.txt        # Backend dependencies
├── README.md               # Project documentation
│
└── frontend/               # Next.js/React Interface Source
    ├── package.json        # Node dependency manifest
    ├── vite.config.ts      # Client asset compilation mappings
    ├── src/                # Frontend component logic
    └── dist/               # Production build output (served by main.py)
        ├── index.html      # Compiled single-page document
        └── assets/         # Optimized CSS and JS bundles
```

---

## ⚡ Setup & Installation

### Prerequisites

- Python **3.10+**
- Node.js **LTS (v18+)** and npm
- **Docker Desktop** installed, configured, and actively running

### 1. Backend Configuration

```bash
# Clone the repo and navigate to the project root
git clone https://github.com/your-username/nuke-sandbox.git
cd nuke-sandbox

# Create and activate a virtual environment
python -m venv venv

# macOS/Linux:
source venv/bin/activate

# Windows PowerShell:
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### 2. Environment Variables

Create a `.env` file in the project root:

```env
# Google AI Studio API Key
GOOGLE_API_KEY="AIzaSyYourActualKeyFromGoogleAIStudio"

# Model overrides (optional)
NOTIONGUARD_MODEL="gemini-2.5-flash"
NUKESANDBOX_MODEL="gemini-2.5-flash"
```

### 3. Frontend Compilation

```bash
cd frontend
npm install
npm run build
```

> **Note:** Ensure your bundler outputs to `frontend/dist/` so `main.py` can serve `index.html` via `FileResponse`.

### 4. Start the Server

```bash
# From the project root (venv active)
python main.py
```

Then open your browser and navigate to **http://localhost:8000**.

---

## 🧪 API Reference

### `GET /health`

Basic connectivity ping.

**Response:**
```json
{
  "status": "ok"
}
```

---

### `POST /api/analyze`

Executes the URL triage sandbox pipeline.

**Request:**
```json
{
  "target_url": "https://example.com"
}
```

**Response:**
```json
{
  "target_url": "https://example.com",
  "telemetry_excerpt": "[Raw network output, curl diagnostics, SSL cert data...]",
  "report": {
    "risk_level": "LOW",
    "summary": "This webpage appears safe to browse...",
    "technical_findings": [
      "HTTP/2 200 OK response confirmed",
      "SSL certificate issued by a trusted CA",
      "No anomalous subdomain redirects detected"
    ],
    "user_recommendation": "You can safely follow this link inside your active workspace."
  }
}
```

**Error Codes:**

| Code | Meaning |
|---|---|
| `400 Bad Request` | URL does not validate as `http` or `https` |
| `422 Unprocessable Entity` | Sandbox ran successfully but returned empty output (host unresolvable) |
| `502 Bad Gateway` | Execution breached the 10-second timeout, or Docker returned a runtime error |

---

## 🧠 UX & Engineering Empathy

When security alerts are written in hyper-technical jargon, users experience alert fatigue and tune them out. NukeSandbox treats **communication as an engineering feature**.

The Gemini pipeline enforces strict type mapping (`LOW`, `MEDIUM`, `HIGH`) via structured output schemas while instructing the model to compose user-facing copy with clarity and empathy.

**Instead of raw output like:**
```
TLSv1.3 / Alert (Level: Fatal, Description: Certificate Unknown)
```

**NukeSandbox surfaces:**
> *"We noticed this link is routing your browser through an unrecognized encryption path. This typically happens when a site is mimicking a legitimate corporate login window. We recommend you do not type or paste any personal passwords on this page."*

---

## 🔒 Security & Code Quality

- **Strict Type Assertions:** Written with modern Python type hints and Pydantic parsing wrappers for cross-service input integrity.
- **Zero Prompt Leakage:** A native `_redact_url_in_text()` regex routine actively scrubs injected target URLs into a unified `<TARGET_URL>` placeholder before dispatching payloads to external LLM channels.
