# Scavibe

**AI-powered pre-launch audit for vibe-coded apps.**

Built using Codex. GPT-5.6 Terra is the primary audit provider; NVIDIA NIM is
an explicitly labeled credit-limited fallback.

---

## What is Scavibe?

Vibe coding — building apps by describing features to AI tools like Cursor, Lovable, v0, Bolt, or Codex — has made it possible for anyone to ship a working SaaS product in days. But speed comes at a cost: these apps consistently ship with broken authentication, missing authorization checks, SQL injection vulnerabilities, exposed secrets, and no plan for what happens when real traffic — or a real attacker — shows up.

Right now, catching these problems means hiring a security consultancy for $1,500+ and waiting 3-5 business days for a manually written report. Non-technical founders don't know to ask for this, and they usually find out the hard way.

Scavibe automates the audit. Paste your GitHub repo and deployed app URL, and three AI agents — Performance, Security, and Legal Compliance — work through your project in sequence, each producing a clear report and asking permission before making any changes.

---

## How It Works

```
GitHub repo URL + Deployed app URL
              │
              ▼
┌─────────────────────────┐
│   STAGE 1: PERFORMANCE   │  Deploys a disposable sandbox copy of your app
│                          │  Ramps simulated concurrent users to find the
│                          │  actual breaking point (10 → 25 → ... → 200)
│                          │  Reports response times, error rates, fixes
└────────────┬─────────────┘
             │ (asks permission before any change)
             ▼
┌─────────────────────────┐
│   STAGE 2: SECURITY      │  Reviews the codebase like a senior security
│                          │  analyst, using the OWASP Top 10 / ASVS
│                          │  Ranks findings by real exploitability, not
│                          │  just theoretical presence
└────────────┬─────────────┘
             │ (asks permission before any change)
             ▼
┌─────────────────────────┐
│   STAGE 3: LEGAL         │  Scans what user data is actually collected
│   DATA & CONSENT AUDIT   │  Reports evidence-backed data-handling and
│                          │  consent product recommendations
│                          │  Never drafts legal documents
└────────────┬─────────────┘
             │
             ▼
   Full report + any pull requests opened on your repo
```

Scavibe can create an explicitly approved **draft artifact pull request**, never
a direct push. The implemented PR contains the evidence-backed report and,
for the data-handling and consent stage, a consent-checkbox example. It does
not modify application source code. Source remediation patches require a
separate reviewed patch workflow.

---

## Why Sandbox Load Testing?

Running a load test directly against a live production URL can look identical to a denial-of-service attack to a hosting provider, and can generate unexpected billing on the user's own infrastructure. Scavibe defaults to deploying a temporary, disposable copy of the app and testing against that instead. Users can opt into testing their live URL directly, but only after an explicit warning and confirmation.

---

## Operational Scope and Report Downloads

The performance ramp is fixed at nine exploratory steps: "10, 25, 50, 75,
100, 125, 150, 175, 200" concurrent users. Each exploratory step lasts
exactly 12 seconds. Scavibe then confirms the first breach, or the 200-user
no-breach result, for exactly 60 seconds. A performance finding requires all
three qualifying measurements: at least 100 concurrent users, at least 60
seconds, and at least 20 completed samples. The thresholds are p95 latency
above 500 ms or error rate above 1.0%.

Each completed stage exports an actual PDF. Once all three stages finish, the
dashboard downloads one "scavibe-audit-reports.zip" archive containing:

- scavibe-performance-audit.pdf
- scavibe-security-audit.pdf
- scavibe-data-handling-and-consent-audit.pdf

Repository intake can select at most 120 supported text files, each no larger
than 131,072 bytes, with a total source-content cap of 2,097,152 bytes. A
specialist model receives at most 60 complete source files and 280,000
serialized JSON characters. The UI displays the selected-file count against
the repository manifest count. When any cap applies, the report explicitly
states that it cannot prove repository-wide absence of a problem.

---

## Agent Backbone (Current Implementation)

The backend runs three specialist agents in this fixed order: Performance,
Security, then Legal. A malformed or unsupported response fails its stage and
prevents later stages from running. No agent can change source code, deploy an
app, or open a pull request.

- **Performance** accepts sandbox measurements only. It can report p95 latency
  only when a test has at least 100 concurrent users, runs for at least 60
  seconds, has at least 20 samples, and exceeds 500 ms. It can report error
  rate only above 1.0% under those same minimum test conditions.
- **Security** requires a copied source quote with its exact file and inclusive
  line range for every finding. It rejects findings based only on a filename,
  TODO, dependency name, comment, or hypothetical endpoint. Every static
  finding is labeled `candidate_unconfirmed` unless a signed Scavibe sandbox
  returns the exact status and source-cited response marker required by a
  validated proof plan. The model may propose the plan, but Scavibe executes
  only its fixed one-GET template: 5.0-second timeout, no redirects, no query
  string, no request body, no authentication header, and an exact sandbox-host
  match. The report and PDF retain proposed code, executed code, response
  status, a response excerpt capped at 4,096 bytes, its SHA-256, and the final
  confirmation state. Unsafe or incomplete plans remain unconfirmed.
- **Data-handling and consent** maps observed data handling only to explicitly supplied
  jurisdictions. It does not state that a product is legally compliant or in
  violation of a law, and every report includes the legal disclaimer.

Severity is calculated in code as `impact points + attacker-access points`,
capped at 100: critical 90-100, high 70-89, medium 40-69, low 1-39, info 0.
Confidence is evidence-derived: a validated source location contributes 35
points, a validated sandbox measurement contributes 50 points, and a second
distinct evidence item adds 15 points, capped at 100. The model cannot set
either score.

The agent API takes a pinned 40-character commit SHA plus exact source,
repository path manifest, sandbox measurements, and jurisdictions. GitHub
cloning and sandbox provisioning remain separate integrations; the API does
not imitate either one.

### Audit-provider selection

`SCAVIBE_LLM_PROVIDER=openai` is the default and sends specialist audit prompts
to OpenAI's Responses API using GPT-5.6 Terra (`gpt-5.6-terra`).
`SCAVIBE_LLM_PROVIDER=nvidia` sends the same validated specialist prompts to
NVIDIA NIM's Chat Completions API instead. It is a fallback for a credit-limited
deployment, not GPT-5.6 output. Every specialist report and PDF identifies the
exact analysis engine that produced it.

For Security, NVIDIA mode and auto fallback use the verified free NVIDIA API
endpoint `deepseek-ai/deepseek-v4-pro`. Other NVIDIA specialist calls use
`SCAVIBE_NVIDIA_MODEL`, or its documented default when that variable is absent.

`SCAVIBE_LLM_PROVIDER=auto` tries OpenAI first for every specialist request and
retries once with NVIDIA only after an OpenAI gateway failure (HTTP failure,
timeout, invalid API response, or empty API response). It requires both keys.
The next request returns to GPT-5.6 automatically as soon as OpenAI succeeds.
Agent-draft validation, evidence rejection, and proof-of-concept safety
rejection do not trigger fallback because they are not API availability errors.

The performance ramp does not use either LLM. It is a deterministic, bounded
HTTP GET measurement against the authorized disposable sandbox; the report
identifies it as such.

---

## Legal Disclaimer

Scavibe does not draft policy text, terms, or other legal documents. Its data-handling and consent audit identifies evidence-backed product gaps and recommends specific UI or process changes. It is not a substitute for review by a licensed attorney in the relevant jurisdiction.

---

## Tech Stack

| Layer | Choice |
|---|---|
| Frontend | Next.js 14 (App Router) + Tailwind CSS, deployed to Vercel |
| Backend | FastAPI (Python), async background tasks, deployed to Railway |
| Specialist audit provider | OpenAI Responses API with GPT-5.6 Terra (`gpt-5.6-terra`) by default; NVIDIA NIM only when explicitly selected and labeled in every report |
| Load testing | Async HTTPX bounded GET ramp against an authorized sandbox deployment |
| GitHub integration | GitHub API — reads repos, opens pull requests |
| Storage | PDFs are generated per request; the backend does not claim persistent report storage |
| Real-time updates | Server-Sent Events for the ramp and specialist-stage evidence milestones |

---

## Setup

### Prerequisites
- Node.js 18+
- Python 3.11+
- A GitHub personal access token (repo scope)
- One provider credential: an OpenAI API key with GPT-5.6 Terra access, or an NVIDIA NIM API key for the explicitly labeled fallback

### Environment Variables

**Backend (`.env`)**
```
# Select exactly one provider: openai, nvidia, or auto.
SCAVIBE_LLM_PROVIDER=openai
OPENAI_API_KEY=your_openai_project_key
# NVIDIA fallback example:
# SCAVIBE_LLM_PROVIDER=nvidia
# NVIDIA_API_KEY=your_nvidia_nim_key
# SCAVIBE_NVIDIA_MODEL=nvidia/llama-3.3-nemotron-super-49b-v1.5  # non-Security NVIDIA calls
# Automatic recovery, requiring both keys:
# SCAVIBE_LLM_PROVIDER=auto
GITHUB_TOKEN=ghp_...
BLOB_READ_WRITE_TOKEN=...
```

**Frontend (`.env.local`)**
```
NEXT_PUBLIC_BACKEND_URL=https://your-backend-url.railway.app
```

### Running Locally

```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn main:app --reload

# Frontend
npm install
npm run dev
```

The Next.js frontend lives at the repository root. The FastAPI service lives in
`backend/` and currently exposes the safe audit-job lifecycle used by the UI.
Live repository cloning, sandbox deployment, AI analysis, and pull-request
creation are the next integration layer; the UI intentionally never sends load
traffic to a production URL by default.

---

## Scope Notes (Hackathon Build)

- Supports public GitHub repositories only
- Load testing tuned for common frameworks (Next.js, Express, Flask, Django)
- Load test ceiling is capped conservatively for demo safety — not a full production stress-test suite
- Legal compliance stage identifies common data-collection patterns; it is not exhaustive across all jurisdictions

---

## Built With

Codex + GPT-5.6, used across all three agent stages for code understanding, security analysis, and document generation.
