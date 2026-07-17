# Scavibe

**AI-powered pre-launch audit for vibe-coded apps.**

Built using Codex + NVIDIA NIM.

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
│   COMPLIANCE             │  Reports what's missing (privacy policy, ToS,
│                          │  age/region gating)
│                          │  Can generate DRAFT legal documents on request
└────────────┬─────────────┘
             │
             ▼
   Full report + any pull requests opened on your repo
```

Scavibe can create an explicitly approved **draft artifact pull request**, never
a direct push. The implemented PR contains the evidence-backed report and,
for Legal, the generated working drafts. It does not modify application source
code. Source remediation patches require a separate reviewed patch workflow.

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
- scavibe-legal-audit-and-drafts.pdf

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
  TODO, dependency name, comment, or hypothetical endpoint.
- **Legal** maps observed data handling only to explicitly supplied
  jurisdictions. It does not state that a product is legally compliant or in
  violation of a law, and every report includes the legal-draft disclaimer.

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

---

## Legal Disclaimer

Any legal documents (Terms & Conditions, Privacy Policy, consent components) generated by Scavibe are **AI-generated starting drafts only**. They are not a substitute for review by a licensed attorney in your jurisdiction, and should not be published or relied upon as-is. Data protection requirements vary significantly by region (GDPR, CCPA, POPIA, and others), and Scavibe's output is meant to accelerate that process, not replace legal counsel.

---

## Tech Stack

| Layer | Choice |
|---|---|
| Frontend | Next.js 14 (App Router) + Tailwind CSS, deployed to Vercel |
| Backend | FastAPI (Python), async background tasks, deployed to Railway |
| LLM | NVIDIA NIM `nvidia/llama-3.3-nemotron-super-49b-v1` free trial endpoint — powers all three agent stages |
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
- An NVIDIA Build API key with access to the selected NVIDIA NIM endpoint

### Environment Variables

**Backend (`.env`)**
```
NVIDIA_API_KEY=nvapi-...
SCAVIBE_NVIDIA_MODEL=nvidia/llama-3.3-nemotron-super-49b-v1
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

Codex + NVIDIA NIM, used across all three agent stages for code understanding, security analysis, and document generation.
