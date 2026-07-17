"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";

type Stage = "performance" | "security" | "legal";
type Finding = {
  title: string;
  statement: string;
  remediation: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  risk_score: number;
  confidence_score: number;
  evidence: Array<{ kind: string; file_path?: string; start_line?: number; end_line?: number; endpoint?: string; observed_value?: number; threshold?: number; metric?: string }>;
};
type Report = { stage: Stage; summary: string; findings: Finding[]; limitations: string[]; evidence_commit_sha: string };
type StageResult = {
  stage: Stage;
  repository: { commit_sha: string; selected_files: string[]; source_content_complete: boolean };
  report: Report;
  measurement?: { concurrent_users: number; duration_seconds: number; sample_count: number; p95_latency_ms: number; error_rate_percent: number };
  successful_requests?: number;
  failed_requests?: number;
  sandbox_teardown?: string;
};
type SandboxSuggestion = { url: string; provider: string; environment: string; commit_sha: string };
type VercelSandbox = { deployment_id: string; ready_state: string; deployment_url?: string; ticket: string; expires_at: number; commit_sha: string };

const stages: Array<{ id: Stage; number: string; name: string; label: string }> = [
  { id: "performance", number: "01", name: "Performance", label: "Sandbox load lab" },
  { id: "security", number: "02", name: "Cybersecurity", label: "OWASP evidence review" },
  { id: "legal", number: "03", name: "Legal", label: "Data & policy review" },
];
const jurisdictionOptions = ["KE", "EU", "US-CA"];

function apiUrl(path: string) {
  const base = (process.env.NEXT_PUBLIC_BACKEND_URL || "/api").replace(/\/$/, "");
  return `${base}${path}`;
}

async function apiRequest<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(apiUrl(path), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail || `Request failed with HTTP ${response.status}`);
  return payload as T;
}

function Icon({ name }: { name: "arrow" | "check" | "bolt" | "shield" | "scale" | "download" | "branch" | "lock" }) {
  const paths = {
    arrow: <path d="M5 12h14m-6-6 6 6-6 6" />,
    check: <path d="m5 12 4 4L19 6" />,
    bolt: <path d="m13 2-9 12h7l-1 8 10-13h-7l0-7Z" />,
    shield: <path d="M12 3 5 6v5c0 5 3 8.5 7 10 4-1.5 7-5 7-10V6l-4 4-2-2" />,
    scale: <path d="M12 3v18m-7 0h14M5 7h14M5 7l-3 6h6L5 7Zm14 0-3 6h6l-3-6Z" />,
    download: <path d="M12 3v11m0 0 4-4m-4 4-4-4m-5 9h18" />,
    branch: <path d="M6 3v12m0-12a3 3 0 1 0 0 6 3 3 0 0 0 0-6Zm0 12a3 3 0 1 0 0 6 3 3 0 0 0 0-6Zm12-6a3 3 0 1 0 0 6 3 3 0 0 0 0-6Zm-9-3c0 3 2 6 6 6" />,
    lock: <path d="M7 10V7a5 5 0 0 1 10 0v3m-11 0h12v10H6V10Zm6 4v2" />,
  };
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>;
}

export default function Home() {
  const [stage, setStage] = useState<Stage | null>(null);
  const [repository, setRepository] = useState("");
  const [appUrl, setAppUrl] = useState("");
  const [sandboxUrl, setSandboxUrl] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [users, setUsers] = useState(100);
  const [duration, setDuration] = useState(60);
  const [jurisdictions, setJurisdictions] = useState<string[]>(["KE"]);
  const [results, setResults] = useState<Partial<Record<Stage, StageResult>>>({});
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const [prApproved, setPrApproved] = useState(false);
  const [prUrl, setPrUrl] = useState("");
  const [sandboxSuggestions, setSandboxSuggestions] = useState<SandboxSuggestion[]>([]);
  const [suggestingSandbox, setSuggestingSandbox] = useState(false);
  const [useScavibeSandbox, setUseScavibeSandbox] = useState(false);
  const [sandboxStatus, setSandboxStatus] = useState("");

  const activeResult = stage ? results[stage] : undefined;
  const payload = useMemo(() => ({
    repository_url: repository.trim(),
    app_url: appUrl.trim(),
    sandbox_url: sandboxUrl.trim() || undefined,
    sandbox_authorized: authorized,
    concurrent_users: users,
    duration_seconds: duration,
    jurisdictions,
  }), [repository, appUrl, sandboxUrl, authorized, users, duration, jurisdictions]);

  useEffect(() => {
    const value = repository.trim();
    if (!/^https:\/\/github\.com\/[^/]+\/[^/]+\/?$/.test(value)) {
      setSandboxSuggestions([]);
      return;
    }
    let active = true;
    const timer = window.setTimeout(async () => {
      setSuggestingSandbox(true);
      try {
        const response = await fetch(`${apiUrl("/sandbox-suggestions")}?repository_url=${encodeURIComponent(value)}`);
        const suggestions = response.ok ? await response.json() : [];
        if (active) setSandboxSuggestions(suggestions as SandboxSuggestion[]);
      } catch {
        if (active) setSandboxSuggestions([]);
      } finally {
        if (active) setSuggestingSandbox(false);
      }
    }, 700);
    return () => { active = false; window.clearTimeout(timer); };
  }, [repository]);

  function start(event: FormEvent) {
    event.preventDefault();
    setError("");
    if (!repository.trim() || !appUrl.trim() || (!sandboxUrl.trim() && !useScavibeSandbox)) {
      setError("Repository URL and deployed app URL are required. Select a sandbox URL or enable the Scavibe disposable sandbox.");
      return;
    }
    setStage("performance");
  }

  async function runStage() {
    if (!stage) return;
    setRunning(true); setError(""); setPrUrl("");
    try {
      let result: StageResult;
      if (stage === "performance" && useScavibeSandbox) {
        setSandboxStatus("Creating isolated Vercel project for the pinned GitHub commit…");
        const created = await apiRequest<VercelSandbox>("/sandboxes/vercel", {
          repository_url: repository.trim(), authorized_deployment: true,
        });
        let sandbox = created;
        for (let attempt = 1; attempt <= 36; attempt += 1) {
          if (sandbox.ready_state.toUpperCase() === "READY" && sandbox.deployment_url) break;
          if (["ERROR", "CANCELED"].includes(sandbox.ready_state.toUpperCase())) throw new Error(`Vercel sandbox build ended as ${sandbox.ready_state}. No load test was sent.`);
          setSandboxStatus(`Vercel build state: ${sandbox.ready_state}. Readiness check ${attempt}/36.`);
          await new Promise((resolve) => window.setTimeout(resolve, 5000));
          const response = await fetch(`${apiUrl(`/sandboxes/vercel/${created.deployment_id}`)}?ticket=${encodeURIComponent(created.ticket)}`);
          const statusPayload = await response.json().catch(() => ({}));
          if (!response.ok) throw new Error(statusPayload.detail || `Sandbox status failed with HTTP ${response.status}`);
          sandbox = statusPayload as VercelSandbox;
        }
        if (sandbox.ready_state.toUpperCase() !== "READY" || !sandbox.deployment_url) {
          throw new Error("Vercel did not report READY within 180 seconds. No load test was sent.");
        }
        setSandboxUrl(sandbox.deployment_url);
        setSandboxStatus("Sandbox ready. Sending bounded GET traffic, then deleting the sandbox project…");
        result = await apiRequest<StageResult>(`/sandboxes/vercel/${sandbox.deployment_id}/load-test`, {
          repository_url: repository.trim(), app_url: appUrl.trim(), ticket: sandbox.ticket,
          concurrent_users: users, duration_seconds: duration, jurisdictions,
        });
        setSandboxStatus(result.sandbox_teardown === "deleted" ? "Sandbox project deleted after the test." : `Sandbox teardown: ${result.sandbox_teardown || "not reported"}`);
      } else {
        result = await apiRequest<StageResult>(`/audit-stages/${stage}`, payload);
      }
      setResults((current) => ({ ...current, [stage]: result }));
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "The audit request failed.");
    } finally { setRunning(false); }
  }

  function nextStage() {
    if (stage === "performance") setStage("security");
    if (stage === "security") setStage("legal");
  }

  async function requestPullRequest() {
    if (!activeResult || !prApproved) return;
    setRunning(true); setError("");
    try {
      const result = await apiRequest<{ url: string }>("/audit-stages/pull-request", {
        repository_url: repository,
        report: activeResult.report,
        jurisdictions,
        approved: true,
      });
      setPrUrl(result.url);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Pull request creation failed.");
    } finally { setRunning(false); }
  }

  async function downloadLegalBundle() {
    if (!activeResult) return;
    setRunning(true); setError("");
    try {
      const response = await fetch(apiUrl("/audit-stages/legal-artifacts"), {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ report: activeResult.report, jurisdictions }),
      });
      if (!response.ok) {
        const message = await response.json().catch(() => ({}));
        throw new Error(message.detail || `Download failed with HTTP ${response.status}`);
      }
      const link = document.createElement("a");
      link.href = URL.createObjectURL(await response.blob());
      link.download = "scavibe-legal-drafts.zip";
      link.click();
      URL.revokeObjectURL(link.href);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Legal draft download failed.");
    } finally { setRunning(false); }
  }

  function toggleJurisdiction(value: string) {
    setJurisdictions((current) => current.includes(value) ? current.filter((item) => item !== value) : [...current, value]);
  }

  if (!stage) {
    return <main className="audit-shell"><div className="grid-noise" /><nav className="topbar"><a className="logo" href="#"><span>sc</span>avibe</a><p><i /> evidence-first launch audits</p></nav><section className="launch-wrap"><div className="launch-copy"><span className="eyebrow">The pre-launch control room</span><h1>See what your app does before users do.</h1><p>Bring a public GitHub repository. Use your own disposable deployment, or let Scavibe create an isolated Vercel build with no production secrets.</p><div className="promise-row"><span><Icon name="lock" /> Sandbox only</span><span><Icon name="check" /> Evidence pinned to commit</span></div></div><form className="intake-card" onSubmit={start}><div className="card-heading"><span>Begin a real audit</span><small>Stage 01 of 03</small></div><label>Public GitHub repository<input type="url" value={repository} onChange={(event) => setRepository(event.target.value)} placeholder="https://github.com/owner/repository" required /></label><label>Deployed app URL<input type="url" value={appUrl} onChange={(event) => setAppUrl(event.target.value)} placeholder="https://your-app.vercel.app" required /></label><label className="checkline sandbox-choice"><input type="checkbox" checked={useScavibeSandbox} onChange={(event) => setUseScavibeSandbox(event.target.checked)} /><span>Use a disposable Scavibe Vercel sandbox. It receives no production environment variables and is deleted after this load test.</span></label><label>Authorized sandbox URL {useScavibeSandbox ? "(manual alternative)" : ""}<input type="url" value={sandboxUrl} onChange={(event) => setSandboxUrl(event.target.value)} placeholder="https://preview-your-app.vercel.app" required={!useScavibeSandbox} /></label>{suggestingSandbox && <p className="suggestion-note">Searching GitHub deployment statuses for this repository…</p>}{sandboxSuggestions.length > 0 && <div className="sandbox-suggestions"><span>Suggested deployment URLs</span>{sandboxSuggestions.map((suggestion) => <button key={suggestion.url} type="button" onClick={() => setSandboxUrl(suggestion.url)}><i><Icon name="check" /></i><b>{suggestion.provider}</b><code>{suggestion.url}</code><small>{suggestion.environment} · {suggestion.commit_sha.slice(0, 8)}</small></button>)}<p>Suggestions come from GitHub deployment status evidence. Select one only if it is your disposable sandbox.</p></div>}<label className="checkline"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} /><span>I own or am explicitly authorized to load test this sandbox or deploy this repository in the Scavibe sandbox.</span></label>{error && <p className="form-error">{error}</p>}<button className="primary" type="submit" disabled={!authorized}>Enter performance lab <Icon name="arrow" /></button></form></section><footer>Scavibe never sends load traffic to your live URL by default.</footer></main>;
  }

  const stageMeta = stages.find((item) => item.id === stage)!;
  const canAdvance = Boolean(activeResult) && stage !== "legal";
  const sceneIcon = stage === "performance" ? "bolt" : stage === "security" ? "shield" : "scale";
  return <main className={`audit-shell stage-${stage}`}><div className="grid-noise" /><nav className="topbar"><button className="logo button-logo" onClick={() => setStage(null)}><span>sc</span>avibe</button><p><i /> pinned repository audit</p></nav><div className="audit-layout"><aside className="pipeline"><div className="pipeline-title">Launch sequence<span>{stageMeta.label}</span></div>{stages.map((item, index) => { const complete = Boolean(results[item.id]); const active = item.id === stage; const locked = index > 0 && !results[stages[index - 1].id]; return <button key={item.id} className={`pipe-stage ${active ? "active" : ""} ${complete ? "complete" : ""}`} disabled={locked} onClick={() => setStage(item.id)}><b>{complete ? <Icon name="check" /> : item.number}</b><span>{item.name}<small>{complete ? "Report ready" : active ? "Current stage" : locked ? "Locked" : "Ready"}</small></span></button>; })}<div className="pipeline-note"><Icon name="lock" /> Each stage uses the exact Git commit returned by GitHub. Results never infer unseen source files.</div></aside><section className="stage-content"><header className="stage-header"><div><span className="eyebrow">{stageMeta.number} / {stageMeta.label}</span><h1>{stage === "performance" ? "Measure the point it bends." : stage === "security" ? "Follow the path an attacker sees." : "Make every data promise visible."}</h1></div><span className="commit-pill">{activeResult ? `commit ${activeResult.repository.commit_sha.slice(0, 8)}` : "Awaiting repository scan"}</span></header><div className="work-grid"><section className="lab-card"><div className="scene-head"><span><Icon name={sceneIcon as "bolt"} /> {stage === "performance" ? "Sandbox traffic map" : stage === "security" ? "OWASP inspection trace" : "Data-use document map"}</span><b>{running ? "Running" : activeResult ? "Measured" : "Ready"}</b></div><StageScene stage={stage} users={users} result={activeResult} running={running} /><div className="control-board">{stage === "performance" && <><label className="range-label">Concurrent users <strong>{users}</strong><input type="range" min="10" max="200" step="10" value={users} onChange={(event) => setUsers(Number(event.target.value))} /></label><label className="range-label">Test duration <strong>{duration}s</strong><input type="range" min="30" max="300" step="30" value={duration} onChange={(event) => setDuration(Number(event.target.value))} /></label><p className="safe-copy"><Icon name="lock" /> Hard safety limit: 200 users for 300 seconds. The test sends GET requests only to the authorized sandbox root.</p>{sandboxStatus && <p className="sandbox-status">{sandboxStatus}</p>}</>}{stage === "security" && <p className="stage-explainer">The repository is pinned to one Git commit, then the specialist reviews supplied source evidence for authentication, authorization, input handling, secrets, and dependency signals. Findings without exact source evidence are rejected.</p>}{stage === "legal" && <><p className="stage-explainer">Choose every jurisdiction you want reviewed. The legal stage maps observed collection signals; it does not declare legal compliance.</p><div className="jurisdiction-row">{jurisdictionOptions.map((item) => <button key={item} onClick={() => toggleJurisdiction(item)} className={jurisdictions.includes(item) ? "selected" : ""}>{jurisdictions.includes(item) && <Icon name="check" />}{item}</button>)}</div></>}</div><button className="primary run-stage" onClick={runStage} disabled={running || (stage === "legal" && jurisdictions.length === 0)}>{running ? "Auditing exact evidence…" : activeResult ? "Run this stage again" : stage === "performance" ? "Run authorized sandbox test" : `Analyze repository for ${stage}`}<Icon name="arrow" /></button>{error && <p className="form-error panel-error">{error}</p>}</section><ReportPanel result={activeResult} stage={stage} /></div>{activeResult && <section className="evidence-section"><div className="evidence-top"><div><span className="eyebrow">Evidence set</span><h2>Files actually analyzed</h2><p>{activeResult.repository.source_content_complete ? "The supplied source selection includes every supported text file in the repository." : "The source selection reached a hard cap; absence claims are limited to the supplied files."}</p></div><span>{activeResult.repository.selected_files.length} selected files</span></div><div className="file-strip">{activeResult.repository.selected_files.slice(0, 16).map((path) => <code key={path}>{path}</code>)}</div></section>}{activeResult && <section className="action-row"><div><span className="eyebrow">Controlled next move</span><h2>{stage === "legal" ? "Generate the legal review pack." : "Keep the evidence with your repository."}</h2><p>{stage === "legal" ? "Download draft policy, terms, review notes, and a consent component. All legal files are marked as attorney-review drafts." : "A pull request is created only after you approve it. It contains the evidence-backed report—not unreviewed source-code changes."}</p></div><div className="actions"><label className="checkline"><input type="checkbox" checked={prApproved} onChange={(event) => setPrApproved(event.target.checked)} /><span>I approve a draft PR containing generated audit artifacts.</span></label><button className="secondary" disabled={!prApproved || running} onClick={requestPullRequest}><Icon name="branch" /> Create draft PR</button>{stage === "legal" && <button className="secondary" disabled={running} onClick={downloadLegalBundle}><Icon name="download" /> Download legal pack</button>}{prUrl && <a className="pr-link" href={prUrl} target="_blank" rel="noreferrer">Open draft pull request <Icon name="arrow" /></a>}{canAdvance && <button className="primary next-button" onClick={nextStage}>Continue to {stage === "performance" ? "cybersecurity" : "legal"}<Icon name="arrow" /></button>}</div></section>}</section></div></main>;
}

function StageScene({ stage, users, result, running }: { stage: Stage; users: number; result?: StageResult; running: boolean }) {
  const [progress, setProgress] = useState(result ? 100 : 0);

  useEffect(() => {
    if (!running) {
      setProgress(result ? 100 : 0);
      return;
    }
    setProgress(8);
    const timer = window.setInterval(() => setProgress((current) => Math.min(current + 4, 90)), 800);
    return () => window.clearInterval(timer);
  }, [running, result]);

  const progressLabel = result && !running
    ? "Validated report ready"
    : progress < 35
      ? "Request accepted"
      : progress < 75
        ? "Evidence analysis in progress"
        : "Validating evidence report";

  return <div className={`stage-scene ${stage}-scene`}>
    <div className="scene-progress-copy">
      <span>{stage === "performance" ? `Testing ${users} concurrent users` : stage === "security" ? "Tracing source evidence" : "Reviewing data handling"}</span>
      <b>{stage === "performance" && result?.measurement ? `${result.measurement.p95_latency_ms}ms p95` : stage === "security" ? "OWASP review" : "Policy review"}</b>
    </div>
    <div className={`scene-orbit ${running ? "moving" : ""}`}><i /><i /><i /></div>
    <span className="scene-status">{running ? "Audit in progress" : result ? "Evidence trace complete" : "Ready to run"}</span>
    <div className="stage-progress" aria-live="polite">
      <div><span>{progressLabel}</span><strong>{progress}%</strong></div>
      <div className="stage-progress-track"><i style={{ width: `${progress}%` }} /></div>
      <small>{running ? "Progress reflects the active audit request. Completion reaches 100% only after report validation." : result ? "Evidence report validated and ready for review." : "Run this stage to begin progress tracking."}</small>
    </div>
  </div>;

  if (stage === "security") return <div className="stage-scene security-scene"><div className="code-paper">{["identity.verify(token)", "route /api/users/:id", "ownership.assert(user, id)", "input.sanitize(payload)", "database.query(statement)"].map((line, index) => <p key={line}><span>{String(index + 1).padStart(2, "0")}</span>{line}</p>)}<div className={running ? "scanline moving" : "scanline"} /></div><div className="security-orbit"><i /><i /><i /><i /></div><span className="scene-status">{running ? "Tracing evidence paths" : result ? "Evidence trace complete" : "Authentication · access · input"}</span></div>;
  return <div className="stage-scene legal-scene"><div className="paper-stack"><article><b>DATA MAP</b><i /><i /><i /></article><article><b>PRIVACY</b><i /><i /><i /><i /></article><article><b>TERMS</b><i /><i /><i /><em>{running ? "SCANNING" : result ? "REVIEW" : "READY"}</em></article></div><div className="legal-orbit"><i /><i /><i /></div><span className="scene-status">Collection · processors · consent</span></div>;
}

function ReportPanel({ result, stage }: { result?: StageResult; stage: Stage }) {
  if (!result) return <aside className="report-panel empty"><AuditConsole stage={stage} /></aside>;
  return <aside className="report-panel"><div className="report-top"><span className="eyebrow">Stage report</span><b>{result.report.findings.length} finding{result.report.findings.length === 1 ? "" : "s"}</b></div>{result.measurement && <div className="metric-grid"><div><span>P95</span><strong>{result.measurement.p95_latency_ms}<small>ms</small></strong></div><div><span>Error rate</span><strong>{result.measurement.error_rate_percent}<small>%</small></strong></div><div><span>Requests</span><strong>{(result.successful_requests || 0) + (result.failed_requests || 0)}</strong></div></div>}<p className="report-summary">{result.report.summary}</p><div className="findings">{result.report.findings.length === 0 && <p className="no-findings"><Icon name="check" /> No configured threshold breach was found in this stage’s evidence.</p>}{result.report.findings.map((finding) => <article key={finding.title} className={`finding ${finding.severity}`}><div><span>{finding.severity}</span><b>{finding.risk_score}/100</b></div><h3>{finding.title}</h3><p>{finding.statement}</p><strong>Required change</strong><p>{finding.remediation}</p></article>)}</div><details><summary>Evidence and limitations</summary><ul>{result.report.limitations.map((item) => <li key={item}>{item}</li>)}</ul></details></aside>;
}

function AuditConsole({ stage }: { stage: Stage }) {
  const process = stage === "performance"
    ? ["verify authorized sandbox target", "pin the submitted Git commit", "send bounded GET load to sandbox root", "calculate p95 latency and error rate", "validate qualifying measurement and issue verdict"]
    : stage === "security"
      ? ["request the current Git commit", "select security-relevant source files", "trace authentication, authorization, input, and secret paths", "validate each cited source line and exploit path", "score verified findings and issue verdict"]
      : ["request the current Git commit", "select data-handling and policy-relevant source files", "trace collection, storage, transfer, and SDK calls", "validate each cited source line against supplied jurisdictions", "assemble the evidence-backed legal review verdict"];

  return <div className="audit-console" aria-label={`${stage} audit process preview`}>
    <div className="console-top"><span><i /> SCAVIBE / {stage.toUpperCase()}</span><b>PROCESS QUEUED</b></div>
    <p className="console-command">$ scavibe audit --stage {stage} --evidence-only</p>
    <div className="console-lines">{process.map((item, index) => <p key={item} style={{ animationDelay: `${index * 140}ms` }}><span>{String(index + 1).padStart(2, "0")}</span><i>›</i>{item}</p>)}</div>
    <div className="console-file"><span>FILES</span><code>Selected after the repository commit is fetched.</code></div>
    <p className="console-note">The terminal lists the exact process. File names appear only after Scavibe receives the backend’s selected-file evidence.</p>
  </div>
}
