"use client";

import { FormEvent, useEffect, useMemo, useRef, useState } from "react";

type Stage = "performance" | "security" | "legal";
type Operation = "idle" | "auditing" | "creating_pr" | "exporting";
type IconName = "arrow" | "check" | "bolt" | "shield" | "scale" | "download" | "branch" | "lock" | "terminal" | "file" | "chart" | "refresh";

type Evidence = {
  kind: "source" | "runtime" | "manifest";
  file_path?: string;
  start_line?: number;
  end_line?: number;
  quote?: string;
  measurement_id?: string;
  endpoint?: string;
  metric?: string;
  observed_value?: number;
  threshold?: number;
};
type Finding = {
  title: string;
  statement: string;
  remediation: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  risk_score: number;
  confidence_score: number;
  evidence: Evidence[];
};
type RampAssessment = {
  tested_range: number[];
  breaking_point_concurrent_users: number | null;
  metric: "p95_latency_ms" | "error_rate_percent" | null;
  observed_value: number | null;
  threshold: number | null;
};
type Report = {
  stage: Stage;
  summary: string;
  findings: Finding[];
  limitations: string[];
  evidence_commit_sha: string;
  generated_at?: string;
  ramp_assessment?: RampAssessment | null;
};
type RuntimeMeasurement = {
  concurrent_users: number;
  duration_seconds: number;
  sample_count: number;
  successful_sample_count: number;
  p95_latency_ms: number | null;
  error_rate_percent: number;
};
type StageResult = {
  stage: Stage;
  audit_id: string;
  audit_pin: string;
  repository: { commit_sha: string; selected_files: string[]; source_content_complete: boolean };
  report: Report;
  measurement?: RuntimeMeasurement;
};
type SandboxSuggestion = { url: string; provider: string; environment: string; commit_sha: string };
type VercelSandbox = { deployment_id: string; ready_state: string; deployment_url?: string; ticket: string; expires_at: number; commit_sha: string };
type RampLane = {
  phase: "exploratory" | "confirmation";
  index: number;
  users: number;
  status: "waiting" | "running" | "completed";
  p95: number | null;
  errorRate: number | null;
  samples: number;
  breached: boolean;
};
type Trace = { id: string; stage: Stage; text: string; kind: "info" | "success" | "warn" | "error"; at: string };
type Coverage = { commitSha: string; selected: number; manifest: number; complete: boolean };
type SpecialistStage = Exclude<Stage, "performance">;
type SpecialistPhaseName = "repository_fetch" | "specialist_analysis" | "evidence_validation";
type SpecialistPhaseState = { status: "waiting" | "running" | "completed"; activity: string };
type SpecialistPhaseMap = Partial<Record<SpecialistStage, Partial<Record<SpecialistPhaseName, SpecialistPhaseState>>>>;
type AutoFixType = "consent_checkbox" | "rate_limit_middleware";
type AutoFixOffer = { fixType: AutoFixType; label: string };

type RampEvent =
  | { type: "step_started"; phase: "exploratory" | "confirmation"; step_index: number; concurrent_users: number; planned_duration_seconds: number }
  | { type: "sample_tick"; step_index: number; elapsed_seconds: number; live_p95_latency_ms: number | null; live_error_rate_percent: number; samples_so_far: number }
  | { type: "step_completed"; phase: "exploratory" | "confirmation"; step_index: number; concurrent_users: number; p95_latency_ms: number | null; error_rate_percent: number; sample_count: number; breached: boolean }
  | { type: "breaking_point_found"; concurrent_users: number; metric: "p95_latency_ms" | "error_rate_percent"; observed_value: number; threshold: number }
  | { type: "candidate_discarded" }
  | { type: "ramp_completed"; tested_range: [number, number]; breaking_point_concurrent_users: number | null };
type SpecialistEvent =
  | { type: "phase_started" | "phase_completed"; stage: SpecialistStage; phase: SpecialistPhaseName; activity: string; commit_sha?: string; selected_file_count?: number; repository_path_count?: number; source_content_complete?: boolean }
  | { type: "report_ready"; stage: SpecialistStage; result: StageResult }
  | { type: "stage_failed"; stage: SpecialistStage; detail: string };

const schedule = [10, 25, 50, 75, 100, 125, 150, 175, 200];
const stages: Array<{ id: Stage; no: string; name: string; label: string; icon: IconName }> = [
  { id: "performance", no: "01", name: "Performance", label: "Sandbox load lab", icon: "bolt" },
  { id: "security", no: "02", name: "Cybersecurity", label: "OWASP evidence review", icon: "shield" },
  { id: "legal", no: "03", name: "Data & consent", label: "Data-handling and consent audit", icon: "scale" },
];
const emptyProgress: Record<Stage, number | null> = { performance: null, security: null, legal: null };

function apiUrl(path: string) {
  const base = (process.env.NEXT_PUBLIC_BACKEND_URL || "/api").replace(/\/$/, "");
  return base + path;
}

function iconPath(name: IconName) {
  const icons: Record<IconName, React.ReactNode> = {
    arrow: <path d="M5 12h14m-6-6 6 6-6 6" />,
    check: <path d="m5 12 4 4L19 6" />,
    bolt: <path d="M13 2 4 14h7l-1 8 10-13h-7V2Z" />,
    shield: <path d="M12 3 5 6v5c0 5 3 8.5 7 10 4-1.5 7-5 7-10V6l-7-3Z" />,
    scale: <path d="M12 3v18m-7 0h14M5 7h14M5 7l-3 6h6L5 7Zm14 0-3 6h6l-3-6Z" />,
    download: <path d="M12 3v11m0 0 4-4m-4 4-4-4m-5 9h18" />,
    branch: <path d="M6 3v12m0-12a3 3 0 1 0 0 6 3 3 0 0 0 0-6Zm0 12a3 3 0 1 0 0 6 3 3 0 0 0 0-6Zm12-6a3 3 0 1 0 0 6 3 3 0 0 0 0-6Zm-9-3c0 3 2 6 6 6" />,
    lock: <path d="M7 10V7a5 5 0 0 1 10 0v3m-11 0h12v10H6V10Zm6 4v2" />,
    terminal: <path d="m5 7 4 5-4 5m6 0h8" />,
    file: <path d="M7 3h7l3 3v15H7V3Zm7 0v4h4M10 12h4m-4 4h4" />,
    chart: <path d="M4 19V5m0 14h16M8 16v-4m4 4V8m4 8v-6" />,
    refresh: <path d="M20 11a8 8 0 1 0 2 5m-2-5V6m0 5h-5" />,
  };
  return icons[name];
}

function Icon({ name }: { name: IconName }) {
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{iconPath(name)}</svg>;
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(apiUrl(path), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail || "Request failed with HTTP " + response.status);
  return payload as T;
}

async function readSse(response: Response, onBlock: (id: string, data: string) => void) {
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.detail || "Stream failed with HTTP " + response.status);
  }
  if (!response.body) throw new Error("The audit server did not return a readable event stream.");
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  const consume = (block: string) => {
    const lines = block.split(/\r?\n/);
    const id = (lines.find((line) => line.startsWith("id:")) || "").slice(3).trim();
    const data = (lines.find((line) => line.startsWith("data:")) || "").slice(5).trim();
    if (id || data) onBlock(id, data);
  };
  while (true) {
    const next = await reader.read();
    buffer += decoder.decode(next.value || new Uint8Array(), { stream: !next.done });
    const blocks = buffer.split(/\r?\n\r?\n/);
    buffer = blocks.pop() || "";
    blocks.forEach(consume);
    if (next.done) break;
  }
  if (buffer.trim()) consume(buffer);
}

function triggerDownload(blob: Blob, filename: string) {
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

function autoFixOffer(stage: Stage, finding: Finding): AutoFixOffer | null {
  const text = [finding.title, finding.statement, finding.remediation].join(" ").toLowerCase();
  const hasSourceEvidence = finding.evidence.some((item) => item.kind === "source" && Boolean(item.file_path));
  if (!hasSourceEvidence) return null;
  const consentSignal = text.includes("consent") || text.includes("age-confirm") || text.includes("age confirmation");
  const checkboxSignal = text.includes("checkbox") || text.includes("check box");
  if (stage === "legal" && consentSignal && checkboxSignal) return { fixType: "consent_checkbox", label: "Add this checkbox for me" };
  if ((stage === "security" || stage === "performance") && (text.includes("rate limit") || text.includes("rate-limit") || text.includes("rate limiting") || text.includes("throttl"))) {
    return { fixType: "rate_limit_middleware", label: "Add rate limiting for me" };
  }
  return null;
}

export default function Home() {
  const [stage, setStage] = useState<Stage | null>(null);
  const [repository, setRepository] = useState("");
  const [appUrl, setAppUrl] = useState("");
  const [sandboxUrl, setSandboxUrl] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [useScavibeSandbox, setUseScavibeSandbox] = useState(true);
  const [jurisdictions, setJurisdictions] = useState<string[]>(["KE"]);
  const [auditId, setAuditId] = useState("");
  const [auditPin, setAuditPin] = useState("");
  const [results, setResults] = useState<Partial<Record<Stage, StageResult>>>({});
  const [operation, setOperation] = useState<Operation>("idle");
  const [error, setError] = useState("");
  const [trace, setTrace] = useState<Trace[]>([]);
  const [progress, setProgress] = useState<Record<Stage, number | null>>(emptyProgress);
  const [lanes, setLanes] = useState<Record<string, RampLane>>({});
  const activeRampLaneRef = useRef<{ key: string; index: number } | null>(null);
  const [breakingPoint, setBreakingPoint] = useState<RampAssessment | null>(null);
  const [coverage, setCoverage] = useState<Partial<Record<Stage, Coverage>>>({});
  const [specialistPhases, setSpecialistPhases] = useState<SpecialistPhaseMap>({});
  const [suggestions, setSuggestions] = useState<SandboxSuggestion[]>([]);
  const [suggesting, setSuggesting] = useState(false);
  const [sandboxStatus, setSandboxStatus] = useState("");
  const [prApproved, setPrApproved] = useState(false);
  const [prUrl, setPrUrl] = useState("");
  const [sourceFixApproval, setSourceFixApproval] = useState<Record<string, boolean>>({});
  const [sourceFixUrls, setSourceFixUrls] = useState<Record<string, string>>({});

  const activeResult = stage ? results[stage] : undefined;
  const activeMeta = stages.find((item) => item.id === stage);
  const busy = operation !== "idle";
  const allComplete = stages.every((item) => Boolean(results[item.id]));
  const totalFindings = useMemo(() => Object.values(results).reduce((total, item) => total + (item ? item.report.findings.length : 0), 0), [results]);

  useEffect(() => {
    const source = repository.trim();
    if (!/^https:\/\/github\.com\/[^/]+\/[^/]+\/?$/.test(source)) {
      setSuggestions([]);
      return;
    }
    let live = true;
    const timer = window.setTimeout(async () => {
      setSuggesting(true);
      try {
        const response = await fetch(apiUrl("/sandbox-suggestions") + "?repository_url=" + encodeURIComponent(source));
        if (live) setSuggestions(response.ok ? await response.json() as SandboxSuggestion[] : []);
      } catch {
        if (live) setSuggestions([]);
      } finally {
        if (live) setSuggesting(false);
      }
    }, 500);
    return () => {
      live = false;
      window.clearTimeout(timer);
    };
  }, [repository]);

  function addTrace(target: Stage, text: string, kind: Trace["kind"] = "info") {
    setTrace((current) => current.concat({ id: crypto.randomUUID(), stage: target, text, kind, at: new Date().toISOString().slice(11, 19) }).slice(-100));
  }

  function resetAudit() {
    setResults({});
    setAuditId(crypto.randomUUID());
    setAuditPin("");
    setError("");
    setTrace([]);
    setProgress(emptyProgress);
    setLanes({});
    setBreakingPoint(null);
    setCoverage({});
    setSpecialistPhases({});
    setSandboxStatus("");
    setPrApproved(false);
    setPrUrl("");
    setSourceFixApproval({});
    setSourceFixUrls({});
  }

  function begin(event: FormEvent) {
    event.preventDefault();
    if (!repository.trim() || !appUrl.trim() || (!sandboxUrl.trim() && !useScavibeSandbox)) {
      setError("Enter a public GitHub repository, deployed app URL, and either a sandbox URL or the disposable Scavibe sandbox.");
      return;
    }
    if (!authorized) {
      setError("Confirm explicit authorization before Scavibe sends sandbox traffic.");
      return;
    }
    resetAudit();
    setStage("performance");
  }

  function requestBody(targetSandbox?: string) {
    return {
      repository_url: repository.trim(),
      app_url: appUrl.trim(),
      sandbox_url: targetSandbox || sandboxUrl.trim() || undefined,
      sandbox_authorized: authorized,
      jurisdictions,
      audit_id: auditId || undefined,
      audit_pin: auditPin || undefined,
    };
  }

  function upsertLane(key: string, fallback: RampLane, change: Partial<RampLane>) {
    setLanes((current) => ({ ...current, [key]: { ...(current[key] || fallback), ...change } }));
  }

  function handleRamp(event: RampEvent) {
    if (event.type === "step_started") {
      const key = event.phase + ":" + event.step_index;
      activeRampLaneRef.current = { key, index: event.step_index };
      const fallback: RampLane = { phase: event.phase, index: event.step_index, users: event.concurrent_users, status: "running", p95: null, errorRate: null, samples: 0, breached: false };
      upsertLane(key, fallback, { status: "running", users: event.concurrent_users });
      if (event.phase === "exploratory") {
        setProgress((current) => ({ ...current, performance: Math.max(4, Math.round(event.step_index / schedule.length * 70)) }));
        addTrace("performance", "Started exploratory step at " + event.concurrent_users + " concurrent users for " + event.planned_duration_seconds + " seconds.");
      } else {
        setProgress((current) => ({ ...current, performance: 78 }));
        addTrace("performance", "Started the 60-second confirmation at " + event.concurrent_users + " concurrent users.");
      }
      return;
    }
    if (event.type === "sample_tick") {
      const currentLane = activeRampLaneRef.current;
      const key = currentLane && currentLane.index === event.step_index ? currentLane.key : "exploratory:" + event.step_index;
      const phase = key.startsWith("confirmation") ? "confirmation" : "exploratory";
      const fallback: RampLane = { phase, index: event.step_index, users: schedule[event.step_index], status: "running", p95: null, errorRate: null, samples: 0, breached: false };
      upsertLane(key, fallback, { p95: event.live_p95_latency_ms, errorRate: event.live_error_rate_percent, samples: event.samples_so_far });
      return;
    }
    if (event.type === "step_completed") {
      const key = event.phase + ":" + event.step_index;
      if (activeRampLaneRef.current?.key === key) activeRampLaneRef.current = null;
      const fallback: RampLane = { phase: event.phase, index: event.step_index, users: event.concurrent_users, status: "completed", p95: event.p95_latency_ms, errorRate: event.error_rate_percent, samples: event.sample_count, breached: event.breached };
      upsertLane(key, fallback, { status: "completed", p95: event.p95_latency_ms, errorRate: event.error_rate_percent, samples: event.sample_count, breached: event.breached });
      if (event.phase === "exploratory") {
        setProgress((current) => ({ ...current, performance: Math.round((event.step_index + 1) / schedule.length * 70) }));
        addTrace("performance", "Exploratory step " + (event.step_index + 1) + "/9 completed with " + event.sample_count + " responses.", event.breached ? "warn" : "success");
      } else {
        setProgress((current) => ({ ...current, performance: 94 }));
        addTrace("performance", "Confirmation completed with " + event.sample_count + " responses.", event.breached ? "warn" : "success");
      }
      return;
    }
    if (event.type === "breaking_point_found") {
      setBreakingPoint({ tested_range: [10, 200], breaking_point_concurrent_users: event.concurrent_users, metric: event.metric, observed_value: event.observed_value, threshold: event.threshold });
      addTrace("performance", "First breach at " + event.concurrent_users + " users: " + event.metric + "=" + event.observed_value + ".", "warn");
      return;
    }
    if (event.type === "candidate_discarded") {
      addTrace("performance", "Exploratory candidate cleared by its 60-second confirmation; continuing the ramp.", "info");
      return;
    }
    setProgress((current) => ({ ...current, performance: 96 }));
    addTrace("performance", event.breaking_point_concurrent_users === null ? "Ramp completed without a confirmed breaking point from 10 to 200 users." : "Ramp completed. Sealing confirmed evidence.", "success");
  }

  async function runRamp(target: string): Promise<StageResult> {
    let token = "";
    const response = await fetch(apiUrl("/audit-stages/performance/ramp"), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(requestBody(target)) });
    await readSse(response, (id, data) => {
      if (id) token = id;
      if (data) handleRamp(JSON.parse(data) as RampEvent);
    });
    if (!token) throw new Error("The load ramp ended without a signed report token.");
    addTrace("performance", "Retrieving report from the sealed confirmation measurement.");
    const result = await post<StageResult>("/audit-stages/performance/ramp/report", { ramp_report_token: token });
    setProgress((current) => ({ ...current, performance: 100 }));
    return result;
  }

  async function runSpecialist(target: Exclude<Stage, "performance">): Promise<StageResult> {
    let result: StageResult | null = null;
    const response = await fetch(apiUrl("/audit-stages/" + target + "/stream"), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(requestBody()) });
    await readSse(response, (_id, data) => {
      if (!data) return;
      const event = JSON.parse(data) as SpecialistEvent;
      if (event.type === "stage_failed") throw new Error(event.detail);
      if (event.type === "phase_started" || event.type === "phase_completed") {
        setSpecialistPhases((current) => ({
          ...current,
          [target]: { ...(current[target] || {}), [event.phase]: { status: event.type === "phase_started" ? "running" : "completed", activity: event.activity } },
        }));
        const progressByPhase: Record<SpecialistPhaseName, number> = event.type === "phase_started"
          ? { repository_fetch: 4, specialist_analysis: 34, evidence_validation: 72 }
          : { repository_fetch: 24, specialist_analysis: 66, evidence_validation: 94 };
        setProgress((current) => ({ ...current, [target]: progressByPhase[event.phase] }));
        if (event.phase === "repository_fetch" && event.type === "phase_completed" && event.commit_sha && event.selected_file_count !== undefined && event.repository_path_count !== undefined && event.source_content_complete !== undefined) {
          setCoverage((current) => ({ ...current, [target]: { commitSha: event.commit_sha!, selected: event.selected_file_count!, manifest: event.repository_path_count!, complete: event.source_content_complete! } }));
          addTrace(target, "Pinned " + event.commit_sha.slice(0, 8) + "; selected " + event.selected_file_count + "/" + event.repository_path_count + " source paths.", "success");
        } else {
          addTrace(target, (event.type === "phase_started" ? "Started: " : "Completed: ") + event.activity, event.type === "phase_completed" ? "success" : "info");
        }
      } else if (event.type === "report_ready") {
        result = event.result;
        setProgress((current) => ({ ...current, [target]: 100 }));
        addTrace(target, "Report ready: " + event.result.report.findings.length + " evidence-backed finding(s).", "success");
      }
    });
    if (!result) throw new Error("The specialist stream ended without a report.");
    return result;
  }

  async function createSandbox(): Promise<VercelSandbox> {
    addTrace("performance", "Creating disposable Vercel sandbox from the pinned repository.");
    const created = await post<VercelSandbox>("/sandboxes/vercel", { repository_url: repository.trim(), authorized_deployment: true });
    let sandbox = created;
    for (let attempt = 1; attempt <= 36; attempt += 1) {
      if (sandbox.ready_state.toUpperCase() === "READY" && sandbox.deployment_url) return sandbox;
      if (["ERROR", "CANCELED"].includes(sandbox.ready_state.toUpperCase())) throw new Error("Vercel sandbox build ended as " + sandbox.ready_state + ". No load traffic was sent.");
      setSandboxStatus("Vercel build state " + sandbox.ready_state + ". Readiness check " + attempt + "/36.");
      await new Promise<void>((resolve) => window.setTimeout(resolve, 5000));
      const response = await fetch(apiUrl("/sandboxes/vercel/" + created.deployment_id) + "?ticket=" + encodeURIComponent(created.ticket));
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.detail || "Sandbox status failed with HTTP " + response.status);
      sandbox = payload as VercelSandbox;
    }
    throw new Error("Vercel did not report a ready sandbox within 180 seconds. No load traffic was sent.");
  }

  async function cleanupSandbox(sandbox: VercelSandbox) {
    try {
      const response = await fetch(apiUrl("/sandboxes/vercel/" + sandbox.deployment_id) + "?ticket=" + encodeURIComponent(sandbox.ticket), { method: "DELETE" });
      if (response.status !== 204) throw new Error("Sandbox deletion returned HTTP " + response.status);
      setSandboxStatus("Disposable sandbox deleted after the ramp.");
      addTrace("performance", "Disposable sandbox deleted.", "success");
    } catch (cleanupError) {
      const message = cleanupError instanceof Error ? cleanupError.message : "Sandbox cleanup failed.";
      setSandboxStatus(message);
      addTrace("performance", message, "warn");
    }
  }

  async function runStage() {
    if (!stage || busy) return;
    setOperation("auditing");
    setError("");
    setPrUrl("");
    setProgress((current) => ({ ...current, [stage]: null }));
    setTrace((current) => current.filter((line) => line.stage !== stage));
    if (stage === "performance") {
      setLanes({});
      activeRampLaneRef.current = null;
      setBreakingPoint(null);
    } else {
      setCoverage((current) => ({ ...current, [stage]: undefined }));
      setSpecialistPhases((current) => ({ ...current, [stage]: {} }));
    }
    let sandbox: VercelSandbox | null = null;
    try {
      let result: StageResult;
      if (stage === "performance") {
        let target = sandboxUrl.trim();
        if (useScavibeSandbox) {
          setSandboxStatus("Creating isolated Vercel preview with no production environment variables.");
          sandbox = await createSandbox();
          target = sandbox.deployment_url || "";
          setSandboxUrl(target);
          setSandboxStatus("Sandbox ready. Starting the fixed 10–200 user ramp.");
        }
        if (!target) throw new Error("A ready HTTPS sandbox URL is required.");
        result = await runRamp(target);
      } else {
        result = await runSpecialist(stage);
      }
      setResults((current) => {
        const next = { ...current, [stage]: result };
        if (stage === "performance") {
          delete next.security;
          delete next.legal;
        }
        if (stage === "security") delete next.legal;
        return next;
      });
      setAuditId(result.audit_id);
      setAuditPin(result.audit_pin);
    } catch (requestError) {
      const message = requestError instanceof Error ? requestError.message : "Audit request failed.";
      setError(message);
      addTrace(stage, message, "error");
    } finally {
      if (sandbox) await cleanupSandbox(sandbox);
      setOperation("idle");
    }
  }

  async function createArtifactPr() {
    if (!activeResult || !prApproved || busy) return;
    setOperation("creating_pr");
    setError("");
    try {
      const result = await post<{ url: string }>("/audit-stages/pull-request", { repository_url: repository.trim(), report: activeResult.report, jurisdictions, approved: true });
      setPrUrl(result.url);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Artifact PR creation failed.");
    } finally {
      setOperation("idle");
    }
  }

  async function createSourceFix(findingIndex: number, fixType: AutoFixType) {
    if (!activeResult || !stage || busy) return;
    const key = stage + ":" + findingIndex;
    if (!sourceFixApproval[key]) return;
    setOperation("creating_pr");
    setError("");
    try {
      const result = await post<{ url: string }>("/audit-stages/source-fix-pull-request", {
        repository_url: repository.trim(),
        app_url: appUrl.trim(),
        audit_id: activeResult.audit_id,
        audit_pin: activeResult.audit_pin,
        report: activeResult.report,
        finding_index: findingIndex,
        fix_type: fixType,
        source_change_approved: true,
      });
      setSourceFixUrls((current) => ({ ...current, [key]: result.url }));
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Source-fix pull request creation failed.");
    } finally {
      setOperation("idle");
    }
  }

  async function fetchDownload(target: Stage, result: StageResult) {
    const path = target === "legal" ? "/audit-stages/legal/pdf" : "/audit-stages/" + target + "/pdf";
    const body = { report: result.report };
    const filenames: Record<Stage, string> = { performance: "scavibe-performance-audit.pdf", security: "scavibe-security-audit.pdf", legal: "scavibe-data-handling-and-consent-audit.pdf" };
    const response = await fetch(apiUrl(path), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.detail || "PDF download failed with HTTP " + response.status);
    }
    triggerDownload(await response.blob(), filenames[target]);
  }

  async function downloadPdf(target: Stage) {
    const result = results[target];
    if (!result || busy) return;
    setOperation("exporting");
    setError("");
    try {
      await fetchDownload(target, result);
    } catch (downloadError) {
      setError(downloadError instanceof Error ? downloadError.message : "PDF download failed.");
    } finally {
      setOperation("idle");
    }
  }

  async function downloadAll() {
    if (!allComplete || busy) return;
    const performance = results.performance;
    const security = results.security;
    const legal = results.legal;
    if (!performance || !security || !legal) return;
    setOperation("exporting");
    setError("");
    try {
      const response = await fetch(apiUrl("/audit-stages/pdf-archive"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          performance: performance.report,
          security: security.report,
          legal: legal.report,
        }),
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload.detail || "PDF archive download failed with HTTP " + response.status);
      }
      triggerDownload(await response.blob(), "scavibe-audit-reports.zip");
    } catch (downloadError) {
      setError(downloadError instanceof Error ? downloadError.message : "PDF archive download failed.");
    } finally {
      setOperation("idle");
    }
  }

  async function downloadConsent() {
    const legal = results.legal;
    if (!legal || busy) return;
    setOperation("exporting");
    try {
      const response = await fetch(apiUrl("/audit-stages/consent-example"), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ report: legal.report }) });
      if (!response.ok) throw new Error("Consent component download failed with HTTP " + response.status);
      triggerDownload(await response.blob(), "scavibe-consent-checkbox-example.zip");
    } catch (downloadError) {
      setError(downloadError instanceof Error ? downloadError.message : "Consent component download failed.");
    } finally {
      setOperation("idle");
    }
  }

  function toggleJurisdiction(value: string) {
    setJurisdictions((current) => current.includes(value) ? current.filter((item) => item !== value) : current.concat(value));
  }

  if (!stage) {
    return <main className="audit-shell launch-shell">
      <div className="ambient-grid" />
      <nav className="topbar"><a className="brand" href="#"><span>sc</span>avibe</a><p><i /> Evidence-first release audit</p></nav>
      <section className="launch-grid">
        <div className="launch-copy">
          <span className="eyebrow">Pre-release control room</span>
          <h1>Watch your release meet reality before your users do.</h1>
          <p>Pin a public Git commit, run a real bounded sandbox ramp, inspect evidence through security and data-handling and consent stages, then download the exact reports.</p>
          <div className="launch-proof"><span><Icon name="lock" /> Sandbox traffic only</span><span><Icon name="file" /> Exact evidence</span><span><Icon name="chart" /> Measured results</span></div>
        </div>
        <form className="intake-card" onSubmit={begin}>
          <div className="card-top"><b>Open an audit session</b><small>3 evidence stages</small></div>
          <label>Public GitHub repository<input type="url" value={repository} onChange={(event) => setRepository(event.target.value)} placeholder="https://github.com/owner/repository" required /></label>
          <label>Deployed app URL<input type="url" value={appUrl} onChange={(event) => setAppUrl(event.target.value)} placeholder="https://your-app.vercel.app" required /></label>
          <label className="sandbox-toggle"><input type="checkbox" checked={useScavibeSandbox} onChange={(event) => setUseScavibeSandbox(event.target.checked)} /><span><b>Use a disposable Scavibe Vercel sandbox</b>It receives no production environment variables and is deleted after the performance ramp.</span></label>
          <label>Authorized sandbox URL {useScavibeSandbox ? <small>(manual alternative)</small> : null}<input type="url" value={sandboxUrl} onChange={(event) => setSandboxUrl(event.target.value)} placeholder="https://preview-your-app.vercel.app" required={!useScavibeSandbox} /></label>
          {suggesting ? <p className="subtle">Reading deployment suggestions…</p> : null}
          {suggestions.length > 0 ? <div className="suggestions"><span>Commit-aware deployment suggestions</span>{suggestions.map((item) => <button key={item.url} type="button" onClick={() => setSandboxUrl(item.url)}><Icon name="check" /><b>{item.provider}</b><code>{item.url}</code><small>{item.environment} · {item.commit_sha.slice(0, 8)}</small></button>)}</div> : null}
          <label className="checkline"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} /><span>I own this sandbox or have explicit authorization to test it. The performance stage sends bounded GET requests only to the sandbox.</span></label>
          {error ? <p className="form-error">{error}</p> : null}
          <button className="primary full" type="submit" disabled={!authorized}>Enter performance lab <Icon name="arrow" /></button>
        </form>
      </section>
    </main>;
  }

  const canRun = !busy && (stage !== "legal" || jurisdictions.length > 0);
  return <main className={"audit-shell stage-" + stage}>
    <div className="ambient-grid" />
    <nav className="topbar"><button className="brand reset-button" onClick={() => setStage(null)}><span>sc</span>avibe</button><p><i /> Commit-pinned audit session</p></nav>
    <div className="audit-layout">
      <aside className="pipeline">
        <div className="pipeline-title">Audit sequence<span>{activeMeta?.label}</span></div>
        {stages.map((item, index) => {
          const complete = Boolean(results[item.id]);
          const active = item.id === stage;
          const locked = index > 0 && !results[stages[index - 1].id];
          return <button key={item.id} className={["pipeline-step", active ? "active" : "", complete ? "complete" : ""].join(" ")} disabled={locked} onClick={() => setStage(item.id)}><b>{complete ? <Icon name="check" /> : item.no}</b><span>{item.name}<small>{complete ? "Report sealed" : active ? "Current stage" : locked ? "Awaiting prior stage" : "Ready"}</small></span></button>;
        })}
        <p className="pipeline-note"><Icon name="lock" /> Scavibe shows evidence coverage. It does not claim repository-wide absence when source selection is capped.</p>
      </aside>
      <section className="stage-content">
        <header className="stage-heading">
          <div><span className="eyebrow">{activeMeta?.no} / {activeMeta?.label}</span><h1>{stage === "performance" ? "Find the load level where it changes." : stage === "security" ? "Trace the evidence an attacker would exploit." : "Map the data handling and consent paths your product must keep."}</h1></div>
          <div className="session-chip"><span>{activeResult ? "commit " + activeResult.repository.commit_sha.slice(0, 8) : coverage[stage] ? "commit " + coverage[stage]?.commitSha.slice(0, 8) : "Commit pending"}</span><small>{operation === "auditing" ? "live audit" : activeResult ? "report ready" : "not started"}</small></div>
        </header>
        <div className="stage-grid">
          <section className="visual-card">
            <div className="visual-top"><span><Icon name={activeMeta?.icon || "bolt"} /> {stage === "performance" ? "Live sandbox ramp" : stage === "security" ? "OWASP evidence trace" : "Data-handling and consent trace"}</span><b>{operation === "auditing" ? "LIVE" : activeResult ? "SEALED" : "READY"}</b></div>
            <StageVisual stage={stage} progress={progress[stage]} lanes={lanes} assessment={breakingPoint || activeResult?.report.ramp_assessment || null} phases={stage === "performance" ? undefined : specialistPhases[stage]} auditing={operation === "auditing"} />
            <div className="control-board">
              {stage === "performance" ? <><div className="fixed-spec"><span>Fixed exploratory schedule</span><b>10 → 200 users</b><small>9 × 12-second steps · 60-second confirmation · GET / only</small></div><div className="fixed-spec"><span>Finding admission gate</span><b>100 users · 60s · 20 samples</b><small>Lower-load results remain recorded but cannot create a performance finding.</small></div>{sandboxStatus ? <p className="sandbox-status"><Icon name="lock" /> {sandboxStatus}</p> : null}</> : null}
              {stage === "security" ? <p className="stage-explainer">The specialist follows OWASP-oriented checks over the pinned source evidence. Every filed finding requires exact source evidence.</p> : null}
              {stage === "legal" ? <><p className="stage-explainer">The data-handling and consent audit maps observed product signals to specific recommendations. It does not certify compliance or replace legal counsel.</p><div className="jurisdiction-row">{["KE", "EU", "US-CA"].map((item) => <button key={item} type="button" className={jurisdictions.includes(item) ? "selected" : ""} onClick={() => toggleJurisdiction(item)}>{jurisdictions.includes(item) ? <Icon name="check" /> : null}{item}</button>)}</div></> : null}
            </div>
            <button className="primary full run-button" disabled={!canRun} onClick={() => void runStage()}>{operation === "auditing" ? "Processing verified evidence…" : activeResult ? "Run this stage again" : stage === "performance" ? "Run authorized load ramp" : stage === "legal" ? "Start data-handling and consent audit" : "Start security review"} {operation === "auditing" ? <Icon name="terminal" /> : activeResult ? <Icon name="refresh" /> : <Icon name="arrow" />}</button>
            {error ? <p className="form-error panel-error">{error}</p> : null}
          </section>
          <Terminal stage={stage} trace={trace} coverage={coverage[stage]} progress={progress[stage]} auditing={operation === "auditing"} />
        </div>
        {activeResult ? <ReportPanel result={activeResult} busy={busy} approvals={sourceFixApproval} urls={sourceFixUrls} onApprovalChange={(key, approved) => setSourceFixApproval((current) => ({ ...current, [key]: approved }))} onCreateSourceFix={(findingIndex, fixType) => void createSourceFix(findingIndex, fixType)} /> : null}
        {activeResult || coverage[stage] ? <EvidencePanel result={activeResult} coverage={coverage[stage]} /> : null}
        {activeResult ? <section className="action-card"><div><span className="eyebrow">Controlled next actions</span><h2>{stage === "legal" ? "Keep the data-handling and consent audit together." : "Turn the measured result into a reviewable artifact."}</h2><p>PDF exports preserve exact evidence, precomputed scores, limitations, timestamp, and pinned commit. The artifact PR adds the audit report and consent example only; it does not silently edit application code.</p></div><div className="action-buttons"><button className="secondary" disabled={busy} onClick={() => void downloadPdf(stage)}><Icon name="download" /> Download {stage === "legal" ? "data-handling" : stage} PDF</button>{stage === "legal" ? <button className="secondary" disabled={busy} onClick={() => void downloadConsent()}><Icon name="file" /> Consent checkbox example (.zip)</button> : null}<label className="checkline approval"><input type="checkbox" checked={prApproved} onChange={(event) => setPrApproved(event.target.checked)} /><span>I approve a draft PR containing audit artifacts, not unreviewed source-code edits.</span></label><button className="secondary" disabled={!prApproved || busy} onClick={() => void createArtifactPr()}><Icon name="branch" /> Create artifact PR</button>{prUrl ? <a className="pr-link" href={prUrl} target="_blank" rel="noreferrer">Open draft PR <Icon name="arrow" /></a> : null}{stage !== "legal" ? <button className="primary" disabled={busy} onClick={() => setStage(stage === "performance" ? "security" : "legal")}>Continue to {stage === "performance" ? "cybersecurity" : "data handling and consent"} <Icon name="arrow" /></button> : null}</div></section> : null}
        {allComplete ? <FinalAnalytics results={results as Record<Stage, StageResult>} total={totalFindings} busy={busy} onDownload={() => void downloadAll()} /> : null}
      </section>
    </div>
  </main>;
}

function StageVisual({ stage, progress, lanes, assessment, phases, auditing }: { stage: Stage; progress: number | null; lanes: Record<string, RampLane>; assessment: RampAssessment | null; phases?: Partial<Record<SpecialistPhaseName, SpecialistPhaseState>>; auditing: boolean }) {
  const label = progress === null ? "Waiting for a server event" : progress + "% event-derived progress";
  if (stage === "performance") return <div className="stage-visual performance-visual"><div className="visual-progress"><span>{label}</span><b>{progress === null ? "—" : progress + "%"}</b></div><div className="ramp-grid">{schedule.map((users, index) => { const confirmation = lanes["confirmation:" + index]; const exploratory = lanes["exploratory:" + index]; const lane = confirmation || exploratory; const phase = confirmation ? "confirmed" : lane?.status === "running" ? "exploring" : lane?.status === "completed" ? "explored" : "queued"; return <article key={users} className={["ramp-lane", lane?.status || "waiting", lane?.breached ? "breached" : ""].join(" ")}><div><span>{String(index + 1).padStart(2, "0")}</span><b>{users}</b></div><i /><small>{phase}</small><em>{lane?.samples ? lane.samples + " samples" : "—"}</em></article>; })}</div><div className="visual-foot"><span>{assessment?.breaking_point_concurrent_users ? "First breach: " + assessment.breaking_point_concurrent_users + " users" : "No breaking point recorded yet."}</span><span>{assessment?.metric ? assessment.metric + " " + assessment.observed_value + " / " + assessment.threshold : "p95 > 500ms or errors > 1.0%"}</span></div></div>;
  const phaseLabels: Record<SpecialistPhaseName, string> = { repository_fetch: "Repository evidence", specialist_analysis: "Specialist analysis", evidence_validation: "Evidence validation" };
  const phaseIcons: Record<SpecialistPhaseName, IconName> = { repository_fetch: "file", specialist_analysis: stage === "security" ? "shield" : "scale", evidence_validation: "check" };
  const orderedPhases: SpecialistPhaseName[] = ["repository_fetch", "specialist_analysis", "evidence_validation"];
  return <div className={["stage-visual", "specialist-visual", stage === "security" ? "security-visual" : "legal-visual"].join(" ")}><div className="visual-progress"><span>{label}</span><b>{progress === null ? "—" : progress + "%"}</b></div><div className={["scanner-core", auditing ? "active" : ""].join(" ")}><i /><i /><i /><i /></div><div className="phase-cards">{orderedPhases.map((phase) => { const current = phases?.[phase]; return <article key={phase} className={current?.status || "waiting"}><Icon name={phaseIcons[phase]} /><span>{phaseLabels[phase]}</span><small>{current?.status || "waiting"}</small><i /></article>; })}</div><p>{auditing ? "Animation state follows the live server phase." : "This visual activates only from server-delivered phase transitions."}</p></div>;
}

function Terminal({ stage, trace, coverage, progress, auditing }: { stage: Stage; trace: Trace[]; coverage?: Coverage; progress: number | null; auditing: boolean }) {
  const lines = trace.filter((item) => item.stage === stage).slice(-14);
  return <section className="console-card" aria-live="polite" aria-busy={auditing}><header><span><i /> Evidence terminal</span><b>{auditing ? "STREAM OPEN" : progress === 100 ? "REPORT SEALED" : "IDLE"}</b></header><p className="console-command">$ scavibe audit --stage {stage} --evidence-only</p><div className="console-lines">{lines.length === 0 ? <p className="console-empty">No server event received yet. Start the stage to stream verified work.</p> : lines.map((line) => <p key={line.id} className={"trace-" + line.kind}><time>{line.at}</time><i>{line.kind === "error" || line.kind === "warn" ? "!" : line.kind === "success" ? "✓" : "›"}</i><span>{line.text}</span></p>)}</div>{coverage ? <div className="coverage-readout"><span>Evidence coverage</span><b>{coverage.selected} selected / {coverage.manifest} manifest paths</b><small>{coverage.complete ? "Every supported text file was supplied." : "Source selection is capped; repository-wide absence claims are blocked."}</small></div> : null}</section>;
}

function ReportPanel({ result, busy, approvals, urls, onApprovalChange, onCreateSourceFix }: { result: StageResult; busy: boolean; approvals: Record<string, boolean>; urls: Record<string, string>; onApprovalChange: (key: string, approved: boolean) => void; onCreateSourceFix: (findingIndex: number, fixType: AutoFixType) => void }) {
  const report = result.report;
  const measurement = result.measurement;
  const assessment = report.ramp_assessment;
  return <section className="report-panel"><header><div><span className="eyebrow">Verified report</span><h2>{report.stage === "legal" ? "data-handling and consent verdict" : report.stage + " verdict"}</h2></div><b>{report.findings.length} finding{report.findings.length === 1 ? "" : "s"}</b></header>{measurement ? <div className="metric-grid"><div><span>Confirmed load</span><b>{measurement.concurrent_users}</b><small>users</small></div><div><span>P95 latency</span><b>{measurement.p95_latency_ms === null ? "N/A" : measurement.p95_latency_ms}</b><small>{measurement.p95_latency_ms === null ? "0 successes" : "ms"}</small></div><div><span>Error rate</span><b>{measurement.error_rate_percent}</b><small>%</small></div></div> : null}{assessment ? <p className="breakpoint-readout">{assessment.breaking_point_concurrent_users === null ? "Confirmed ramp result: no breaking point identified from 10 to 200 users." : "Confirmed ramp result: " + assessment.metric + "=" + assessment.observed_value + " at " + assessment.breaking_point_concurrent_users + " users (threshold " + assessment.threshold + ")."}</p> : null}<p className="report-summary">{report.summary}</p><div className="finding-list">{report.findings.length === 0 ? <p className="no-findings"><Icon name="check" /> No evidence-backed findings were filed.</p> : report.findings.map((finding, findingIndex) => { const offer = autoFixOffer(report.stage, finding); const key = report.stage + ":" + findingIndex; return <article className={["finding", finding.severity].join(" ")} key={finding.title}><div><span>{finding.severity}</span><b>{finding.risk_score}/100 · {finding.confidence_score}% confidence</b></div><h3>{finding.title}</h3><p>{finding.statement}</p><strong>Required change</strong><p>{finding.remediation}</p><details><summary>Exact evidence</summary><ul>{finding.evidence.map((item, index) => <li key={item.kind + index}>{item.kind === "source" ? item.file_path + " lines " + item.start_line + "-" + item.end_line + ": " + item.quote : item.kind === "runtime" ? item.measurement_id + " " + item.endpoint + ": " + item.metric + "=" + item.observed_value + ", threshold=" + item.threshold : "Manifest path: " + item.file_path}</li>)}</ul></details>{offer ? <div className="source-fix"><b>Bounded source change</b><p>{offer.fixType === "rate_limit_middleware" ? "Creates a FastAPI middleware at 60 requests per 60 seconds per IP, a conservative starting point to review." : "Creates one React/Next checkbox component and integrates it into the cited form."}</p><label className="checkline"><input type="checkbox" checked={Boolean(approvals[key])} onChange={(event) => onApprovalChange(key, event.target.checked)} /><span>This will generate real source code and open a pull request containing an actual code change to your repository. Review the diff carefully before merging — I am not responsible for reviewing this code for you.</span></label><button className="secondary" disabled={busy || !approvals[key]} onClick={() => onCreateSourceFix(findingIndex, offer.fixType)}><Icon name="branch" /> {offer.label}</button>{urls[key] ? <a className="pr-link" href={urls[key]} target="_blank" rel="noreferrer">Open source-fix PR <Icon name="arrow" /></a> : null}</div> : null}</article>; })}</div><details className="limitations"><summary>Limitations ({report.limitations.length})</summary><ul>{report.limitations.map((item) => <li key={item}>{item}</li>)}</ul></details></section>;
}

function EvidencePanel({ result, coverage }: { result?: StageResult; coverage?: Coverage }) {
  const paths = result?.repository.selected_files || [];
  const complete = result ? result.repository.source_content_complete : coverage?.complete;
  const count = result ? paths.length : coverage?.selected || 0;
  return <section className="evidence-panel"><div><span className="eyebrow">Evidence scope</span><h2>Files actually supplied to this stage</h2><p>{complete ? "All supported text source files were supplied as evidence." : "This audit shows selected evidence. A capped source selection does not become a repository-wide absence claim."}</p></div><b>{count} source files</b>{result ? <div className="file-strip">{paths.map((path) => <code key={path}>{path}</code>)}</div> : <p className="evidence-pending">The live stream reports the verified count only. Exact paths appear after the sealed report is returned.</p>}</section>;
}

function FinalAnalytics({ results, total, busy, onDownload }: { results: Record<Stage, StageResult>; total: number; busy: boolean; onDownload: () => void }) {
  const findings = Object.values(results).flatMap((result) => result.report.findings);
  const serious = findings.filter((item) => item.severity === "high" || item.severity === "critical").length;
  const sourceCount = Object.values(results).reduce((sum, result) => sum + result.repository.selected_files.length, 0);
  const breakpoint = results.performance.report.ramp_assessment?.breaking_point_concurrent_users;
  return <section className="final-analytics"><div className="final-copy"><span className="eyebrow">All stages complete</span><h2>One commit. Three evidence-backed views.</h2><p>The dashboard aggregates returned reports only. It does not recompute score or severity in the browser.</p></div><div className="analytics-grid"><article><span>Total findings</span><b>{total}</b><small>across all stages</small></article><article><span>High / critical</span><b>{serious}</b><small>precomputed severity</small></article><article><span>Evidence files</span><b>{sourceCount}</b><small>selected source inputs</small></article><article><span>Load ramp</span><b>{breakpoint || "none"}</b><small>{breakpoint ? "confirmed breaking point users" : "no confirmed break 10–200"}</small></article></div><div className="final-actions"><span>Commit {results.performance.repository.commit_sha.slice(0, 12)} · Downloaded PDFs retain their audit timestamp and exact evidence.</span><button className="primary" disabled={busy} onClick={onDownload}><Icon name="download" /> Download all 3 PDFs</button></div></section>;
}
