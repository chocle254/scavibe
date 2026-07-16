"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";

type StageKey = "performance" | "security" | "legal";

type Stage = {
  key: StageKey;
  eyebrow: string;
  title: string;
  subtitle: string;
  accent: string;
  systems: string[];
  checks: string[];
  finding: string;
};

const stages: Stage[] = [
  {
    key: "performance",
    eyebrow: "01 / Performance",
    title: "Find the moment it bends.",
    subtitle: "A disposable sandbox is warmed, observed, and ramped through realistic traffic layers.",
    accent: "#79f2c0",
    systems: ["Sandbox deployment", "Route discovery", "Database connection pool", "CDN & asset cache"],
    checks: ["10 concurrent users", "100 concurrent users", "1,000 user projection"],
    finding: "Checkout p95 crosses 800 ms at the projected 300-user layer.",
  },
  {
    key: "security",
    eyebrow: "02 / Security",
    title: "Trace the path an attacker sees.",
    subtitle: "The codebase is mapped into authentication, input, secrets, and authorization layers before findings are ranked.",
    accent: "#b6a5ff",
    systems: ["Identity & sessions", "API authorization", "Input boundaries", "Secrets & dependencies"],
    checks: ["Authentication flow", "SQL injection paths", "Object-level access control"],
    finding: "One admin route needs a server-side ownership check before launch.",
  },
  {
    key: "legal",
    eyebrow: "03 / Legal compliance",
    title: "Make data practices visible.",
    subtitle: "Scavibe follows data from collection to vendor and region signals, then identifies the documents your product needs.",
    accent: "#ffcd75",
    systems: ["Data collection map", "Cookies & analytics", "Third-party processors", "Regional requirements"],
    checks: ["Privacy disclosures", "Consent surface", "Retention & deletion signals"],
    finding: "Privacy policy and analytics consent copy are needed for the current collection map.",
  },
];

function Mark({ name }: { name: "bolt" | "shield" | "scale" | "arrow" | "check" }) {
  const paths = {
    bolt: <path d="m13 2-9 12h7l-1 8 10-13h-7l0-7Z" />,
    shield: <path d="M12 3 5 6v5c0 5 3 8.5 7 10 4-1.5 7-5 7-10V6l-7-3Zm-3 9 2 2 4-4" />,
    scale: <path d="M12 3v18m-7 0h14M5 7h14M5 7l-3 6h6L5 7Zm14 0-3 6h6l-3-6Z" />,
    arrow: <path d="M5 12h14m-6-6 6 6-6 6" />,
    check: <path d="m5 12 4 4L19 6" />,
  };
  return <svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">{paths[name]}</svg>;
}

function StageVisual({ stage, progress }: { stage: Stage; progress: number }) {
  if (stage.key === "performance") {
    return (
      <div className="visual-frame perf-visual" style={{ "--accent": stage.accent } as React.CSSProperties}>
        <div className="visual-label"><i className="signal-dot" /> sandbox load stream</div>
        <div className="load-grid" aria-label="Animated load test visualization">
          {[{ n: "10", text: "baseline" }, { n: "100", text: "steady traffic" }, { n: "1K", text: "projected surge" }].map((layer, index) => (
            <div className={`load-layer layer-${index + 1}`} key={layer.n}>
              <div className="layer-copy"><strong>{layer.n}</strong><span>{layer.text}</span></div>
              <div className="traffic-lane"><b /><b /><b /><b /><b /></div>
              <em>{index === 2 && progress > 45 ? "p95 842ms" : index === 1 ? "p95 214ms" : "p95 118ms"}</em>
            </div>
          ))}
        </div>
        <div className="meter"><span>Load progression</span><div><i style={{ width: `${Math.max(progress, 6)}%` }} /></div><b>{Math.round(progress)}%</b></div>
      </div>
    );
  }
  if (stage.key === "security") {
    return (
      <div className="visual-frame security-visual" style={{ "--accent": stage.accent } as React.CSSProperties}>
        <div className="visual-label"><i className="signal-dot" /> live code trace</div>
        <div className="terminal-lines">
          <p><span>01</span><b>auth</b> validateSession(request)</p>
          <p><span>02</span>route <b>/api/users/:id</b></p>
          <p><span>03</span>query.where(<b>"owner_id"</b>, user.id)</p>
          <p><span>04</span>input <b>sanitize(payload)</b></p>
          <p><span>05</span>secret <b>env.DATABASE_URL</b></p>
          <div className="scan-beam" style={{ top: `${14 + (progress / 100) * 68}%` }} />
        </div>
        <div className="node-map"><i /><i /><i /><i /><i /><i /></div>
        <div className="scan-caption"><span>Scanning attack surface</span><b>{Math.max(1, Math.round(progress / 8))} paths traced</b></div>
      </div>
    );
  }
  return (
    <div className="visual-frame legal-visual" style={{ "--accent": stage.accent } as React.CSSProperties}>
      <div className="visual-label"><i className="signal-dot" /> data-use discovery</div>
      <div className="document-stack">
        <article className="doc doc-back"><span>COOKIE SIGNALS</span><i /><i /><i /></article>
        <article className="doc doc-mid"><span>DATA MAP</span><i /><i /><i /><i /></article>
        <article className="doc doc-front"><span>PRIVACY CHECK</span><i /><i /><i /><b>REVIEW</b></article>
      </div>
      <div className="data-orbit"><i /><i /><i /><i /></div>
      <div className="scan-caption"><span>Following collected data</span><b>{Math.max(1, Math.round(progress / 10))} signals mapped</b></div>
    </div>
  );
}

export default function Home() {
  const [selected, setSelected] = useState(0);
  const [totalProgress, setTotalProgress] = useState(0);
  const [running, setRunning] = useState(false);
  const [repository, setRepository] = useState("github.com/your-team/your-app");
  const [appUrl, setAppUrl] = useState("your-app.vercel.app");

  useEffect(() => {
    if (!running) return;
    const timer = window.setInterval(() => {
      setTotalProgress((current) => {
        const next = Math.min(current + 2.5, 300);
        setSelected(Math.min(Math.floor(next / 100), 2));
        if (next === 300) setRunning(false);
        return next;
      });
    }, 85);
    return () => window.clearInterval(timer);
  }, [running]);

  const activeStage = stages[selected];
  const stageProgress = useMemo(() => Math.min(100, Math.max(0, totalProgress - selected * 100)), [selected, totalProgress]);

  function startAudit(event: FormEvent) {
    event.preventDefault();
    setTotalProgress(0);
    setSelected(0);
    setRunning(true);
  }

  function statusFor(index: number) {
    const progress = totalProgress - index * 100;
    if (progress >= 100) return "complete";
    if (progress > 0) return "running";
    return "queued";
  }

  return (
    <main>
      <div className="ambient ambient-one" /><div className="ambient ambient-two" />
      <nav className="nav"><a className="brand" href="#top"><span>sc</span>avibe</a><div className="nav-right"><span className="secure-pill"><i /> sandbox-first auditing</span><a href="#how-it-works">How it works</a><button className="ghost-button">Sign in <Mark name="arrow" /></button></div></nav>

      <section className="hero" id="top">
        <div className="hero-copy"><p className="kicker"><i /> launch with receipts, not hope</p><h1>Before your users find the cracks.</h1><p className="lede">Scavibe audits your vibe-coded app across performance, security, and compliance—then turns every issue into an understandable next move.</p></div>
        <form className="audit-form" onSubmit={startAudit}>
          <div className="form-top"><span>New pre-launch audit</span><small>~ 8 minutes</small></div>
          <label>GitHub repository<input value={repository} onChange={(e) => setRepository(e.target.value)} aria-label="GitHub repository URL" /></label>
          <label>Deployed app URL<input value={appUrl} onChange={(e) => setAppUrl(e.target.value)} aria-label="Deployed application URL" /></label>
          <p className="sandbox-note"><Mark name="shield" /> We test a disposable sandbox by default. Your live app stays untouched.</p>
          <button className="run-button" type="submit">{running ? "Audit in progress" : "Start audit"}<Mark name="arrow" /></button>
        </form>
      </section>

      <section className="workspace" id="how-it-works">
        <header className="workspace-header"><div><p className="kicker"><i /> audit pipeline</p><h2>Three lenses. One launch decision.</h2></div><div className="run-state"><i className={running ? "is-running" : ""} />{running ? "Analysis is flowing" : totalProgress === 300 ? "Audit preview complete" : "Ready when you are"}</div></header>
        <div className="stage-tabs" role="tablist" aria-label="Audit stages">
          {stages.map((stage, index) => {
            const status = statusFor(index);
            return <button key={stage.key} role="tab" aria-selected={selected === index} onClick={() => setSelected(index)} className={`stage-tab ${selected === index ? "selected" : ""}`} style={{ "--accent": stage.accent } as React.CSSProperties}><span className={`stage-number ${status}`}>{status === "complete" ? <Mark name="check" /> : `0${index + 1}`}</span><span><b>{stage.key === "legal" ? "Legal" : stage.key[0].toUpperCase() + stage.key.slice(1)}</b><small>{status === "running" ? "Analyzing" : status === "complete" ? "Reviewed" : "Queued"}</small></span><em>{status === "running" ? `${Math.round(Math.min(100, Math.max(0, totalProgress - index * 100)))}%` : ""}</em></button>;
          })}
        </div>

        <div className="stage-panel" style={{ "--accent": activeStage.accent } as React.CSSProperties}>
          <div className="panel-main"><div className="panel-intro"><p>{activeStage.eyebrow}</p><h3>{activeStage.title}</h3><span>{activeStage.subtitle}</span></div><StageVisual stage={activeStage} progress={stageProgress} /></div>
          <aside className="inspection-panel"><div className="inspection-heading"><span>Inspection layers</span><b>{running && statusFor(selected) === "running" ? "Live" : "Preview"}</b></div><ol>{activeStage.systems.map((system, index) => <li key={system} className={stageProgress > index * 21 ? "revealed" : ""}><span>{String(index + 1).padStart(2, "0")}</span>{system}<i><Mark name="check" /></i></li>)}</ol><div className="test-list"><p>Current checks</p>{activeStage.checks.map((check, index) => <span key={check}><i className={stageProgress > (index + 1) * 24 ? "done" : ""} />{check}</span>)}</div></aside>
        </div>

        <div className="finding-strip"><div className="finding-icon">{activeStage.key === "performance" ? <Mark name="bolt" /> : activeStage.key === "security" ? <Mark name="shield" /> : <Mark name="scale" />}</div><div><span>What this layer can surface</span><p>{activeStage.finding}</p></div><button onClick={() => setSelected((selected + 1) % 3)}>Explore next <Mark name="arrow" /></button></div>
      </section>

      <section className="promise"><p>Every fix is proposed as a pull request.</p><span>Nothing touches your repository or production environment without your review.</span></section>
      <footer><a className="brand" href="#top"><span>sc</span>avibe</a><p>Built for builders who care what happens after launch.</p><small>Legal drafts are starting points, not legal advice.</small></footer>
    </main>
  );
}
