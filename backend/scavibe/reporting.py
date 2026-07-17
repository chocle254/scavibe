"""Shared report text rendering used by downloadable artifacts."""

from __future__ import annotations

from .contracts import AgentReport, Evidence, EvidenceKind


def format_evidence_markdown(evidence: Evidence) -> str:
    """Render each evidence kind once so all exports preserve the same facts."""
    if evidence.kind == EvidenceKind.SOURCE:
        return f"- `{evidence.file_path}` lines {evidence.start_line}-{evidence.end_line}: `{evidence.quote}`"
    if evidence.kind == EvidenceKind.RUNTIME:
        return (
            f"- Sandbox `{evidence.measurement_id}` at `{evidence.endpoint}`: "
            f"{evidence.metric}={evidence.observed_value}, threshold={evidence.threshold}"
        )
    return f"- Manifest path: `{evidence.file_path}`"


def report_markdown(report: AgentReport) -> str:
    """Create the evidence-backed Markdown representation of an AgentReport."""
    lines = [f"# Scavibe {report.stage.value.title()} Audit", "", report.summary, "", "## Findings", ""]
    if not report.findings:
        lines.extend(["No evidence-backed findings were returned for the supplied evidence set.", ""])
    for finding in report.findings:
        lines.extend(
            [
                f"### {finding.severity.value.upper()} · {finding.title}",
                "",
                f"Risk score: {finding.risk_score}/100 · Confidence: {finding.confidence_score}/100",
                "",
                finding.statement,
                "",
                "**Required change**",
                "",
                finding.remediation,
                "",
                "**Evidence**",
            ]
        )
        lines.extend(format_evidence_markdown(evidence) for evidence in finding.evidence)
        lines.append("")
    lines.extend(["## Limitations", ""])
    lines.extend(f"- {limitation}" for limitation in report.limitations)
    lines.extend(["", f"Evidence commit: `{report.evidence_commit_sha}`", ""])
    return "\n".join(lines)
