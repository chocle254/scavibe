"""Shared report text rendering used by downloadable artifacts."""

from __future__ import annotations

import re

from .contracts import AgentReport, Evidence, EvidenceKind, Stage


STAGE_AUDIT_LABELS = {
    Stage.PERFORMANCE: "Performance audit",
    Stage.SECURITY: "Security audit",
    Stage.LEGAL: "Data-handling and consent audit",
}


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


def _code_fence(content: str) -> str:
    longest_run = max((len(match.group()) for match in re.finditer(r"`+", content)), default=0)
    return "`" * max(3, longest_run + 1)


def evidence_inventory_markdown(report: AgentReport) -> list[str]:
    """Render every retained audit input so artifact readers can inspect the supplied evidence."""
    inventory = report.evidence_inventory
    if inventory is None:
        return ["This legacy report has no retained evidence inventory.", ""]
    lines = [
        "## Evidence appendix",
        "",
        f"Source files reproduced: {len(inventory.source_files)}.",
        f"Repository manifest paths reproduced: {len(inventory.repository_paths)}.",
        (
            "Source coverage is complete."
            if inventory.source_content_complete
            else "Source coverage is capped; the manifest is complete but only the reproduced source files were supplied for analysis."
        ),
        "",
        "### Repository manifest",
        "",
    ]
    lines.extend(f"- `{path}`" for path in inventory.repository_paths)
    lines.extend(["", "### Supplied source files", ""])
    for source in inventory.source_files:
        fence = _code_fence(source.content)
        numbered = "\n".join(f"{line_number:06d} | {line}" for line_number, line in enumerate(source.content.splitlines(), start=1)) or "000001 | "
        lines.extend([f"#### `{source.path}`", "", fence, numbered, fence, ""])
    lines.extend(["### Runtime measurements", ""])
    if inventory.runtime_measurements:
        for measurement in inventory.runtime_measurements:
            p95 = "null (no successful response latency was measured)" if measurement.p95_latency_ms is None else str(measurement.p95_latency_ms)
            lines.extend(
                [
                    f"- Measurement `{measurement.id}`: target_mode={measurement.target_mode}; endpoint=`{measurement.endpoint}`; concurrent_users={measurement.concurrent_users}; duration_seconds={measurement.duration_seconds}; completed_requests={measurement.sample_count}; successful_requests={measurement.successful_sample_count}; p95_latency_ms={p95}; error_rate_percent={measurement.error_rate_percent}",
                ]
            )
    else:
        lines.append("- No runtime measurement was supplied to this stage.")
    lines.extend(["", "### Declared jurisdictions", ""])
    lines.append(
        ", ".join(f"`{jurisdiction}`" for jurisdiction in inventory.jurisdictions)
        if inventory.jurisdictions
        else "No jurisdiction code was supplied to this stage."
    )
    lines.append("")
    return lines


def report_markdown(report: AgentReport) -> str:
    """Create the evidence-backed Markdown representation of an AgentReport."""
    lines = [f"# Scavibe {STAGE_AUDIT_LABELS[report.stage]}", "", report.summary, "", "## Findings", ""]
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
    lines.extend(["## Remediation plan", ""])
    if report.findings:
        lines.extend(f"- **{finding.title}**: {finding.remediation}" for finding in report.findings)
    else:
        lines.append("No remediation is proposed because no finding met the evidence admission rule. Do not apply a speculative fix from this report.")
    lines.extend(["## Limitations", ""])
    lines.extend(f"- {limitation}" for limitation in report.limitations)
    lines.extend(["", f"Evidence commit: `{report.evidence_commit_sha}`", ""])
    lines.extend(evidence_inventory_markdown(report))
    return "\n".join(lines)
