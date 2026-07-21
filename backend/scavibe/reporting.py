"""Shared report text rendering used by downloadable artifacts."""

from __future__ import annotations

import re

from .contracts import AgentReport, Evidence, EvidenceKind, ExploitabilityStatus, Finding, Stage


STAGE_AUDIT_LABELS = {
    Stage.PERFORMANCE: "Performance audit",
    Stage.SECURITY: "Security audit",
    Stage.LEGAL: "Data-handling and consent audit",
}

EXPLOITABILITY_LABELS = {
    ExploitabilityStatus.CONFIRMED_EXPLOITABLE: "Confirmed exploitable",
    ExploitabilityStatus.CANDIDATE_UNCONFIRMED: "Candidate — unconfirmed",
}


def ordered_findings(findings: list[Finding]) -> list[Finding]:
    """Keep confirmed sandbox results ahead of static candidates in every export."""
    return sorted(
        findings,
        key=lambda finding: 0 if finding.exploitability_status == ExploitabilityStatus.CONFIRMED_EXPLOITABLE else 1,
    )


def exploitability_label(finding: Finding) -> str | None:
    if finding.exploitability_status is None:
        return None
    return EXPLOITABILITY_LABELS[finding.exploitability_status]


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
    """Render a concise, finding-linked evidence summary without exporting the repository."""
    inventory = report.evidence_inventory
    if inventory is None:
        return ["This legacy report has no retained evidence inventory.", ""]
    lines = [
        "## Evidence summary",
        "",
        f"Source files supplied to the audit: {len(inventory.source_files)}.",
        f"Repository manifest paths supplied to the audit: {len(inventory.repository_paths)}.",
        (
            "Source coverage is complete."
            if inventory.source_content_complete
            else "Source coverage is capped; the manifest is complete but only the supplied source files were available for analysis."
        ),
        "Full repository source and the full manifest are retained for validation but are not embedded in this export.",
        "",
    ]

    if report.findings:
        lines.extend(["### Finding evidence and required changes", ""])
        for finding in ordered_findings(report.findings):
            lines.extend([f"#### {finding.title}", "", "**Cited evidence**", ""])
            lines.extend(format_evidence_markdown(evidence) for evidence in finding.evidence)
            lines.extend(["", "**Required change**", "", finding.remediation, ""])
    else:
        lines.extend(
            [
                "No evidence citation met the finding admission rule. No source excerpt or speculative fix is included.",
                "",
            ]
        )

    lines.extend(["### Runtime measurements supplied", ""])
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
    if report.analysis_engine is not None:
        lines[3:3] = [f"Analysis engine: `{report.analysis_engine}`", ""]
    if not report.findings:
        lines.extend(["No evidence-backed findings were returned for the supplied evidence set.", ""])
    for finding in ordered_findings(report.findings):
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
        label = exploitability_label(finding)
        if label is not None:
            lines.extend(["", "**Exploitability status**", "", label])
        if finding.poc_execution is not None:
            execution = finding.poc_execution
            proposed_fence = _code_fence(execution.proposed_test_code)
            lines.extend(
                [
                    "",
                    "**Sandbox proof-of-concept audit trail**",
                    "",
                    "Model-proposed test code:",
                    "",
                    proposed_fence,
                    execution.proposed_test_code,
                    proposed_fence,
                    "",
                    f"Execution state: `{execution.execution_state}`",
                    f"Result: {execution.reason}",
                ]
            )
            if execution.executed_test_code is not None:
                executed_fence = _code_fence(execution.executed_test_code)
                lines.extend(["", "Executed fixed-template test code:", "", executed_fence, execution.executed_test_code, executed_fence])
            if execution.request_path is not None:
                lines.append(f"Validated request: `{execution.request_method} {execution.request_path}`")
            if execution.response_status_code is not None:
                lines.append(f"Observed HTTP status: `{execution.response_status_code}`")
            if execution.response_sha256 is not None:
                lines.append(f"Response excerpt SHA-256: `{execution.response_sha256}`")
            if execution.response_excerpt is not None:
                response_fence = _code_fence(execution.response_excerpt)
                lines.extend(["", "Captured response excerpt:", "", response_fence, execution.response_excerpt, response_fence])
        lines.append("")
    lines.extend(["## Remediation plan", ""])
    if report.findings:
        lines.extend(f"- **{finding.title}**: {finding.remediation}" for finding in ordered_findings(report.findings))
    else:
        lines.append("No remediation is proposed because no finding met the evidence admission rule. Do not apply a speculative fix from this report.")
    lines.extend(["## Limitations", ""])
    lines.extend(f"- {limitation}" for limitation in report.limitations)
    if report.citation_exclusions:
        lines.extend(
            [
                "",
                f"## Excluded source citations ({len(report.citation_exclusions)})",
                "",
                "These model-proposed citations failed exact quote validation. They are not evidence, were not scored, and their related findings are excluded from this report.",
                "",
            ]
        )
        lines.extend(
            f"- `{item.file_path}` lines {item.start_line}-{item.end_line}: quote does not match the pinned source lines."
            for item in report.citation_exclusions
        )
    lines.extend(["", f"Evidence commit: `{report.evidence_commit_sha}`", ""])
    lines.extend(evidence_inventory_markdown(report))
    return "\n".join(lines)
