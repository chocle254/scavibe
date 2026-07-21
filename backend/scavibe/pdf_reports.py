"""Evidence-preserving PDF exports for Scavibe audit reports."""

from __future__ import annotations

from datetime import timezone
from importlib.resources import as_file, files
from io import BytesIO
from typing import Iterable
from xml.sax.saxutils import escape

import reportlab
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .contracts import AgentReport, Finding, Stage
from .reporting import STAGE_AUDIT_LABELS, exploitability_label, format_evidence_markdown, ordered_findings


class PdfGenerationError(RuntimeError):
    """A required PDF rendering resource is unavailable."""


PAGE_BACKGROUND = "#08100d"
PANEL_BACKGROUND = "#111918"
BODY_TEXT = "#ecf5ef"
MUTED_TEXT = "#a7b9ae"
PERFORMANCE_ACCENT = "#83f5bf"
SECURITY_ACCENT = "#b8a7ff"
LEGAL_ACCENT = "#ffce73"
STAGE_ACCENTS = {
    Stage.PERFORMANCE: PERFORMANCE_ACCENT,
    Stage.SECURITY: SECURITY_ACCENT,
    Stage.LEGAL: LEGAL_ACCENT,
}
SEVERITY_COLORS = {
    "info": "#7bc8ff",
    "low": "#83f5bf",
    "medium": "#ffce73",
    "high": "#ff9b6a",
    "critical": "#ff6d86",
}
FONT_REGULAR = "ScavibeVera"
FONT_BOLD = "ScavibeVeraBold"


def _register_fonts() -> None:
    """Embed a Unicode font so exact source evidence is never ASCII-rewritten."""
    if FONT_REGULAR in pdfmetrics.getRegisteredFontNames():
        return
    fonts = files("reportlab").joinpath("fonts")
    try:
        with as_file(fonts.joinpath("Vera.ttf")) as regular, as_file(fonts.joinpath("VeraBd.ttf")) as bold:
            pdfmetrics.registerFont(TTFont(FONT_REGULAR, str(regular)))
            pdfmetrics.registerFont(TTFont(FONT_BOLD, str(bold)))
    except FileNotFoundError as error:
        raise PdfGenerationError("ReportLab bundled Vera fonts are required to preserve Unicode audit evidence") from error


def _color(value: str) -> colors.HexColor:
    return colors.HexColor(value)


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "eyebrow": ParagraphStyle(
            "ScavibeEyebrow",
            parent=base["Normal"],
            fontName=FONT_BOLD,
            fontSize=8,
            leading=10,
            textColor=_color(MUTED_TEXT),
            spaceAfter=5,
        ),
        "title": ParagraphStyle(
            "ScavibeTitle",
            parent=base["Title"],
            fontName=FONT_BOLD,
            fontSize=26,
            leading=31,
            textColor=_color(BODY_TEXT),
            spaceAfter=9,
            wordWrap="CJK",
        ),
        "section": ParagraphStyle(
            "ScavibeSection",
            parent=base["Heading2"],
            fontName=FONT_BOLD,
            fontSize=14,
            leading=18,
            textColor=_color(BODY_TEXT),
            spaceBefore=12,
            spaceAfter=6,
            wordWrap="CJK",
        ),
        "finding": ParagraphStyle(
            "ScavibeFinding",
            parent=base["Heading3"],
            fontName=FONT_BOLD,
            fontSize=12,
            leading=16,
            textColor=_color(BODY_TEXT),
            spaceAfter=5,
            wordWrap="CJK",
        ),
        "body": ParagraphStyle(
            "ScavibeBody",
            parent=base["BodyText"],
            fontName=FONT_REGULAR,
            fontSize=9.4,
            leading=14,
            textColor=_color(BODY_TEXT),
            spaceAfter=7,
            wordWrap="CJK",
            splitLongWords=True,
        ),
        "muted": ParagraphStyle(
            "ScavibeMuted",
            parent=base["BodyText"],
            fontName=FONT_REGULAR,
            fontSize=8.3,
            leading=11,
            textColor=_color(MUTED_TEXT),
            spaceAfter=5,
            wordWrap="CJK",
            splitLongWords=True,
        ),
        "code": ParagraphStyle(
            "ScavibeEvidenceCode",
            parent=base["Code"],
            fontName=FONT_REGULAR,
            fontSize=6.3,
            leading=7.8,
            textColor=_color(BODY_TEXT),
        ),
        "badge": ParagraphStyle(
            "ScavibeBadge",
            parent=base["BodyText"],
            fontName=FONT_BOLD,
            fontSize=7.5,
            leading=9,
            textColor=_color(PAGE_BACKGROUND),
            alignment=TA_LEFT,
        ),
        "footer": ParagraphStyle(
            "ScavibeFooter",
            parent=base["Normal"],
            fontName=FONT_REGULAR,
            fontSize=7.5,
            leading=9,
            textColor=_color(MUTED_TEXT),
            alignment=TA_RIGHT,
        ),
    }


def _paragraph(text: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(text).replace("\n", "<br/>"), style)


def _panel(content: Iterable[object], width: float) -> Table:
    table = Table([[item] for item in content], colWidths=[width], splitByRow=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), _color(PANEL_BACKGROUND)),
                ("BOX", (0, 0), (-1, -1), 0.5, _color("#26372d")),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                ("TOPPADDING", (0, 0), (-1, -1), 11),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return table


def _finding_flowables(finding: Finding, styles: dict[str, ParagraphStyle], content_width: float) -> list[object]:
    badge_color = _color(SEVERITY_COLORS[finding.severity.value])
    badge = Table([[_paragraph(finding.severity.value.upper(), styles["badge"])]], colWidths=[58])
    badge.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), badge_color),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    evidence_lines = [_paragraph(format_evidence_markdown(item), styles["muted"]) for item in finding.evidence]
    card_content: list[object] = [
        badge,
        Spacer(1, 7),
        _paragraph(finding.title, styles["finding"]),
        _paragraph(f"Risk score: {finding.risk_score}/100 · Confidence: {finding.confidence_score}/100", styles["muted"]),
        _paragraph(finding.statement, styles["body"]),
        _paragraph("Required change", styles["eyebrow"]),
        _paragraph(finding.remediation, styles["body"]),
        _paragraph("Evidence", styles["eyebrow"]),
        *evidence_lines,
    ]
    label = exploitability_label(finding)
    if label is not None:
        card_content.extend([_paragraph("Exploitability status", styles["eyebrow"]), _paragraph(label, styles["body"])])
    poc_code_flowables: list[object] = []
    if finding.poc_execution is not None:
        execution = finding.poc_execution
        card_content.extend(
            [
                _paragraph("Sandbox proof-of-concept audit trail", styles["eyebrow"]),
                _paragraph(f"Execution state: {execution.execution_state}", styles["muted"]),
                _paragraph(execution.reason, styles["body"]),
            ]
        )
        poc_code_flowables.extend(
            [
                _paragraph("Model-proposed test code", styles["eyebrow"]),
                _verbatim_evidence_block(execution.proposed_test_code, styles),
            ]
        )
        if execution.executed_test_code is not None:
            poc_code_flowables.extend([_paragraph("Executed fixed-template test code", styles["eyebrow"]), _verbatim_evidence_block(execution.executed_test_code, styles)])
        if execution.request_path is not None:
            card_content.append(_paragraph(f"Validated request: {execution.request_method} {execution.request_path}", styles["muted"]))
        if execution.response_status_code is not None:
            card_content.append(_paragraph(f"Observed HTTP status: {execution.response_status_code}", styles["muted"]))
        if execution.response_sha256 is not None:
            card_content.append(_paragraph(f"Response excerpt SHA-256: {execution.response_sha256}", styles["muted"]))
        if execution.response_excerpt is not None:
            poc_code_flowables.extend([_paragraph("Captured response excerpt", styles["eyebrow"]), _verbatim_evidence_block(execution.response_excerpt, styles)])
    return [_panel(card_content, content_width), *poc_code_flowables, Spacer(1, 9)]


def _verbatim_evidence_block(text: str, styles: dict[str, ParagraphStyle]) -> Preformatted:
    """Render supplied evidence verbatim, without treating source text as PDF markup."""
    return Preformatted(text, styles["code"], maxLineLength=112)


def _evidence_inventory_flowables(report: AgentReport, styles: dict[str, ParagraphStyle], content_width: float) -> list[object]:
    inventory = report.evidence_inventory
    if inventory is None:
        return [
            _panel(
                [_paragraph("This legacy report has no retained evidence inventory. It cannot prove which supplied files, manifest paths, runtime measurements, or jurisdictions were inspected.", styles["body"])],
                content_width,
            )
        ]

    content: list[object] = [
        _paragraph("Evidence summary", styles["section"]),
        _panel(
            [
                _paragraph(f"Source files supplied to the audit: {len(inventory.source_files)}.", styles["body"]),
                _paragraph(f"Repository manifest paths supplied to the audit: {len(inventory.repository_paths)}.", styles["body"]),
                _paragraph(
                    "Source coverage is complete." if inventory.source_content_complete else "Source coverage is capped; the manifest is complete but only the supplied source files were available for analysis.",
                    styles["body"],
                ),
                _paragraph("Full repository source and the full manifest are retained for validation but are not embedded in this export.", styles["body"]),
            ],
            content_width,
        ),
    ]
    if report.findings:
        content.append(_paragraph("Finding evidence and required changes", styles["section"]))
        finding_summaries: list[object] = []
        for finding in ordered_findings(report.findings):
            finding_summaries.extend(
                [
                    _paragraph(finding.title, styles["finding"]),
                    _paragraph("Cited evidence", styles["eyebrow"]),
                    *[_paragraph(format_evidence_markdown(evidence), styles["muted"]) for evidence in finding.evidence],
                    _paragraph("Required change", styles["eyebrow"]),
                    _paragraph(finding.remediation, styles["body"]),
                ]
            )
        content.append(_panel(finding_summaries, content_width))
    else:
        content.append(
            _panel(
                [_paragraph("No evidence citation met the finding admission rule. No source excerpt or speculative fix is included.", styles["body"])],
                content_width,
            )
        )
    content.append(_paragraph("Runtime measurements supplied", styles["section"]))
    if inventory.runtime_measurements:
        for measurement in inventory.runtime_measurements:
            p95 = "null (no successful response latency was measured)" if measurement.p95_latency_ms is None else str(measurement.p95_latency_ms)
            content.append(
                _panel(
                    [
                        _paragraph(f"Measurement ID: {measurement.id}", styles["body"]),
                        _paragraph(f"Target mode: {measurement.target_mode}; endpoint: {measurement.endpoint}", styles["body"]),
                        _paragraph(f"Concurrent users: {measurement.concurrent_users}; duration seconds: {measurement.duration_seconds}", styles["body"]),
                        _paragraph(f"Completed requests: {measurement.sample_count}; successful requests: {measurement.successful_sample_count}", styles["body"]),
                        _paragraph(f"P95 latency ms: {p95}; error rate percent: {measurement.error_rate_percent}", styles["body"]),
                    ],
                    content_width,
                )
            )
    else:
        content.append(_panel([_paragraph("No runtime measurement was supplied to this stage.", styles["body"])], content_width))
    content.append(_paragraph("Declared jurisdictions", styles["section"]))
    jurisdiction_text = ", ".join(inventory.jurisdictions) if inventory.jurisdictions else "No jurisdiction code was supplied to this stage."
    content.append(_panel([_paragraph(jurisdiction_text, styles["body"])], content_width))
    return content


def _draw_page(accent: str):
    def draw(canvas, document) -> None:
        canvas.saveState()
        width, height = A4
        canvas.setFillColor(_color(PAGE_BACKGROUND))
        canvas.rect(0, 0, width, height, fill=1, stroke=0)
        canvas.setFillColor(_color(accent))
        canvas.rect(document.leftMargin, height - 17 * mm, width - document.leftMargin - document.rightMargin, 1.2, fill=1, stroke=0)
        canvas.setFillColor(_color(MUTED_TEXT))
        canvas.setFont(FONT_REGULAR, 7.5)
        canvas.drawString(document.leftMargin, 10 * mm, "Scavibe — evidence-backed audit export")
        canvas.drawRightString(width - document.rightMargin, 10 * mm, f"Page {document.page}")
        canvas.restoreState()

    return draw


def generate_pdf_report(report: AgentReport, stage_color: str, stage_label: str) -> bytes:
    """Render one evidence-backed audit report from the supplied AgentReport only."""
    _register_fonts()
    accent = stage_color
    styles = _styles()
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=24 * mm,
        bottomMargin=18 * mm,
        title=f"Scavibe {stage_label}",
        author="Scavibe",
    )
    content_width = A4[0] - document.leftMargin - document.rightMargin
    generated_at = report.generated_at
    if generated_at.tzinfo is None:
        generated_at = generated_at.replace(tzinfo=timezone.utc)
    timestamp = generated_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    story: list[object] = [
        _paragraph("SCAVIBE · VERIFIED AUDIT", styles["eyebrow"]),
        _paragraph(stage_label, styles["title"]),
        HRFlowable(width="100%", thickness=1.3, color=_color(accent), spaceAfter=10),
        _panel(
            [
                _paragraph(f"Generated at: {timestamp}", styles["muted"]),
                _paragraph(f"Evidence commit: {report.evidence_commit_sha}", styles["muted"]),
                *([_paragraph(f"Analysis engine: {report.analysis_engine}", styles["muted"])] if report.analysis_engine is not None else []),
                _paragraph(report.summary, styles["body"]),
            ],
            content_width,
        ),
        _paragraph("Findings", styles["section"]),
    ]
    if report.ramp_assessment is not None:
        assessment = report.ramp_assessment
        if assessment.breaking_point_concurrent_users is None:
            ramp_text = "Confirmed ramp result: no breaking point identified within the tested range of 10 to 200 concurrent users."
        else:
            ramp_text = (
                f"Confirmed ramp breaking point: {assessment.metric}={assessment.observed_value} against "
                f"threshold={assessment.threshold} at {assessment.breaking_point_concurrent_users} concurrent users."
            )
        story.extend([_paragraph("Load ramp confirmation", styles["section"]), _panel([_paragraph(ramp_text, styles["body"])], content_width)])
    if report.findings:
        for finding in ordered_findings(report.findings):
            story.extend(_finding_flowables(finding, styles, content_width))
    else:
        story.extend(
            [
                _panel(
                    [
                        _paragraph("No evidence-backed findings were returned for the supplied evidence set.", styles["body"]),
                        _paragraph("No code, configuration, security, or legal change is proposed without a verified finding. Review the evidence summary and provide targeted additional evidence if needed.", styles["body"]),
                    ],
                    content_width,
                ),
                Spacer(1, 8),
            ]
        )
    story.append(_paragraph("Remediation plan", styles["section"]))
    if report.findings:
        remediation_lines: list[object] = []
        for finding in ordered_findings(report.findings):
            remediation_lines.extend(
                [
                    _paragraph(finding.title, styles["finding"]),
                    _paragraph(finding.remediation, styles["body"]),
                ]
            )
        story.append(_panel(remediation_lines, content_width))
    else:
        story.append(_panel([_paragraph("No remediation is proposed because no finding met the evidence admission rule. Do not apply a speculative fix from this report.", styles["body"])], content_width))
    story.append(_paragraph("Limitations", styles["section"]))
    limitation_lines = [_paragraph(f"• {limitation}", styles["body"]) for limitation in report.limitations]
    story.append(_panel(limitation_lines, content_width))
    if report.citation_exclusions:
        exclusion_lines: list[object] = [
            _paragraph(
                "These model-proposed citations failed exact quote validation. They are not evidence, were not scored, and their related findings are excluded from this report.",
                styles["body"],
            )
        ]
        exclusion_lines.extend(
            _paragraph(
                f"{item.file_path} lines {item.start_line}-{item.end_line}: quote does not match the pinned source lines.",
                styles["muted"],
            )
            for item in report.citation_exclusions
        )
        story.extend(
            [
                _paragraph(f"Excluded source citations ({len(report.citation_exclusions)})", styles["section"]),
                _panel(exclusion_lines, content_width),
            ]
        )
    story.extend(_evidence_inventory_flowables(report, styles, content_width))
    document.build(story, onFirstPage=_draw_page(accent), onLaterPages=_draw_page(accent))
    return buffer.getvalue()


def build_stage_pdf(report: AgentReport) -> bytes:
    """Compatibility wrapper for callers that select a standard Scavibe stage palette."""
    return generate_pdf_report(report, STAGE_ACCENTS[report.stage], STAGE_AUDIT_LABELS[report.stage])
