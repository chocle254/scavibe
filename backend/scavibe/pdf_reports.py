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
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .contracts import AgentReport, Finding, Stage
from .reporting import format_evidence_markdown


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
        "badge": ParagraphStyle(
            "ScavibeBadge",
            parent=base["BodyText"],
            fontName=FONT_BOLD,
            fontSize=7.5,
            leading=9,
            textColor=_color(PAGE_BACKGROUND),
            alignment=TA_LEFT,
        ),
        "document_heading": ParagraphStyle(
            "ScavibeDocumentHeading",
            parent=base["Heading2"],
            fontName=FONT_BOLD,
            fontSize=17,
            leading=21,
            textColor=_color(BODY_TEXT),
            spaceBefore=8,
            spaceAfter=8,
            wordWrap="CJK",
        ),
        "document_body": ParagraphStyle(
            "ScavibeDocumentBody",
            parent=base["BodyText"],
            fontName=FONT_REGULAR,
            fontSize=8.4,
            leading=12,
            textColor=_color(BODY_TEXT),
            spaceAfter=4,
            wordWrap="CJK",
            splitLongWords=True,
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
    return [_panel(card_content, content_width), Spacer(1, 9)]


def _append_legal_document(
    story: list[object],
    *,
    title: str,
    document: str,
    styles: dict[str, ParagraphStyle],
) -> None:
    story.append(PageBreak())
    story.append(_paragraph(title, styles["document_heading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_color(LEGAL_ACCENT), spaceAfter=9))
    for line in document.splitlines():
        stripped = line.strip()
        if not stripped:
            story.append(Spacer(1, 4))
        elif stripped.startswith("#"):
            heading = stripped.lstrip("#").strip()
            story.append(_paragraph(heading, styles["document_heading"]))
        elif stripped.startswith("- "):
            story.append(_paragraph(f"• {stripped[2:]}", styles["document_body"]))
        else:
            story.append(_paragraph(stripped, styles["document_body"]))


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


def build_stage_pdf(
    report: AgentReport,
    *,
    legal_drafts: tuple[str, str] | None = None,
) -> bytes:
    """Render one report, plus legal publication drafts when supplied, to PDF bytes."""
    _register_fonts()
    accent = STAGE_ACCENTS[report.stage]
    styles = _styles()
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=24 * mm,
        bottomMargin=18 * mm,
        title=f"Scavibe {report.stage.value.title()} Audit",
        author="Scavibe",
    )
    content_width = A4[0] - document.leftMargin - document.rightMargin
    generated_at = report.generated_at
    if generated_at.tzinfo is None:
        generated_at = generated_at.replace(tzinfo=timezone.utc)
    timestamp = generated_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    story: list[object] = [
        _paragraph("SCAVIBE · VERIFIED AUDIT", styles["eyebrow"]),
        _paragraph(f"{report.stage.value.title()} report", styles["title"]),
        HRFlowable(width="100%", thickness=1.3, color=_color(accent), spaceAfter=10),
        _panel(
            [
                _paragraph(f"Generated at: {timestamp}", styles["muted"]),
                _paragraph(f"Evidence commit: {report.evidence_commit_sha}", styles["muted"]),
                _paragraph(report.summary, styles["body"]),
            ],
            content_width,
        ),
        _paragraph("Findings", styles["section"]),
    ]
    if report.ramp_assessment is not None:
        assessment = report.ramp_assessment
        if assessment.breaking_point_concurrent_users is None:
            ramp_text = "Ramp result: no breaking point identified within the tested range of 10 to 200 concurrent users."
        else:
            ramp_text = (
                f"Ramp result: first exploratory breach at {assessment.breaking_point_concurrent_users} concurrent users; "
                f"{assessment.metric}={assessment.observed_value} against threshold={assessment.threshold}."
            )
        story.extend([_paragraph("Load ramp confirmation", styles["section"]), _panel([_paragraph(ramp_text, styles["body"])], content_width)])
    if report.findings:
        for finding in report.findings:
            story.extend(_finding_flowables(finding, styles, content_width))
    else:
        story.extend([_panel([_paragraph("No evidence-backed findings were returned for the supplied evidence set.", styles["body"])], content_width), Spacer(1, 8)])
    story.append(_paragraph("Limitations", styles["section"]))
    limitation_lines = [_paragraph(f"• {limitation}", styles["body"]) for limitation in report.limitations]
    story.append(_panel(limitation_lines, content_width))
    if legal_drafts is not None:
        privacy_policy, terms_of_service = legal_drafts
        _append_legal_document(story, title="Draft Privacy Policy", document=privacy_policy, styles=styles)
        _append_legal_document(story, title="Draft Terms of Service", document=terms_of_service, styles=styles)
    document.build(story, onFirstPage=_draw_page(accent), onLaterPages=_draw_page(accent))
    return buffer.getvalue()
