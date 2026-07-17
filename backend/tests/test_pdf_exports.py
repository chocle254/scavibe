import unittest
from io import BytesIO
from unittest.mock import patch
from zipfile import ZipFile

from fastapi import HTTPException

from main import (
    LegalArtifactRequest,
    StagePdfRequest,
    _legal_artifact_files,
    download_legal_artifacts,
    download_legal_pdf,
    download_performance_pdf,
    download_security_pdf,
)
from scavibe.contracts import AgentReport, AttackerAccess, Evidence, EvidenceKind, Finding, Impact, Severity, Stage
from scavibe.pdf_reports import build_stage_pdf
import scavibe.pdf_reports as pdf_reports


def report_for(stage: Stage, *, findings: list[Finding] | None = None) -> AgentReport:
    evidence_kind = EvidenceKind.RUNTIME if stage == Stage.PERFORMANCE else EvidenceKind.SOURCE
    evidence = (
        Evidence(
            kind=evidence_kind,
            statement="Sandbox runtime measurement contains the verified threshold result.",
            measurement_id="ramp_100",
            endpoint="/",
            metric="error_rate_percent",
            observed_value=5.0,
            threshold=1.0,
        )
        if evidence_kind == EvidenceKind.RUNTIME
        else Evidence(
            kind=EvidenceKind.SOURCE,
            statement="The quoted source line contains the verified data handling behavior.",
            file_path="src/handlers.ts",
            start_line=12,
            end_line=12,
            quote="return request.headers.get('authorization')",
        )
    )
    finding = Finding(
        title="Verified audit condition requires a targeted remediation",
        statement="The supplied evidence identifies an exact condition that needs a documented remediation before release.",
        impact=Impact.SERVICE_UNAVAILABLE if stage == Stage.PERFORMANCE else Impact.SINGLE_USER_DATA,
        attacker_access=AttackerAccess.UNAUTHENTICATED_REMOTE,
        evidence=[evidence],
        remediation="Apply the targeted code or configuration change, add a regression test, and repeat this exact evidence-backed audit.",
        risk_score=80,
        severity=Severity.HIGH,
        confidence_score=35,
    )
    return AgentReport(
        stage=stage,
        summary="The audit report is generated only from the supplied source or runtime evidence.",
        findings=findings if findings is not None else [finding],
        limitations=["Only the supplied immutable evidence commit is covered by this report."],
        evidence_commit_sha="a" * 40,
    )


async def response_bytes(response) -> bytes:
    return b"".join([chunk async for chunk in response.body_iterator])


class PdfExportTests(unittest.IsolatedAsyncioTestCase):
    async def test_zero_finding_report_still_exports_a_valid_pdf(self) -> None:
        response = await download_security_pdf(StagePdfRequest(report=report_for(Stage.SECURITY, findings=[])))
        document = await response_bytes(response)

        self.assertTrue(document.startswith(b"%PDF-"))
        self.assertTrue(document.rstrip().endswith(b"%%EOF"))
        self.assertGreater(len(document), 3_000)

    async def test_stage_endpoints_return_structural_pdfs_with_exact_filenames(self) -> None:
        performance = await download_performance_pdf(StagePdfRequest(report=report_for(Stage.PERFORMANCE)))
        security = await download_security_pdf(StagePdfRequest(report=report_for(Stage.SECURITY)))
        legal = await download_legal_pdf(LegalArtifactRequest(report=report_for(Stage.LEGAL), jurisdictions=["KE"]))

        for response, filename in (
            (performance, "scavibe-performance-audit.pdf"),
            (security, "scavibe-security-audit.pdf"),
            (legal, "scavibe-legal-audit-and-drafts.pdf"),
        ):
            document = await response_bytes(response)
            self.assertEqual(response.media_type, "application/pdf")
            self.assertEqual(response.headers["content-disposition"], f"attachment; filename={filename}")
            self.assertTrue(document.startswith(b"%PDF-"))
            self.assertTrue(document.rstrip().endswith(b"%%EOF"))
            self.assertGreater(len(document), 3_000)

    async def test_mismatched_stage_is_rejected_and_consent_zip_contains_only_the_component(self) -> None:
        with self.assertRaises(HTTPException) as raised:
            await download_security_pdf(StagePdfRequest(report=report_for(Stage.PERFORMANCE)))
        self.assertEqual(raised.exception.status_code, 422)

        response = await download_legal_artifacts(LegalArtifactRequest(report=report_for(Stage.LEGAL), jurisdictions=["KE"]))
        archive = ZipFile(BytesIO(await response_bytes(response)))
        self.assertEqual(archive.namelist(), ["ConsentCheckbox.tsx"])
        self.assertIn("TermsConsent", archive.read("ConsentCheckbox.tsx").decode("utf-8"))
        self.assertEqual(response.headers["content-disposition"], "attachment; filename=scavibe-consent-component.zip")

    async def test_shared_evidence_formatter_is_called_and_legal_drafts_are_passed_verbatim(self) -> None:
        security = report_for(Stage.SECURITY)
        with patch("scavibe.pdf_reports.format_evidence_markdown", wraps=pdf_reports.format_evidence_markdown) as formatter:
            document = build_stage_pdf(security)
        self.assertTrue(document.startswith(b"%PDF-"))
        self.assertEqual(formatter.call_count, len(security.findings[0].evidence))

        legal = report_for(Stage.LEGAL)
        artifacts = _legal_artifact_files(legal, ["KE"])
        with patch("main._stage_pdf_bytes", return_value=b"%PDF-test\n%%EOF\n") as build_pdf:
            response = await download_legal_pdf(LegalArtifactRequest(report=legal, jurisdictions=["KE"]))
        self.assertEqual(response.media_type, "application/pdf")
        self.assertEqual(
            build_pdf.call_args.kwargs["legal_drafts"],
            (artifacts["DRAFT_PRIVACY_POLICY.md"], artifacts["DRAFT_TERMS_OF_SERVICE.md"]),
        )
