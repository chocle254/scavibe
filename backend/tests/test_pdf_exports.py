import unittest
from io import BytesIO
from unittest.mock import patch
from zipfile import ZipFile

from fastapi import HTTPException

from main import (
    AuditPdfArchiveRequest,
    ConsentExampleRequest,
    StagePdfRequest,
    _consent_example_files,
    download_audit_pdf_archive,
    download_consent_example,
    download_legal_pdf,
    download_performance_pdf,
    download_security_pdf,
    _stage_pdf_bytes,
)
from scavibe.contracts import AgentReport, AttackerAccess, Evidence, EvidenceInventory, EvidenceKind, ExploitabilityStatus, Finding, Impact, RampAssessment, RuntimeMeasurement, SecurityPocExecution, Severity, SourceFile, Stage
from scavibe.pdf_reports import build_stage_pdf, generate_pdf_report
from scavibe.reporting import report_markdown
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
    async def test_security_exports_show_poc_audit_trail_and_confirmed_findings_first(self) -> None:
        candidate = report_for(Stage.SECURITY).findings[0].model_copy(
            update={
                "title": "Candidate static finding",
                "exploitability_status": ExploitabilityStatus.CANDIDATE_UNCONFIRMED,
            }
        )
        confirmed = report_for(Stage.SECURITY).findings[0].model_copy(
            update={
                "title": "Confirmed sandbox finding",
                "exploitability_status": ExploitabilityStatus.CONFIRMED_EXPLOITABLE,
                "poc_execution": SecurityPocExecution(
                    proposed_test_code="await client.get('/profile')",
                    executed_test_code="response = await client.get('https://sandbox.example.vercel.app/profile')",
                    execution_state="executed",
                    request_method="GET",
                    request_path="/profile",
                    expected_status_code=200,
                    expected_response_marker="private_email",
                    response_status_code=200,
                    response_excerpt='{"private_email":"audit@example.test"}',
                    response_sha256="a" * 64,
                    reason="The validated GET probe returned the planned status and the source-cited response marker.",
                ),
            }
        )
        report = report_for(Stage.SECURITY, findings=[candidate, confirmed])
        markdown = report_markdown(report)
        self.assertLess(markdown.index("Confirmed sandbox finding"), markdown.index("Candidate static finding"))
        self.assertIn("Confirmed exploitable", markdown)
        self.assertIn("Sandbox proof-of-concept audit trail", markdown)
        self.assertIn("Captured response excerpt", markdown)

        with patch("scavibe.pdf_reports._paragraph", wraps=pdf_reports._paragraph) as paragraph:
            document = build_stage_pdf(report)
        rendered_text = [call.args[0] for call in paragraph.call_args_list]
        self.assertTrue(document.startswith(b"%PDF-"))
        self.assertLess(rendered_text.index("Confirmed sandbox finding"), rendered_text.index("Candidate static finding"))
        self.assertIn("Confirmed exploitable", rendered_text)
        self.assertIn("Sandbox proof-of-concept audit trail", rendered_text)

    async def test_all_pdf_routes_share_the_single_generator(self) -> None:
        for stage in (Stage.PERFORMANCE, Stage.SECURITY, Stage.LEGAL):
            report = report_for(stage)
            with patch("scavibe.pdf_reports.generate_pdf_report", return_value=b"%PDF-test\n%%EOF\n") as generate:
                document = _stage_pdf_bytes(report)
            self.assertEqual(document, b"%PDF-test\n%%EOF\n")
            self.assertEqual(generate.call_args.args, (report, pdf_reports.STAGE_ACCENTS[stage], pdf_reports.STAGE_AUDIT_LABELS[stage]))

    async def test_performance_pdf_uses_confirmed_ramp_metrics(self) -> None:
        performance = report_for(Stage.PERFORMANCE).model_copy(
            update={
                "ramp_assessment": RampAssessment(
                    tested_range=[10, 200],
                    breaking_point_concurrent_users=100,
                    metric="error_rate_percent",
                    observed_value=4.0,
                    threshold=1.0,
                )
            }
        )
        with patch("scavibe.pdf_reports._paragraph", wraps=pdf_reports._paragraph) as paragraph:
            document = generate_pdf_report(performance, "#83f5bf", "Performance audit")

        rendered_text = [call.args[0] for call in paragraph.call_args_list]
        self.assertTrue(document.startswith(b"%PDF-"))
        self.assertIn(
            "Confirmed ramp breaking point: error_rate_percent=4.0 against threshold=1.0 at 100 concurrent users.",
            rendered_text,
        )

    async def test_complete_audit_archive_contains_three_real_pdfs(self) -> None:
        response = await download_audit_pdf_archive(
            AuditPdfArchiveRequest(
                performance=report_for(Stage.PERFORMANCE),
                security=report_for(Stage.SECURITY),
                legal=report_for(Stage.LEGAL),
            )
        )

        self.assertEqual(response.media_type, "application/zip")
        self.assertEqual(response.headers["content-disposition"], "attachment; filename=scavibe-audit-reports.zip")
        archive = ZipFile(BytesIO(await response_bytes(response)))
        self.assertEqual(
            archive.namelist(),
            [
                "scavibe-performance-audit.pdf",
                "scavibe-security-audit.pdf",
                "scavibe-data-handling-and-consent-audit.pdf",
            ],
        )
        for filename in archive.namelist():
            document = archive.read(filename)
            self.assertTrue(document.startswith(b"%PDF-"))
            self.assertTrue(document.rstrip().endswith(b"%%EOF"))
            self.assertGreater(len(document), 3_000)

    async def test_zero_finding_report_still_exports_a_valid_pdf(self) -> None:
        response = await download_security_pdf(StagePdfRequest(report=report_for(Stage.SECURITY, findings=[])))
        document = await response_bytes(response)

        self.assertTrue(document.startswith(b"%PDF-"))
        self.assertTrue(document.rstrip().endswith(b"%%EOF"))
        self.assertGreater(len(document), 3_000)

    async def test_zero_finding_pdf_reproduces_full_evidence_inventory_and_remediation_decision(self) -> None:
        inventory = EvidenceInventory(
            source_files=[SourceFile(path="src/consent.ts", content="const collectEmail = true;\nreturn collectEmail;")],
            repository_paths=["README.md", "src/consent.ts"],
            source_content_complete=False,
            runtime_measurements=[
                RuntimeMeasurement(
                    id="ramp_100",
                    target_mode="sandbox",
                    endpoint="/",
                    concurrent_users=100,
                    duration_seconds=60,
                    sample_count=20,
                    successful_sample_count=20,
                    p95_latency_ms=210.0,
                    error_rate_percent=0.0,
                )
            ],
            jurisdictions=["KE"],
        )
        report = report_for(Stage.LEGAL, findings=[]).model_copy(update={"evidence_inventory": inventory})

        with (
            patch("scavibe.pdf_reports._verbatim_evidence_block", wraps=pdf_reports._verbatim_evidence_block) as block,
            patch("scavibe.pdf_reports._paragraph", wraps=pdf_reports._paragraph) as paragraph,
        ):
            document = build_stage_pdf(report)

        blocks = [call.args[0] for call in block.call_args_list]
        rendered_text = [call.args[0] for call in paragraph.call_args_list]
        self.assertTrue(document.startswith(b"%PDF-"))
        self.assertIn("README.md\nsrc/consent.ts", blocks)
        self.assertIn("000001 | const collectEmail = true;\n000002 | return collectEmail;", blocks)
        self.assertIn("Remediation plan", rendered_text)
        self.assertIn("No remediation is proposed because no finding met the evidence admission rule. Do not apply a speculative fix from this report.", rendered_text)
        self.assertIn("Measurement ID: ramp_100", rendered_text)
        self.assertIn("KE", rendered_text)

    async def test_stage_endpoints_return_structural_pdfs_with_exact_filenames(self) -> None:
        performance = await download_performance_pdf(StagePdfRequest(report=report_for(Stage.PERFORMANCE)))
        security = await download_security_pdf(StagePdfRequest(report=report_for(Stage.SECURITY)))
        legal = await download_legal_pdf(StagePdfRequest(report=report_for(Stage.LEGAL)))

        for response, filename in (
            (performance, "scavibe-performance-audit.pdf"),
            (security, "scavibe-security-audit.pdf"),
            (legal, "scavibe-data-handling-and-consent-audit.pdf"),
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

        response = await download_consent_example(ConsentExampleRequest(report=report_for(Stage.LEGAL)))
        archive = ZipFile(BytesIO(await response_bytes(response)))
        self.assertEqual(archive.namelist(), ["ConsentCheckbox.tsx"])
        self.assertIn("ConsentCheckbox", archive.read("ConsentCheckbox.tsx").decode("utf-8"))
        self.assertEqual(response.headers["content-disposition"], "attachment; filename=scavibe-consent-checkbox-example.zip")

    async def test_shared_evidence_formatter_is_called_and_legal_pdf_has_no_document_appendix(self) -> None:
        security = report_for(Stage.SECURITY)
        with patch("scavibe.pdf_reports.format_evidence_markdown", wraps=pdf_reports.format_evidence_markdown) as formatter:
            document = build_stage_pdf(security)
        self.assertTrue(document.startswith(b"%PDF-"))
        self.assertEqual(formatter.call_count, len(security.findings[0].evidence))

        legal = report_for(Stage.LEGAL)
        with patch("main._stage_pdf_bytes", return_value=b"%PDF-test\n%%EOF\n") as build_pdf:
            response = await download_legal_pdf(StagePdfRequest(report=legal))
        self.assertEqual(response.media_type, "application/pdf")
        self.assertEqual(build_pdf.call_args.args, (legal,))
        self.assertEqual(_consent_example_files().keys(), {"ConsentCheckbox.tsx"})
