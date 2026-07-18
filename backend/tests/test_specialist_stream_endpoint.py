import json
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from main import StageAuditRequest, StageAuditResponse, audit_legal_stream, audit_security_stream
from scavibe.contracts import AgentReport, AuditContext, SourceFile, Stage
from scavibe.repository import RepositorySnapshot


class SpecialistStreamEndpointTests(unittest.IsolatedAsyncioTestCase):
    async def test_security_stream_emits_only_real_repository_analysis_and_validation_phases(self) -> None:
        audit_id = "audit_security_stream"
        audit_pin = "signed-pinned-audit-token"
        commit_sha = "f" * 40
        selected_paths = ["api/auth.py", "src/db/queries.py"]
        snapshot = RepositorySnapshot(
            context=AuditContext(
                audit_id=audit_id,
                repository_url="https://github.com/acme/storefront",
                app_url="https://storefront.example.com",
                commit_sha=commit_sha,
                source_files=[
                    SourceFile(path="api/auth.py", content="def authenticate(request):\n    return request.user\n"),
                    SourceFile(path="src/db/queries.py", content="def query():\n    return 'SELECT 1'\n"),
                ],
                repository_paths=selected_paths,
            ),
            selected_paths=selected_paths,
            source_content_complete=True,
        )

        async def fake_snapshot(request, measurements, *, initial_commit_sha=None):
            self.assertEqual(measurements, [])
            self.assertEqual(request.audit_id, audit_id)
            self.assertIsNone(initial_commit_sha)
            return snapshot, audit_id, audit_pin

        async def fake_specialist_report(stage: Stage, context: AuditContext, *, on_phase=None) -> AgentReport:
            self.assertEqual(stage, Stage.SECURITY)
            self.assertEqual(context.commit_sha, commit_sha)
            self.assertIsNotNone(on_phase)
            await on_phase("phase_started", "specialist_analysis")
            await on_phase("phase_completed", "specialist_analysis")
            await on_phase("phase_started", "evidence_validation")
            await on_phase("phase_completed", "evidence_validation")
            return AgentReport(
                stage=Stage.SECURITY,
                summary="Security report is based only on the pinned repository source evidence.",
                findings=[],
                limitations=[],
                evidence_commit_sha=commit_sha,
            )

        request = StageAuditRequest(
            repository_url="https://github.com/acme/storefront",
            app_url="https://storefront.example.com",
            audit_id=audit_id,
        )
        with (
            patch("main._pinned_repository_snapshot", new=fake_snapshot),
            patch("main._specialist_report", new=fake_specialist_report),
        ):
            response = await audit_security_stream(request)
            raw_chunks = [chunk async for chunk in response.body_iterator]

        events = []
        for chunk in raw_chunks:
            text = chunk.decode("utf-8") if isinstance(chunk, bytes) else chunk
            self.assertTrue(text.startswith("data: "))
            events.append(json.loads(text.removeprefix("data: ").strip()))

        self.assertEqual(
            [event["type"] for event in events],
            [
                "phase_started",
                "phase_completed",
                "phase_started",
                "phase_completed",
                "phase_started",
                "phase_completed",
                "report_ready",
            ],
        )
        self.assertEqual([event.get("phase") for event in events[:-1]], [
            "repository_fetch",
            "repository_fetch",
            "specialist_analysis",
            "specialist_analysis",
            "evidence_validation",
            "evidence_validation",
        ])
        self.assertEqual(events[1]["commit_sha"], commit_sha)
        self.assertEqual(events[1]["selected_file_count"], 2)
        self.assertEqual(
            [event for event in events if event["type"] == "file_queued"],
            [],
        )

        final_response = StageAuditResponse.model_validate(events[-1]["result"])
        self.assertEqual(final_response.audit_id, audit_id)
        self.assertEqual(final_response.audit_pin, audit_pin)
        self.assertEqual(final_response.repository.commit_sha, commit_sha)
        self.assertEqual(final_response.report.evidence_commit_sha, commit_sha)

    async def test_legal_stream_rejects_empty_jurisdictions(self) -> None:
        request = StageAuditRequest(
            repository_url="https://github.com/acme/storefront",
            app_url="https://storefront.example.com",
            jurisdictions=[],
        )

        with self.assertRaises(HTTPException) as raised:
            await audit_legal_stream(request)

        self.assertEqual(raised.exception.status_code, 422)
        self.assertEqual(raised.exception.detail, "data-handling and consent audit requires at least one explicit jurisdiction code")
