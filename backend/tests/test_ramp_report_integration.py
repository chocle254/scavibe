import json
import os
import unittest
from unittest.mock import patch

from main import (
    RampReportRequest,
    StageAuditRequest,
    _performance_report,
    _ramp_assessment,
    _ramp_load_test_summary,
    audit_performance_ramp,
    read_performance_ramp_report,
)
from scavibe.audit_pin import issue_audit_pin
from scavibe.contracts import AuditContext, EvidenceKind, RuntimeMeasurement, SourceFile
from scavibe.load_test import RampResult, RampStepResult
from scavibe.repository import RepositorySnapshot


class RampReportIntegrationTests(unittest.IsolatedAsyncioTestCase):
    def test_no_breaking_point_is_preserved_as_the_exact_report_limitation(self) -> None:
        measurement = RuntimeMeasurement(
            id="ramp_200",
            target_mode="sandbox",
            endpoint="/",
            concurrent_users=200,
            duration_seconds=60,
            sample_count=20,
            successful_sample_count=20,
            p95_latency_ms=450.0,
            error_rate_percent=0.0,
        )
        result = RampResult(
            exploratory_steps=(),
            confirmation_measurement=measurement,
            breaking_point_concurrent_users=None,
        )
        report = _performance_report(
            AuditContext(
                audit_id="audit_ramp_200",
                repository_url="https://github.com/acme/storefront",
                app_url="https://storefront.example.com",
                commit_sha="e" * 40,
                source_files=[SourceFile(path="src/app.py", content="def app():\n    return 'ready'\n")],
                repository_paths=["src/app.py"],
            ),
            _ramp_load_test_summary(result),
            ramp_assessment=_ramp_assessment(result),
        )

        self.assertEqual(report.findings, [])
        self.assertIn(
            "no breaking point identified within the tested range of 10 to 200 concurrent users",
            report.limitations,
        )
        self.assertIsNotNone(report.ramp_assessment)
        self.assertIsNone(report.ramp_assessment.breaking_point_concurrent_users)
        self.assertEqual(report.evidence_inventory.runtime_measurements, [measurement])

    async def test_confirmation_measurement_creates_one_runtime_finding_and_persists_ramp_break(self) -> None:
        audit_id = "audit_ramp_100"
        commit_sha = "c" * 40
        with patch.dict(os.environ, {"SCAVIBE_AUDIT_PIN_SECRET": "x" * 32}, clear=False):
            audit_pin = issue_audit_pin(
                audit_id=audit_id,
                repository_url="https://github.com/acme/storefront",
                app_url="https://storefront.example.com",
                commit_sha=commit_sha,
            )
        snapshot = RepositorySnapshot(
            context=AuditContext(
                audit_id=audit_id,
                repository_url="https://github.com/acme/storefront",
                app_url="https://storefront.example.com",
                commit_sha=commit_sha,
                source_files=[SourceFile(path="src/app.py", content="def app():\n    return 'ready'\n")],
                repository_paths=["src/app.py"],
            ),
            selected_paths=["src/app.py"],
            source_content_complete=True,
        )
        confirmation = RuntimeMeasurement(
            id="ramp_100",
            target_mode="sandbox",
            endpoint="/",
            concurrent_users=100,
            duration_seconds=60,
            sample_count=20,
            successful_sample_count=19,
            p95_latency_ms=450.0,
            error_rate_percent=5.0,
        )

        async def fake_snapshot(request, measurements, *, initial_commit_sha=None):
            return snapshot, audit_id, audit_pin

        async def fake_ramp(*, sandbox_url: str, on_event):
            exploratory = RampStepResult(
                phase="exploratory",
                step_index=4,
                concurrent_users=100,
                duration_seconds=12,
                sample_count=10,
                successful_sample_count=9,
                p95_latency_ms=450.0,
                error_rate_percent=5.0,
            )
            await on_event(
                {
                    "type": "step_started",
                    "phase": "exploratory",
                    "step_index": 4,
                    "concurrent_users": 100,
                    "planned_duration_seconds": 12,
                }
            )
            await on_event(
                {
                    "type": "step_completed",
                    "phase": "exploratory",
                    "step_index": 4,
                    "concurrent_users": 100,
                    "p95_latency_ms": 450.0,
                    "error_rate_percent": 5.0,
                    "sample_count": 10,
                    "breached": True,
                }
            )
            await on_event(
                {
                    "type": "breaking_point_found",
                    "concurrent_users": 100,
                    "metric": "error_rate_percent",
                    "observed_value": 5.0,
                    "threshold": 1.0,
                }
            )
            await on_event(
                {
                    "type": "step_started",
                    "phase": "confirmation",
                    "step_index": 4,
                    "concurrent_users": 100,
                    "planned_duration_seconds": 60,
                }
            )
            await on_event(
                {
                    "type": "step_completed",
                    "phase": "confirmation",
                    "step_index": 4,
                    "concurrent_users": 100,
                    "p95_latency_ms": 450.0,
                    "error_rate_percent": 5.0,
                    "sample_count": 20,
                    "breached": True,
                }
            )
            await on_event(
                {
                    "type": "ramp_completed",
                    "tested_range": [10, 200],
                    "breaking_point_concurrent_users": 100,
                }
            )
            return RampResult(
                exploratory_steps=(exploratory,),
                confirmation_measurement=confirmation,
                breaking_point_concurrent_users=100,
                breaking_point_metric="error_rate_percent",
                breaking_point_observed_value=5.0,
                breaking_point_threshold=1.0,
            )

        request = StageAuditRequest(
            repository_url="https://github.com/acme/storefront",
            app_url="https://storefront.example.com",
            sandbox_url="https://sandbox.example",
            sandbox_authorized=True,
            audit_id=audit_id,
        )
        with (
            patch.dict(os.environ, {"SCAVIBE_AUDIT_PIN_SECRET": "x" * 32}, clear=False),
            patch("main._pinned_repository_snapshot", new=fake_snapshot),
            patch("main.run_ramp_load_test", new=fake_ramp),
        ):
            response = await audit_performance_ramp(request)
            chunks = [chunk async for chunk in response.body_iterator]
            token = next(chunk.removeprefix("id: ").strip() for chunk in chunks if chunk.startswith("id: "))
            persisted = await read_performance_ramp_report(RampReportRequest(ramp_report_token=token))

        completed_payload = json.loads(next(chunk.removeprefix("data: ").strip() for chunk in chunks if "ramp_completed" in chunk))
        self.assertEqual(completed_payload["breaking_point_concurrent_users"], 100)
        self.assertEqual(len(persisted.report.findings), 1)
        evidence = persisted.report.findings[0].evidence
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0].kind, EvidenceKind.RUNTIME)
        self.assertEqual(evidence[0].measurement_id, "ramp_100")
        self.assertEqual(evidence[0].metric, "error_rate_percent")
        self.assertEqual(evidence[0].observed_value, 5.0)
        self.assertEqual(evidence[0].threshold, 1.0)
        self.assertIsNotNone(persisted.report.ramp_assessment)
        self.assertEqual(persisted.report.ramp_assessment.breaking_point_concurrent_users, 100)
        self.assertEqual(persisted.report.ramp_assessment.metric, "error_rate_percent")
        self.assertEqual(persisted.report.ramp_assessment.observed_value, 5.0)
        self.assertEqual(persisted.report.ramp_assessment.threshold, 1.0)
        self.assertEqual(persisted.report.evidence_inventory.runtime_measurements, [confirmation])
