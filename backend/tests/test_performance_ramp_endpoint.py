import asyncio
import json
import os
import unittest
from unittest.mock import patch

from main import StageAuditRequest, audit_performance_ramp
from scavibe.audit_pin import issue_audit_pin
from scavibe.contracts import AuditContext, RuntimeMeasurement, SourceFile
from scavibe.agents import AuditOrchestrator
from scavibe.load_test import RampResult
from scavibe.repository import RepositorySnapshot
from tests.test_agents import FakeGateway, context


class PerformanceRampEndpointTests(unittest.IsolatedAsyncioTestCase):
    async def test_sse_stream_encodes_null_p95_as_json_null(self) -> None:
        audit_id = "audit_sse_null"
        commit_sha = "d" * 40
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
            id="ramp_null_p95",
            target_mode="sandbox",
            endpoint="/",
            concurrent_users=10,
            duration_seconds=60,
            sample_count=20,
            successful_sample_count=0,
            p95_latency_ms=None,
            error_rate_percent=100.0,
        )

        async def fake_snapshot(request, measurements, *, initial_commit_sha=None):
            return snapshot, audit_id, audit_pin

        async def fake_ramp(*, sandbox_url: str, on_event):
            await on_event(
                {
                    "type": "step_started",
                    "phase": "exploratory",
                    "step_index": 0,
                    "concurrent_users": 10,
                    "planned_duration_seconds": 12,
                }
            )
            await asyncio.sleep(0)
            await on_event(
                {
                    "type": "step_completed",
                    "phase": "exploratory",
                    "step_index": 0,
                    "concurrent_users": 10,
                    "p95_latency_ms": None,
                    "error_rate_percent": 100.0,
                    "sample_count": 20,
                    "breached": True,
                }
            )
            await on_event(
                {
                    "type": "ramp_completed",
                    "tested_range": [10, 200],
                    "breaking_point_concurrent_users": None,
                }
            )
            return RampResult(
                exploratory_steps=(),
                confirmation_measurement=confirmation,
                breaking_point_concurrent_users=10,
                breaking_point_metric="error_rate_percent",
                breaking_point_observed_value=100.0,
                breaking_point_threshold=1.0,
            )

        request = StageAuditRequest(
            repository_url="https://github.com/acme/storefront",
            app_url="https://storefront.example.com",
            sandbox_url="https://sandbox.example",
            sandbox_authorized=True,
            audit_id=audit_id,
        )
        with patch.dict(os.environ, {"SCAVIBE_AUDIT_PIN_SECRET": "x" * 32}, clear=False):
            audit_pin = issue_audit_pin(
                audit_id=audit_id,
                repository_url="https://github.com/acme/storefront",
                app_url="https://storefront.example.com",
                commit_sha=commit_sha,
            )
            with (
                patch("main._pinned_repository_snapshot", new=fake_snapshot),
                patch("main.run_ramp_load_test", new=fake_ramp),
            ):
                response = await audit_performance_ramp(request)
                chunks = [chunk async for chunk in response.body_iterator]

        self.assertEqual(response.media_type, "text/event-stream")
        self.assertEqual(response.headers["x-accel-buffering"], "no")
        decoded_events = [json.loads(chunk.removeprefix("data: ").strip()) for chunk in chunks if chunk.startswith("data: ")]
        self.assertEqual(decoded_events[0]["type"], "step_started")
        self.assertIsNone(decoded_events[1]["p95_latency_ms"])
        self.assertIn('"p95_latency_ms":null', chunks[1])
        self.assertEqual(decoded_events[2]["type"], "ramp_completed")
        self.assertTrue(any(chunk.startswith("id: ") for chunk in chunks))

    async def test_nonqualifying_raw_breach_produces_zero_findings_and_qualifying_gate_limitation(self) -> None:
        measurement = RuntimeMeasurement(
            id="sandbox_low_load",
            target_mode="sandbox",
            endpoint="/",
            concurrent_users=10,
            duration_seconds=30,
            sample_count=25,
            successful_sample_count=25,
            p95_latency_ms=900.0,
            error_rate_percent=5.0,
        )
        low_load_context = context().model_copy(update={"runtime_measurements": [measurement]})
        run = await AuditOrchestrator(FakeGateway()).run(low_load_context)
        performance = run.stage_results[0]

        self.assertEqual(performance.stage, "performance")
        self.assertEqual(performance.status, "blocked")
        self.assertIsNotNone(performance.report)
        self.assertEqual(performance.report.findings, [])
        self.assertIn("did not meet the qualifying gate", performance.report.limitations[0])
        self.assertEqual(performance.report.evidence_inventory.runtime_measurements, [measurement])
