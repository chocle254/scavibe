import asyncio
import json
import unittest
from unittest.mock import patch

from main import StageAuditRequest, _performance_report, audit_performance_ramp
from scavibe.contracts import RuntimeMeasurement
from scavibe.load_test import LoadTestError, LoadTestSummary


class PerformanceRampEndpointTests(unittest.IsolatedAsyncioTestCase):
    async def test_streams_json_sse_events_as_the_ramp_emits_them(self) -> None:
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
            return None

        request = StageAuditRequest(
            repository_url="https://github.com/acme/storefront",
            app_url="https://storefront.example.com",
            sandbox_url="https://sandbox.example",
            sandbox_authorized=True,
        )
        with patch("main.run_ramp_load_test", new=fake_ramp):
            response = await audit_performance_ramp(request)
            chunks = [chunk async for chunk in response.body_iterator]

        self.assertEqual(response.media_type, "text/event-stream")
        self.assertEqual(response.headers["x-accel-buffering"], "no")
        decoded_events = [json.loads(chunk.removeprefix("data: ").strip()) for chunk in chunks]
        self.assertEqual(decoded_events[0]["type"], "step_started")
        self.assertIsNone(decoded_events[1]["p95_latency_ms"])
        self.assertIn('"p95_latency_ms":null', chunks[1])
        self.assertEqual(decoded_events[2]["type"], "ramp_completed")

    async def test_performance_report_rejects_a_nonqualifying_measurement(self) -> None:
        measurement = RuntimeMeasurement(
            id="sandbox_low_load",
            target_mode="sandbox",
            endpoint="/",
            concurrent_users=10,
            duration_seconds=30,
            sample_count=20,
            successful_sample_count=20,
            p95_latency_ms=900.0,
            error_rate_percent=0.0,
        )
        summary = LoadTestSummary(measurement=measurement, successful_requests=20, failed_requests=0)

        with self.assertRaisesRegex(LoadTestError, "at least 100 concurrent users, 60 seconds, and 20 samples"):
            _performance_report(None, summary)
