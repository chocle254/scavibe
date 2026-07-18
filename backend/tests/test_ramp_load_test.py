import unittest
from unittest.mock import patch

import httpx

from scavibe.contracts import RuntimeMeasurement
from scavibe.load_test import (
    LOAD_TEST_HTTP_LIMITS,
    LoadTestError,
    RampStepResult,
    run_ramp_load_test,
    run_sandbox_load_test,
)


class AdvancingClock:
    def __init__(self, increment_seconds: float = 0.25) -> None:
        self.value = 0.0
        self.increment_seconds = increment_seconds

    def __call__(self) -> float:
        self.value += self.increment_seconds
        return self.value


class FailedResponseClient:
    def __init__(self, *args, **kwargs) -> None:
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return None

    async def get(self, url: str) -> httpx.Response:
        return httpx.Response(503, request=httpx.Request("GET", url))


class ZeroResponseClient:
    def __init__(self, *args, **kwargs) -> None:
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return None

    async def get(self, url: str) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=httpx.Request("GET", url))


class CapturingSuccessClient:
    options: list[dict] = []

    def __init__(self, *args, **kwargs) -> None:
        type(self).options.append(kwargs)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return None

    async def get(self, url: str) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url))


class RampLoadTestTests(unittest.IsolatedAsyncioTestCase):
    async def test_completed_failures_emit_null_p95_and_100_percent_error_without_load_test_error(self) -> None:
        events: list[dict] = []

        async def on_event(event: dict) -> None:
            events.append(event)

        with (
            patch("scavibe.load_test.validate_sandbox_url", return_value="https://sandbox.example"),
            patch("scavibe.load_test.httpx.AsyncClient", FailedResponseClient),
            patch("scavibe.load_test._monotonic", new=AdvancingClock()),
        ):
            result = await run_ramp_load_test(sandbox_url="https://sandbox.example", on_event=on_event)

        breaking_events = [event for event in events if event["type"] == "breaking_point_found"]
        exploratory_completed = [event for event in events if event["type"] == "step_completed" and event["phase"] == "exploratory"]
        self.assertEqual(len(breaking_events), 1)
        self.assertEqual(breaking_events[0]["metric"], "error_rate_percent")
        self.assertEqual(breaking_events[0]["observed_value"], 100.0)
        self.assertEqual(breaking_events[0]["threshold"], 1.0)
        self.assertIsNone(exploratory_completed[0]["p95_latency_ms"])
        self.assertEqual(exploratory_completed[0]["error_rate_percent"], 100.0)
        self.assertEqual(len(result.exploratory_steps), 1)
        self.assertTrue(all(not isinstance(step, RuntimeMeasurement) for step in result.exploratory_steps))
        self.assertIsInstance(result.confirmation_measurement, RuntimeMeasurement)
        self.assertGreaterEqual(result.confirmation_measurement.sample_count, 20)
        self.assertGreaterEqual(result.confirmation_measurement.duration_seconds, 60)
        self.assertEqual(result.confirmation_measurement.successful_sample_count, 0)
        self.assertIsNone(result.confirmation_measurement.p95_latency_ms)

    async def test_zero_completed_responses_raise_load_test_error(self) -> None:
        async def on_event(event: dict) -> None:
            return None

        with (
            patch("scavibe.load_test.validate_sandbox_url", return_value="https://sandbox.example"),
            patch("scavibe.load_test.httpx.AsyncClient", ZeroResponseClient),
            patch("scavibe.load_test._monotonic", new=AdvancingClock()),
        ):
            with self.assertRaisesRegex(LoadTestError, "step 0 at 10 concurrent users completed zero HTTP responses"):
                await run_ramp_load_test(sandbox_url="https://sandbox.example", on_event=on_event)

    async def test_confirmation_reuses_candidate_step_index_and_error_rate_wins_tie(self) -> None:
        events: list[dict] = []

        async def on_event(event: dict) -> None:
            events.append(event)

        async def fake_step(**kwargs) -> RampStepResult:
            phase = kwargs["phase"]
            index = kwargs["step_index"]
            users = kwargs["concurrent_users"]
            duration = kwargs["duration_seconds"]
            if phase == "exploratory" and index < 5:
                return RampStepResult(phase, index, users, duration, 10, 10, 120.0, 0.0)
            if phase == "exploratory":
                return RampStepResult(phase, index, users, duration, 10, 9, 640.0, 10.0)
            return RampStepResult(phase, index, users, duration, 20, 18, 640.0, 10.0)

        with (
            patch("scavibe.load_test.validate_sandbox_url", return_value="https://sandbox.example"),
            patch("scavibe.load_test._run_ramp_step", new=fake_step),
        ):
            await run_ramp_load_test(sandbox_url="https://sandbox.example", on_event=on_event)

        breaking_event = next(event for event in events if event["type"] == "breaking_point_found")
        exploratory_step = next(event for event in events if event["type"] == "step_completed" and event["phase"] == "exploratory" and event["step_index"] == 5)
        confirmation_started = next(event for event in events if event["type"] == "step_started" and event["phase"] == "confirmation")
        confirmation_completed = next(event for event in events if event["type"] == "step_completed" and event["phase"] == "confirmation")
        self.assertEqual(breaking_event["metric"], "error_rate_percent")
        self.assertEqual(breaking_event["observed_value"], 10.0)
        self.assertEqual(breaking_event["threshold"], 1.0)
        self.assertEqual(exploratory_step["step_index"], 5)
        self.assertEqual(confirmation_started["step_index"], 5)
        self.assertEqual(confirmation_completed["step_index"], 5)
        self.assertEqual(confirmation_started["phase"], "confirmation")
        self.assertEqual(confirmation_completed["phase"], "confirmation")
        self.assertEqual(exploratory_step["phase"], "exploratory")

    async def test_clean_confirmation_discards_candidate_and_reports_only_later_confirmed_break(self) -> None:
        events: list[dict] = []

        async def on_event(event: dict) -> None:
            events.append(event)

        async def fake_step(**kwargs) -> RampStepResult:
            phase = kwargs["phase"]
            index = kwargs["step_index"]
            users = kwargs["concurrent_users"]
            duration = kwargs["duration_seconds"]
            if phase == "exploratory" and index in {1, 4}:
                return RampStepResult(phase, index, users, duration, 25, 24, 650.0, 4.0)
            if phase == "confirmation" and index == 1:
                return RampStepResult(phase, index, users, duration, 25, 25, 240.0, 0.0)
            if phase == "confirmation" and index == 4:
                return RampStepResult(phase, index, users, duration, 25, 24, 710.0, 4.0)
            return RampStepResult(phase, index, users, duration, 25, 25, 240.0, 0.0)

        with (
            patch("scavibe.load_test.validate_sandbox_url", return_value="https://sandbox.example"),
            patch("scavibe.load_test._run_ramp_step", new=fake_step),
        ):
            result = await run_ramp_load_test(sandbox_url="https://sandbox.example", on_event=on_event)

        discarded = [event for event in events if event["type"] == "candidate_discarded"]
        breaking = [event for event in events if event["type"] == "breaking_point_found"]
        completed = next(event for event in events if event["type"] == "ramp_completed")
        self.assertEqual(discarded, [{"type": "candidate_discarded"}])
        self.assertEqual(len(breaking), 1)
        self.assertEqual(breaking[0]["concurrent_users"], 100)
        self.assertEqual(breaking[0]["metric"], "error_rate_percent")
        self.assertEqual(breaking[0]["observed_value"], 4.0)
        self.assertEqual(completed["breaking_point_concurrent_users"], 100)
        self.assertEqual(result.breaking_point_concurrent_users, 100)
        self.assertEqual(result.confirmation_measurement.concurrent_users, 100)
        self.assertEqual(result.breaking_point_metric, "error_rate_percent")

    async def test_single_and_ramp_clients_use_the_explicit_connection_limits(self) -> None:
        async def on_event(event: dict) -> None:
            return None

        CapturingSuccessClient.options = []
        with (
            patch("scavibe.load_test.validate_sandbox_url", return_value="https://sandbox.example"),
            patch("scavibe.load_test.httpx.AsyncClient", CapturingSuccessClient),
            patch("scavibe.load_test._monotonic", new=AdvancingClock()),
        ):
            await run_sandbox_load_test(
                sandbox_url="https://sandbox.example",
                concurrent_users=10,
                duration_seconds=30,
            )
            await run_ramp_load_test(sandbox_url="https://sandbox.example", on_event=on_event)

        self.assertGreaterEqual(len(CapturingSuccessClient.options), 2)
        self.assertEqual(LOAD_TEST_HTTP_LIMITS.max_connections, 250)
        self.assertEqual(LOAD_TEST_HTTP_LIMITS.max_keepalive_connections, 250)
        for options in CapturingSuccessClient.options:
            self.assertIs(options["limits"], LOAD_TEST_HTTP_LIMITS)
