"""Bounded HTTP load tests for explicitly authorized sandbox URLs."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal, TypeAlias, TypedDict
from urllib.parse import urlparse

import httpx

from .contracts import RuntimeMeasurement
from .agents.thresholds import (
    PERFORMANCE_ERROR_RATE_THRESHOLD_PERCENT,
    PERFORMANCE_MIN_DURATION_SECONDS,
    PERFORMANCE_MIN_SAMPLE_COUNT,
    PERFORMANCE_P95_LATENCY_THRESHOLD_MS,
)

MIN_CONCURRENT_USERS = 10
MAX_CONCURRENT_USERS = 200
MIN_DURATION_SECONDS = 30
MAX_DURATION_SECONDS = 300
REQUEST_TIMEOUT_SECONDS = 10.0
EXPLORATORY_DURATION_SECONDS = 12
RAMP_CONCURRENT_USERS = (10, 25, 50, 75, 100, 125, 150, 175, 200)


def _monotonic() -> float:
    """Provide a testable monotonic clock without replacing asyncio's clock."""
    return time.monotonic()


class LoadTestError(RuntimeError):
    """The authorized sandbox target does not meet the fixed safety controls."""


class StepStartedEvent(TypedDict):
    type: Literal["step_started"]
    phase: Literal["exploratory", "confirmation"]
    step_index: int
    concurrent_users: int
    planned_duration_seconds: int


class SampleTickEvent(TypedDict):
    type: Literal["sample_tick"]
    step_index: int
    elapsed_seconds: float
    live_p95_latency_ms: float | None
    live_error_rate_percent: float
    samples_so_far: int


class StepCompletedEvent(TypedDict):
    type: Literal["step_completed"]
    phase: Literal["exploratory", "confirmation"]
    step_index: int
    concurrent_users: int
    p95_latency_ms: float | None
    error_rate_percent: float
    sample_count: int
    breached: bool


class BreakingPointFoundEvent(TypedDict):
    type: Literal["breaking_point_found"]
    concurrent_users: int
    metric: Literal["p95_latency_ms", "error_rate_percent"]
    observed_value: float
    threshold: float


class RampCompletedEvent(TypedDict):
    type: Literal["ramp_completed"]
    tested_range: list[int]
    breaking_point_concurrent_users: int | None


RampEvent: TypeAlias = StepStartedEvent | SampleTickEvent | StepCompletedEvent | BreakingPointFoundEvent | RampCompletedEvent
RampEventCallback: TypeAlias = Callable[[RampEvent], Awaitable[None]]


def validate_sandbox_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise LoadTestError("sandbox_url must be an HTTPS URL")
    try:
        resolved = socket.gethostbyname(parsed.hostname)
        if ipaddress.ip_address(resolved).is_private or ipaddress.ip_address(resolved).is_loopback:
            raise LoadTestError("sandbox_url must not resolve to a private or loopback IPv4 address")
    except socket.gaierror as error:
        raise LoadTestError("sandbox_url hostname could not be resolved") from error
    return value.rstrip("/")


@dataclass(frozen=True)
class LoadTestSummary:
    measurement: RuntimeMeasurement
    successful_requests: int
    failed_requests: int


@dataclass(frozen=True)
class RampStepResult:
    phase: str
    step_index: int
    concurrent_users: int
    duration_seconds: int
    sample_count: int
    successful_sample_count: int
    p95_latency_ms: float | None
    error_rate_percent: float


@dataclass(frozen=True)
class RampResult:
    exploratory_steps: tuple[RampStepResult, ...]
    confirmation_measurement: RuntimeMeasurement
    breaking_point_concurrent_users: int | None


async def run_sandbox_load_test(*, sandbox_url: str, concurrent_users: int, duration_seconds: int) -> LoadTestSummary:
    """Run GET requests for the exact requested duration with a fixed 200-user cap."""
    if not MIN_CONCURRENT_USERS <= concurrent_users <= MAX_CONCURRENT_USERS:
        raise LoadTestError(f"concurrent_users must be between {MIN_CONCURRENT_USERS} and {MAX_CONCURRENT_USERS}")
    if not MIN_DURATION_SECONDS <= duration_seconds <= MAX_DURATION_SECONDS:
        raise LoadTestError(f"duration_seconds must be between {MIN_DURATION_SECONDS} and {MAX_DURATION_SECONDS}")
    target = validate_sandbox_url(sandbox_url)
    deadline = _monotonic() + duration_seconds
    latencies: list[float] = []
    failures = 0
    successes = 0
    lock = asyncio.Lock()
    timeout = httpx.Timeout(REQUEST_TIMEOUT_SECONDS, connect=REQUEST_TIMEOUT_SECONDS)

    async def worker(client: httpx.AsyncClient) -> None:
        nonlocal failures, successes
        while _monotonic() < deadline:
            started = time.perf_counter()
            try:
                response = await client.get(target)
                elapsed_ms = (time.perf_counter() - started) * 1000
                async with lock:
                    latencies.append(elapsed_ms)
                    if 200 <= response.status_code < 400:
                        successes += 1
                    else:
                        failures += 1
            except httpx.HTTPError:
                async with lock:
                    failures += 1

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers={"User-Agent": "ScavibeSandboxLoadTest/0.1"}) as client:
        await asyncio.gather(*(worker(client) for _ in range(concurrent_users)))
    samples = len(latencies) + failures
    if samples < 20 or not latencies:
        raise LoadTestError("load test produced fewer than 20 response samples; no performance conclusion is valid")
    ordered_latencies = sorted(latencies)
    percentile_index = max(0, min(len(ordered_latencies) - 1, int((len(ordered_latencies) - 1) * 0.95)))
    return LoadTestSummary(
        measurement=RuntimeMeasurement(
            id=f"sandbox_{int(time.time())}",
            target_mode="sandbox",
            endpoint="/",
            concurrent_users=concurrent_users,
            duration_seconds=duration_seconds,
            sample_count=samples,
            successful_sample_count=successes,
            p95_latency_ms=round(ordered_latencies[percentile_index], 2),
            error_rate_percent=round((failures / samples) * 100, 3),
        ),
        successful_requests=successes,
        failed_requests=failures,
    )


def _p95_latency(latencies: list[float]) -> float | None:
    if not latencies:
        return None
    ordered_latencies = sorted(latencies)
    percentile_index = max(0, min(len(ordered_latencies) - 1, int((len(ordered_latencies) - 1) * 0.95)))
    return round(ordered_latencies[percentile_index], 2)


def _breach_details(step: RampStepResult) -> tuple[str, float, float] | None:
    """Use error rate first; p95 is valid only when successful samples exist."""
    if step.error_rate_percent > PERFORMANCE_ERROR_RATE_THRESHOLD_PERCENT:
        return ("error_rate_percent", step.error_rate_percent, PERFORMANCE_ERROR_RATE_THRESHOLD_PERCENT)
    if step.p95_latency_ms is not None and step.p95_latency_ms > PERFORMANCE_P95_LATENCY_THRESHOLD_MS:
        return ("p95_latency_ms", step.p95_latency_ms, PERFORMANCE_P95_LATENCY_THRESHOLD_MS)
    return None


async def _run_ramp_step(
    *,
    target: str,
    phase: str,
    step_index: int,
    concurrent_users: int,
    duration_seconds: int,
    on_event: RampEventCallback,
) -> RampStepResult:
    deadline = _monotonic() + duration_seconds
    started_at = _monotonic()
    latencies: list[float] = []
    successful_requests = 0
    failed_requests = 0
    last_tick_at = started_at
    lock = asyncio.Lock()
    timeout = httpx.Timeout(REQUEST_TIMEOUT_SECONDS, connect=REQUEST_TIMEOUT_SECONDS)

    async def worker(client: httpx.AsyncClient) -> None:
        nonlocal successful_requests, failed_requests, last_tick_at
        while _monotonic() < deadline:
            request_started = time.perf_counter()
            try:
                response = await client.get(target)
            except httpx.HTTPError:
                # No HTTP response completed, so this request contributes no sample.
                continue
            elapsed_ms = (time.perf_counter() - request_started) * 1000
            tick: SampleTickEvent | None = None
            async with lock:
                if 200 <= response.status_code < 400:
                    successful_requests += 1
                    latencies.append(elapsed_ms)
                else:
                    failed_requests += 1
                now = _monotonic()
                if now - last_tick_at >= 1.0:
                    completed = successful_requests + failed_requests
                    tick = {
                        "type": "sample_tick",
                        "step_index": step_index,
                        "elapsed_seconds": round(now - started_at, 3),
                        "live_p95_latency_ms": _p95_latency(latencies),
                        "live_error_rate_percent": round((failed_requests / completed) * 100, 3) if completed else 0.0,
                        "samples_so_far": completed,
                    }
                    last_tick_at = now
            if tick is not None:
                await on_event(tick)

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers={"User-Agent": "ScavibeSandboxRampTest/0.1"}) as client:
        await asyncio.gather(*(worker(client) for _ in range(concurrent_users)))
    sample_count = successful_requests + failed_requests
    if sample_count == 0:
        raise LoadTestError(
            f"ramp {phase} step {step_index} at {concurrent_users} concurrent users completed zero HTTP responses"
        )
    p95_latency_ms = _p95_latency(latencies)
    error_rate_percent = 100.0 if successful_requests == 0 else round((failed_requests / sample_count) * 100, 3)
    return RampStepResult(
        phase=phase,
        step_index=step_index,
        concurrent_users=concurrent_users,
        duration_seconds=duration_seconds,
        sample_count=sample_count,
        successful_sample_count=successful_requests,
        p95_latency_ms=p95_latency_ms,
        error_rate_percent=error_rate_percent,
    )


async def run_ramp_load_test(*, sandbox_url: str, on_event: RampEventCallback) -> RampResult:
    """Run nine 12-second exploratory steps and one 60-second confirmation step."""
    target = validate_sandbox_url(sandbox_url)
    exploratory_steps: list[RampStepResult] = []
    candidate_step: RampStepResult | None = None
    for step_index, concurrent_users in enumerate(RAMP_CONCURRENT_USERS):
        await on_event(
            {
                "type": "step_started",
                "phase": "exploratory",
                "step_index": step_index,
                "concurrent_users": concurrent_users,
                "planned_duration_seconds": EXPLORATORY_DURATION_SECONDS,
            }
        )
        step = await _run_ramp_step(
            target=target,
            phase="exploratory",
            step_index=step_index,
            concurrent_users=concurrent_users,
            duration_seconds=EXPLORATORY_DURATION_SECONDS,
            on_event=on_event,
        )
        exploratory_steps.append(step)
        breach = _breach_details(step)
        await on_event(
            {
                "type": "step_completed",
                "phase": "exploratory",
                "step_index": step_index,
                "concurrent_users": concurrent_users,
                "p95_latency_ms": step.p95_latency_ms,
                "error_rate_percent": step.error_rate_percent,
                "sample_count": step.sample_count,
                "breached": breach is not None,
            }
        )
        if breach is not None:
            metric, observed_value, threshold = breach
            if metric == "p95_latency_ms" and step.p95_latency_ms is None:
                raise AssertionError("p95_latency_ms cannot be a breach metric when no successful sample exists")
            if step.p95_latency_ms is None and metric != "error_rate_percent":
                raise AssertionError("a null p95 latency breach must use error_rate_percent")
            await on_event(
                {
                    "type": "breaking_point_found",
                    "concurrent_users": concurrent_users,
                    "metric": metric,
                    "observed_value": observed_value,
                    "threshold": threshold,
                }
            )
            candidate_step = step
            break
    confirmation_step = candidate_step or exploratory_steps[-1]
    await on_event(
        {
            "type": "step_started",
            "phase": "confirmation",
            "step_index": confirmation_step.step_index,
            "concurrent_users": confirmation_step.concurrent_users,
            "planned_duration_seconds": PERFORMANCE_MIN_DURATION_SECONDS,
        }
    )
    confirmation = await _run_ramp_step(
        target=target,
        phase="confirmation",
        step_index=confirmation_step.step_index,
        concurrent_users=confirmation_step.concurrent_users,
        duration_seconds=PERFORMANCE_MIN_DURATION_SECONDS,
        on_event=on_event,
    )
    if confirmation.sample_count < PERFORMANCE_MIN_SAMPLE_COUNT:
        raise LoadTestError(
            f"ramp confirmation step {confirmation.step_index} at {confirmation.concurrent_users} concurrent users produced {confirmation.sample_count} samples; at least {PERFORMANCE_MIN_SAMPLE_COUNT} are required"
        )
    confirmation_breach = _breach_details(confirmation)
    await on_event(
        {
            "type": "step_completed",
            "phase": "confirmation",
            "step_index": confirmation.step_index,
            "concurrent_users": confirmation.concurrent_users,
            "p95_latency_ms": confirmation.p95_latency_ms,
            "error_rate_percent": confirmation.error_rate_percent,
            "sample_count": confirmation.sample_count,
            "breached": confirmation_breach is not None,
        }
    )
    measurement = RuntimeMeasurement(
        id=f"ramp_{int(time.time())}_{confirmation.concurrent_users}",
        target_mode="sandbox",
        endpoint="/",
        concurrent_users=confirmation.concurrent_users,
        duration_seconds=PERFORMANCE_MIN_DURATION_SECONDS,
        sample_count=confirmation.sample_count,
        successful_sample_count=confirmation.successful_sample_count,
        p95_latency_ms=confirmation.p95_latency_ms,
        error_rate_percent=confirmation.error_rate_percent,
    )
    await on_event(
        {
            "type": "ramp_completed",
            "tested_range": [MIN_CONCURRENT_USERS, MAX_CONCURRENT_USERS],
            "breaking_point_concurrent_users": candidate_step.concurrent_users if candidate_step else None,
        }
    )
    return RampResult(
        exploratory_steps=tuple(exploratory_steps),
        confirmation_measurement=measurement,
        breaking_point_concurrent_users=candidate_step.concurrent_users if candidate_step else None,
    )
