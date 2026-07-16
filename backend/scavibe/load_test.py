"""Bounded HTTP load tests for explicitly authorized sandbox URLs."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import statistics
import time
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from .contracts import RuntimeMeasurement

MIN_CONCURRENT_USERS = 10
MAX_CONCURRENT_USERS = 200
MIN_DURATION_SECONDS = 30
MAX_DURATION_SECONDS = 300
REQUEST_TIMEOUT_SECONDS = 10.0


class LoadTestError(RuntimeError):
    """The authorized sandbox target does not meet the fixed safety controls."""


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


async def run_sandbox_load_test(*, sandbox_url: str, concurrent_users: int, duration_seconds: int) -> LoadTestSummary:
    """Run GET requests for the exact requested duration with a fixed 200-user cap."""
    if not MIN_CONCURRENT_USERS <= concurrent_users <= MAX_CONCURRENT_USERS:
        raise LoadTestError(f"concurrent_users must be between {MIN_CONCURRENT_USERS} and {MAX_CONCURRENT_USERS}")
    if not MIN_DURATION_SECONDS <= duration_seconds <= MAX_DURATION_SECONDS:
        raise LoadTestError(f"duration_seconds must be between {MIN_DURATION_SECONDS} and {MAX_DURATION_SECONDS}")
    target = validate_sandbox_url(sandbox_url)
    deadline = time.monotonic() + duration_seconds
    latencies: list[float] = []
    failures = 0
    successes = 0
    lock = asyncio.Lock()
    timeout = httpx.Timeout(REQUEST_TIMEOUT_SECONDS, connect=REQUEST_TIMEOUT_SECONDS)

    async def worker(client: httpx.AsyncClient) -> None:
        nonlocal failures, successes
        while time.monotonic() < deadline:
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
            p95_latency_ms=round(ordered_latencies[percentile_index], 2),
            error_rate_percent=round((failures / samples) * 100, 3),
        ),
        successful_requests=successes,
        failed_requests=failures,
    )
