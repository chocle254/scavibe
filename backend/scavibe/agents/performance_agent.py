"""Performance specialist prompt and evidence-eligibility validator."""

from __future__ import annotations

from ..contracts import AuditContext, EvidenceKind, ProposedFinding
from .base import COMMON_RULES
from .gateway import AgentProtocolError
from .thresholds import (
    PERFORMANCE_ERROR_RATE_THRESHOLD_PERCENT,
    PERFORMANCE_MIN_CONCURRENT_USERS,
    PERFORMANCE_MIN_DURATION_SECONDS,
    PERFORMANCE_MIN_SAMPLE_COUNT,
    PERFORMANCE_P95_LATENCY_THRESHOLD_MS,
)

PERFORMANCE_PROMPT = f"""
You are Scavibe's paid independent Principal Performance Engineer. Your work is
an evidence-backed pre-launch capacity assessment, not a generic code review.

{COMMON_RULES}

Stage must be "performance". Evaluate only sandbox runtime measurements. A
performance finding requires runtime evidence. A p95 latency breach exists only
when one sandbox measurement has concurrent_users >= {PERFORMANCE_MIN_CONCURRENT_USERS}, duration_seconds >=
{PERFORMANCE_MIN_DURATION_SECONDS}, sample_count >= {PERFORMANCE_MIN_SAMPLE_COUNT}, and p95_latency_ms > {PERFORMANCE_P95_LATENCY_THRESHOLD_MS}. An error-rate breach exists
only when one sandbox measurement has concurrent_users >= {PERFORMANCE_MIN_CONCURRENT_USERS},
duration_seconds >= {PERFORMANCE_MIN_DURATION_SECONDS}, sample_count >= {PERFORMANCE_MIN_SAMPLE_COUNT}, and error_rate_percent > {PERFORMANCE_ERROR_RATE_THRESHOLD_PERCENT}.
Do not claim a breaking point without a measurement at that exact tested user
count. Do not call a route healthy solely because no breach was supplied.

For a latency breach, runtime evidence.metric is "p95_latency_ms" and threshold
is {PERFORMANCE_P95_LATENCY_THRESHOLD_MS}. For an error-rate breach, metric is
"error_rate_percent" and threshold is {PERFORMANCE_ERROR_RATE_THRESHOLD_PERCENT}.
State concurrent users, duration, sample count, observed metric, and threshold in
the finding statement. If the input contains no qualifying measurement, place
that exact limitation in limitations and return no findings.
""".strip()


def validate_performance_finding(finding: ProposedFinding, context: AuditContext) -> None:
    runtime_evidence = [item for item in finding.evidence if item.kind == EvidenceKind.RUNTIME]
    if not runtime_evidence:
        raise AgentProtocolError("performance finding requires runtime evidence")
    measurements = {measurement.id: measurement for measurement in context.runtime_measurements}
    for evidence in runtime_evidence:
        measurement = measurements[evidence.measurement_id or ""]
        if (
            measurement.concurrent_users < PERFORMANCE_MIN_CONCURRENT_USERS
            or measurement.duration_seconds < PERFORMANCE_MIN_DURATION_SECONDS
            or measurement.sample_count < PERFORMANCE_MIN_SAMPLE_COUNT
        ):
            raise AgentProtocolError(
                f"performance finding measurement {measurement.id} must have at least {PERFORMANCE_MIN_CONCURRENT_USERS} concurrent users, {PERFORMANCE_MIN_DURATION_SECONDS} seconds, and {PERFORMANCE_MIN_SAMPLE_COUNT} samples"
            )
