"""Deterministic severity and confidence calculations.

The LLM does not choose severity or confidence. It supplies evidence and the
two scored facts below; this module maps them to repeatable numeric outcomes.
"""

from .contracts import AttackerAccess, Evidence, EvidenceKind, Impact, Severity

IMPACT_POINTS: dict[Impact, int] = {
    Impact.NONE: 0,
    Impact.SINGLE_USER_DATA: 20,
    Impact.MULTI_USER_DATA: 40,
    Impact.ALL_USER_DATA: 60,
    Impact.CREDENTIAL_COMPROMISE: 50,
    Impact.ARBITRARY_CODE_EXECUTION: 60,
    Impact.SERVICE_UNAVAILABLE: 45,
}
ACCESS_POINTS: dict[AttackerAccess, int] = {
    AttackerAccess.LOCAL: 5,
    AttackerAccess.AUTHENTICATED_LOW_PRIVILEGE: 25,
    AttackerAccess.UNAUTHENTICATED_REMOTE: 40,
}


def risk_score(impact: Impact, attacker_access: AttackerAccess) -> int:
    """Return min(100, impact points + access points)."""
    return min(100, IMPACT_POINTS[impact] + ACCESS_POINTS[attacker_access])


def severity_for(score: int) -> Severity:
    """Critical=90-100, high=70-89, medium=40-69, low=1-39, info=0."""
    if score >= 90:
        return Severity.CRITICAL
    if score >= 70:
        return Severity.HIGH
    if score >= 40:
        return Severity.MEDIUM
    if score >= 1:
        return Severity.LOW
    return Severity.INFO


def confidence_score(evidence: list[Evidence]) -> int:
    """Score evidence quality on a fixed 0-100 scale.

    Source evidence with a validated quote contributes 35 points per distinct
    location. Runtime evidence contributes 50 points when its measurement is
    from a >=60-second, >=20-sample sandbox test. A second distinct evidence
    item adds 15 corroboration points. The score is capped at 100.
    """
    score = 0
    source_locations: set[tuple[str | None, int | None, int | None]] = set()
    runtime_ids: set[str] = set()
    for item in evidence:
        if item.kind == EvidenceKind.SOURCE:
            source_locations.add((item.file_path, item.start_line, item.end_line))
        if item.kind == EvidenceKind.RUNTIME and item.measurement_id:
            runtime_ids.add(item.measurement_id)
    score += min(70, 35 * len(source_locations))
    score += min(50, 50 * len(runtime_ids))
    if len(source_locations) + len(runtime_ids) >= 2:
        score += 15
    return min(score, 100)
