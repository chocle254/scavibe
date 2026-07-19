"""Data contracts for audit inputs and agent outputs.

Every finding is rejected unless it identifies an exact source range or a
measured sandbox endpoint. This rule prevents impression-based findings.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, Field, HttpUrl, model_validator


class Stage(str, Enum):
    PERFORMANCE = "performance"
    SECURITY = "security"
    LEGAL = "legal"


class EvidenceKind(str, Enum):
    SOURCE = "source"
    RUNTIME = "runtime"
    MANIFEST = "manifest"


class Impact(str, Enum):
    NONE = "none"
    SINGLE_USER_DATA = "single_user_data"
    MULTI_USER_DATA = "multi_user_data"
    ALL_USER_DATA = "all_user_data"
    CREDENTIAL_COMPROMISE = "credential_compromise"
    ARBITRARY_CODE_EXECUTION = "arbitrary_code_execution"
    SERVICE_UNAVAILABLE = "service_unavailable"


class AttackerAccess(str, Enum):
    LOCAL = "local"
    AUTHENTICATED_LOW_PRIVILEGE = "authenticated_low_privilege"
    UNAUTHENTICATED_REMOTE = "unauthenticated_remote"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ExploitabilityStatus(str, Enum):
    """Dynamic confirmation state for a source-evidenced security finding."""

    CONFIRMED_EXPLOITABLE = "confirmed_exploitable"
    CANDIDATE_UNCONFIRMED = "candidate_unconfirmed"


class Evidence(BaseModel):
    kind: EvidenceKind
    statement: Annotated[str, Field(min_length=12, max_length=500)]
    file_path: str | None = None
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    quote: str | None = None
    measurement_id: str | None = None
    endpoint: str | None = None
    metric: Literal["p95_latency_ms", "error_rate_percent", "request_count"] | None = None
    observed_value: float | None = Field(default=None, ge=0)
    threshold: float | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def require_exact_location(self) -> "Evidence":
        if self.kind == EvidenceKind.SOURCE:
            if not all([self.file_path, self.start_line, self.end_line, self.quote]):
                raise ValueError("source evidence requires file_path, start_line, end_line, and quote")
            if self.end_line < self.start_line:
                raise ValueError("end_line must be greater than or equal to start_line")
        elif self.kind == EvidenceKind.RUNTIME:
            if not all([self.measurement_id, self.endpoint, self.metric, self.threshold is not None]):
                raise ValueError("runtime evidence requires measurement_id, endpoint, metric, and threshold")
            if self.observed_value is None:
                raise ValueError("runtime evidence requires observed_value")
        elif self.kind == EvidenceKind.MANIFEST and not self.file_path:
            raise ValueError("manifest evidence requires file_path")
        return self


class SourceFile(BaseModel):
    path: Annotated[str, Field(pattern=r"^[^\\]+$")]
    content: Annotated[str, Field(min_length=1, max_length=500_000)]


class RuntimeMeasurement(BaseModel):
    id: Annotated[str, Field(pattern=r"^[a-zA-Z0-9_-]{4,64}$")]
    target_mode: Literal["sandbox"]
    endpoint: Annotated[str, Field(pattern=r"^/")]
    concurrent_users: Annotated[int, Field(ge=1, le=1_000)]
    duration_seconds: Annotated[int, Field(ge=30, le=1_800)]
    sample_count: Annotated[int, Field(ge=20)]
    successful_sample_count: Annotated[int, Field(ge=0)]
    p95_latency_ms: Annotated[float | None, Field(default=None, ge=0)]
    error_rate_percent: Annotated[float, Field(ge=0, le=100)]


class AuditContext(BaseModel):
    """The complete evidence set for a single immutable repository revision.

    The 40-character SHA-1 requirement is deliberate: an agent result is not
    accepted without a reproducible Git commit identifier.
    """

    audit_id: Annotated[str, Field(pattern=r"^[a-zA-Z0-9_-]{4,64}$")]
    repository_url: HttpUrl
    app_url: HttpUrl | None = None
    commit_sha: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    source_files: Annotated[list[SourceFile], Field(min_length=1, max_length=2_000)]
    repository_paths: Annotated[list[str], Field(min_length=1, max_length=10_000)]
    source_content_complete: bool = True
    runtime_measurements: list[RuntimeMeasurement] = Field(default_factory=list)
    jurisdictions: list[Annotated[str, Field(pattern=r"^[A-Z]{2}(-[A-Z]{2})?$")]] = Field(default_factory=list)

    @model_validator(mode="after")
    def sources_must_be_listed(self) -> "AuditContext":
        listed = set(self.repository_paths)
        missing = [file.path for file in self.source_files if file.path not in listed]
        if missing:
            raise ValueError(f"source_files absent from repository_paths: {missing}")
        return self


class EvidenceInventory(BaseModel):
    """The complete supplied evidence set reproduced in exported audit artifacts."""

    source_files: Annotated[list[SourceFile], Field(max_length=2_000)] = Field(default_factory=list)
    repository_paths: Annotated[list[str], Field(max_length=10_000)] = Field(default_factory=list)
    source_content_complete: bool
    runtime_measurements: list[RuntimeMeasurement] = Field(default_factory=list)
    jurisdictions: list[Annotated[str, Field(pattern=r"^[A-Z]{2}(-[A-Z]{2})?$")]] = Field(default_factory=list)

    @model_validator(mode="after")
    def sources_must_be_listed(self) -> "EvidenceInventory":
        listed = set(self.repository_paths)
        missing = [file.path for file in self.source_files if file.path not in listed]
        if missing:
            raise ValueError(f"evidence inventory source_files absent from repository_paths: {missing}")
        return self

    @classmethod
    def from_context(cls, context: AuditContext) -> "EvidenceInventory":
        return cls(
            source_files=context.source_files,
            repository_paths=context.repository_paths,
            source_content_complete=context.source_content_complete,
            runtime_measurements=context.runtime_measurements,
            jurisdictions=context.jurisdictions,
        )


class ProposedFinding(BaseModel):
    """The model supplies facts; deterministic code supplies score and severity."""

    title: Annotated[str, Field(min_length=8, max_length=140)]
    statement: Annotated[str, Field(min_length=20, max_length=1_200)]
    impact: Impact
    attacker_access: AttackerAccess
    evidence: Annotated[list[Evidence], Field(min_length=1, max_length=5)]
    remediation: Annotated[str, Field(min_length=20, max_length=1_200)]


class AgentDraft(BaseModel):
    stage: Stage
    summary: Annotated[str, Field(min_length=20, max_length=1_000)]
    findings: Annotated[list[ProposedFinding], Field(max_length=30)]
    limitations: Annotated[list[str], Field(max_length=10)]


class SecurityPocExecution(BaseModel):
    """A non-destructive sandbox probe and its immutable execution record."""

    proposed_test_code: Annotated[str, Field(min_length=1, max_length=2_000)]
    executed_test_code: Annotated[str | None, Field(default=None, max_length=2_000)]
    execution_state: Literal["not_executed", "executed"]
    request_method: Literal["GET"] | None = None
    request_path: Annotated[str | None, Field(default=None, max_length=256)]
    expected_status_code: Annotated[int | None, Field(default=None, ge=200, le=299)]
    expected_response_marker: Annotated[str | None, Field(default=None, min_length=1, max_length=128)]
    response_status_code: Annotated[int | None, Field(default=None, ge=100, le=599)]
    response_excerpt: Annotated[str | None, Field(default=None, max_length=4_096)]
    response_sha256: Annotated[str | None, Field(default=None, pattern=r"^[0-9a-f]{64}$")]
    reason: Annotated[str, Field(min_length=20, max_length=800)]


class Finding(ProposedFinding):
    risk_score: Annotated[int, Field(ge=0, le=100)]
    severity: Severity
    confidence_score: Annotated[int, Field(ge=0, le=100)]
    exploitability_status: ExploitabilityStatus | None = None
    poc_execution: SecurityPocExecution | None = None


class RampAssessment(BaseModel):
    """The measured outcome of the fixed nine-step sandbox ramp."""

    tested_range: Annotated[list[int], Field(min_length=2, max_length=2)]
    breaking_point_concurrent_users: Annotated[int | None, Field(default=None, ge=1, le=1_000)]
    metric: Literal["p95_latency_ms", "error_rate_percent"] | None = None
    observed_value: Annotated[float | None, Field(default=None, ge=0)]
    threshold: Annotated[float | None, Field(default=None, ge=0)]

    @model_validator(mode="after")
    def require_complete_breaking_point_details(self) -> "RampAssessment":
        details = (self.metric, self.observed_value, self.threshold)
        if self.breaking_point_concurrent_users is None and any(value is not None for value in details):
            raise ValueError("ramp assessment without a breaking point cannot include breach details")
        if self.breaking_point_concurrent_users is not None and any(value is None for value in details):
            raise ValueError("ramp assessment with a breaking point requires metric, observed_value, and threshold")
        return self


class AgentReport(BaseModel):
    stage: Stage
    summary: str
    findings: list[Finding]
    limitations: list[str]
    evidence_commit_sha: str
    ramp_assessment: RampAssessment | None = None
    evidence_inventory: EvidenceInventory | None = None
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class StageResult(BaseModel):
    stage: Stage
    status: Literal["completed", "blocked", "failed"]
    report: AgentReport | None = None
    reason: str | None = None


class AuditRun(BaseModel):
    audit_id: str
    commit_sha: str
    stage_results: list[StageResult]
