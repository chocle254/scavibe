"""Scavibe API foundation.

This local implementation models the job lifecycle used by the frontend. Real
repository cloning, sandbox provisioning, and AI analysis are intentionally
kept behind explicit integrations so no live target is ever tested by default.
"""

import os
import hmac
import asyncio
import json
from base64 import b64decode, b64encode
from datetime import datetime, timezone
from io import BytesIO
from uuid import uuid4
from zipfile import ZIP_DEFLATED, ZipFile

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, HttpUrl
import httpx

from scavibe.agents import AgentProtocolError, AuditOrchestrator, NvidiaNimGateway, NvidiaNimSettings, SpecialistAgent
from scavibe.contracts import (
    AgentReport,
    AuditContext,
    AuditRun,
    AttackerAccess,
    Evidence,
    EvidenceKind,
    Finding,
    Impact,
    RampAssessment,
    RuntimeMeasurement,
    Stage,
)
from scavibe.load_test import (
    MAX_CONCURRENT_USERS,
    MIN_CONCURRENT_USERS,
    LoadTestError,
    LoadTestSummary,
    RampResult,
    run_ramp_load_test,
    run_sandbox_load_test,
)
from scavibe.repository import (
    RepositoryIntakeError,
    RepositorySnapshot,
    fetch_public_repository,
    fetch_repository_identity,
    parse_github_repository,
    suggest_sandboxes,
)
from scavibe.reporting import report_markdown
from scavibe.fix_plans import AutoFixPlanError, FixType, build_auto_fix_plan
from scavibe.scoring import confidence_score, risk_score, severity_for
from scavibe.agents.thresholds import (
    PERFORMANCE_ERROR_RATE_THRESHOLD_PERCENT,
    PERFORMANCE_MIN_CONCURRENT_USERS,
    PERFORMANCE_MIN_DURATION_SECONDS,
    PERFORMANCE_MIN_SAMPLE_COUNT,
    PERFORMANCE_P95_LATENCY_THRESHOLD_MS,
)
from scavibe.audit_pin import (
    AuditPinError,
    issue_audit_pin,
    issue_ramp_report_token,
    read_audit_pin,
    read_ramp_report_token,
)
from scavibe.vercel_sandbox import (
    VercelSandboxError,
    VercelSandboxSettings,
    create_sandbox,
    delete_sandbox,
    get_sandbox,
)


def configured_origins() -> list[str]:
    """Return the exact browser origins allowed to call this API.

    The local default permits only the Next.js development server. Production
    deployment requires SCAVIBE_ALLOWED_ORIGINS to list each Vercel origin.
    Wildcard origins are not accepted because this API accepts bearer secrets.
    """
    raw_origins = os.environ.get("SCAVIBE_ALLOWED_ORIGINS", "http://localhost:3000")
    origins = [origin.strip().rstrip("/") for origin in raw_origins.split(",") if origin.strip()]
    if not origins or "*" in origins:
        raise RuntimeError("SCAVIBE_ALLOWED_ORIGINS must contain one or more exact origins and cannot contain *")
    return origins


app = FastAPI(title="Scavibe API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=configured_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def remove_vercel_api_prefix(request, call_next):
    """Allow Vercel Services `/api/*` routing without changing Railway paths."""
    if request.scope["path"] == "/api" or request.scope["path"].startswith("/api/"):
        request.scope["path"] = request.scope["path"][4:] or "/"
        request.scope["raw_path"] = request.scope["path"].encode("ascii")
    return await call_next(request)


class AuditRequest(BaseModel):
    repository_url: HttpUrl
    app_url: HttpUrl | None = None
    live_target_confirmed: bool = False


class AuditJob(BaseModel):
    id: str
    status: str
    repository_url: HttpUrl
    app_url: HttpUrl | None = None
    target_mode: str
    created_at: datetime


class StageAuditRequest(BaseModel):
    repository_url: HttpUrl
    app_url: HttpUrl | None = None
    sandbox_url: HttpUrl | None = None
    sandbox_authorized: bool = False
    concurrent_users: int = 100
    duration_seconds: int = 60
    jurisdictions: list[str] = []
    audit_id: str | None = None
    audit_pin: str | None = None


class RepositoryEvidenceSummary(BaseModel):
    commit_sha: str
    selected_files: list[str]
    source_content_complete: bool


class StageAuditResponse(BaseModel):
    stage: Stage
    audit_id: str
    audit_pin: str
    repository: RepositoryEvidenceSummary
    report: AgentReport
    measurement: RuntimeMeasurement | None = None
    successful_requests: int | None = None
    failed_requests: int | None = None
    sandbox_teardown: str | None = None


class ConsentExampleRequest(BaseModel):
    report: AgentReport


class StagePdfRequest(BaseModel):
    report: AgentReport


class AuditPdfArchiveRequest(BaseModel):
    """The three sealed stage reports required for one downloadable audit archive."""

    performance: AgentReport
    security: AgentReport
    legal: AgentReport


class RampReportRequest(BaseModel):
    ramp_report_token: str


class PullRequestRequest(BaseModel):
    repository_url: HttpUrl
    report: AgentReport
    jurisdictions: list[str] = []
    approved: bool = False


class PullRequestResponse(BaseModel):
    url: HttpUrl
    branch: str


class SourceFixPullRequestRequest(BaseModel):
    repository_url: HttpUrl
    app_url: HttpUrl | None = None
    audit_id: str
    audit_pin: str
    report: AgentReport
    finding_index: int = Field(ge=0)
    fix_type: FixType
    source_change_approved: bool = False


class SandboxSuggestionResponse(BaseModel):
    url: HttpUrl
    provider: str
    environment: str
    commit_sha: str


class CreateVercelSandboxRequest(BaseModel):
    repository_url: HttpUrl
    authorized_deployment: bool = False


class VercelSandboxResponse(BaseModel):
    deployment_id: str
    project_id: str
    ready_state: str
    deployment_url: HttpUrl | None = None
    ticket: str
    expires_at: int
    commit_sha: str


class VercelSandboxLoadTestRequest(BaseModel):
    repository_url: HttpUrl
    app_url: HttpUrl | None = None
    ticket: str
    concurrent_users: int = 100
    duration_seconds: int = 60
    jurisdictions: list[str] = []
    audit_id: str | None = None
    audit_pin: str | None = None


JOBS: dict[str, AuditJob] = {}


def _optional_url(value: HttpUrl | None) -> str | None:
    """Preserve absent deployed-app metadata as null, never the string 'None'."""
    return str(value) if value is not None else None


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "scavibe-api", "version": "0.1.0"}


@app.get("/sandbox-suggestions", response_model=list[SandboxSuggestionResponse])
async def sandbox_suggestions(repository_url: HttpUrl) -> list[SandboxSuggestionResponse]:
    try:
        suggestions = await suggest_sandboxes(str(repository_url))
    except RepositoryIntakeError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    return [SandboxSuggestionResponse(**suggestion.__dict__) for suggestion in suggestions]


def _sandbox_response(sandbox) -> VercelSandboxResponse:
    return VercelSandboxResponse(
        deployment_id=sandbox.deployment_id,
        project_id=sandbox.project_id,
        ready_state=sandbox.ready_state,
        deployment_url=sandbox.deployment_url,
        ticket=sandbox.ticket,
        expires_at=sandbox.expires_at,
        commit_sha=sandbox.commit_sha,
    )


def _require_sandbox_access(presented_key: str | None) -> None:
    try:
        settings = VercelSandboxSettings.from_environment()
    except VercelSandboxError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    if settings.demo_mode:
        return
    if not presented_key or not hmac.compare_digest(presented_key, settings.access_key):
        raise HTTPException(status_code=401, detail="a valid X-Scavibe-Sandbox-Key is required for Scavibe-owned sandbox provisioning")


@app.post("/sandboxes/vercel", response_model=VercelSandboxResponse, status_code=201)
async def provision_vercel_sandbox(
    request: CreateVercelSandboxRequest,
    x_scavibe_sandbox_key: str | None = Header(default=None),
) -> VercelSandboxResponse:
    """Provision an isolated, no-secret preview build for one GitHub commit."""
    if request.authorized_deployment is not True:
        raise HTTPException(status_code=422, detail="authorized_deployment=true is required before Scavibe deploys repository code")
    _require_sandbox_access(x_scavibe_sandbox_key)
    try:
        identity = await fetch_repository_identity(str(request.repository_url))
        sandbox = await create_sandbox(
            repository_url=str(request.repository_url),
            commit_sha=identity.commit_sha,
            default_branch=identity.default_branch,
        )
    except (RepositoryIntakeError, VercelSandboxError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    return _sandbox_response(sandbox)


@app.get("/sandboxes/vercel/{deployment_id}", response_model=VercelSandboxResponse)
async def read_vercel_sandbox(deployment_id: str, ticket: str) -> VercelSandboxResponse:
    try:
        sandbox = await get_sandbox(ticket)
    except VercelSandboxError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    if sandbox.deployment_id != deployment_id:
        raise HTTPException(status_code=422, detail="sandbox ticket does not match the requested deployment")
    return _sandbox_response(sandbox)


@app.delete("/sandboxes/vercel/{deployment_id}", status_code=204)
async def remove_vercel_sandbox(deployment_id: str, ticket: str) -> None:
    try:
        sandbox = await get_sandbox(ticket)
    except VercelSandboxError as error:
        # An expired ticket must still be allowed to clean up its known project.
        try:
            from scavibe.vercel_sandbox import read_ticket

            settings = VercelSandboxSettings.from_environment()
            old_ticket = read_ticket(settings, ticket, require_unexpired=False)
            if old_ticket.deployment_id != deployment_id:
                raise HTTPException(status_code=422, detail="sandbox ticket does not match the requested deployment")
            await delete_sandbox(ticket)
            return None
        except VercelSandboxError as cleanup_error:
            raise HTTPException(status_code=422, detail=str(cleanup_error)) from cleanup_error
    if sandbox.deployment_id != deployment_id:
        raise HTTPException(status_code=422, detail="sandbox ticket does not match the requested deployment")
    try:
        await delete_sandbox(ticket)
    except VercelSandboxError as error:
        raise HTTPException(status_code=502, detail=str(error)) from error


@app.post("/sandboxes/vercel/{deployment_id}/load-test", response_model=StageAuditResponse)
async def test_vercel_sandbox(
    deployment_id: str,
    request: VercelSandboxLoadTestRequest,
    x_scavibe_sandbox_key: str | None = Header(default=None),
) -> StageAuditResponse:
    """Test the ready disposable deployment, then delete its project in all cases."""
    _require_sandbox_access(x_scavibe_sandbox_key)
    try:
        sandbox = await get_sandbox(request.ticket)
    except VercelSandboxError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    if sandbox.deployment_id != deployment_id:
        raise HTTPException(status_code=422, detail="sandbox ticket does not match the requested deployment")
    if sandbox.ready_state.upper() != "READY" or sandbox.deployment_url is None:
        raise HTTPException(status_code=409, detail=f"sandbox deployment is {sandbox.ready_state}; load testing starts only after Vercel reports READY")
    stage_request = StageAuditRequest(
        repository_url=request.repository_url,
        app_url=request.app_url,
        sandbox_url=sandbox.deployment_url,
        sandbox_authorized=True,
        concurrent_users=request.concurrent_users,
        duration_seconds=request.duration_seconds,
        jurisdictions=request.jurisdictions,
        audit_id=request.audit_id,
        audit_pin=request.audit_pin,
    )
    teardown = "deleted"
    try:
        snapshot, audit_id, audit_pin = await _pinned_repository_snapshot(
            stage_request,
            [],
            initial_commit_sha=sandbox.commit_sha,
        )
        test_summary = await run_sandbox_load_test(
            sandbox_url=sandbox.deployment_url,
            concurrent_users=request.concurrent_users,
            duration_seconds=request.duration_seconds,
        )
        # The report uses the same immutable commit that the Vercel request was instructed to deploy.
        snapshot.context.runtime_measurements.append(test_summary.measurement)
        report = _performance_report(snapshot.context, test_summary)
        result = StageAuditResponse(
            stage=Stage.PERFORMANCE,
            audit_id=audit_id,
            audit_pin=audit_pin,
            repository=_repository_summary(snapshot),
            report=report,
            measurement=test_summary.measurement,
            successful_requests=test_summary.successful_requests,
            failed_requests=test_summary.failed_requests,
            sandbox_teardown=teardown,
        )
    except (RepositoryIntakeError, LoadTestError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    finally:
        try:
            await delete_sandbox(request.ticket)
        except VercelSandboxError as teardown_error:
            teardown = f"delete failed: {teardown_error}"
    if teardown != "deleted":
        result.sandbox_teardown = teardown
    return result


@app.post("/audits", response_model=AuditJob, status_code=201)
async def create_audit(request: AuditRequest) -> AuditJob:
    job = AuditJob(
        id=str(uuid4()),
        status="queued",
        repository_url=request.repository_url,
        app_url=request.app_url,
        target_mode="live-confirmed" if request.live_target_confirmed else "sandbox-required",
        created_at=datetime.now(timezone.utc),
    )
    JOBS[job.id] = job
    return job


@app.get("/audits/{audit_id}", response_model=AuditJob)
async def get_audit(audit_id: str) -> AuditJob:
    job = JOBS.get(audit_id)
    if not job:
        raise HTTPException(status_code=404, detail="Audit not found")
    return job


@app.post("/audits/{audit_id}/run", response_model=AuditRun)
async def run_audit(audit_id: str, context: AuditContext) -> AuditRun:
    """Run the validated, read-only analysis pipeline for one pinned commit.

    This endpoint accepts an evidence bundle. Repository cloning and sandbox
    provisioning are separate integrations and are not silently emulated here.
    """
    job = JOBS.get(audit_id)
    if not job:
        raise HTTPException(status_code=404, detail="Audit not found")
    if context.audit_id != audit_id:
        raise HTTPException(status_code=422, detail="context.audit_id must equal the URL audit_id")
    if str(context.repository_url) != str(job.repository_url):
        raise HTTPException(status_code=422, detail="context.repository_url must equal the repository_url used to create the audit")
    if _optional_url(context.app_url) != _optional_url(job.app_url):
        raise HTTPException(status_code=422, detail="context.app_url must equal the app_url used to create the audit")
    try:
        settings = NvidiaNimSettings.from_environment()
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    pipeline = AuditOrchestrator(NvidiaNimGateway(settings))
    result = await pipeline.run(context)
    job.status = "completed" if all(item.status != "failed" for item in result.stage_results) else "failed"
    return result


async def _repository_snapshot(
    request: StageAuditRequest,
    measurements: list[RuntimeMeasurement],
    *,
    audit_id: str,
    commit_sha_override: str | None = None,
) -> RepositorySnapshot:
    try:
        return await fetch_public_repository(
            audit_id=audit_id,
            repository_url=str(request.repository_url),
            app_url=_optional_url(request.app_url),
            jurisdictions=request.jurisdictions,
            runtime_measurements=measurements,
            commit_sha_override=commit_sha_override,
        )
    except RepositoryIntakeError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


def _repository_summary(snapshot: RepositorySnapshot) -> RepositoryEvidenceSummary:
    return RepositoryEvidenceSummary(
        commit_sha=snapshot.context.commit_sha,
        selected_files=snapshot.selected_paths,
        source_content_complete=snapshot.source_content_complete,
    )


async def _pinned_repository_snapshot(
    request: StageAuditRequest,
    measurements: list[RuntimeMeasurement],
    *,
    initial_commit_sha: str | None = None,
) -> tuple[RepositorySnapshot, str, str]:
    """Fetch an initial commit once or reuse the client-carried signed pin."""
    audit_id = request.audit_id or f"audit_{uuid4().hex[:20]}"
    if request.audit_pin:
        try:
            pin = read_audit_pin(request.audit_pin)
        except AuditPinError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        if pin.audit_id != audit_id:
            raise HTTPException(status_code=422, detail="audit_pin does not match audit_id")
        if pin.repository_url != str(request.repository_url):
            raise HTTPException(status_code=422, detail="audit_pin does not match repository_url")
        if pin.app_url != _optional_url(request.app_url):
            raise HTTPException(status_code=422, detail="audit_pin app_url does not match incoming app_url")
        snapshot = await _repository_snapshot(
            request,
            measurements,
            audit_id=audit_id,
            commit_sha_override=pin.commit_sha,
        )
        return snapshot, audit_id, request.audit_pin
    snapshot = await _repository_snapshot(
        request,
        measurements,
        audit_id=audit_id,
        commit_sha_override=initial_commit_sha,
    )
    try:
        audit_pin = issue_audit_pin(
            audit_id=audit_id,
            repository_url=str(request.repository_url),
            app_url=_optional_url(request.app_url),
            commit_sha=snapshot.context.commit_sha,
        )
    except AuditPinError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    return snapshot, audit_id, audit_pin


def _ramp_assessment(result: RampResult) -> RampAssessment:
    """Convert only the recorded ramp outcome; do not infer a breaking point."""
    return RampAssessment(
        tested_range=[MIN_CONCURRENT_USERS, MAX_CONCURRENT_USERS],
        breaking_point_concurrent_users=result.breaking_point_concurrent_users,
        metric=result.breaking_point_metric,
        observed_value=result.breaking_point_observed_value,
        threshold=result.breaking_point_threshold,
    )


def _ramp_load_test_summary(result: RampResult) -> LoadTestSummary:
    measurement = result.confirmation_measurement
    return LoadTestSummary(
        measurement=measurement,
        successful_requests=measurement.successful_sample_count,
        failed_requests=measurement.sample_count - measurement.successful_sample_count,
    )


def _performance_report(
    context: AuditContext,
    summary: LoadTestSummary,
    *,
    ramp_assessment: RampAssessment | None = None,
) -> AgentReport:
    """Create a deterministic report from measured sandbox values only."""
    measurement = summary.measurement
    qualifying_gate_failed = (
        measurement.concurrent_users < PERFORMANCE_MIN_CONCURRENT_USERS
        or measurement.duration_seconds < PERFORMANCE_MIN_DURATION_SECONDS
        or measurement.sample_count < PERFORMANCE_MIN_SAMPLE_COUNT
    )
    limitations = [
        "This measurement covers only GET / on the supplied sandbox URL.",
        "No conclusion is made for user counts, routes, regions, or durations that were not measured.",
    ]
    if qualifying_gate_failed:
        limitations.insert(
            0,
            f"performance measurement did not meet the qualifying gate: at least {PERFORMANCE_MIN_CONCURRENT_USERS} concurrent users, "
            f"{PERFORMANCE_MIN_DURATION_SECONDS}+ seconds, and {PERFORMANCE_MIN_SAMPLE_COUNT}+ samples",
        )
    if ramp_assessment is not None:
        if ramp_assessment.breaking_point_concurrent_users is None:
            limitations.append(
                "no breaking point identified within the tested range of 10 to 200 concurrent users"
            )
        else:
            limitations.append(
                f"The first exploratory ramp breach occurred at {ramp_assessment.breaking_point_concurrent_users} concurrent users: "
                f"{ramp_assessment.metric}={ramp_assessment.observed_value} against threshold={ramp_assessment.threshold}."
            )
    if qualifying_gate_failed:
        return AgentReport(
            stage=Stage.PERFORMANCE,
            summary="No performance finding was generated because the supplied sandbox measurement was rejected by the qualifying gate.",
            findings=[],
            limitations=limitations,
            evidence_commit_sha=context.commit_sha,
            ramp_assessment=ramp_assessment,
        )
    findings: list[Finding] = []
    conditions = [
        (
            measurement.p95_latency_ms is not None and measurement.p95_latency_ms > PERFORMANCE_P95_LATENCY_THRESHOLD_MS,
            f"P95 latency exceeds {PERFORMANCE_P95_LATENCY_THRESHOLD_MS} ms at the tested load",
            f"Sandbox test {measurement.id} recorded p95 latency {measurement.p95_latency_ms} ms at {measurement.concurrent_users} concurrent users for {measurement.duration_seconds} seconds across {measurement.sample_count} samples; the threshold is {PERFORMANCE_P95_LATENCY_THRESHOLD_MS} ms.",
            "p95_latency_ms",
            measurement.p95_latency_ms,
            PERFORMANCE_P95_LATENCY_THRESHOLD_MS,
            "Profile the tested route, remove the measured bottleneck, and repeat the same sandbox test before release.",
        ),
        (
            measurement.error_rate_percent > PERFORMANCE_ERROR_RATE_THRESHOLD_PERCENT,
            f"Error rate exceeds {PERFORMANCE_ERROR_RATE_THRESHOLD_PERCENT}% at the tested load",
            f"Sandbox test {measurement.id} recorded error rate {measurement.error_rate_percent}% at {measurement.concurrent_users} concurrent users for {measurement.duration_seconds} seconds across {measurement.sample_count} samples; the threshold is {PERFORMANCE_ERROR_RATE_THRESHOLD_PERCENT}%.",
            "error_rate_percent",
            measurement.error_rate_percent,
            PERFORMANCE_ERROR_RATE_THRESHOLD_PERCENT,
            "Inspect failed responses from the tested route, correct the failure path, and repeat the same sandbox test before release.",
        ),
    ]
    for breached, title, statement, metric, observed_value, threshold, remediation in conditions:
        if not breached:
            continue
        evidence = [
            Evidence(
                kind=EvidenceKind.RUNTIME,
                statement=f"Sandbox measurement {measurement.id} recorded {metric} on {measurement.endpoint}.",
                measurement_id=measurement.id,
                endpoint=measurement.endpoint,
                metric=metric,
                observed_value=observed_value,
                threshold=threshold,
            )
        ]
        score = risk_score(Impact.SERVICE_UNAVAILABLE, AttackerAccess.UNAUTHENTICATED_REMOTE)
        findings.append(
            Finding(
                title=title,
                statement=statement,
                impact=Impact.SERVICE_UNAVAILABLE,
                attacker_access=AttackerAccess.UNAUTHENTICATED_REMOTE,
                evidence=evidence,
                remediation=remediation,
                risk_score=score,
                severity=severity_for(score),
                confidence_score=confidence_score(evidence),
            )
        )
    request_total = summary.successful_requests + summary.failed_requests
    audit_summary = (
        f"The sandbox test completed {request_total} requests at {measurement.concurrent_users} concurrent users. "
        + (f"{len(findings)} measured threshold breach(es) require action." if findings else f"P95 latency was {measurement.p95_latency_ms} ms and error rate was {measurement.error_rate_percent}%, both within the configured thresholds.")
    )
    return AgentReport(
        stage=Stage.PERFORMANCE,
        summary=audit_summary,
        findings=findings,
        limitations=limitations,
        evidence_commit_sha=context.commit_sha,
        ramp_assessment=ramp_assessment,
    )


async def _specialist_report(stage: Stage, context: AuditContext, *, on_phase=None) -> AgentReport:
    try:
        settings = NvidiaNimSettings.from_environment()
        report = await SpecialistAgent(stage, NvidiaNimGateway(settings)).analyze(context, on_phase=on_phase)
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except AgentProtocolError as error:
        raise HTTPException(status_code=502, detail=str(error)) from error
    if not context.source_content_complete:
        report.limitations.append(
            "Only the capped source-file selection was supplied to this stage; repository-wide absence claims are not valid."
        )
    return report


def _sse_data(event: dict) -> str:
    return f"data: {json.dumps(event, separators=(',', ':'))}\n\n"


def _specialist_stage_stream(stage: Stage, request: StageAuditRequest) -> StreamingResponse:
    """Stream only the real repository, analysis, and evidence-validation phases."""
    async def event_stream():
        yield _sse_data(
            {
                "type": "phase_started",
                "stage": stage.value,
                "phase": "repository_fetch",
                "activity": "fetching and pinning immutable repository evidence",
            }
        )
        try:
            snapshot, audit_id, audit_pin = await _pinned_repository_snapshot(request, [])
        except HTTPException as error:
            yield _sse_data({"type": "stage_failed", "stage": stage.value, "detail": str(error.detail)})
            return
        yield _sse_data(
            {
                "type": "phase_completed",
                "stage": stage.value,
                "phase": "repository_fetch",
                "activity": "immutable repository evidence is pinned",
                "commit_sha": snapshot.context.commit_sha,
                "selected_file_count": len(snapshot.selected_paths),
                "repository_path_count": len(snapshot.context.repository_paths),
                "source_content_complete": snapshot.source_content_complete,
            }
        )

        phase_events: asyncio.Queue[dict] = asyncio.Queue()

        async def on_phase(event_type: str, phase: str) -> None:
            activity = {
                "specialist_analysis": "analyzing the pinned specialist evidence input",
                "evidence_validation": "validating exact evidence and deterministic scoring",
            }[phase]
            await phase_events.put({"type": event_type, "stage": stage.value, "phase": phase, "activity": activity})

        task = asyncio.create_task(_specialist_report(stage, snapshot.context, on_phase=on_phase))
        try:
            while not task.done() or not phase_events.empty():
                if not phase_events.empty():
                    yield _sse_data(phase_events.get_nowait())
                    continue
                phase_waiter = asyncio.create_task(phase_events.get())
                completed, _ = await asyncio.wait({task, phase_waiter}, return_when=asyncio.FIRST_COMPLETED)
                if phase_waiter in completed:
                    yield _sse_data(phase_waiter.result())
                else:
                    phase_waiter.cancel()
                    await asyncio.gather(phase_waiter, return_exceptions=True)
                    await task
            report = await task
        except HTTPException as error:
            yield _sse_data({"type": "stage_failed", "stage": stage.value, "detail": str(error.detail)})
            return
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        result = StageAuditResponse(
            stage=stage,
            audit_id=audit_id,
            audit_pin=audit_pin,
            repository=_repository_summary(snapshot),
            report=report,
        )
        yield _sse_data(
            {
                "type": "report_ready",
                "stage": stage.value,
                "result": result.model_dump(mode="json"),
            }
        )

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/audit-stages/performance", response_model=StageAuditResponse)
async def audit_performance(request: StageAuditRequest) -> StageAuditResponse:
    if request.sandbox_url is None or request.sandbox_authorized is not True:
        raise HTTPException(status_code=422, detail="performance requires sandbox_url and sandbox_authorized=true; live URLs are not tested by default")
    try:
        test_summary = await run_sandbox_load_test(
            sandbox_url=str(request.sandbox_url),
            concurrent_users=request.concurrent_users,
            duration_seconds=request.duration_seconds,
        )
    except LoadTestError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    snapshot, audit_id, audit_pin = await _pinned_repository_snapshot(request, [test_summary.measurement])
    try:
        report = _performance_report(snapshot.context, test_summary)
    except LoadTestError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    return StageAuditResponse(
        stage=Stage.PERFORMANCE,
        audit_id=audit_id,
        audit_pin=audit_pin,
        repository=_repository_summary(snapshot),
        report=report,
        measurement=test_summary.measurement,
        successful_requests=test_summary.successful_requests,
        failed_requests=test_summary.failed_requests,
    )


@app.post("/audit-stages/performance/ramp")
async def audit_performance_ramp(request: StageAuditRequest) -> StreamingResponse:
    """Stream exact ramp events while testing only an authorized sandbox URL."""
    if request.sandbox_url is None or request.sandbox_authorized is not True:
        raise HTTPException(status_code=422, detail="performance requires sandbox_url and sandbox_authorized=true; live URLs are not tested by default")
    snapshot, audit_id, audit_pin = await _pinned_repository_snapshot(request, [])

    async def event_stream():
        events: asyncio.Queue[dict] = asyncio.Queue()
        ramp_completed_event: dict | None = None

        async def on_event(event: dict) -> None:
            await events.put(event)

        task = asyncio.create_task(run_ramp_load_test(sandbox_url=str(request.sandbox_url), on_event=on_event))
        try:
            while not task.done() or not events.empty():
                if not events.empty():
                    event = events.get_nowait()
                    if event["type"] == "ramp_completed":
                        ramp_completed_event = event
                    else:
                        yield f"data: {json.dumps(event, separators=(',', ':'))}\n\n"
                    continue
                event_waiter = asyncio.create_task(events.get())
                completed, _ = await asyncio.wait({task, event_waiter}, return_when=asyncio.FIRST_COMPLETED)
                if event_waiter in completed:
                    event = event_waiter.result()
                else:
                    event_waiter.cancel()
                    await asyncio.gather(event_waiter, return_exceptions=True)
                    await task
                    continue
                if event["type"] == "ramp_completed":
                    ramp_completed_event = event
                    continue
                yield f"data: {json.dumps(event, separators=(',', ':'))}\n\n"
            ramp_result = await task
            if ramp_completed_event is None:
                raise LoadTestError("ramp completed without a ramp_completed event")
            summary = _ramp_load_test_summary(ramp_result)
            snapshot.context.runtime_measurements.append(summary.measurement)
            report = _performance_report(
                snapshot.context,
                summary,
                ramp_assessment=_ramp_assessment(ramp_result),
            )
            ramp_report_token = issue_ramp_report_token(
                audit_id=audit_id,
                audit_pin=audit_pin,
                repository=_repository_summary(snapshot).model_dump(mode="json"),
                report=report.model_dump(mode="json"),
                measurement=summary.measurement.model_dump(mode="json"),
                successful_requests=summary.successful_requests,
                failed_requests=summary.failed_requests,
            )
            # The SSE data object remains the specified fixed shape. The opaque
            # SSE id carries the signed report retrieval token for POST clients.
            yield f"id: {ramp_report_token}\n"
            yield f"data: {json.dumps(ramp_completed_event, separators=(',', ':'))}\n\n"
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/audit-stages/performance/ramp/report", response_model=StageAuditResponse)
async def read_performance_ramp_report(request: RampReportRequest) -> StageAuditResponse:
    """Return the report sealed into the final SSE event id without retesting."""
    try:
        token = read_ramp_report_token(request.ramp_report_token)
        pin = read_audit_pin(token.audit_pin)
        repository = RepositoryEvidenceSummary.model_validate(token.repository)
        report = AgentReport.model_validate(token.report)
        measurement = RuntimeMeasurement.model_validate(token.measurement)
    except (AuditPinError, ValueError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    if token.audit_id != pin.audit_id:
        raise HTTPException(status_code=422, detail="ramp_report_token audit_id does not match its audit_pin")
    if report.stage != Stage.PERFORMANCE:
        raise HTTPException(status_code=422, detail="ramp_report_token does not contain a performance report")
    if report.evidence_commit_sha != pin.commit_sha or repository.commit_sha != pin.commit_sha:
        raise HTTPException(status_code=422, detail="ramp_report_token does not match the pinned evidence commit")
    if report.ramp_assessment is None:
        raise HTTPException(status_code=422, detail="ramp_report_token does not contain a ramp assessment")
    if measurement.successful_sample_count != token.successful_requests:
        raise HTTPException(status_code=422, detail="ramp_report_token successful request count does not match its measurement")
    if measurement.sample_count - measurement.successful_sample_count != token.failed_requests:
        raise HTTPException(status_code=422, detail="ramp_report_token failed request count does not match its measurement")
    return StageAuditResponse(
        stage=Stage.PERFORMANCE,
        audit_id=token.audit_id,
        audit_pin=token.audit_pin,
        repository=repository,
        report=report,
        measurement=measurement,
        successful_requests=token.successful_requests,
        failed_requests=token.failed_requests,
    )


@app.post("/audit-stages/security", response_model=StageAuditResponse)
async def audit_security(request: StageAuditRequest) -> StageAuditResponse:
    snapshot, audit_id, audit_pin = await _pinned_repository_snapshot(request, [])
    report = await _specialist_report(Stage.SECURITY, snapshot.context)
    return StageAuditResponse(stage=Stage.SECURITY, audit_id=audit_id, audit_pin=audit_pin, repository=_repository_summary(snapshot), report=report)


@app.post("/audit-stages/security/stream")
async def audit_security_stream(request: StageAuditRequest) -> StreamingResponse:
    return _specialist_stage_stream(Stage.SECURITY, request)


@app.post("/audit-stages/legal", response_model=StageAuditResponse)
async def audit_legal(request: StageAuditRequest) -> StageAuditResponse:
    if not request.jurisdictions:
        raise HTTPException(status_code=422, detail="data-handling and consent audit requires at least one explicit jurisdiction code")
    snapshot, audit_id, audit_pin = await _pinned_repository_snapshot(request, [])
    report = await _specialist_report(Stage.LEGAL, snapshot.context)
    return StageAuditResponse(stage=Stage.LEGAL, audit_id=audit_id, audit_pin=audit_pin, repository=_repository_summary(snapshot), report=report)


@app.post("/audit-stages/legal/stream")
async def audit_legal_stream(request: StageAuditRequest) -> StreamingResponse:
    if not request.jurisdictions:
        raise HTTPException(status_code=422, detail="data-handling and consent audit requires at least one explicit jurisdiction code")
    return _specialist_stage_stream(Stage.LEGAL, request)


def _consent_example_files() -> dict[str, str]:
    """Return one additive UI-pattern example, never a drafted legal document."""
    return {
        "ConsentCheckbox.tsx": (
            "type ConsentCheckboxProps = {\n"
            "  onConsentChange?: (accepted: boolean) => void;\n"
            "};\n\n"
            "export function ConsentCheckbox({ onConsentChange }: ConsentCheckboxProps) {\n"
            "  return (\n"
            "    <label style={{ display: 'flex', gap: 8, alignItems: 'flex-start', fontSize: 14, lineHeight: 1.5 }}>\n"
            "      <input\n"
            "        type=\"checkbox\"\n"
            "        name=\"dataConsent\"\n"
            "        required\n"
            "        onChange={(event) => onConsentChange?.(event.target.checked)}\n"
            "      />\n"
            "      <span>I confirm that I meet the eligibility requirements and consent to the data handling described to me.</span>\n"
            "    </label>\n"
            "  );\n"
            "}\n"
        )
    }

def _pdf_response(pdf: bytes, filename: str) -> StreamingResponse:
    document = BytesIO(pdf)
    document.seek(0)
    return StreamingResponse(
        document,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def _stage_pdf_bytes(report: AgentReport) -> bytes:
    try:
        from scavibe.pdf_reports import PdfGenerationError, STAGE_ACCENTS, generate_pdf_report
        from scavibe.reporting import STAGE_AUDIT_LABELS
    except ModuleNotFoundError as error:
        if error.name in {"reportlab", "PIL"}:
            raise HTTPException(status_code=503, detail="reportlab==5.0.0 and pillow==12.3.0 are required for PDF exports") from error
        raise
    try:
        return generate_pdf_report(report, STAGE_ACCENTS[report.stage], STAGE_AUDIT_LABELS[report.stage])
    except PdfGenerationError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error


def _require_pdf_stage(report: AgentReport, expected_stage: Stage) -> None:
    if report.stage != expected_stage:
        raise HTTPException(status_code=422, detail=f"{expected_stage.value} PDF endpoint requires a {expected_stage.value} report")


@app.post("/audit-stages/performance/pdf")
async def download_performance_pdf(request: StagePdfRequest) -> StreamingResponse:
    _require_pdf_stage(request.report, Stage.PERFORMANCE)
    return _pdf_response(_stage_pdf_bytes(request.report), "scavibe-performance-audit.pdf")


@app.post("/audit-stages/security/pdf")
async def download_security_pdf(request: StagePdfRequest) -> StreamingResponse:
    _require_pdf_stage(request.report, Stage.SECURITY)
    return _pdf_response(_stage_pdf_bytes(request.report), "scavibe-security-audit.pdf")


@app.post("/audit-stages/legal/pdf")
async def download_legal_pdf(request: StagePdfRequest) -> StreamingResponse:
    _require_pdf_stage(request.report, Stage.LEGAL)
    return _pdf_response(_stage_pdf_bytes(request.report), "scavibe-data-handling-and-consent-audit.pdf")


@app.post("/audit-stages/pdf-archive")
async def download_audit_pdf_archive(request: AuditPdfArchiveRequest) -> StreamingResponse:
    """Return the three real stage PDFs in one browser-safe download."""
    _require_pdf_stage(request.performance, Stage.PERFORMANCE)
    _require_pdf_stage(request.security, Stage.SECURITY)
    _require_pdf_stage(request.legal, Stage.LEGAL)
    archive = BytesIO()
    with ZipFile(archive, "w", compression=ZIP_DEFLATED) as zip_file:
        zip_file.writestr(
            "scavibe-performance-audit.pdf",
            _stage_pdf_bytes(request.performance),
        )
        zip_file.writestr(
            "scavibe-security-audit.pdf",
            _stage_pdf_bytes(request.security),
        )
        zip_file.writestr(
            "scavibe-data-handling-and-consent-audit.pdf",
            _stage_pdf_bytes(request.legal),
        )
    archive.seek(0)
    return StreamingResponse(
        archive,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=scavibe-audit-reports.zip"},
    )


@app.post("/audit-stages/consent-example")
async def download_consent_example(request: ConsentExampleRequest) -> StreamingResponse:
    _require_pdf_stage(request.report, Stage.LEGAL)
    archive = BytesIO()
    with ZipFile(archive, "w", compression=ZIP_DEFLATED) as zip_file:
        zip_file.writestr("ConsentCheckbox.tsx", _consent_example_files()["ConsentCheckbox.tsx"])
    archive.seek(0)
    return StreamingResponse(
        archive,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=scavibe-consent-checkbox-example.zip"},
    )


@app.post("/audit-stages/pull-request", response_model=PullRequestResponse)
async def create_document_pull_request(request: PullRequestRequest) -> PullRequestResponse:
    """Open an approved artifact PR; it never applies application source edits."""
    if request.approved is not True:
        raise HTTPException(status_code=422, detail="approved=true is required before Scavibe opens a pull request")
    github_token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not github_token:
        raise HTTPException(status_code=503, detail="GITHUB_TOKEN is required to create a pull request")
    try:
        owner, repository = parse_github_repository(str(request.repository_url))
    except RepositoryIntakeError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    headers = {"Authorization": f"Bearer {github_token}", "Accept": "application/vnd.github+json"}
    timeout = httpx.Timeout(20.0, connect=10.0)
    branch = f"scavibe/audit-{uuid4().hex[:12]}"
    async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
        repository_response = await client.get(f"https://api.github.com/repos/{owner}/{repository}")
        if repository_response.status_code != 200:
            raise HTTPException(status_code=502, detail=f"GitHub repository request returned HTTP {repository_response.status_code}")
        base_branch = repository_response.json().get("default_branch")
        ref_response = await client.get(f"https://api.github.com/repos/{owner}/{repository}/git/ref/heads/{base_branch}")
        if ref_response.status_code != 200:
            raise HTTPException(status_code=502, detail=f"GitHub base branch request returned HTTP {ref_response.status_code}")
        base_sha = ref_response.json().get("object", {}).get("sha")
        branch_response = await client.post(
            f"https://api.github.com/repos/{owner}/{repository}/git/refs",
            json={"ref": f"refs/heads/{branch}", "sha": base_sha},
        )
        if branch_response.status_code != 201:
            raise HTTPException(status_code=502, detail=f"GitHub branch creation returned HTTP {branch_response.status_code}")
        if request.report.stage == Stage.LEGAL:
            files = {
                "scavibe-audit/SCAVIBE_DATA_HANDLING_AND_CONSENT_AUDIT.md": report_markdown(request.report),
                "scavibe-audit/ConsentCheckbox.tsx": _consent_example_files()["ConsentCheckbox.tsx"],
            }
        else:
            files = {"scavibe-audit/SCAVIBE_AUDIT_REPORT.md": report_markdown(request.report)}
        for path, content in files.items():
            content_response = await client.put(
                f"https://api.github.com/repos/{owner}/{repository}/contents/{path}",
                json={
                    "message": f"Add Scavibe {request.report.stage.value} audit artifact",
                    "content": b64encode(content.encode("utf-8")).decode("ascii"),
                    "branch": branch,
                },
            )
            if content_response.status_code not in {200, 201}:
                raise HTTPException(status_code=502, detail=f"GitHub file creation for {path} returned HTTP {content_response.status_code}")
        pull_response = await client.post(
            f"https://api.github.com/repos/{owner}/{repository}/pulls",
            json={
                "title": (
                    "Scavibe data-handling and consent audit artifacts"
                    if request.report.stage == Stage.LEGAL
                    else f"Scavibe {request.report.stage.value} audit artifacts"
                ),
                "head": branch,
                "base": base_branch,
                "draft": True,
                "body": "This draft PR was explicitly approved in Scavibe. It contains evidence-backed audit artifacts and does not modify existing application source code.",
            },
        )
        if pull_response.status_code != 201:
            raise HTTPException(status_code=502, detail=f"GitHub pull request creation returned HTTP {pull_response.status_code}")
    return PullRequestResponse(url=pull_response.json()["html_url"], branch=branch)


@app.post("/audit-stages/source-fix-pull-request", response_model=PullRequestResponse)
async def create_source_fix_pull_request(request: SourceFixPullRequestRequest) -> PullRequestResponse:
    """Open one explicitly approved, two-file additive source-fix PR."""
    if request.source_change_approved is not True:
        raise HTTPException(status_code=422, detail="source_change_approved=true is required before Scavibe generates source code")
    github_token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not github_token:
        raise HTTPException(status_code=503, detail="GITHUB_TOKEN is required to create a pull request")
    stage_request = StageAuditRequest(
        repository_url=request.repository_url,
        app_url=request.app_url,
        audit_id=request.audit_id,
        audit_pin=request.audit_pin,
    )
    snapshot, audit_id, _ = await _pinned_repository_snapshot(stage_request, [])
    if request.report.evidence_commit_sha != snapshot.context.commit_sha:
        raise HTTPException(status_code=422, detail="report evidence_commit_sha does not match the signed audit pin")
    try:
        plan = build_auto_fix_plan(request.report, request.finding_index, snapshot.context.source_files)
    except AutoFixPlanError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    if plan.fix_type != request.fix_type:
        raise HTTPException(status_code=422, detail="fix_type does not match the only bounded source-fix plan supported by this finding")
    try:
        owner, repository = parse_github_repository(str(request.repository_url))
    except RepositoryIntakeError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    headers = {"Authorization": f"Bearer {github_token}", "Accept": "application/vnd.github+json"}
    timeout = httpx.Timeout(20.0, connect=10.0)
    branch = f"scavibe/fix-{uuid4().hex[:12]}"
    async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
        repository_response = await client.get(f"https://api.github.com/repos/{owner}/{repository}")
        if repository_response.status_code != 200:
            raise HTTPException(status_code=502, detail=f"GitHub repository request returned HTTP {repository_response.status_code}")
        base_branch = repository_response.json().get("default_branch")
        ref_response = await client.get(f"https://api.github.com/repos/{owner}/{repository}/git/ref/heads/{base_branch}")
        if ref_response.status_code != 200:
            raise HTTPException(status_code=502, detail=f"GitHub base branch request returned HTTP {ref_response.status_code}")
        base_sha = ref_response.json().get("object", {}).get("sha")
        existing_shas: dict[str, str] = {}
        for file in plan.files:
            if file.original_content is None:
                continue
            existing_response = await client.get(
                f"https://api.github.com/repos/{owner}/{repository}/contents/{file.path}",
                params={"ref": base_branch},
            )
            if existing_response.status_code != 200:
                raise HTTPException(status_code=502, detail=f"GitHub integration file request for {file.path} returned HTTP {existing_response.status_code}")
            payload = existing_response.json()
            try:
                current_content = b64decode(payload["content"].encode("ascii")).decode("utf-8")
                existing_shas[file.path] = payload["sha"]
            except (KeyError, UnicodeError, ValueError) as error:
                raise HTTPException(status_code=502, detail=f"GitHub integration file payload for {file.path} is invalid") from error
            if current_content != file.original_content:
                raise HTTPException(status_code=409, detail=f"GitHub integration file {file.path} changed after the pinned audit; rerun the audit before generating a fix")
        branch_response = await client.post(
            f"https://api.github.com/repos/{owner}/{repository}/git/refs",
            json={"ref": f"refs/heads/{branch}", "sha": base_sha},
        )
        if branch_response.status_code != 201:
            raise HTTPException(status_code=502, detail=f"GitHub branch creation returned HTTP {branch_response.status_code}")
        for file in plan.files:
            payload = {
                "message": f"Add Scavibe {plan.fix_type} fix",
                "content": b64encode(file.content.encode("utf-8")).decode("ascii"),
                "branch": branch,
            }
            if file.original_content is not None:
                payload["sha"] = existing_shas[file.path]
            content_response = await client.put(f"https://api.github.com/repos/{owner}/{repository}/contents/{file.path}", json=payload)
            if content_response.status_code not in {200, 201}:
                raise HTTPException(status_code=502, detail=f"GitHub file update for {file.path} returned HTTP {content_response.status_code}")
        pull_response = await client.post(
            f"https://api.github.com/repos/{owner}/{repository}/pulls",
            json={
                "title": f"Scavibe auto-fix: {plan.label}",
                "head": branch,
                "base": base_branch,
                "draft": True,
                "body": (
                    f"This draft PR was explicitly approved for the cited finding at `{plan.citation}`.\n\n"
                    f"It changes exactly two files: one new additive implementation file and one minimal integration edit.\n\n"
                    f"{plan.verification_note}\n\n"
                    + (
                        "Rate-limit default: 60 requests per 60 seconds per IP. This is a conservative starting point and must be reviewed for the product's traffic profile."
                        if plan.fix_type == "rate_limit_middleware"
                        else "The generated checkbox is a UI pattern only; review its wording and the surrounding consent flow before merging."
                    )
                ),
            },
        )
        if pull_response.status_code != 201:
            raise HTTPException(status_code=502, detail=f"GitHub pull request creation returned HTTP {pull_response.status_code}")
    return PullRequestResponse(url=pull_response.json()["html_url"], branch=branch)
