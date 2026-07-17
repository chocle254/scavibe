"""Scavibe API foundation.

This local implementation models the job lifecycle used by the frontend. Real
repository cloning, sandbox provisioning, and AI analysis are intentionally
kept behind explicit integrations so no live target is ever tested by default.
"""

import os
import hmac
import asyncio
import json
from base64 import b64encode
from datetime import datetime, timezone
from io import BytesIO
from uuid import uuid4
from zipfile import ZIP_DEFLATED, ZipFile

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, HttpUrl
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
    app_url: HttpUrl
    live_target_confirmed: bool = False


class AuditJob(BaseModel):
    id: str
    status: str
    repository_url: HttpUrl
    app_url: HttpUrl
    target_mode: str
    created_at: datetime


class StageAuditRequest(BaseModel):
    repository_url: HttpUrl
    app_url: HttpUrl
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


class LegalArtifactRequest(BaseModel):
    report: AgentReport
    jurisdictions: list[str]


class StagePdfRequest(BaseModel):
    report: AgentReport


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
    app_url: HttpUrl
    ticket: str
    concurrent_users: int = 100
    duration_seconds: int = 60
    jurisdictions: list[str] = []
    audit_id: str | None = None
    audit_pin: str | None = None


JOBS: dict[str, AuditJob] = {}


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
    if str(context.repository_url) != str(job.repository_url) or str(context.app_url) != str(job.app_url):
        raise HTTPException(status_code=422, detail="context URLs must equal the URLs used to create the audit")
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
            app_url=str(request.app_url),
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
        if pin.repository_url != str(request.repository_url) or pin.app_url != str(request.app_url):
            raise HTTPException(status_code=422, detail="audit_pin does not match repository_url and app_url")
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
            app_url=str(request.app_url),
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


async def _specialist_report(stage: Stage, context: AuditContext) -> AgentReport:
    try:
        settings = NvidiaNimSettings.from_environment()
        report = await SpecialistAgent(stage, NvidiaNimGateway(settings)).analyze(context)
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except AgentProtocolError as error:
        raise HTTPException(status_code=502, detail=str(error)) from error
    if not context.source_content_complete:
        report.limitations.append(
            "Only the capped source-file selection was supplied to this stage; repository-wide absence claims are not valid."
        )
    return report


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


@app.post("/audit-stages/legal", response_model=StageAuditResponse)
async def audit_legal(request: StageAuditRequest) -> StageAuditResponse:
    if not request.jurisdictions:
        raise HTTPException(status_code=422, detail="legal requires at least one explicit jurisdiction code")
    snapshot, audit_id, audit_pin = await _pinned_repository_snapshot(request, [])
    report = await _specialist_report(Stage.LEGAL, snapshot.context)
    return StageAuditResponse(stage=Stage.LEGAL, audit_id=audit_id, audit_pin=audit_pin, repository=_repository_summary(snapshot), report=report)


def _legal_artifact_files(report: AgentReport, jurisdictions: list[str]) -> dict[str, str]:
    jurisdiction_label = ", ".join(jurisdictions) or "No jurisdiction supplied"
    finding_rows = "\n".join(
        f"- **{finding.severity.value.upper()}** — {finding.title}: {finding.remediation}"
        for finding in report.findings
    ) or "- No evidence-backed legal findings were returned. This is not a compliance determination."
    return {
        "README.md": (
            "# Scavibe legal review pack\n\n"
            "This pack is an AI-generated working draft built from the supplied repository evidence and the listed jurisdictions. "
            "It is not legal advice, it does not establish compliance, and it must be reviewed by a qualified lawyer before publication.\n\n"
            "## Included files\n\n"
            "- `SCAVIBE_LEGAL_REVIEW.md` — evidence-backed audit report.\n"
            "- `DRAFT_PRIVACY_POLICY.md` — publication draft with completion fields.\n"
            "- `DRAFT_TERMS_OF_SERVICE.md` — publication draft with completion fields.\n"
            "- `DATA_PROCESSING_INVENTORY.md` — evidence and completion inventory.\n"
            "- `IMPLEMENTATION_CHECKLIST.md` — product implementation tasks.\n"
            "- `ConsentCheckbox.tsx` — styled React consent component.\n\n"
            "## Required completion rule\n\n"
            "Replace every `[VERIFY: ...]` field using verified product, entity, data-flow, and legal-review information. Do not publish a draft with unresolved completion fields.\n"
        ),
        "SCAVIBE_LEGAL_REVIEW.md": report_markdown(report),
        "DRAFT_PRIVACY_POLICY.md": (
            "# Draft Privacy Policy\n\n"
            "**Status:** AI-generated working draft. Obtain review from a licensed attorney before publication.\n\n"
            f"**Jurisdictions supplied for review:** {jurisdiction_label}.\n\n"
            "## 1. Who operates this service\n\n"
            "[VERIFY: legal entity name, trading name, physical address, and privacy contact email.]\n\n"
            "## 2. Scope of this notice\n\n"
            "This notice must describe the information practices of [VERIFY: product name and domains/apps covered]. It must be published where users can access it before submitting personal information.\n\n"
            "## 3. Information inventory\n\n"
            "| Category | Source | Purpose | Required or optional | Evidence / owner |\n"
            "| --- | --- | --- | --- | --- |\n"
            "| [VERIFY: account data] | [VERIFY] | [VERIFY] | [VERIFY] | [VERIFY] |\n"
            "| [VERIFY: device or usage data] | [VERIFY] | [VERIFY] | [VERIFY] | [VERIFY] |\n"
            "| [VERIFY: payment/support data] | [VERIFY] | [VERIFY] | [VERIFY] | [VERIFY] |\n\n"
            "## 4. How information is used\n\n"
            "[VERIFY: list each processing purpose supported by the completed inventory. Do not describe a purpose that is not actually implemented.]\n\n"
            "## 5. Sharing, processors, and transfers\n\n"
            "[VERIFY: list every service provider, analytics provider, hosting provider, payment provider, and transfer destination. State the operational role and contractual status for each.]\n\n"
            "## 6. Retention and deletion\n\n"
            "[VERIFY: retention period or objective retention rule for every information category, deletion method, backup treatment, and account-closure process.]\n\n"
            "## 7. Security and access controls\n\n"
            "[VERIFY: state only implemented technical and organizational controls. Do not promise absolute security or controls that have not been verified.]\n\n"
            "## 8. User requests and contact\n\n"
            "[VERIFY: request channel, identity-verification process, escalation route, and response workflow for each supplied jurisdiction.]\n\n"
            "## 9. Children and age gating\n\n"
            "[VERIFY: applicable age rule, age-screen behavior, parental-consent flow if applicable, and deletion/escalation procedure. Do not publish a numeric age without legal review for the supplied jurisdictions.]\n\n"
            "## 10. Changes to this notice\n\n"
            "[VERIFY: effective-date process, material-change notice method, and archive location for prior versions.]\n"
        ),
        "DRAFT_TERMS_OF_SERVICE.md": (
            "# Draft Terms of Service\n\n"
            "**Status:** AI-generated working draft. Obtain review from a licensed attorney before publication.\n\n"
            "## 1. Agreement and service operator\n\n"
            "[VERIFY: product name, legal entity, contact address, effective date, and acceptance event.]\n\n"
            "## 2. Eligibility and accounts\n\n"
            "[VERIFY: eligibility requirements, age-screen behavior, account-registration data, credential responsibilities, and account suspension/deletion process.]\n\n"
            "## 3. Permitted use\n\n"
            "[VERIFY: product-specific permitted use, technical limits, and user-content rules.]\n\n"
            "## 4. Prohibited conduct\n\n"
            "[VERIFY: prohibited use categories that are appropriate for this product, including security abuse, impersonation, unlawful content, and interference with service operation.]\n\n"
            "## 5. Fees, subscriptions, and refunds\n\n"
            "[VERIFY: whether payments exist. If they do, specify pricing display, renewal, cancellation, refund, tax, and payment-processor terms.]\n\n"
            "## 6. Intellectual property and user content\n\n"
            "[VERIFY: ownership, permitted license, user-content license if applicable, takedown process, and third-party material rules.]\n\n"
            "## 7. Service availability and changes\n\n"
            "[VERIFY: maintenance, change-notice, support, and discontinuation commitments. Do not promise uptime levels that have not been adopted operationally.]\n\n"
            "## 8. Disclaimers, liability, and dispute terms\n\n"
            "[VERIFY WITH COUNSEL: jurisdiction-specific disclaimer, liability, indemnity, governing-law, venue, and dispute-resolution language.]\n\n"
            "## 9. Contact\n\n"
            "[VERIFY: legal and support contact details.]\n"
        ),
        "DATA_PROCESSING_INVENTORY.md": (
            "# Data Processing Inventory\n\n"
            f"**Supplied jurisdictions:** {jurisdiction_label}\n\n"
            "## Evidence-backed audit outcomes\n\n"
            f"{finding_rows}\n\n"
            "## Completion inventory\n\n"
            "| Data element | Collection point | Storage location | Processor | Purpose | Retention rule | Owner | Verification status |\n"
            "| --- | --- | --- | --- | --- | --- | --- | --- |\n"
            "| [VERIFY] | [VERIFY] | [VERIFY] | [VERIFY] | [VERIFY] | [VERIFY] | [VERIFY] | Open |\n"
            "| [VERIFY] | [VERIFY] | [VERIFY] | [VERIFY] | [VERIFY] | [VERIFY] | [VERIFY] | Open |\n"
            "| [VERIFY] | [VERIFY] | [VERIFY] | [VERIFY] | [VERIFY] | [VERIFY] | [VERIFY] | Open |\n\n"
            "## Required review questions\n\n"
            "1. Does each collected field have an evidence-backed purpose?\n"
            "2. Is each processor and transfer destination listed?\n"
            "3. Does each field have a verified retention rule and owner?\n"
            "4. Does the completed privacy notice match this inventory exactly?\n"
        ),
        "IMPLEMENTATION_CHECKLIST.md": (
            "# Legal and Privacy Implementation Checklist\n\n"
            "## Before publication\n\n"
            "- [ ] Replace every `[VERIFY: ...]` completion field in the drafts.\n"
            "- [ ] Confirm the policy inventory against the deployed product and every processor.\n"
            "- [ ] Obtain qualified legal review for the supplied jurisdictions.\n"
            "- [ ] Publish the approved Privacy Policy and Terms at stable URLs.\n"
            "- [ ] Link both documents from signup, checkout, account, and footer surfaces that exist in the product.\n"
            "- [ ] Store a version identifier and acceptance timestamp when terms acceptance is required.\n"
            "- [ ] Implement age screening only after the applicable rule and flow are verified.\n"
            "- [ ] Test request, deletion, export, and support workflows that the completed policy promises.\n\n"
            "## Engineering evidence to retain\n\n"
            "- [ ] Commit SHA reviewed by Scavibe.\n"
            "- [ ] Approved policy and terms version IDs.\n"
            "- [ ] Processor and data-flow inventory.\n"
            "- [ ] Consent and acceptance event schema.\n"
            "- [ ] Legal-review approval record.\n"
        ),
        "ConsentCheckbox.tsx": (
            "type TermsConsentProps = {\n"
            "  privacyPolicyUrl: string;\n"
            "  termsUrl: string;\n"
            "  onAcceptanceChange?: (accepted: boolean) => void;\n"
            "};\n\n"
            "export function TermsConsent({ privacyPolicyUrl, termsUrl, onAcceptanceChange }: TermsConsentProps) {\n"
            "  return (\n"
            "    <label style={{ display: 'flex', gap: 8, alignItems: 'flex-start', fontSize: 14, lineHeight: 1.5 }}>\n"
            "      <input\n"
            "        type=\"checkbox\"\n"
            "        name=\"termsAccepted\"\n"
            "        required\n"
            "        onChange={(event) => onAcceptanceChange?.(event.target.checked)}\n"
            "      />\n"
            "      <span>\n"
            "        I confirm that I meet the applicable eligibility requirements and have read the{' '}\n"
            "        <a href={termsUrl} target=\"_blank\" rel=\"noreferrer\">Terms of Service</a>{' '}and{' '}\n"
            "        <a href={privacyPolicyUrl} target=\"_blank\" rel=\"noreferrer\">Privacy Policy</a>.\n"
            "      </span>\n"
            "    </label>\n"
            "  );\n"
            "}\n"
        ),
    }


def _pdf_response(pdf: bytes, filename: str) -> StreamingResponse:
    document = BytesIO(pdf)
    document.seek(0)
    return StreamingResponse(
        document,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def _stage_pdf_bytes(report: AgentReport, *, legal_drafts: tuple[str, str] | None = None) -> bytes:
    try:
        from scavibe.pdf_reports import PdfGenerationError, build_stage_pdf
    except ModuleNotFoundError as error:
        if error.name in {"reportlab", "PIL"}:
            raise HTTPException(status_code=503, detail="reportlab==5.0.0 and pillow==12.3.0 are required for PDF exports") from error
        raise
    try:
        return build_stage_pdf(report, legal_drafts=legal_drafts)
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
async def download_legal_pdf(request: LegalArtifactRequest) -> StreamingResponse:
    _require_pdf_stage(request.report, Stage.LEGAL)
    artifacts = _legal_artifact_files(request.report, request.jurisdictions)
    return _pdf_response(
        _stage_pdf_bytes(
            request.report,
            legal_drafts=(artifacts["DRAFT_PRIVACY_POLICY.md"], artifacts["DRAFT_TERMS_OF_SERVICE.md"]),
        ),
        "scavibe-legal-audit-and-drafts.pdf",
    )


@app.post("/audit-stages/legal-artifacts")
async def download_legal_artifacts(request: LegalArtifactRequest) -> StreamingResponse:
    _require_pdf_stage(request.report, Stage.LEGAL)
    archive = BytesIO()
    with ZipFile(archive, "w", compression=ZIP_DEFLATED) as zip_file:
        zip_file.writestr("ConsentCheckbox.tsx", _legal_artifact_files(request.report, request.jurisdictions)["ConsentCheckbox.tsx"])
    archive.seek(0)
    return StreamingResponse(
        archive,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=scavibe-consent-component.zip"},
    )


@app.post("/audit-stages/pull-request", response_model=PullRequestResponse)
async def create_document_pull_request(request: PullRequestRequest) -> PullRequestResponse:
    """Open a draft PR containing reports and legal drafts, never direct source edits."""
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
        files = {f"scavibe-audit/{path}": content for path, content in _legal_artifact_files(request.report, request.jurisdictions).items()}
        if request.report.stage != Stage.LEGAL:
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
                "title": f"Scavibe {request.report.stage.value} audit artifacts",
                "head": branch,
                "base": base_branch,
                "draft": True,
                "body": "This draft PR was explicitly approved in Scavibe. It contains audit reports and legal draft artifacts only; it does not modify application source code.",
            },
        )
        if pull_response.status_code != 201:
            raise HTTPException(status_code=502, detail=f"GitHub pull request creation returned HTTP {pull_response.status_code}")
    return PullRequestResponse(url=pull_response.json()["html_url"], branch=branch)
