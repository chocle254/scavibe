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
    RuntimeMeasurement,
    Stage,
)
from scavibe.load_test import LoadTestError, LoadTestSummary, run_ramp_load_test, run_sandbox_load_test
from scavibe.repository import (
    RepositoryIntakeError,
    RepositorySnapshot,
    fetch_public_repository,
    fetch_repository_identity,
    parse_github_repository,
    suggest_sandboxes,
)
from scavibe.scoring import confidence_score, risk_score, severity_for
from scavibe.agents.thresholds import (
    PERFORMANCE_ERROR_RATE_THRESHOLD_PERCENT,
    PERFORMANCE_MIN_CONCURRENT_USERS,
    PERFORMANCE_MIN_DURATION_SECONDS,
    PERFORMANCE_MIN_SAMPLE_COUNT,
    PERFORMANCE_P95_LATENCY_THRESHOLD_MS,
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


class RepositoryEvidenceSummary(BaseModel):
    commit_sha: str
    selected_files: list[str]
    source_content_complete: bool


class StageAuditResponse(BaseModel):
    stage: Stage
    repository: RepositoryEvidenceSummary
    report: AgentReport
    measurement: RuntimeMeasurement | None = None
    successful_requests: int | None = None
    failed_requests: int | None = None
    sandbox_teardown: str | None = None


class LegalArtifactRequest(BaseModel):
    report: AgentReport
    jurisdictions: list[str]


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
    )
    teardown = "deleted"
    try:
        snapshot = await _repository_snapshot(stage_request, [], commit_sha_override=sandbox.commit_sha)
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
    request: StageAuditRequest, measurements: list[RuntimeMeasurement], *, commit_sha_override: str | None = None
) -> RepositorySnapshot:
    try:
        return await fetch_public_repository(
            audit_id=f"stage_{uuid4().hex[:20]}",
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


def _performance_report(context: AuditContext, summary: LoadTestSummary) -> AgentReport:
    """Create a deterministic report from measured sandbox values only."""
    measurement = summary.measurement
    if (
        measurement.concurrent_users < PERFORMANCE_MIN_CONCURRENT_USERS
        or measurement.duration_seconds < PERFORMANCE_MIN_DURATION_SECONDS
        or measurement.sample_count < PERFORMANCE_MIN_SAMPLE_COUNT
    ):
        raise LoadTestError(
            f"performance report requires measurement {measurement.id} to have at least {PERFORMANCE_MIN_CONCURRENT_USERS} concurrent users, {PERFORMANCE_MIN_DURATION_SECONDS} seconds, and {PERFORMANCE_MIN_SAMPLE_COUNT} samples"
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
        limitations=[
            "This measurement covers only GET / on the supplied sandbox URL.",
            "No conclusion is made for user counts, routes, regions, or durations that were not measured.",
        ],
        evidence_commit_sha=context.commit_sha,
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
    snapshot = await _repository_snapshot(request, [test_summary.measurement])
    try:
        report = _performance_report(snapshot.context, test_summary)
    except LoadTestError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    return StageAuditResponse(
        stage=Stage.PERFORMANCE,
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

    async def event_stream():
        events: asyncio.Queue[dict] = asyncio.Queue()

        async def on_event(event: dict) -> None:
            await events.put(event)

        task = asyncio.create_task(run_ramp_load_test(sandbox_url=str(request.sandbox_url), on_event=on_event))
        try:
            while not task.done() or not events.empty():
                if not events.empty():
                    event = events.get_nowait()
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
                yield f"data: {json.dumps(event, separators=(',', ':'))}\n\n"
            await task
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/audit-stages/security", response_model=StageAuditResponse)
async def audit_security(request: StageAuditRequest) -> StageAuditResponse:
    snapshot = await _repository_snapshot(request, [])
    report = await _specialist_report(Stage.SECURITY, snapshot.context)
    return StageAuditResponse(stage=Stage.SECURITY, repository=_repository_summary(snapshot), report=report)


@app.post("/audit-stages/legal", response_model=StageAuditResponse)
async def audit_legal(request: StageAuditRequest) -> StageAuditResponse:
    if not request.jurisdictions:
        raise HTTPException(status_code=422, detail="legal requires at least one explicit jurisdiction code")
    snapshot = await _repository_snapshot(request, [])
    report = await _specialist_report(Stage.LEGAL, snapshot.context)
    return StageAuditResponse(stage=Stage.LEGAL, repository=_repository_summary(snapshot), report=report)


def _report_markdown(report: AgentReport) -> str:
    lines = [f"# Scavibe {report.stage.value.title()} Audit", "", report.summary, "", "## Findings", ""]
    if not report.findings:
        lines.extend(["No evidence-backed findings were returned for the supplied evidence set.", ""])
    for finding in report.findings:
        lines.extend(
            [
                f"### {finding.severity.value.upper()} · {finding.title}",
                "",
                f"Risk score: {finding.risk_score}/100 · Confidence: {finding.confidence_score}/100",
                "",
                finding.statement,
                "",
                "**Required change**",
                "",
                finding.remediation,
                "",
                "**Evidence**",
            ]
        )
        for evidence in finding.evidence:
            if evidence.kind == EvidenceKind.SOURCE:
                lines.append(f"- `{evidence.file_path}` lines {evidence.start_line}-{evidence.end_line}: `{evidence.quote}`")
            elif evidence.kind == EvidenceKind.RUNTIME:
                lines.append(f"- Sandbox `{evidence.measurement_id}` at `{evidence.endpoint}`: {evidence.metric}={evidence.observed_value}, threshold={evidence.threshold}")
            else:
                lines.append(f"- Manifest path: `{evidence.file_path}`")
        lines.append("")
    lines.extend(["## Limitations", ""])
    lines.extend(f"- {limitation}" for limitation in report.limitations)
    lines.extend(["", f"Evidence commit: `{report.evidence_commit_sha}`", ""])
    return "\n".join(lines)


def _legal_artifact_files(report: AgentReport, jurisdictions: list[str]) -> dict[str, str]:
    jurisdiction_label = ", ".join(jurisdictions)
    return {
        "SCAVIBE_LEGAL_REVIEW.md": _report_markdown(report),
        "DRAFT_PRIVACY_POLICY.md": (
            "# Draft Privacy Policy\n\n"
            "Status: AI-generated working draft. Obtain review from a licensed attorney before publication.\n\n"
            f"Target jurisdictions supplied for review: {jurisdiction_label}.\n\n"
            "## Information we collect\n[REPLACE WITH VERIFIED DATA-COLLECTION INVENTORY]\n\n"
            "## How we use information\n[REPLACE WITH VERIFIED PURPOSES]\n\n"
            "## Sharing and processors\n[REPLACE WITH VERIFIED VENDORS AND TRANSFERS]\n\n"
            "## Retention and deletion\n[REPLACE WITH VERIFIED RETENTION PERIODS AND REQUEST PROCESS]\n"
        ),
        "DRAFT_TERMS_OF_SERVICE.md": (
            "# Draft Terms of Service\n\n"
            "Status: AI-generated working draft. Obtain review from a licensed attorney before publication.\n\n"
            "## Acceptance of terms\n[REPLACE WITH YOUR PRODUCT AND LEGAL ENTITY DETAILS]\n\n"
            "## Account responsibilities\n[REPLACE WITH VERIFIED ACCOUNT RULES]\n\n"
            "## Acceptable use\n[REPLACE WITH PRODUCT-SPECIFIC RESTRICTIONS]\n\n"
            "## Contact\n[REPLACE WITH LEGAL CONTACT DETAILS]\n"
        ),
        "ConsentCheckbox.tsx": (
            "export function TermsConsent() {\n"
            "  return (\n"
            "    <label>\n"
            "      <input type=\"checkbox\" name=\"termsAccepted\" required />\n"
            "      I confirm I meet the applicable minimum age and have read the Terms of Service and Privacy Policy.\n"
            "    </label>\n"
            "  );\n"
            "}\n"
        ),
    }


@app.post("/audit-stages/legal-artifacts")
async def download_legal_artifacts(request: LegalArtifactRequest) -> StreamingResponse:
    archive = BytesIO()
    with ZipFile(archive, "w", compression=ZIP_DEFLATED) as zip_file:
        for path, content in _legal_artifact_files(request.report, request.jurisdictions).items():
            zip_file.writestr(path, content)
    archive.seek(0)
    return StreamingResponse(
        archive,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=scavibe-legal-drafts.zip"},
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
            files = {"scavibe-audit/SCAVIBE_AUDIT_REPORT.md": _report_markdown(request.report)}
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
