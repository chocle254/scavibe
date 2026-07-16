"""Scavibe API foundation.

This local implementation models the job lifecycle used by the frontend. Real
repository cloning, sandbox provisioning, and AI analysis are intentionally
kept behind explicit integrations so no live target is ever tested by default.
"""

import os
from base64 import b64encode
from datetime import datetime, timezone
from io import BytesIO
from uuid import uuid4
from zipfile import ZIP_DEFLATED, ZipFile

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, HttpUrl
import httpx

from scavibe.agents import AuditOrchestrator, NvidiaNimGateway, NvidiaNimSettings, SpecialistAgent
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
from scavibe.load_test import LoadTestError, LoadTestSummary, run_sandbox_load_test
from scavibe.repository import RepositoryIntakeError, RepositorySnapshot, fetch_public_repository, parse_github_repository
from scavibe.scoring import confidence_score, risk_score, severity_for


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


JOBS: dict[str, AuditJob] = {}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "scavibe-api", "version": "0.1.0"}


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


async def _repository_snapshot(request: StageAuditRequest, measurements: list[RuntimeMeasurement]) -> RepositorySnapshot:
    try:
        return await fetch_public_repository(
            audit_id=f"stage_{uuid4().hex[:20]}",
            repository_url=str(request.repository_url),
            app_url=str(request.app_url),
            jurisdictions=request.jurisdictions,
            runtime_measurements=measurements,
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
    findings: list[Finding] = []
    conditions = [
        (
            measurement.p95_latency_ms > 500,
            "P95 latency exceeds 500 ms at the tested load",
            f"Sandbox test {measurement.id} recorded p95 latency {measurement.p95_latency_ms} ms at {measurement.concurrent_users} concurrent users for {measurement.duration_seconds} seconds across {measurement.sample_count} samples; the threshold is 500 ms.",
            "p95_latency_ms",
            measurement.p95_latency_ms,
            500.0,
            "Profile the tested route, remove the measured bottleneck, and repeat the same sandbox test before release.",
        ),
        (
            measurement.error_rate_percent > 1.0,
            "Error rate exceeds 1.0% at the tested load",
            f"Sandbox test {measurement.id} recorded error rate {measurement.error_rate_percent}% at {measurement.concurrent_users} concurrent users for {measurement.duration_seconds} seconds across {measurement.sample_count} samples; the threshold is 1.0%.",
            "error_rate_percent",
            measurement.error_rate_percent,
            1.0,
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
    report = _performance_report(snapshot.context, test_summary)
    return StageAuditResponse(
        stage=Stage.PERFORMANCE,
        repository=_repository_summary(snapshot),
        report=report,
        measurement=test_summary.measurement,
        successful_requests=test_summary.successful_requests,
        failed_requests=test_summary.failed_requests,
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
