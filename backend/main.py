"""Scavibe API foundation.

This local implementation models the job lifecycle used by the frontend. Real
repository cloning, sandbox provisioning, and AI analysis are intentionally
kept behind explicit integrations so no live target is ever tested by default.
"""

import os
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl

from scavibe.agents import AuditOrchestrator, NvidiaNimGateway, NvidiaNimSettings
from scavibe.contracts import AuditContext, AuditRun


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
