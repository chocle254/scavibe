"""Disposable Vercel sandbox lifecycle for Scavibe performance tests.

This provider creates a new Vercel project for one pinned GitHub commit.  The
project has no user-supplied environment variables.  Its deployment is deleted
after a successful or failed load-test request; the project deletion also
removes its deployments and settings.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

import httpx

from .repository import RepositoryIntakeError, parse_github_repository

VERCEL_API = "https://api.vercel.com"
MIN_ACCESS_KEY_LENGTH = 32
MIN_SIGNING_KEY_LENGTH = 32
MIN_SANDBOX_TTL_SECONDS = 300
MAX_SANDBOX_TTL_SECONDS = 1800


class VercelSandboxError(RuntimeError):
    """The disposable sandbox could not be created, read, or deleted."""


@dataclass(frozen=True)
class VercelSandboxSettings:
    token: str
    access_key: str
    signing_key: str
    team_id: str | None
    ttl_seconds: int
    demo_mode: bool

    @classmethod
    def from_environment(cls) -> "VercelSandboxSettings":
        token = os.environ.get("VERCEL_SANDBOX_TOKEN", "").strip()
        access_key = os.environ.get("SCAVIBE_SANDBOX_ACCESS_KEY", "").strip()
        signing_key = os.environ.get("SCAVIBE_SANDBOX_SIGNING_KEY", "").strip()
        if not token:
            raise VercelSandboxError("VERCEL_SANDBOX_TOKEN is required to provision a Scavibe-owned Vercel sandbox")
        demo_mode = os.environ.get("SCAVIBE_SANDBOX_DEMO_MODE", "false").strip().lower() == "true"
        if not demo_mode and len(access_key) < MIN_ACCESS_KEY_LENGTH:
            raise VercelSandboxError("SCAVIBE_SANDBOX_ACCESS_KEY must contain at least 32 characters before sandbox provisioning is enabled")
        if len(signing_key) < MIN_SIGNING_KEY_LENGTH:
            raise VercelSandboxError("SCAVIBE_SANDBOX_SIGNING_KEY must contain at least 32 characters before sandbox provisioning is enabled")
        raw_ttl = os.environ.get("SCAVIBE_SANDBOX_TTL_SECONDS", "900").strip()
        try:
            ttl_seconds = int(raw_ttl)
        except ValueError as error:
            raise VercelSandboxError("SCAVIBE_SANDBOX_TTL_SECONDS must be an integer from 300 through 1800") from error
        if not MIN_SANDBOX_TTL_SECONDS <= ttl_seconds <= MAX_SANDBOX_TTL_SECONDS:
            raise VercelSandboxError("SCAVIBE_SANDBOX_TTL_SECONDS must be from 300 through 1800")
        return cls(
            token=token,
            access_key=access_key,
            signing_key=signing_key,
            team_id=os.environ.get("VERCEL_SANDBOX_TEAM_ID", "").strip() or None,
            ttl_seconds=ttl_seconds,
            demo_mode=demo_mode,
        )


@dataclass(frozen=True)
class SandboxTicket:
    deployment_id: str
    project_id: str
    repository_url: str
    commit_sha: str
    expires_at: int


@dataclass(frozen=True)
class SandboxDeployment:
    deployment_id: str
    project_id: str
    project_name: str
    ready_state: str
    deployment_url: str | None
    ticket: str
    expires_at: int
    commit_sha: str


def _query(settings: VercelSandboxSettings, **values: str) -> dict[str, str]:
    query = {key: value for key, value in values.items() if value}
    if settings.team_id:
        query["teamId"] = settings.team_id
    return query


def _headers(settings: VercelSandboxSettings) -> dict[str, str]:
    return {"Authorization": f"Bearer {settings.token}", "Content-Type": "application/json"}


def _error_message(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return f"Vercel returned HTTP {response.status_code}"
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict) and isinstance(error.get("message"), str):
        return f"Vercel returned HTTP {response.status_code}: {error['message']}"
    if isinstance(payload, dict) and isinstance(payload.get("message"), str):
        return f"Vercel returned HTTP {response.status_code}: {payload['message']}"
    return f"Vercel returned HTTP {response.status_code}"


def _project_name(repository: str) -> str:
    slug = re.sub(r"[^a-z0-9-]", "-", repository.lower()).strip("-")[:32] or "repo"
    return f"scavibe-sandbox-{slug}-{uuid4().hex[:10]}"


def _make_ticket(settings: VercelSandboxSettings, ticket: SandboxTicket) -> str:
    payload = json.dumps(ticket.__dict__, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = hmac.new(settings.signing_key.encode("utf-8"), payload, hashlib.sha256).digest()
    return f"{base64.urlsafe_b64encode(payload).decode('ascii').rstrip('=')}.{base64.urlsafe_b64encode(signature).decode('ascii').rstrip('=')}"


def read_ticket(settings: VercelSandboxSettings, token: str, *, require_unexpired: bool) -> SandboxTicket:
    try:
        payload_part, signature_part = token.split(".", 1)
        padding = "=" * (-len(payload_part) % 4)
        signature_padding = "=" * (-len(signature_part) % 4)
        payload = base64.urlsafe_b64decode(payload_part + padding)
        received_signature = base64.urlsafe_b64decode(signature_part + signature_padding)
        expected_signature = hmac.new(settings.signing_key.encode("utf-8"), payload, hashlib.sha256).digest()
        data = json.loads(payload)
        ticket = SandboxTicket(**data)
    except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VercelSandboxError("sandbox ticket is malformed") from error
    if not hmac.compare_digest(received_signature, expected_signature):
        raise VercelSandboxError("sandbox ticket signature is invalid")
    if require_unexpired and ticket.expires_at < int(time.time()):
        raise VercelSandboxError("sandbox ticket expired; create a new disposable sandbox")
    return ticket


def _deployment_url(payload: dict[str, Any]) -> str | None:
    value = payload.get("url")
    if not isinstance(value, str) or not value:
        return None
    url = f"https://{value}" if not value.startswith("https://") else value
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or not parsed.hostname.endswith(".vercel.app"):
        return None
    return url.rstrip("/")


async def create_sandbox(*, repository_url: str, commit_sha: str, default_branch: str) -> SandboxDeployment:
    """Create a no-secret Vercel project and deploy exactly ``commit_sha``."""
    settings = VercelSandboxSettings.from_environment()
    owner, repository = parse_github_repository(repository_url)
    project_name = _project_name(repository)
    timeout = httpx.Timeout(30.0, connect=10.0)
    async with httpx.AsyncClient(timeout=timeout, headers=_headers(settings)) as client:
        project_response = await client.post(
            f"{VERCEL_API}/v11/projects",
            params=_query(settings),
            json={"name": project_name, "gitRepository": {"type": "github", "repo": f"{owner}/{repository}"}},
        )
        if project_response.status_code not in {200, 201}:
            raise VercelSandboxError(
                f"{_error_message(project_response)}. The Vercel Git integration must have access to {owner}/{repository}."
            )
        project = project_response.json()
        project_id = project.get("id")
        repository_id = project.get("link", {}).get("repoId") if isinstance(project.get("link"), dict) else None
        if not isinstance(project_id, str) or not project_id or not isinstance(repository_id, (int, str)):
            await _delete_project(client, settings, project_id if isinstance(project_id, str) else None)
            raise VercelSandboxError("Vercel project creation did not return a project ID and linked GitHub repository ID")
        deployment_response = await client.post(
            f"{VERCEL_API}/v13/deployments",
            params=_query(settings, forceNew="1", skipAutoDetectionConfirmation="1"),
            json={
                "name": project_name,
                "project": project_id,
                "gitSource": {
                    "type": "github",
                    "repoId": str(repository_id),
                    "ref": default_branch,
                    "sha": commit_sha,
                },
            },
        )
        if deployment_response.status_code not in {200, 201}:
            await _delete_project(client, settings, project_id)
            raise VercelSandboxError(f"{_error_message(deployment_response)}. The disposable Vercel project was deleted.")
        deployment = deployment_response.json()
    deployment_id = deployment.get("id")
    if not isinstance(deployment_id, str) or not deployment_id:
        raise VercelSandboxError("Vercel deployment creation did not return a deployment ID")
    expires_at = int(time.time()) + settings.ttl_seconds
    ticket = SandboxTicket(deployment_id, project_id, repository_url, commit_sha, expires_at)
    return SandboxDeployment(
        deployment_id=deployment_id,
        project_id=project_id,
        project_name=project_name,
        ready_state=str(deployment.get("readyState") or deployment.get("status") or "QUEUED"),
        deployment_url=_deployment_url(deployment),
        ticket=_make_ticket(settings, ticket),
        expires_at=expires_at,
        commit_sha=commit_sha,
    )


async def get_sandbox(ticket_token: str) -> SandboxDeployment:
    settings = VercelSandboxSettings.from_environment()
    ticket = read_ticket(settings, ticket_token, require_unexpired=True)
    timeout = httpx.Timeout(20.0, connect=10.0)
    async with httpx.AsyncClient(timeout=timeout, headers=_headers(settings)) as client:
        response = await client.get(f"{VERCEL_API}/v13/deployments/{ticket.deployment_id}", params=_query(settings))
    if response.status_code == 404:
        raise VercelSandboxError("sandbox deployment no longer exists")
    if response.status_code != 200:
        raise VercelSandboxError(_error_message(response))
    deployment = response.json()
    project_id = deployment.get("projectId") or deployment.get("project", {}).get("id")
    if project_id != ticket.project_id:
        raise VercelSandboxError("sandbox ticket project does not match the Vercel deployment")
    return SandboxDeployment(
        deployment_id=ticket.deployment_id,
        project_id=ticket.project_id,
        project_name=str(deployment.get("name") or "scavibe-sandbox"),
        ready_state=str(deployment.get("readyState") or deployment.get("status") or "UNKNOWN"),
        deployment_url=_deployment_url(deployment),
        ticket=ticket_token,
        expires_at=ticket.expires_at,
        commit_sha=ticket.commit_sha,
    )


async def _delete_project(client: httpx.AsyncClient, settings: VercelSandboxSettings, project_id: str | None) -> None:
    if not project_id:
        return
    response = await client.delete(f"{VERCEL_API}/v9/projects/{project_id}", params=_query(settings))
    if response.status_code not in {200, 204, 404}:
        raise VercelSandboxError(_error_message(response))


async def delete_sandbox(ticket_token: str) -> None:
    """Delete the whole ephemeral project; expired tickets remain valid for cleanup."""
    settings = VercelSandboxSettings.from_environment()
    ticket = read_ticket(settings, ticket_token, require_unexpired=False)
    timeout = httpx.Timeout(20.0, connect=10.0)
    async with httpx.AsyncClient(timeout=timeout, headers=_headers(settings)) as client:
        await _delete_project(client, settings, ticket.project_id)
