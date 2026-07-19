"""Sandbox-only, read-only confirmation for static security candidates.

The model may propose a proof-of-concept plan, but Scavibe never executes
model-supplied Python or shell. This module materializes one constrained GET
request from a validated plan, preventing a malformed model response from
becoming arbitrary code execution infrastructure.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Literal
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, Field, ValidationError, model_validator

from .agents.gateway import AgentProtocolError, Gateway
from .contracts import ExploitabilityStatus, Finding, SecurityPocExecution


SAFE_POC_METHOD: Literal["GET"] = "GET"
SAFE_POC_TIMEOUT_SECONDS = 5.0
SAFE_POC_MAX_RESPONSE_BYTES = 4_096
SAFE_POC_MAX_PATH_CHARACTERS = 256
SAFE_POC_MAX_REDIRECTS = 0
SAFE_POC_USER_AGENT = "Scavibe-Safe-PoC/1.0"

SECURITY_POC_PROMPT = """
You are producing a proof-of-concept proposal for a Scavibe security finding.
You must return exactly one JSON object and no Markdown.

Each candidate already has static source evidence. Propose exactly one plan for
every candidate index. A plan is safe_to_execute=true only when all conditions
below are true:
- a single unauthenticated HTTP GET request to one literal route found in the
  supplied cited source is sufficient to test the claim;
- the path begins with exactly one slash, has no query string or fragment, and
  has no path parameter, wildcard, or placeholder;
- expected_status_code is an integer from 200 through 299;
- response_marker is a 1-128 character literal that appears in the candidate's
  cited source quote and would demonstrate the claimed unauthorized behavior;
- the test has no request body, cookies, authorization header, redirect, write,
  privilege change, deletion, or call to any host other than the sandbox.

For all other vulnerability classes, return safe_to_execute=false and state
the exact reason. Do not downgrade these safety conditions. The model-proposed
test code is an audit artifact only: Scavibe will validate the plan and use its
own fixed GET template instead of executing model-provided code.

Return this exact schema:
{"plans":[{"candidate_index":0,"safe_to_execute":false,"request_path":null,"expected_status_code":null,"response_marker":null,"proposed_test_code":"# not executed","non_execution_reason":"exact reason"}]}
""".strip()


class SafePocPlan(BaseModel):
    candidate_index: int = Field(ge=0, le=29)
    safe_to_execute: bool
    request_path: str | None = Field(default=None, max_length=SAFE_POC_MAX_PATH_CHARACTERS)
    expected_status_code: int | None = Field(default=None, ge=200, le=299)
    response_marker: str | None = Field(default=None, min_length=1, max_length=128)
    proposed_test_code: str = Field(min_length=1, max_length=2_000)
    non_execution_reason: str | None = Field(default=None, min_length=20, max_length=800)

    @model_validator(mode="after")
    def require_complete_safe_plan(self) -> "SafePocPlan":
        if self.safe_to_execute and (
            self.request_path is None or self.expected_status_code is None or self.response_marker is None
        ):
            raise ValueError("safe proof-of-concept plan requires request_path, expected_status_code, and response_marker")
        if not self.safe_to_execute and not self.non_execution_reason:
            raise ValueError("non-executed proof-of-concept plan requires non_execution_reason")
        return self


class SafePocDraft(BaseModel):
    plans: list[SafePocPlan] = Field(max_length=30)


def _parse_plan_json(raw_output: str) -> SafePocDraft:
    content = raw_output.lstrip("\ufeff").strip()
    if content.startswith("```"):
        lines = content.splitlines()
        if len(lines) < 3 or lines[0].strip().lower() not in {"```", "```json"} or lines[-1].strip() != "```":
            raise AgentProtocolError("security proof-of-concept response is not a single fenced JSON object")
        content = "\n".join(lines[1:-1]).strip()
    try:
        payload = json.loads(content)
        return SafePocDraft.model_validate(payload)
    except (json.JSONDecodeError, ValidationError) as error:
        raise AgentProtocolError(f"security proof-of-concept response is not valid: {error}") from error


def _candidate_payload(index: int, finding: Finding) -> dict:
    return {
        "candidate_index": index,
        "title": finding.title,
        "statement": finding.statement,
        "attacker_access": finding.attacker_access.value,
        "evidence": [
            {
                "file_path": item.file_path,
                "start_line": item.start_line,
                "end_line": item.end_line,
                "quote": item.quote,
            }
            for item in finding.evidence
            if item.kind.value == "source"
        ],
    }


def _safe_path(path: str) -> bool:
    if not path.startswith("/") or path.startswith("//") or len(path) > SAFE_POC_MAX_PATH_CHARACTERS:
        return False
    parsed = urlsplit(path)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment or "\\" in path:
        return False
    return all(segment not in {".", ".."} for segment in parsed.path.split("/"))


def _cited_source_text(finding: Finding) -> str:
    return "\n".join(item.quote or "" for item in finding.evidence if item.kind.value == "source")


def _path_is_in_cited_file(path: str, finding: Finding, source_by_path: dict[str, str]) -> bool:
    for item in finding.evidence:
        if item.kind.value != "source" or not item.file_path:
            continue
        if path in source_by_path.get(item.file_path, ""):
            return True
    return False


def _canonical_test_code(*, sandbox_url: str, path: str, expected_status_code: int, marker: str) -> str:
    target = f"{sandbox_url.rstrip('/')}{path}"
    return (
        "import httpx\n\n"
        "async with httpx.AsyncClient(follow_redirects=False, timeout=5.0) as client:\n"
        f"    response = await client.get({target!r}, headers={{'User-Agent': {SAFE_POC_USER_AGENT!r}}})\n"
        f"assert response.status_code == {expected_status_code}\n"
        f"assert {marker!r} in response.text\n"
    )


def _unexecuted(plan: SafePocPlan, reason: str) -> SecurityPocExecution:
    return SecurityPocExecution(
        proposed_test_code=plan.proposed_test_code,
        executed_test_code=None,
        execution_state="not_executed",
        request_method=None,
        request_path=plan.request_path,
        expected_status_code=plan.expected_status_code,
        expected_response_marker=plan.response_marker,
        response_status_code=None,
        response_excerpt=None,
        response_sha256=None,
        reason=reason,
    )


async def _read_response_excerpt(response: httpx.Response) -> tuple[str, str]:
    captured = bytearray()
    async for chunk in response.aiter_bytes():
        remaining = SAFE_POC_MAX_RESPONSE_BYTES - len(captured)
        if remaining <= 0:
            break
        captured.extend(chunk[:remaining])
        if len(captured) >= SAFE_POC_MAX_RESPONSE_BYTES:
            break
    raw = bytes(captured)
    return raw.decode("utf-8", errors="replace"), hashlib.sha256(raw).hexdigest()


async def _execute_safe_plan(
    *,
    plan: SafePocPlan,
    finding: Finding,
    sandbox_url: str,
    source_by_path: dict[str, str],
    transport: httpx.AsyncBaseTransport | None,
) -> SecurityPocExecution:
    if not plan.safe_to_execute:
        return _unexecuted(plan, plan.non_execution_reason or "The model did not authorize a safe proof-of-concept execution.")
    if plan.request_path is None or plan.expected_status_code is None or plan.response_marker is None:
        return _unexecuted(plan, "The proposed proof-of-concept omitted a required safe execution value.")
    if not _safe_path(plan.request_path):
        return _unexecuted(plan, "The proposed path was rejected: only a literal relative GET path without query, fragment, traversal, or host override is executable.")
    if plan.response_marker not in _cited_source_text(finding):
        return _unexecuted(plan, "The proposed response marker was not present in the finding's cited source evidence, so it cannot support confirmation.")
    if not _path_is_in_cited_file(plan.request_path, finding, source_by_path):
        return _unexecuted(plan, "The proposed path was not found in a source file cited by this finding, so Scavibe did not send a network request.")

    root = urlsplit(sandbox_url)
    target_url = f"{sandbox_url.rstrip('/')}{plan.request_path}"
    target = urlsplit(target_url)
    if root.scheme != "https" or target.scheme != "https" or root.hostname != target.hostname or target.port not in {None, 443}:
        return _unexecuted(plan, "The target did not resolve to the exact HTTPS host of the signed Scavibe sandbox.")
    executed_code = _canonical_test_code(
        sandbox_url=sandbox_url,
        path=plan.request_path,
        expected_status_code=plan.expected_status_code,
        marker=plan.response_marker,
    )
    try:
        timeout = httpx.Timeout(SAFE_POC_TIMEOUT_SECONDS, connect=SAFE_POC_TIMEOUT_SECONDS)
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            max_redirects=SAFE_POC_MAX_REDIRECTS,
            transport=transport,
            headers={"User-Agent": SAFE_POC_USER_AGENT},
        ) as client:
            async with client.stream(SAFE_POC_METHOD, target_url) as response:
                excerpt, response_sha256 = await _read_response_excerpt(response)
    except httpx.HTTPError as error:
        return SecurityPocExecution(
            proposed_test_code=plan.proposed_test_code,
            executed_test_code=executed_code,
            execution_state="executed",
            request_method=SAFE_POC_METHOD,
            request_path=plan.request_path,
            expected_status_code=plan.expected_status_code,
            expected_response_marker=plan.response_marker,
            response_status_code=None,
            response_excerpt=None,
            response_sha256=None,
            reason=f"The validated GET probe did not complete: {error}.",
        )
    confirmed = response.status_code == plan.expected_status_code and plan.response_marker in excerpt
    reason = (
        "The validated GET probe returned the planned status code and the response marker tied to the cited source evidence."
        if confirmed
        else "The validated GET probe completed, but its status code or response marker did not satisfy the planned confirmation condition."
    )
    return SecurityPocExecution(
        proposed_test_code=plan.proposed_test_code,
        executed_test_code=executed_code,
        execution_state="executed",
        request_method=SAFE_POC_METHOD,
        request_path=plan.request_path,
        expected_status_code=plan.expected_status_code,
        expected_response_marker=plan.response_marker,
        response_status_code=response.status_code,
        response_excerpt=excerpt,
        response_sha256=response_sha256,
        reason=reason,
    )


def _fallback_plan(index: int, reason: str) -> SafePocPlan:
    return SafePocPlan(
        candidate_index=index,
        safe_to_execute=False,
        request_path=None,
        expected_status_code=None,
        response_marker=None,
        proposed_test_code="# No proof-of-concept code was executed.",
        non_execution_reason=reason,
    )


def _plans_by_index(plans: Iterable[SafePocPlan], finding_count: int) -> dict[int, SafePocPlan]:
    indexed: dict[int, SafePocPlan] = {}
    for plan in plans:
        if plan.candidate_index in indexed:
            raise AgentProtocolError(f"security proof-of-concept response repeated candidate_index {plan.candidate_index}")
        indexed[plan.candidate_index] = plan
    expected = set(range(finding_count))
    if set(indexed) != expected:
        raise AgentProtocolError("security proof-of-concept response must contain exactly one plan for every candidate finding")
    return indexed


async def confirm_security_findings(
    *,
    findings: list[Finding],
    sandbox_url: str,
    source_by_path: dict[str, str],
    gateway: Gateway,
    transport: httpx.AsyncBaseTransport | None = None,
) -> list[Finding]:
    """Return candidates with an auditable, safe sandbox confirmation state.

    A gateway protocol failure leaves every finding as a candidate. It cannot
    erase static evidence or upgrade any finding to confirmed exploitable.
    """
    if not findings:
        return []
    payload = json.dumps(
        {"sandbox_host": urlsplit(sandbox_url).hostname, "candidates": [_candidate_payload(index, finding) for index, finding in enumerate(findings)]},
        separators=(",", ":"),
    )
    try:
        plans = _plans_by_index(_parse_plan_json(await gateway.generate(system_prompt=SECURITY_POC_PROMPT, input_json=payload)).plans, len(findings))
    except AgentProtocolError as error:
        plans = {index: _fallback_plan(index, f"No safe proof-of-concept plan was executed because the model response was rejected: {error}.") for index in range(len(findings))}

    enriched: list[Finding] = []
    for index, finding in enumerate(findings):
        execution = await _execute_safe_plan(
            plan=plans[index],
            finding=finding,
            sandbox_url=sandbox_url,
            source_by_path=source_by_path,
            transport=transport,
        )
        status = (
            ExploitabilityStatus.CONFIRMED_EXPLOITABLE
            if execution.execution_state == "executed"
            and execution.response_status_code == execution.expected_status_code
            and execution.expected_response_marker is not None
            and execution.response_excerpt is not None
            and execution.expected_response_marker in execution.response_excerpt
            else ExploitabilityStatus.CANDIDATE_UNCONFIRMED
        )
        enriched.append(finding.model_copy(update={"exploitability_status": status, "poc_execution": execution}))
    return sorted(
        enriched,
        key=lambda finding: 0 if finding.exploitability_status == ExploitabilityStatus.CONFIRMED_EXPLOITABLE else 1,
    )
