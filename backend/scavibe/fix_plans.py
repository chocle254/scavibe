"""Strictly bounded, additive source-fix plans for explicitly approved PRs."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Literal

from .contracts import AgentReport, EvidenceKind, Finding, SourceFile, Stage

FixType = Literal["consent_checkbox", "rate_limit_middleware"]
RATE_LIMIT_REQUESTS_PER_MINUTE = 60
RATE_LIMIT_WINDOW_SECONDS = 60


class AutoFixPlanError(ValueError):
    """The immutable source evidence cannot support one of the two bounded fixes."""


@dataclass(frozen=True)
class GeneratedFile:
    path: str
    content: str
    original_content: str | None


@dataclass(frozen=True)
class AutoFixPlan:
    fix_type: FixType
    label: str
    citation: str
    files: tuple[GeneratedFile, GeneratedFile]
    verification_note: str


def _finding_text(finding: Finding) -> str:
    return " ".join((finding.title, finding.statement, finding.remediation)).lower()


def _source_for_finding(finding: Finding, source_files: list[SourceFile]) -> tuple[SourceFile, str]:
    source_by_path = {source.path: source for source in source_files}
    for evidence in finding.evidence:
        if evidence.kind != EvidenceKind.SOURCE or not evidence.file_path or evidence.start_line is None:
            continue
        source = source_by_path.get(evidence.file_path)
        if source is not None:
            if evidence.end_line is None or evidence.end_line > len(source.content.splitlines()):
                raise AutoFixPlanError("the cited source line range is outside the supplied immutable source file")
            cited_lines = "\n".join(source.content.splitlines()[evidence.start_line - 1 : evidence.end_line])
            if (evidence.quote or "") not in cited_lines:
                raise AutoFixPlanError("the cited source quote does not match the supplied immutable source file")
            return source, f"{evidence.file_path}:{evidence.start_line}"
    raise AutoFixPlanError("the selected finding has no cited source file available for a minimal integration change")


def _manifest(source_files: list[SourceFile], filename: str) -> str | None:
    for source in source_files:
        if PurePosixPath(source.path).name.lower() == filename.lower():
            return source.content
    return None


def _prepend_import(content: str, statement: str) -> str:
    lines = content.splitlines(keepends=True)
    if lines and lines[0].strip() in {'"use client";', "'use client';"}:
        return "".join([lines[0], statement, "\n", *lines[1:]])
    return f"{statement}\n{content}"


def _sibling_path(path: str, filename: str) -> str:
    parent = PurePosixPath(path).parent
    return filename if str(parent) == "." else str(parent / filename)


def _consent_plan(finding: Finding, source_files: list[SourceFile]) -> AutoFixPlan:
    package_json = _manifest(source_files, "package.json")
    source, citation = _source_for_finding(finding, source_files)
    text = _finding_text(finding)
    has_consent_signal = "consent" in text or "age-confirm" in text or "age confirmation" in text
    has_checkbox_signal = "checkbox" in text or "check box" in text
    if not has_consent_signal or not has_checkbox_signal:
        raise AutoFixPlanError("the legal finding is not a missing consent or age-confirmation checkbox finding")
    if package_json is None or ("\"next\"" not in package_json and "\"react\"" not in package_json):
        raise AutoFixPlanError("no Next.js or React framework declaration exists in supplied package.json evidence")
    if not source.path.endswith((".tsx", ".jsx")) or "<form" not in source.content or "</form>" not in source.content:
        raise AutoFixPlanError("the cited source is not a React form with a safe additive checkbox insertion point")
    component_path = _sibling_path(source.path, "ConsentCheckbox.tsx" if source.path.endswith(".tsx") else "ConsentCheckbox.jsx")
    import_statement = 'import { ConsentCheckbox } from "./ConsentCheckbox";'
    integration = _prepend_import(source.content, import_statement)
    integration = re.sub(r"(<form\b[^>]*>)", r"\1\n      <ConsentCheckbox />", integration, count=1)
    component = (
        "type ConsentCheckboxProps = { onConsentChange?: (accepted: boolean) => void };\n\n"
        if source.path.endswith(".tsx")
        else ""
    ) + (
        "export function ConsentCheckbox({ onConsentChange }: ConsentCheckboxProps) {\n"
        if source.path.endswith(".tsx")
        else "export function ConsentCheckbox({ onConsentChange }) {\n"
    ) + (
        "  return (\n"
        "    <label>\n"
        "      <input type=\"checkbox\" name=\"dataConsent\" required onChange={(event) => onConsentChange?.(event.target.checked)} />\n"
        "      I confirm that I meet the eligibility requirements and consent to the data handling described to me.\n"
        "    </label>\n"
        "  );\n"
        "}\n"
    )
    return AutoFixPlan(
        fix_type="consent_checkbox",
        label="Add this checkbox for me",
        citation=citation,
        files=(GeneratedFile(component_path, component, None), GeneratedFile(source.path, integration, source.content)),
        verification_note="No reliable isolated build or lint runner is available to Scavibe for this repository; run the repository's own checks before merging.",
    )


def _rate_limit_plan(finding: Finding, source_files: list[SourceFile]) -> AutoFixPlan:
    requirements = _manifest(source_files, "requirements.txt")
    source, citation = _source_for_finding(finding, source_files)
    text = _finding_text(finding)
    if not any(term in text for term in ("rate limit", "rate-limit", "rate limiting", "throttl")):
        raise AutoFixPlanError("the finding is not a missing rate-limiting middleware finding")
    if requirements is None or not re.search(r"(?im)^fastapi(?:[<>=!~].*)?$", requirements):
        raise AutoFixPlanError("no FastAPI framework declaration exists in supplied requirements.txt evidence")
    match = re.search(r"(?m)^(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*FastAPI\([^\n]*\)", source.content)
    if not source.path.endswith(".py") or match is None:
        raise AutoFixPlanError("the cited source is not a FastAPI application entrypoint with a safe middleware registration point")
    app_name = match.group("name")
    middleware_path = _sibling_path(source.path, "rate_limit_middleware.py")
    import_name = ".rate_limit_middleware" if str(PurePosixPath(source.path).parent) != "." else "rate_limit_middleware"
    import_statement = f"from {import_name} import RateLimitMiddleware"
    integration = _prepend_import(source.content, import_statement)
    insertion = match.group(0) + f"\n{app_name}.add_middleware(RateLimitMiddleware)"
    integration = integration.replace(match.group(0), insertion, 1)
    middleware = (
        "from collections import defaultdict, deque\n"
        "from time import monotonic\n\n"
        "from fastapi import Request\n"
        "from starlette.middleware.base import BaseHTTPMiddleware\n"
        "from starlette.responses import JSONResponse\n\n"
        f"REQUESTS_PER_MINUTE = {RATE_LIMIT_REQUESTS_PER_MINUTE}  # Conservative starting point; review for this product.\n"
        f"WINDOW_SECONDS = {RATE_LIMIT_WINDOW_SECONDS}\n"
        "_requests_by_ip: dict[str, deque[float]] = defaultdict(deque)\n\n"
        "class RateLimitMiddleware(BaseHTTPMiddleware):\n"
        "    async def dispatch(self, request: Request, call_next):\n"
        "        client_ip = request.client.host if request.client else \"unknown\"\n"
        "        now = monotonic()\n"
        "        requests = _requests_by_ip[client_ip]\n"
        "        while requests and now - requests[0] >= WINDOW_SECONDS:\n"
        "            requests.popleft()\n"
        "        if len(requests) >= REQUESTS_PER_MINUTE:\n"
        "            return JSONResponse({\"detail\": \"rate limit exceeded\"}, status_code=429)\n"
        "        requests.append(now)\n"
        "        return await call_next(request)\n"
    )
    return AutoFixPlan(
        fix_type="rate_limit_middleware",
        label="Add rate limiting for me",
        citation=citation,
        files=(GeneratedFile(middleware_path, middleware, None), GeneratedFile(source.path, integration, source.content)),
        verification_note="No reliable isolated build or lint runner is available to Scavibe for this repository; run the repository's own checks before merging.",
    )


def build_auto_fix_plan(report: AgentReport, finding_index: int, source_files: list[SourceFile]) -> AutoFixPlan:
    if not 0 <= finding_index < len(report.findings):
        raise AutoFixPlanError("finding_index is outside the report's findings list")
    finding = report.findings[finding_index]
    if report.stage == Stage.LEGAL:
        return _consent_plan(finding, source_files)
    if report.stage in {Stage.SECURITY, Stage.PERFORMANCE}:
        return _rate_limit_plan(finding, source_files)
    raise AutoFixPlanError("this stage has no bounded auto-fix pattern")
