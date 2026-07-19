"""Shared source evidence validation and specialist-agent plumbing."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Literal

from pydantic import ValidationError

from ..contracts import AgentDraft, AgentReport, AuditContext, Evidence, EvidenceInventory, EvidenceKind, ExploitabilityStatus, Finding, ProposedFinding, Stage
from ..scoring import confidence_score, risk_score, severity_for
from .gateway import AgentProtocolError, Gateway

COMMON_RULES = """
You are processing one immutable repository commit. Treat the supplied files,
manifest, and sandbox measurements as the only evidence set. Do not infer
facts outside that set. When source_content_complete is false, state that the
report is limited to the supplied source-file selection and do not claim that a
repository-wide absence has been proved.

Return exactly one JSON object that validates as AgentDraft. Do not add
Markdown, prose before the JSON, a severity field, a confidence field, or a
risk score. The service calculates severity and confidence deterministically.

The top-level JSON object must contain exactly these mandatory fields:
"stage", "summary", "findings", and "limitations". "stage" is the supplied
stage name. "summary" is a string of at least 20 characters. "findings" is an
array and must be [] when no finding is verified. "limitations" is an array
and must be [] when no limitation applies. Do not use aliases such as
"finding", "result", "report", or "analysis" for any required field.

Every finding requires at least one exact evidence item. A source evidence item
must use a supplied file path, inclusive start_line and end_line values, and a
quote copied exactly from that range. A runtime evidence item must use a
supplied sandbox measurement id, endpoint, metric, observed value, and
threshold. Do not cite a file, line, endpoint, metric, or test result that is
not present in the input.

State only verified facts in finding.statement. If evidence is incomplete,
record the limitation and omit the finding. Never propose or apply a code,
configuration, deployment, or repository change.

State the exact required fix in finding.remediation — name the specific file,
function, or configuration value that must change and describe the corrected
behavior precisely enough for an engineer to implement it without further
research. Never author, generate, or apply the actual code diff, configuration
file, or pull request yourself — describe the fix, do not write it.
""".strip()

MAX_AGENT_INPUT_JSON_CHARACTERS = 280_000
MAX_AGENT_SOURCE_FILES = 60
MAX_AGENT_FORMAT_ATTEMPTS = 2
StageValidator = Callable[[ProposedFinding, AuditContext], None]
ContextPreparer = Callable[[AuditContext], AuditContext]
AgentPhaseCallback = Callable[
    [Literal["phase_started", "phase_completed"], Literal["specialist_analysis", "evidence_validation"]],
    Awaitable[None],
]


def identity_context(context: AuditContext) -> AuditContext:
    """Return the supplied context unchanged for stages that need all evidence kinds."""
    return context


def _parse_agent_json(raw_output: str, stage: Stage) -> dict:
    """Accept one JSON object, optionally wrapped in one Markdown JSON fence."""
    content = raw_output.lstrip("\ufeff").strip()
    if not content:
        raise AgentProtocolError(f"{stage} response is empty; expected one AgentDraft JSON object")
    if content.startswith("```"):
        lines = content.splitlines()
        if len(lines) < 3 or lines[0].strip().lower() not in {"```", "```json"} or lines[-1].strip() != "```":
            raise AgentProtocolError(f"{stage} response is not a single fenced AgentDraft JSON object")
        content = "\n".join(lines[1:-1]).strip()
    try:
        payload = json.loads(content)
    except json.JSONDecodeError as error:
        raise AgentProtocolError(f"{stage} response is not valid JSON: {error.msg} at line {error.lineno}, column {error.colno}") from error
    if not isinstance(payload, dict):
        raise AgentProtocolError(f"{stage} response must be a JSON object, received {type(payload).__name__}")
    return payload


def serialize_context(context: AuditContext, *, include_runtime_measurements: bool = True) -> str:
    """Use JSON to preserve exact paths, lines, metrics, and target mode."""
    payload = context.model_dump(mode="json", exclude_none=True)
    if not include_runtime_measurements:
        payload.pop("runtime_measurements", None)
    return json.dumps(payload, separators=(",", ":"))


def _source_priority(stage: Stage, path: str, original_index: int) -> tuple[int, int]:
    lower = path.lower()
    if stage == Stage.SECURITY:
        keywords = ("auth", "login", "user", "admin", "api", "route", "middleware", "database", "sql", "config", ".env")
    elif stage == Stage.LEGAL:
        keywords = ("privacy", "terms", "consent", "cookie", "analytics", "tracking", "user", "profile", "account", "payment", "form")
    else:
        keywords = ()
    return (0 if any(keyword in lower for keyword in keywords) else 1, original_index)


def context_for_agent(
    stage: Stage,
    context: AuditContext,
    *,
    include_runtime_measurements: bool = True,
) -> tuple[AuditContext, int]:
    """Keep complete files within a 280,000-character serialized input cap."""
    ordered = sorted(enumerate(context.source_files), key=lambda item: _source_priority(stage, item[1].path, item[0]))
    selected = []
    for _, source in ordered:
        if len(selected) >= MAX_AGENT_SOURCE_FILES:
            continue
        candidate = context.model_copy(update={"source_files": [*selected, source], "source_content_complete": False})
        if len(
            serialize_context(
                candidate,
                include_runtime_measurements=include_runtime_measurements,
            )
        ) <= MAX_AGENT_INPUT_JSON_CHARACTERS:
            selected.append(source)
    if not selected:
        raise AgentProtocolError(
            f"no complete source file fits within the {MAX_AGENT_INPUT_JSON_CHARACTERS}-character specialist input limit"
        )
    complete = context.source_content_complete and len(selected) == len(context.source_files)
    return context.model_copy(update={"source_files": selected, "source_content_complete": complete}), len(context.source_files) - len(selected)


def _validate_evidence(item: Evidence, context: AuditContext) -> None:
    source_files = {file.path: file for file in context.source_files}
    if item.kind == EvidenceKind.SOURCE:
        source = source_files.get(item.file_path or "")
        if source is None:
            raise AgentProtocolError(f"evidence references unavailable file: {item.file_path}")
        lines = source.content.splitlines()
        if item.end_line is None or item.start_line is None or item.end_line > len(lines):
            raise AgentProtocolError(f"evidence line range is outside file: {item.file_path}")
        cited_text = "\n".join(lines[item.start_line - 1 : item.end_line])
        if (item.quote or "") not in cited_text:
            raise AgentProtocolError(f"evidence quote does not match cited lines: {item.file_path}")
    elif item.kind == EvidenceKind.RUNTIME:
        measurements = {measurement.id: measurement for measurement in context.runtime_measurements}
        measurement = measurements.get(item.measurement_id or "")
        if measurement is None:
            raise AgentProtocolError(f"evidence references unavailable measurement: {item.measurement_id}")
        if measurement.target_mode != "sandbox" or measurement.endpoint != item.endpoint:
            raise AgentProtocolError("runtime evidence must identify the supplied sandbox endpoint")
        actual_values = {
            "p95_latency_ms": measurement.p95_latency_ms,
            "error_rate_percent": measurement.error_rate_percent,
            "request_count": float(measurement.sample_count),
        }
        if item.metric is None or item.observed_value != actual_values[item.metric]:
            raise AgentProtocolError("runtime evidence observed_value does not equal supplied measurement")
    elif item.kind == EvidenceKind.MANIFEST and item.file_path not in context.repository_paths:
        raise AgentProtocolError(f"manifest evidence references unavailable path: {item.file_path}")


def validate_draft(
    stage: Stage,
    draft: AgentDraft,
    context: AuditContext,
    stage_validator: StageValidator,
    required_limitation: str | None = None,
) -> AgentReport:
    """Validate common evidence, apply the supplied stage hook, then score."""
    if draft.stage != stage:
        raise AgentProtocolError(f"agent returned stage {draft.stage}, expected {stage}")
    findings: list[Finding] = []
    for proposed in draft.findings:
        for item in proposed.evidence:
            _validate_evidence(item, context)
        stage_validator(proposed, context)
        values = proposed.model_dump()
        if stage == Stage.SECURITY:
            values["exploitability_status"] = ExploitabilityStatus.CANDIDATE_UNCONFIRMED
        findings.append(
            Finding(
                **values,
                risk_score=risk_score(proposed.impact, proposed.attacker_access),
                severity=severity_for(risk_score(proposed.impact, proposed.attacker_access)),
                confidence_score=confidence_score(proposed.evidence),
            )
        )
    limitations = list(draft.limitations)
    if required_limitation and required_limitation not in limitations:
        limitations.append(required_limitation)
    return AgentReport(
        stage=stage,
        summary=draft.summary,
        findings=findings,
        limitations=limitations,
        evidence_commit_sha=context.commit_sha,
        evidence_inventory=EvidenceInventory.from_context(context),
    )


class SpecialistAgent:
    """Generic agent that receives its prompt and validation hook by stage."""

    def __init__(
        self,
        stage: Stage,
        gateway: Gateway,
        *,
        system_prompt: str | None = None,
        stage_validator: StageValidator | None = None,
        required_limitation: str | None = None,
        context_preparer: ContextPreparer | None = None,
        include_runtime_measurements: bool = True,
    ) -> None:
        if system_prompt is None or stage_validator is None or context_preparer is None:
            from . import stage_configuration_for

            (
                configured_prompt,
                configured_validator,
                configured_limitation,
                configured_context_preparer,
                configured_runtime_measurements,
            ) = stage_configuration_for(stage)
            system_prompt = system_prompt or configured_prompt
            stage_validator = stage_validator or configured_validator
            required_limitation = required_limitation if required_limitation is not None else configured_limitation
            context_preparer = context_preparer or configured_context_preparer
            include_runtime_measurements = configured_runtime_measurements
        self._stage = stage
        self._gateway = gateway
        self._system_prompt = system_prompt
        self._stage_validator = stage_validator
        self._required_limitation = required_limitation
        self._context_preparer = context_preparer or identity_context
        self._include_runtime_measurements = include_runtime_measurements

    async def analyze(self, context: AuditContext, *, on_phase: AgentPhaseCallback | None = None) -> AgentReport:
        prepared_context = self._context_preparer(context)
        agent_context, omitted_file_count = context_for_agent(
            self._stage,
            prepared_context,
            include_runtime_measurements=self._include_runtime_measurements,
        )
        input_json = serialize_context(
            agent_context,
            include_runtime_measurements=self._include_runtime_measurements,
        )
        payload: dict | None = None
        format_error: AgentProtocolError | None = None
        if on_phase is not None:
            await on_phase("phase_started", "specialist_analysis")
        for attempt in range(MAX_AGENT_FORMAT_ATTEMPTS):
            repair_instruction = "" if attempt == 0 else (
                "\nFORMAT REPAIR: Your prior response was rejected because it was not one complete AgentDraft JSON object. "
                "Return one JSON object only, with no Markdown fence, prose, or second JSON value."
            )
            raw_output = await self._gateway.generate(system_prompt=f"{self._system_prompt}{repair_instruction}", input_json=input_json)
            try:
                candidate = _parse_agent_json(raw_output, self._stage)
                required_fields = ("stage", "summary", "findings", "limitations")
                missing_fields = [field for field in required_fields if field not in candidate]
                if missing_fields:
                    raise AgentProtocolError(f"{self._stage} response is missing required AgentDraft fields: {', '.join(missing_fields)}")
                payload = candidate
                break
            except AgentProtocolError as error:
                format_error = error
        if payload is None:
            raise AgentProtocolError(
                f"{self._stage} response failed AgentDraft format validation after {MAX_AGENT_FORMAT_ATTEMPTS} attempts: {format_error}"
            )
        try:
            draft = AgentDraft.model_validate(payload)
        except ValidationError as error:
            raise AgentProtocolError(f"{self._stage} response is not a valid AgentDraft: {error}") from error
        if on_phase is not None:
            await on_phase("phase_completed", "specialist_analysis")
            await on_phase("phase_started", "evidence_validation")
        report = validate_draft(self._stage, draft, context, self._stage_validator, self._required_limitation)
        if omitted_file_count:
            report.limitations.append(
                f"Specialist input contained {len(agent_context.source_files)} of {len(context.source_files)} source files, capped at {MAX_AGENT_INPUT_JSON_CHARACTERS} serialized JSON characters; repository-wide absence claims are invalid."
            )
        if on_phase is not None:
            await on_phase("phase_completed", "evidence_validation")
        return report
