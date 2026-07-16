"""LLM gateway, evidence validation, and sequential audit orchestrator."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Protocol

from pydantic import ValidationError

from .contracts import (
    AgentDraft,
    AgentReport,
    AuditContext,
    AuditRun,
    Evidence,
    EvidenceKind,
    Finding,
    ProposedFinding,
    Stage,
    StageResult,
)
from .prompts import system_prompt_for
from .scoring import confidence_score, risk_score, severity_for

LEGAL_DISCLAIMER = "This is an AI-generated operational assessment, not legal advice."


class AgentProtocolError(RuntimeError):
    """Raised when an agent response fails its declared contract."""


class Gateway(Protocol):
    async def generate(self, *, system_prompt: str, input_json: str) -> str: ...


NVIDIA_NIM_BASE_URL = "https://integrate.api.nvidia.com/v1"
DEFAULT_NVIDIA_MODEL = "nvidia/llama-3.3-nemotron-super-49b-v1"


@dataclass(frozen=True)
class NvidiaNimSettings:
    """NVIDIA NIM configuration for the selected free trial endpoint.

    The default model was selected explicitly for this project on 2026-07-16.
    It remains overrideable through SCAVIBE_NVIDIA_MODEL for controlled tests.
    """

    model: str

    @classmethod
    def from_environment(cls) -> "NvidiaNimSettings":
        model = os.environ.get("SCAVIBE_NVIDIA_MODEL", DEFAULT_NVIDIA_MODEL).strip()
        if not model:
            raise RuntimeError("SCAVIBE_NVIDIA_MODEL cannot be empty")
        if not os.environ.get("NVIDIA_API_KEY", "").strip():
            raise RuntimeError("NVIDIA_API_KEY is required to run an audit")
        return cls(model=model)


class NvidiaNimGateway:
    """NVIDIA NIM's OpenAI-compatible Chat Completions adapter.

    Temperature 0.0, top_p 1.0, 4,096 completion tokens, a 60-second request
    timeout, and two SDK retries are fixed controls for reproducible test runs.
    """

    def __init__(self, settings: NvidiaNimSettings) -> None:
        self._settings = settings
        # The NVIDIA endpoint is OpenAI-compatible, so the official OpenAI SDK
        # provides the client transport without sending requests to OpenAI.
        try:
            from openai import AsyncOpenAI
        except ImportError as error:
            raise RuntimeError("openai package is required; run pip install -r requirements.txt") from error
        self._client = AsyncOpenAI(
            base_url=NVIDIA_NIM_BASE_URL,
            api_key=os.environ["NVIDIA_API_KEY"],
            max_retries=2,
            timeout=60.0,
        )

    async def generate(self, *, system_prompt: str, input_json: str) -> str:
        response = await self._client.chat.completions.create(
            model=self._settings.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": input_json},
            ],
            temperature=0.0,
            top_p=1.0,
            max_tokens=4096,
            stream=False,
        )
        content = response.choices[0].message.content if response.choices else None
        if not content:
            raise AgentProtocolError("NVIDIA NIM returned no message content")
        return content


def serialize_context(context: AuditContext) -> str:
    """Use JSON to preserve exact paths, lines, metrics, and target mode."""
    return context.model_dump_json(exclude_none=True)


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


def validate_draft(stage: Stage, draft: AgentDraft, context: AuditContext) -> AgentReport:
    """Reject unsupported findings and compute all non-subjective rankings."""
    if draft.stage != stage:
        raise AgentProtocolError(f"agent returned stage {draft.stage}, expected {stage}")
    findings: list[Finding] = []
    for proposed in draft.findings:
        for item in proposed.evidence:
            _validate_evidence(item, context)
        evidence_kinds = {item.kind for item in proposed.evidence}
        if stage == Stage.PERFORMANCE and EvidenceKind.RUNTIME not in evidence_kinds:
            raise AgentProtocolError("performance finding requires runtime evidence")
        if stage in {Stage.SECURITY, Stage.LEGAL} and EvidenceKind.SOURCE not in evidence_kinds:
            raise AgentProtocolError(f"{stage} finding requires source evidence")
        score = risk_score(proposed.impact, proposed.attacker_access)
        findings.append(
            Finding(
                **proposed.model_dump(),
                risk_score=score,
                severity=severity_for(score),
                confidence_score=confidence_score(proposed.evidence),
            )
        )
    limitations = list(draft.limitations)
    if stage == Stage.LEGAL and LEGAL_DISCLAIMER not in limitations:
        limitations.append(LEGAL_DISCLAIMER)
    return AgentReport(
        stage=stage,
        summary=draft.summary,
        findings=findings,
        limitations=limitations,
        evidence_commit_sha=context.commit_sha,
    )


class SpecialistAgent:
    def __init__(self, stage: Stage, gateway: Gateway) -> None:
        self._stage = stage
        self._gateway = gateway

    async def analyze(self, context: AuditContext) -> AgentReport:
        raw_output = await self._gateway.generate(
            system_prompt=system_prompt_for(self._stage),
            input_json=serialize_context(context),
        )
        try:
            draft = AgentDraft.model_validate(json.loads(raw_output))
        except (json.JSONDecodeError, ValidationError) as error:
            raise AgentProtocolError(f"{self._stage} response is not a valid AgentDraft: {error}") from error
        return validate_draft(self._stage, draft, context)


class AuditOrchestrator:
    """Runs performance, security, then legal; an invalid agent response halts later stages."""

    def __init__(self, gateway: Gateway) -> None:
        self._agents = {stage: SpecialistAgent(stage, gateway) for stage in Stage}

    async def run(self, context: AuditContext) -> AuditRun:
        results: list[StageResult] = []
        ordered_stages = [Stage.PERFORMANCE, Stage.SECURITY, Stage.LEGAL]
        for index, stage in enumerate(ordered_stages):
            prerequisite = self._prerequisite_reason(stage, context)
            if prerequisite:
                results.append(StageResult(stage=stage, status="blocked", reason=prerequisite))
                continue
            try:
                report = await self._agents[stage].analyze(context)
            except (AgentProtocolError, RuntimeError) as error:
                results.append(StageResult(stage=stage, status="failed", reason=str(error)))
                for later_stage in ordered_stages[index + 1 :]:
                    results.append(
                        StageResult(
                            stage=later_stage,
                            status="blocked",
                            reason=f"{stage} failed validation; later stages did not run",
                        )
                    )
                break
            results.append(StageResult(stage=stage, status="completed", report=report))
        return AuditRun(audit_id=context.audit_id, commit_sha=context.commit_sha, stage_results=results)

    @staticmethod
    def _prerequisite_reason(stage: Stage, context: AuditContext) -> str | None:
        if stage == Stage.PERFORMANCE:
            qualifying = [
                item
                for item in context.runtime_measurements
                if item.target_mode == "sandbox"
                and item.concurrent_users >= 100
                and item.duration_seconds >= 60
                and item.sample_count >= 20
            ]
            if not qualifying:
                return (
                    "performance requires at least one sandbox measurement with "
                    "100+ concurrent users, 60+ seconds, and 20+ samples"
                )
        if stage == Stage.LEGAL and not context.jurisdictions:
            return "legal requires at least one explicit jurisdiction code; none was supplied"
        return None
