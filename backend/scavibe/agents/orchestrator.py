"""Sequential audit orchestration and evidence prerequisites."""

from __future__ import annotations

from ..contracts import AgentReport, AuditContext, AuditRun, Stage, StageResult
from .base import SpecialistAgent
from .gateway import AgentProtocolError, Gateway
from .legal_agent import LEGAL_DISCLAIMER, LEGAL_PROMPT, validate_legal_finding
from .performance_agent import PERFORMANCE_PROMPT, validate_performance_finding
from .security_agent import SECURITY_PROMPT, prepare_security_context, validate_security_finding
from .thresholds import PERFORMANCE_MIN_CONCURRENT_USERS, PERFORMANCE_MIN_DURATION_SECONDS, PERFORMANCE_MIN_SAMPLE_COUNT


class AuditOrchestrator:
    """Runs performance, security, then legal; an invalid response halts later stages."""

    def __init__(self, gateway: Gateway) -> None:
        self._agents = {
            Stage.PERFORMANCE: SpecialistAgent(Stage.PERFORMANCE, gateway, system_prompt=PERFORMANCE_PROMPT, stage_validator=validate_performance_finding),
            Stage.SECURITY: SpecialistAgent(
                Stage.SECURITY,
                gateway,
                system_prompt=SECURITY_PROMPT,
                stage_validator=validate_security_finding,
                context_preparer=prepare_security_context,
                include_runtime_measurements=False,
            ),
            Stage.LEGAL: SpecialistAgent(Stage.LEGAL, gateway, system_prompt=LEGAL_PROMPT, stage_validator=validate_legal_finding, required_limitation=LEGAL_DISCLAIMER),
        }

    async def run(self, context: AuditContext) -> AuditRun:
        results: list[StageResult] = []
        ordered_stages = [Stage.PERFORMANCE, Stage.SECURITY, Stage.LEGAL]
        for index, stage in enumerate(ordered_stages):
            prerequisite = self._prerequisite_reason(stage, context)
            if prerequisite:
                report = None
                if stage == Stage.PERFORMANCE:
                    report = AgentReport(
                        stage=Stage.PERFORMANCE,
                        summary="No performance finding was generated because no qualifying sandbox measurement was supplied.",
                        findings=[],
                        limitations=[prerequisite],
                        evidence_commit_sha=context.commit_sha,
                    )
                results.append(StageResult(stage=stage, status="blocked", report=report, reason=prerequisite))
                continue
            try:
                report = await self._agents[stage].analyze(context)
            except (AgentProtocolError, RuntimeError) as error:
                results.append(StageResult(stage=stage, status="failed", reason=str(error)))
                for later_stage in ordered_stages[index + 1 :]:
                    results.append(StageResult(stage=later_stage, status="blocked", reason=f"{stage} failed validation; later stages did not run"))
                break
            results.append(StageResult(stage=stage, status="completed", report=report))
        return AuditRun(audit_id=context.audit_id, commit_sha=context.commit_sha, stage_results=results)

    @staticmethod
    def _prerequisite_reason(stage: Stage, context: AuditContext) -> str | None:
        if stage == Stage.PERFORMANCE:
            qualifying = [
                item for item in context.runtime_measurements
                if item.target_mode == "sandbox"
                and item.concurrent_users >= PERFORMANCE_MIN_CONCURRENT_USERS
                and item.duration_seconds >= PERFORMANCE_MIN_DURATION_SECONDS
                and item.sample_count >= PERFORMANCE_MIN_SAMPLE_COUNT
            ]
            if not qualifying:
                return (
                    f"performance measurement did not meet the qualifying gate: at least {PERFORMANCE_MIN_CONCURRENT_USERS} concurrent users, "
                    f"{PERFORMANCE_MIN_DURATION_SECONDS}+ seconds, and {PERFORMANCE_MIN_SAMPLE_COUNT}+ samples"
                )
        if stage == Stage.LEGAL and not context.jurisdictions:
            return "legal requires at least one explicit jurisdiction code; none was supplied"
        return None
