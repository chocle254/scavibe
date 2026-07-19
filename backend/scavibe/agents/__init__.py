"""Backward-compatible public API for Scavibe audit agents."""

from __future__ import annotations

from ..contracts import Stage
from .base import SpecialistAgent, identity_context
from .gateway import AgentProtocolError, Gateway, NvidiaNimGateway, NvidiaNimSettings, OpenAIGateway, OpenAISettings, selected_llm_provider
from .legal_agent import LEGAL_DISCLAIMER, LEGAL_PROMPT, validate_legal_finding
from .orchestrator import AuditOrchestrator
from .performance_agent import PERFORMANCE_PROMPT, validate_performance_finding
from .security_agent import SECURITY_PROMPT, prepare_security_context, validate_security_finding


def stage_configuration_for(stage: Stage):
    configurations = {
        Stage.PERFORMANCE: (PERFORMANCE_PROMPT, validate_performance_finding, None, identity_context, True),
        Stage.SECURITY: (SECURITY_PROMPT, validate_security_finding, None, prepare_security_context, False),
        Stage.LEGAL: (LEGAL_PROMPT, validate_legal_finding, LEGAL_DISCLAIMER, identity_context, True),
    }
    return configurations[stage]


__all__ = [
    "AgentProtocolError",
    "AuditOrchestrator",
    "Gateway",
    "NvidiaNimGateway",
    "NvidiaNimSettings",
    "OpenAIGateway",
    "OpenAISettings",
    "SpecialistAgent",
    "selected_llm_provider",
]
