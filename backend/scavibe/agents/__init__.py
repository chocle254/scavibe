"""Backward-compatible public API for Scavibe audit agents."""

from __future__ import annotations

from ..contracts import Stage
from .base import SpecialistAgent
from .gateway import AgentProtocolError, NvidiaNimGateway, NvidiaNimSettings
from .legal_agent import LEGAL_DISCLAIMER, LEGAL_PROMPT, validate_legal_finding
from .orchestrator import AuditOrchestrator
from .performance_agent import PERFORMANCE_PROMPT, validate_performance_finding
from .security_agent import SECURITY_PROMPT, validate_security_finding


def stage_configuration_for(stage: Stage):
    configurations = {
        Stage.PERFORMANCE: (PERFORMANCE_PROMPT, validate_performance_finding, None),
        Stage.SECURITY: (SECURITY_PROMPT, validate_security_finding, None),
        Stage.LEGAL: (LEGAL_PROMPT, validate_legal_finding, LEGAL_DISCLAIMER),
    }
    return configurations[stage]


__all__ = [
    "AgentProtocolError",
    "AuditOrchestrator",
    "NvidiaNimGateway",
    "NvidiaNimSettings",
    "SpecialistAgent",
]
