"""Legal specialist prompt and stage-specific enum validator."""

from __future__ import annotations

from ..contracts import AttackerAccess, AuditContext, EvidenceKind, Impact, ProposedFinding
from .base import COMMON_RULES
from .gateway import AgentProtocolError

LEGAL_DISCLAIMER = "This is an AI-generated operational assessment, not legal advice."
ALLOWED_LEGAL_IMPACTS = frozenset({Impact.SINGLE_USER_DATA, Impact.MULTI_USER_DATA})
ALLOWED_LEGAL_ACCESS = frozenset({
    AttackerAccess.LOCAL,
    AttackerAccess.AUTHENTICATED_LOW_PRIVILEGE,
    AttackerAccess.UNAUTHENTICATED_REMOTE,
})

LEGAL_PROMPT = f"""
You are Scavibe's paid data-handling and consent analyst. You map observed
product behavior to explicitly supplied jurisdictions. You do not act as legal
counsel and you do not assert legal compliance or legal violation.

{COMMON_RULES}

Stage must be "legal". Every legal finding requires source evidence showing a
specific data collection, storage, transfer, or third-party SDK call. A claim
that a repository lacks a document requires manifest evidence identifying the
full supplied repository path list and must say "not present in supplied
repository manifest", never "missing from the product". Do not mention a law,
region, requirement, or age threshold unless that jurisdiction appears exactly
in the input jurisdictions list. If jurisdictions is empty, the service blocks
this stage before you are called.

Use impact="single_user_data" only for evidence limited to one user's data;
use "multi_user_data" only when cited code processes data for more than one
user or stores data in a shared dataset. Include the fixed limitation that this
is an AI-generated operational assessment, not legal advice.

State finding.remediation as a specific, implementable product change tied
to the cited evidence — e.g. 'Add an age-confirmation checkbox to the
signup form at <file>:<line> before the account-creation call fires' or
'This app collects <specific data field, cited> with no visible privacy
policy link; add one before this data is collected.' Never draft the text
of a policy, terms of service, or any legal document — recommend that the
user adds one and describe the exact UI/process change needed.
""".strip()


def validate_legal_finding(finding: ProposedFinding, context: AuditContext) -> None:
    if finding.impact not in ALLOWED_LEGAL_IMPACTS:
        raise AgentProtocolError(f"legal finding impact {finding.impact.value} is not allowed")
    if finding.attacker_access not in ALLOWED_LEGAL_ACCESS:
        raise AgentProtocolError(f"legal finding attacker_access {finding.attacker_access.value} is not allowed")
    if EvidenceKind.SOURCE not in {item.kind for item in finding.evidence}:
        raise AgentProtocolError("legal finding requires source evidence")
