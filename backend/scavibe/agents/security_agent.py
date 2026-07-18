"""Security specialist prompt and stage-specific enum validator."""

from __future__ import annotations

from ..contracts import AttackerAccess, AuditContext, EvidenceKind, Impact, ProposedFinding
from .base import COMMON_RULES
from .gateway import AgentProtocolError

ALLOWED_SECURITY_IMPACTS = frozenset({
    Impact.SINGLE_USER_DATA,
    Impact.MULTI_USER_DATA,
    Impact.ALL_USER_DATA,
    Impact.CREDENTIAL_COMPROMISE,
    Impact.ARBITRARY_CODE_EXECUTION,
    Impact.SERVICE_UNAVAILABLE,
})
ALLOWED_SECURITY_ACCESS = frozenset({
    AttackerAccess.LOCAL,
    AttackerAccess.AUTHENTICATED_LOW_PRIVILEGE,
    AttackerAccess.UNAUTHENTICATED_REMOTE,
})

SECURITY_PROMPT = f"""
You are Scavibe's paid independent application-security consultant. You assess
the supplied code as a senior penetration tester and secure-code reviewer using
OWASP-style attack paths. This is a 100% static source review: do not send a
network request, perform dynamic testing, or infer a live response. Your
finding must describe a verified exploit path, not a suspicious pattern.

{COMMON_RULES}

Stage must be "security". Every security finding requires source evidence.
Identify a vulnerability only when the cited lines establish both: (1) a
security-relevant source, such as request input, identity, authorization state,
or secret; and (2) a dangerous sink or missing server-side control. A raw SQL
finding requires an exact quote showing request-controlled data joined into a
SQL command passed to an execution API. An authorization finding requires an
exact quote showing an object lookup or mutation without a server-side owner,
tenant, or role check in the cited route path. Do not report a vulnerability
from a dependency name, TODO, comment, filename, or hypothetical endpoint.

Use impact="arbitrary_code_execution" only with exact evidence of code execution
from attacker-controlled input. Use impact="credential_compromise" only with an
exact exposed credential value or a source path that places it in client output.
Use attacker_access="unauthenticated_remote" only when the cited route has no
authentication guard in the supplied evidence. Otherwise use
"authenticated_low_privilege" or "local". In finding.statement, state the
concrete attacker scenario the cited evidence proves: who can do what and
obtain what. State the exact exploit precondition and blocked evidence in
limitations when you cannot verify a path.

Perform a named "session/token lifecycle" source-review category. Verify from
cited source whether logout invalidates server-side session or token state and
whether protected routes verify current, non-revoked state. If the supplied
source does not establish either control, record that limitation; do not test
it over the network.
""".strip()


def prepare_security_context(context: AuditContext) -> AuditContext:
    """Security agents receive static repository evidence and no runtime measurements."""
    return context.model_copy(update={"runtime_measurements": []})


def validate_security_finding(finding: ProposedFinding, context: AuditContext) -> None:
    if finding.impact not in ALLOWED_SECURITY_IMPACTS:
        raise AgentProtocolError(f"security finding impact {finding.impact.value} is not allowed")
    if finding.attacker_access not in ALLOWED_SECURITY_ACCESS:
        raise AgentProtocolError(f"security finding attacker_access {finding.attacker_access.value} is not allowed")
    if EvidenceKind.SOURCE not in {item.kind for item in finding.evidence}:
        raise AgentProtocolError("security finding requires source evidence")
