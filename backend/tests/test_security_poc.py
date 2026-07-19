"""Safety and evidence tests for sandbox-only security PoC confirmation."""

from __future__ import annotations

import json
import unittest

import httpx

from scavibe.contracts import AttackerAccess, Evidence, EvidenceKind, ExploitabilityStatus, Finding, Impact, Severity
from scavibe.security_poc import confirm_security_findings


class FixedGateway:
    def __init__(self, payload: dict) -> None:
        self.payload = payload

    async def generate(self, *, system_prompt: str, input_json: str) -> str:
        return json.dumps(self.payload)


def source_finding() -> Finding:
    quote = '@app.get("/profile")\nasync def profile():\n    return {"private_email": current_user.email}'
    return Finding(
        title="Unauthenticated profile data route",
        statement="The cited route returns the private_email value without a server-side authentication or ownership check.",
        impact=Impact.SINGLE_USER_DATA,
        attacker_access=AttackerAccess.UNAUTHENTICATED_REMOTE,
        evidence=[
            Evidence(
                kind=EvidenceKind.SOURCE,
                statement="The profile route returns private user data without an authentication guard.",
                file_path="api/profile.py",
                start_line=1,
                end_line=3,
                quote=quote,
            )
        ],
        remediation="Require an authenticated server-side identity before this route reads or returns private profile data.",
        risk_score=70,
        severity=Severity.HIGH,
        confidence_score=90,
        exploitability_status=ExploitabilityStatus.CANDIDATE_UNCONFIRMED,
    )


class SecurityPocTests(unittest.IsolatedAsyncioTestCase):
    async def test_source_finding_to_safe_poc_to_confirmed_result(self) -> None:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(200, text='{"private_email":"audit@example.test"}')

        gateway = FixedGateway(
            {
                "plans": [
                    {
                        "candidate_index": 0,
                        "safe_to_execute": True,
                        "request_path": "/profile",
                        "expected_status_code": 200,
                        "response_marker": "private_email",
                        "proposed_test_code": "await client.get('https://sandbox.example.vercel.app/profile')",
                        "non_execution_reason": None,
                    }
                ]
            }
        )
        findings = await confirm_security_findings(
            findings=[source_finding()],
            sandbox_url="https://sandbox.example.vercel.app",
            source_by_path={
                "api/profile.py": '@app.get("/profile")\nasync def profile():\n    return {"private_email": current_user.email}',
            },
            gateway=gateway,
            transport=httpx.MockTransport(handler),
        )

        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].method, "GET")
        self.assertEqual(str(requests[0].url), "https://sandbox.example.vercel.app/profile")
        self.assertNotIn("authorization", requests[0].headers)
        self.assertEqual(findings[0].exploitability_status, ExploitabilityStatus.CONFIRMED_EXPLOITABLE)
        self.assertIsNotNone(findings[0].poc_execution)
        execution = findings[0].poc_execution
        assert execution is not None
        self.assertEqual(execution.execution_state, "executed")
        self.assertEqual(execution.response_status_code, 200)
        self.assertIn("private_email", execution.response_excerpt or "")
        self.assertIn("client.get", execution.executed_test_code or "")

    async def test_unsafe_or_uncited_plan_is_not_sent_to_any_host(self) -> None:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(200, text="unexpected")

        gateway = FixedGateway(
            {
                "plans": [
                    {
                        "candidate_index": 0,
                        "safe_to_execute": True,
                        "request_path": "//outside.example/profile",
                        "expected_status_code": 200,
                        "response_marker": "private_email",
                        "proposed_test_code": "await client.get('https://outside.example/profile')",
                        "non_execution_reason": None,
                    }
                ]
            }
        )
        findings = await confirm_security_findings(
            findings=[source_finding()],
            sandbox_url="https://sandbox.example.vercel.app",
            source_by_path={
                "api/profile.py": '@app.get("/profile")\nasync def profile():\n    return {"private_email": current_user.email}',
            },
            gateway=gateway,
            transport=httpx.MockTransport(handler),
        )

        self.assertEqual(requests, [])
        self.assertEqual(findings[0].exploitability_status, ExploitabilityStatus.CANDIDATE_UNCONFIRMED)
        self.assertEqual(findings[0].poc_execution.execution_state, "not_executed")
        self.assertIn("rejected", findings[0].poc_execution.reason)
