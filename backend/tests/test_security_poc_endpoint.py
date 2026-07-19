"""Endpoint boundary tests for signed-sandbox security confirmation."""

from __future__ import annotations

import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from main import VercelSandboxSecurityAuditRequest, audit_vercel_sandbox_security
from scavibe.agents.gateway import OpenAISettings
from scavibe.contracts import AuditContext, ExploitabilityStatus, SourceFile


class TwoStepGateway:
    async def generate(self, *, system_prompt: str, input_json: str) -> str:
        if 'Stage must be "security"' not in system_prompt:
            raise AssertionError("the endpoint should delegate dynamic confirmation to the dedicated safe PoC service")
        return json.dumps(
            {
                "stage": "security",
                "summary": "One source-evidenced candidate is ready for sandbox-only confirmation.",
                "findings": [
                    {
                        "title": "Profile route lacks a server-side authentication guard",
                        "statement": "api/profile.py lines 1-3 expose private_email at /profile without a server-side authentication check.",
                        "impact": "single_user_data",
                        "attacker_access": "unauthenticated_remote",
                        "evidence": [
                            {
                                "kind": "source",
                                "statement": "The profile route returns private_email without a cited authentication guard.",
                                "file_path": "api/profile.py",
                                "start_line": 1,
                                "end_line": 3,
                                "quote": '@app.get("/profile")\nasync def profile():\n    return {"private_email": current_user.email}',
                            }
                        ],
                        "remediation": "Require a verified server-side identity before this route reads or returns private profile data.",
                    }
                ],
                "limitations": [],
            }
        )

    async def aclose(self) -> None:
        return None


def pinned_context() -> AuditContext:
    return AuditContext(
        audit_id="audit_1234",
        repository_url="https://github.com/acme/example",
        app_url=None,
        commit_sha="a" * 40,
        source_files=[
            SourceFile(
                path="api/profile.py",
                content='@app.get("/profile")\nasync def profile():\n    return {"private_email": current_user.email}',
            )
        ],
        repository_paths=["api/profile.py"],
    )


class SecurityPocEndpointTests(unittest.IsolatedAsyncioTestCase):
    async def test_confirmation_uses_signed_sandbox_url_and_deletes_project(self) -> None:
        context = pinned_context()
        snapshot = SimpleNamespace(context=context, selected_paths=["api/profile.py"], source_content_complete=True)
        sandbox = SimpleNamespace(
            deployment_id="dpl_123",
            ready_state="READY",
            deployment_url="https://signed-sandbox.example.vercel.app",
            commit_sha="a" * 40,
        )
        analysis_gateway = TwoStepGateway()

        async def confirm(*, findings, sandbox_url, source_by_path, gateway):
            self.assertEqual(sandbox_url, "https://signed-sandbox.example.vercel.app")
            self.assertEqual(source_by_path, {"api/profile.py": context.source_files[0].content})
            self.assertIs(gateway, analysis_gateway)
            return [
                findings[0].model_copy(
                    update={"exploitability_status": ExploitabilityStatus.CANDIDATE_UNCONFIRMED}
                )
            ]

        with (
            patch("main._require_sandbox_access") as require_access,
            patch("main.get_sandbox", new=AsyncMock(return_value=sandbox)),
            patch("main.delete_sandbox", new=AsyncMock()) as delete_sandbox,
            patch("main._pinned_repository_snapshot", new=AsyncMock(return_value=(snapshot, "audit_1234", "pin_1234"))) as pin_snapshot,
            patch("main.OpenAISettings.from_environment", return_value=OpenAISettings(api_key="test-key")),
            patch("main.OpenAIGateway", return_value=analysis_gateway),
            patch("main.confirm_security_findings", new=confirm),
        ):
            result = await audit_vercel_sandbox_security(
                "dpl_123",
                VercelSandboxSecurityAuditRequest(
                    repository_url="https://github.com/acme/example",
                    ticket="x" * 20,
                ),
                x_scavibe_sandbox_key="test-access-key",
            )

        require_access.assert_called_once_with("test-access-key")
        pin_snapshot.assert_awaited_once()
        self.assertEqual(pin_snapshot.call_args.kwargs["initial_commit_sha"], "a" * 40)
        delete_sandbox.assert_awaited_once_with("x" * 20)
        self.assertEqual(result.report.findings[0].exploitability_status, ExploitabilityStatus.CANDIDATE_UNCONFIRMED)
        self.assertEqual(result.sandbox_teardown, "deleted")
