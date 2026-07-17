import os
import unittest
from unittest.mock import patch

from main import StageAuditRequest, audit_legal, audit_security
from scavibe.contracts import AgentReport, AuditContext, SourceFile, Stage
from scavibe.repository import RepositorySnapshot


class AuditSessionPinTests(unittest.IsolatedAsyncioTestCase):
    async def test_security_and_legal_reuse_the_same_pinned_commit_and_selected_file_count(self) -> None:
        requested_commit_overrides: list[str | None] = []
        first_head = "a" * 40
        later_head = "b" * 40

        async def fake_fetch_public_repository(**kwargs) -> RepositorySnapshot:
            requested_commit_overrides.append(kwargs.get("commit_sha_override"))
            commit_sha = kwargs.get("commit_sha_override") or (first_head if len(requested_commit_overrides) == 1 else later_head)
            context = AuditContext(
                audit_id=kwargs["audit_id"],
                repository_url=kwargs["repository_url"],
                app_url=kwargs["app_url"],
                commit_sha=commit_sha,
                source_files=[SourceFile(path="src/app.py", content="def run():\n    return 'ok'\n")],
                repository_paths=["src/app.py"],
                jurisdictions=kwargs["jurisdictions"],
                runtime_measurements=kwargs["runtime_measurements"],
            )
            return RepositorySnapshot(context=context, selected_paths=["src/app.py"], source_content_complete=True)

        async def fake_specialist_report(stage: Stage, context: AuditContext) -> AgentReport:
            return AgentReport(
                stage=stage,
                summary=f"{stage.value} report uses the supplied immutable commit evidence.",
                findings=[],
                limitations=[],
                evidence_commit_sha=context.commit_sha,
            )

        security_request = StageAuditRequest(
            repository_url="https://github.com/acme/storefront",
            app_url="https://storefront.example.com",
            audit_id="audit_session_123",
            jurisdictions=["KE"],
        )
        with (
            patch.dict(os.environ, {"SCAVIBE_AUDIT_PIN_SECRET": "x" * 32}, clear=False),
            patch("main.fetch_public_repository", new=fake_fetch_public_repository),
            patch("main._specialist_report", new=fake_specialist_report),
        ):
            security = await audit_security(security_request)
            legal = await audit_legal(
                StageAuditRequest(
                    repository_url="https://github.com/acme/storefront",
                    app_url="https://storefront.example.com",
                    audit_id=security.audit_id,
                    audit_pin=security.audit_pin,
                    jurisdictions=["KE"],
                )
            )

        self.assertEqual(security.report.evidence_commit_sha, first_head)
        self.assertEqual(legal.report.evidence_commit_sha, first_head)
        self.assertEqual(len(security.repository.selected_files), len(legal.repository.selected_files))
        self.assertEqual(requested_commit_overrides, [None, first_head])
