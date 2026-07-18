import os
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from main import StageAuditRequest, _pinned_repository_snapshot, audit_legal, audit_security
from scavibe.contracts import AgentReport, AuditContext, SourceFile, Stage
from scavibe.repository import RepositorySnapshot


class AuditSessionPinTests(unittest.IsolatedAsyncioTestCase):
    def test_audit_context_keeps_omitted_app_url_as_none(self) -> None:
        context = AuditContext(
            audit_id="audit_optional_url_123",
            repository_url="https://github.com/acme/storefront",
            app_url=None,
            commit_sha="a" * 40,
            source_files=[SourceFile(path="src/app.py", content="def run():\n    return 'ok'\n")],
            repository_paths=["src/app.py"],
        )

        self.assertIsNone(context.app_url)
        self.assertNotEqual(context.app_url, "None")

    async def test_security_and_legal_stages_accept_omitted_app_url(self) -> None:
        captured_app_urls: list[str | None] = []

        async def fake_fetch_public_repository(**kwargs) -> RepositorySnapshot:
            captured_app_urls.append(kwargs["app_url"])
            return RepositorySnapshot(
                context=AuditContext(
                    audit_id=kwargs["audit_id"],
                    repository_url=kwargs["repository_url"],
                    app_url=kwargs["app_url"],
                    commit_sha=kwargs.get("commit_sha_override") or ("a" * 40),
                    source_files=[SourceFile(path="src/app.py", content="def run():\n    return 'ok'\n")],
                    repository_paths=["src/app.py"],
                    jurisdictions=kwargs["jurisdictions"],
                    runtime_measurements=kwargs["runtime_measurements"],
                ),
                selected_paths=["src/app.py"],
                source_content_complete=True,
            )

        async def fake_specialist_report(stage: Stage, context: AuditContext) -> AgentReport:
            return AgentReport(
                stage=stage,
                summary="The stage used commit-pinned source evidence.",
                findings=[],
                limitations=[],
                evidence_commit_sha=context.commit_sha,
            )

        security_request = StageAuditRequest(
            repository_url="https://github.com/acme/storefront",
            audit_id="audit_optional_url_456",
        )
        self.assertIsNone(security_request.app_url)
        with (
            patch.dict(os.environ, {"SCAVIBE_AUDIT_PIN_SECRET": "x" * 32}, clear=False),
            patch("main.fetch_public_repository", new=fake_fetch_public_repository),
            patch("main._specialist_report", new=fake_specialist_report),
        ):
            security = await audit_security(security_request)
            legal_request = StageAuditRequest(
                repository_url="https://github.com/acme/storefront",
                audit_id=security.audit_id,
                audit_pin=security.audit_pin,
                jurisdictions=["KE"],
            )
            self.assertIsNone(legal_request.app_url)
            legal = await audit_legal(legal_request)

        self.assertEqual(security.stage, Stage.SECURITY)
        self.assertEqual(legal.stage, Stage.LEGAL)
        self.assertEqual(captured_app_urls, [None, None])

    async def test_audit_pin_rejects_transition_between_real_and_omitted_app_url(self) -> None:
        async def fake_fetch_public_repository(**kwargs) -> RepositorySnapshot:
            return RepositorySnapshot(
                context=AuditContext(
                    audit_id=kwargs["audit_id"],
                    repository_url=kwargs["repository_url"],
                    app_url=kwargs["app_url"],
                    commit_sha=kwargs.get("commit_sha_override") or ("a" * 40),
                    source_files=[SourceFile(path="src/app.py", content="def run():\n    return 'ok'\n")],
                    repository_paths=["src/app.py"],
                    jurisdictions=kwargs["jurisdictions"],
                    runtime_measurements=kwargs["runtime_measurements"],
                ),
                selected_paths=["src/app.py"],
                source_content_complete=True,
            )

        with (
            patch.dict(os.environ, {"SCAVIBE_AUDIT_PIN_SECRET": "x" * 32}, clear=False),
            patch("main.fetch_public_repository", new=fake_fetch_public_repository),
        ):
            _, audit_id, audit_pin = await _pinned_repository_snapshot(
                StageAuditRequest(
                    repository_url="https://github.com/acme/storefront",
                    app_url="https://storefront.example.com",
                    audit_id="audit_url_mismatch_123",
                ),
                [],
            )
            with self.assertRaises(HTTPException) as raised:
                await _pinned_repository_snapshot(
                    StageAuditRequest(
                        repository_url="https://github.com/acme/storefront",
                        audit_id=audit_id,
                        audit_pin=audit_pin,
                    ),
                    [],
                )

        self.assertEqual(raised.exception.status_code, 422)
        self.assertEqual(raised.exception.detail, "audit_pin app_url does not match incoming app_url")

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
