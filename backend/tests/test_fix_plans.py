import unittest

from scavibe.contracts import AgentReport, AttackerAccess, Evidence, EvidenceKind, Finding, Impact, Severity, SourceFile, Stage
from scavibe.fix_plans import AutoFixPlanError, build_auto_fix_plan


def source_evidence(path: str) -> Evidence:
    return Evidence(
        kind=EvidenceKind.SOURCE,
        statement="The supplied source contains the cited entrypoint.",
        file_path=path,
        start_line=1,
        end_line=1,
        quote="export" if path.endswith(".tsx") else "from fastapi import FastAPI",
    )


def report(stage: Stage, finding: Finding) -> AgentReport:
    return AgentReport(
        stage=stage,
        summary="The supplied immutable source evidence supports one bounded source-fix plan.",
        findings=[finding],
        limitations=[],
        evidence_commit_sha="a" * 40,
    )


def finding(title: str, statement: str, remediation: str, evidence: Evidence) -> Finding:
    return Finding(
        title=title,
        statement=statement,
        remediation=remediation,
        impact=Impact.SINGLE_USER_DATA,
        attacker_access=AttackerAccess.UNAUTHENTICATED_REMOTE,
        evidence=[evidence],
        risk_score=50,
        severity=Severity.MEDIUM,
        confidence_score=35,
    )


class AutoFixPlanTests(unittest.TestCase):
    def test_checkbox_fix_plan_contains_only_new_component_and_minimal_integration_diff(self) -> None:
        source_files = [
            SourceFile(path="package.json", content='{"dependencies":{"next":"14.2.5","react":"18.3.1"}}'),
            SourceFile(path="app/signup.tsx", content='export default function Signup() { return <form action="/signup"><button>Create account</button></form>; }\n'),
        ]
        plan = build_auto_fix_plan(
            report(
                Stage.LEGAL,
                finding(
                    "Missing age-confirmation consent checkbox",
                    "app/signup.tsx allows account creation without an age confirmation checkbox.",
                    "Add a required consent checkbox before the account-creation form submits.",
                    source_evidence("app/signup.tsx"),
                ),
            ),
            0,
            source_files,
        )

        self.assertEqual(plan.fix_type, "consent_checkbox")
        self.assertEqual([file.path for file in plan.files], ["app/ConsentCheckbox.tsx", "app/signup.tsx"])
        self.assertIsNone(plan.files[0].original_content)
        self.assertEqual(plan.files[1].original_content, source_files[1].content)
        self.assertIn('import { ConsentCheckbox } from "./ConsentCheckbox";', plan.files[1].content)
        self.assertIn("<ConsentCheckbox />", plan.files[1].content)

    def test_rate_limit_fix_plan_contains_only_new_middleware_and_minimal_integration_diff(self) -> None:
        source_files = [
            SourceFile(path="requirements.txt", content="fastapi==0.111.1\n"),
            SourceFile(path="main.py", content="from fastapi import FastAPI\n\napp = FastAPI()\n"),
        ]
        plan = build_auto_fix_plan(
            report(
                Stage.SECURITY,
                finding(
                    "Missing rate-limiting middleware",
                    "main.py exposes the FastAPI entrypoint without rate limiting.",
                    "Add rate limiting middleware to the FastAPI application before requests reach handlers.",
                    source_evidence("main.py"),
                ),
            ),
            0,
            source_files,
        )

        self.assertEqual(plan.fix_type, "rate_limit_middleware")
        self.assertEqual([file.path for file in plan.files], ["rate_limit_middleware.py", "main.py"])
        self.assertIsNone(plan.files[0].original_content)
        self.assertEqual(plan.files[1].original_content, source_files[1].content)
        self.assertIn("REQUESTS_PER_MINUTE = 60", plan.files[0].content)
        self.assertIn("from rate_limit_middleware import RateLimitMiddleware", plan.files[1].content)
        self.assertIn("app.add_middleware(RateLimitMiddleware)", plan.files[1].content)

    def test_improve_performance_finding_never_has_a_fix_it_for_me_plan(self) -> None:
        source_files = [
            SourceFile(path="requirements.txt", content="fastapi==0.111.1\n"),
            SourceFile(path="main.py", content="from fastapi import FastAPI\n\napp = FastAPI()\n"),
        ]
        with self.assertRaisesRegex(AutoFixPlanError, "not a missing rate-limiting middleware"):
            build_auto_fix_plan(
                report(
                    Stage.PERFORMANCE,
                    finding(
                        "Improve performance under load",
                        "The runtime measurement exceeds the latency threshold.",
                        "Profile the route and improve performance before release.",
                        source_evidence("main.py"),
                    ),
                ),
                0,
                source_files,
            )
