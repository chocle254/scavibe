import json
import unittest

from scavibe.agents import AgentProtocolError, AuditOrchestrator, SpecialistAgent
from scavibe.agents.base import COMMON_RULES, validate_draft
from scavibe.agents.legal_agent import LEGAL_DISCLAIMER, LEGAL_PROMPT, validate_legal_finding
from scavibe.agents.performance_agent import validate_performance_finding
from scavibe.agents.security_agent import validate_security_finding
from scavibe.agents.security_agent import SECURITY_PROMPT
from scavibe.contracts import AgentDraft, AuditContext, Stage


def context() -> AuditContext:
    return AuditContext.model_validate(
        {
            "audit_id": "audit_1234",
            "repository_url": "https://github.com/acme/storefront",
            "app_url": "https://storefront.example.com",
            "commit_sha": "a" * 40,
            "repository_paths": ["api/users.py", "README.md"],
            "source_files": [
                {
                    "path": "api/users.py",
                    "content": "def handler(request):\n    user_id = request.query['id']\n    query = \"SELECT * FROM users WHERE id = '\" + user_id + \"'\"\n    db.execute(query)\n",
                }
            ],
            "runtime_measurements": [
                {
                    "id": "load_100",
                    "target_mode": "sandbox",
                    "endpoint": "/checkout",
                    "concurrent_users": 100,
                    "duration_seconds": 60,
                    "sample_count": 200,
                    "successful_sample_count": 200,
                    "p95_latency_ms": 640,
                    "error_rate_percent": 0.4,
                }
            ],
            "jurisdictions": ["KE"],
        }
    )


class FakeGateway:
    def __init__(self) -> None:
        self._legal_calls = 0

    async def generate(self, *, system_prompt: str, input_json: str) -> str:
        if 'Stage must be "performance"' in system_prompt:
            return json.dumps(
                {
                    "stage": "performance",
                    "summary": "One sandbox latency threshold was exceeded.",
                    "findings": [
                        {
                            "title": "Checkout p95 exceeds the 500 ms threshold",
                            "statement": "At 100 concurrent users for 60 seconds across 200 samples, /checkout p95 was 640 ms; the threshold is 500 ms.",
                            "impact": "service_unavailable",
                            "attacker_access": "unauthenticated_remote",
                            "evidence": [
                                {
                                    "kind": "runtime",
                                    "statement": "Sandbox load_100 measured /checkout p95 latency.",
                                    "measurement_id": "load_100",
                                    "endpoint": "/checkout",
                                    "metric": "p95_latency_ms",
                                    "observed_value": 640,
                                    "threshold": 500,
                                }
                            ],
                            "remediation": "Profile the checkout request path and repeat the 100-user sandbox test for 60 seconds with at least 20 samples.",
                        }
                    ],
                    "limitations": [],
                }
            )
        if 'Stage must be "security"' in system_prompt:
            return json.dumps(
                {
                    "stage": "security",
                    "summary": "One raw SQL execution path is verified.",
                    "findings": [
                        {
                            "title": "Request input is concatenated into SQL",
                            "statement": "api/users.py line 3 adds request-derived user_id to a SELECT command executed at line 4.",
                            "impact": "multi_user_data",
                            "attacker_access": "unauthenticated_remote",
                            "evidence": [
                                {
                                    "kind": "source",
                                    "statement": "The query is built from request-controlled user_id.",
                                    "file_path": "api/users.py",
                                    "start_line": 3,
                                    "end_line": 3,
                                    "quote": "query = \"SELECT * FROM users WHERE id = '\" + user_id + \"'\"",
                                }
                            ],
                            "remediation": "Replace string concatenation with a parameterized query and add a regression test using a quoted identifier.",
                        }
                    ],
                    "limitations": [],
                }
            )
        legal_draft = json.dumps(
            {
                "stage": "legal",
                "summary": "No collection behavior is verified in the supplied source file.",
                "findings": [],
                "limitations": ["No supplied source evidence establishes personal-data collection."],
            }
        )
        self._legal_calls += 1
        if self._legal_calls == 1:
            return f"{legal_draft}\n{{}}"
        return f"```json\n{legal_draft}\n```"


class InvalidQuoteGateway:
    async def generate(self, *, system_prompt: str, input_json: str) -> str:
        return json.dumps(
            {
                "stage": "security",
                "summary": "A claim with invalid evidence.",
                "findings": [
                    {
                        "title": "Invalid finding must be rejected",
                        "statement": "This has an unsupported quote.",
                        "impact": "single_user_data",
                        "attacker_access": "authenticated_low_privilege",
                        "evidence": [
                            {
                                "kind": "source",
                                "statement": "This quote is not present in the source.",
                                "file_path": "api/users.py",
                                "start_line": 3,
                                "end_line": 3,
                                "quote": "not-present",
                            }
                        ],
                        "remediation": "Use a source quote that exists in the cited line range.",
                    }
                ],
                "limitations": [],
            }
        )


class QuoteMismatchThenRepairGateway:
    """Returns a schema-valid but source-invalid citation, then a valid repair."""

    def __init__(self) -> None:
        self.prompts: list[str] = []
        self.inputs: list[dict] = []

    async def generate(self, *, system_prompt: str, input_json: str) -> str:
        self.prompts.append(system_prompt)
        self.inputs.append(json.loads(input_json))
        if len(self.prompts) == 1:
            return json.dumps(
                {
                    "stage": "security",
                    "summary": "The supplied source contains a request-derived SQL construction path.",
                    "findings": [
                        {
                            "title": "Request input is concatenated into SQL",
                            "statement": "api/users.py line 3 constructs a SQL query from request-derived input.",
                            "impact": "multi_user_data",
                            "attacker_access": "unauthenticated_remote",
                            "evidence": [
                                {
                                    "kind": "source",
                                    "statement": "The query construction line uses request-derived user_id.",
                                    "file_path": "api/users.py",
                                    "start_line": 3,
                                    "end_line": 3,
                                    "quote": "SELECT * FROM users WHERE id = request_id",
                                }
                            ],
                            "remediation": "Replace the concatenated query at api/users.py line 3 with a parameterized query.",
                        }
                    ],
                    "limitations": [],
                }
            )
        return await FakeGateway().generate(system_prompt=system_prompt, input_json=input_json)


class NearMissDeepSeekGateway:
    """Reproduces the alternate JSON keys returned by the NVIDIA security fallback."""

    def __init__(self) -> None:
        self.prompts: list[str] = []

    async def generate(self, *, system_prompt: str, input_json: str) -> str:
        self.prompts.append(system_prompt)
        if len(self.prompts) == 1:
            return json.dumps(
                {
                    "stage": "security",
                    "summary": "The supplied route needs a source-evidenced security review.",
                    "findings": [
                        {
                            "statement": "api/users.py line 3 constructs SQL from request-derived user_id.",
                            "impact": "privilege_escalation",
                            "attacker_access": "unauthenticated_remote",
                            "evidence": [
                                {
                                    "type": "source",
                                    "file_path": "api/users.py",
                                    "start_line": 3,
                                    "end_line": 3,
                                    "quote": "MODEL_SOURCE_SENTINEL",
                                }
                            ],
                            "remediation": "Use a parameterized query and test a quoted identifier.",
                        }
                    ],
                    "limitations": [{"category": "source_coverage", "detail": "No absence claim is made."}],
                }
            )
        return await FakeGateway().generate(system_prompt=system_prompt, input_json=input_json)


class CapturingSecurityGateway(FakeGateway):
    def __init__(self) -> None:
        super().__init__()
        self.input_payload: dict | None = None

    async def generate(self, *, system_prompt: str, input_json: str) -> str:
        if 'Stage must be "security"' in system_prompt:
            self.input_payload = json.loads(input_json)
        return await super().generate(system_prompt=system_prompt, input_json=input_json)


class AgentTests(unittest.IsolatedAsyncioTestCase):
    async def test_specialist_report_retains_the_complete_supplied_evidence_inventory(self) -> None:
        supplied = context()
        report = await SpecialistAgent(Stage.LEGAL, FakeGateway()).analyze(supplied)

        self.assertIsNotNone(report.evidence_inventory)
        self.assertEqual(report.evidence_inventory.source_files, supplied.source_files)
        self.assertEqual(report.evidence_inventory.repository_paths, supplied.repository_paths)
        self.assertEqual(report.evidence_inventory.runtime_measurements, supplied.runtime_measurements)
        self.assertEqual(report.evidence_inventory.jurisdictions, supplied.jurisdictions)

    async def test_security_score_is_deterministic(self) -> None:
        self.assertIn('"stage", "summary", "findings", and "limitations"', SECURITY_PROMPT)
        self.assertIn('"findings" is an\narray and must be []', SECURITY_PROMPT)
        report = await SpecialistAgent(Stage.SECURITY, FakeGateway()).analyze(context())
        finding = report.findings[0]
        self.assertEqual(finding.risk_score, 80)
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.confidence_score, 35)

    async def test_security_agent_receives_no_runtime_measurements(self) -> None:
        gateway = CapturingSecurityGateway()
        await SpecialistAgent(Stage.SECURITY, gateway).analyze(context())

        self.assertIsNotNone(gateway.input_payload)
        self.assertNotIn("runtime_measurements", gateway.input_payload)
        self.assertEqual(gateway.input_payload["repository_paths"], ["api/users.py", "README.md"])
        self.assertEqual(gateway.input_payload["source_files"][0]["path"], "api/users.py")

    async def test_specialist_phase_callbacks_follow_actual_analysis_then_evidence_validation(self) -> None:
        phases: list[tuple[str, str]] = []

        async def on_phase(event_type: str, phase: str) -> None:
            phases.append((event_type, phase))

        await SpecialistAgent(Stage.SECURITY, FakeGateway()).analyze(context(), on_phase=on_phase)

        self.assertEqual(
            phases,
            [
                ("phase_started", "specialist_analysis"),
                ("phase_completed", "specialist_analysis"),
                ("phase_started", "evidence_validation"),
                ("phase_completed", "evidence_validation"),
            ],
        )

    async def test_invalid_quote_is_rejected(self) -> None:
        with self.assertRaises(AgentProtocolError):
            await SpecialistAgent(Stage.SECURITY, InvalidQuoteGateway()).analyze(context())

    async def test_security_invalid_evidence_quote_receives_repair_before_report_is_admitted(self) -> None:
        gateway = QuoteMismatchThenRepairGateway()

        report = await SpecialistAgent(Stage.SECURITY, gateway).analyze(context())

        self.assertEqual(len(report.findings), 1)
        self.assertEqual(len(gateway.prompts), 2)
        repair = gateway.prompts[1]
        self.assertIn("evidence quote does not match cited lines: api/users.py", repair)
        self.assertIn("Copy the quote byte-for-byte", repair)
        self.assertIn('"citation_repair_context"', repair)
        self.assertNotIn("AUTHORITATIVE SOURCE EXCERPT", repair)
        repair_context = gateway.inputs[1]["citation_repair_context"]
        self.assertIn("AUTHORITATIVE SOURCE EXCERPT: api/users.py lines 3-3", repair_context)
        self.assertIn(
            "query = \"SELECT * FROM users WHERE id = '\" + user_id + \"'\"",
            repair_context,
        )
        self.assertNotIn("SELECT * FROM users WHERE id = request_id", repair)

    async def test_security_near_miss_schema_receives_exact_repair_and_returns_valid_draft(self) -> None:
        gateway = NearMissDeepSeekGateway()

        report = await SpecialistAgent(Stage.SECURITY, gateway).analyze(context())

        self.assertEqual(len(report.findings), 1)
        self.assertEqual(len(gateway.prompts), 2)
        repair = gateway.prompts[1]
        self.assertIn("FORMAT REPAIR", repair)
        self.assertIn('"title"', repair)
        self.assertIn('"kind": "source"', repair)
        self.assertIn("limitations\" is an array of strings", repair)
        self.assertIn('never use "privilege_escalation"', repair)
        self.assertNotIn("MODEL_SOURCE_SENTINEL", repair)

    async def test_pipeline_runs_verified_stages_in_order(self) -> None:
        result = await AuditOrchestrator(FakeGateway()).run(context())
        self.assertEqual([item.stage for item in result.stage_results], ["performance", "security", "legal"])
        self.assertEqual([item.status for item in result.stage_results], ["completed", "completed", "completed"])
        self.assertIn("not legal advice", result.stage_results[2].report.limitations[-1])


def source_evidence() -> dict:
    return {
        "kind": "source",
        "statement": "The query contains request-derived data.",
        "file_path": "api/users.py",
        "start_line": 3,
        "end_line": 3,
        "quote": "query = \"SELECT * FROM users WHERE id = '\" + user_id + \"'\"",
    }


def runtime_evidence() -> dict:
    return {
        "kind": "runtime",
        "statement": "Sandbox load_100 measured checkout latency.",
        "measurement_id": "load_100",
        "endpoint": "/checkout",
        "metric": "p95_latency_ms",
        "observed_value": 640,
        "threshold": 500,
    }


def draft(stage: str, impact: str, attacker_access: str, evidence: dict) -> AgentDraft:
    return AgentDraft.model_validate(
        {
            "stage": stage,
            "summary": "A stage-specific validator test finding is supplied.",
            "findings": [
                {
                    "title": "Stage validator rejects an unsupported policy value",
                    "statement": "The test supplies exact evidence and an intentionally unsupported stage policy value.",
                    "impact": impact,
                    "attacker_access": attacker_access,
                    "evidence": [evidence],
                    "remediation": "Correct the stage policy value and repeat the evidence-backed analysis.",
                }
            ],
            "limitations": [],
        }
    )


class StageValidatorPolicyTests(unittest.TestCase):
    def test_common_rules_require_the_exact_task_three_remediation_boundary(self) -> None:
        self.assertIn(
            "State the exact required fix in finding.remediation — name the specific file,\n"
            "function, or configuration value that must change and describe the corrected\n"
            "behavior precisely enough for an engineer to implement it without further\n"
            "research. Never author, generate, or apply the actual code diff, configuration\n"
            "file, or pull request yourself — describe the fix, do not write it.",
            COMMON_RULES,
        )

    def test_legal_prompt_requires_implementable_recommendations_without_document_drafts(self) -> None:
        self.assertIn(
            "State finding.remediation as a specific, implementable product change tied\n"
            "to the cited evidence — e.g. 'Add an age-confirmation checkbox to the\n"
            "signup form at <file>:<line> before the account-creation call fires' or\n"
            "'This app collects <specific data field, cited> with no visible privacy\n"
            "policy link; add one before this data is collected.' Never draft the text\n"
            "of a policy, terms of service, or any legal document — recommend that the\n"
            "user adds one and describe the exact UI/process change needed.",
            LEGAL_PROMPT,
        )
    def test_performance_rejects_measurement_below_shared_qualifying_gate(self) -> None:
        original = context()
        low_load_measurement = original.runtime_measurements[0].model_copy(update={"concurrent_users": 10})
        low_load_context = original.model_copy(update={"runtime_measurements": [low_load_measurement]})
        with self.assertRaises(AgentProtocolError):
            validate_draft(
                Stage.PERFORMANCE,
                draft("performance", "service_unavailable", "unauthenticated_remote", runtime_evidence()),
                low_load_context,
                validate_performance_finding,
            )

    def test_security_rejects_none_impact(self) -> None:
        with self.assertRaises(AgentProtocolError):
            validate_draft(
                Stage.SECURITY,
                draft("security", "none", "unauthenticated_remote", source_evidence()),
                context(),
                validate_security_finding,
            )

    def test_legal_rejects_arbitrary_code_execution_impact(self) -> None:
        with self.assertRaises(AgentProtocolError):
            validate_draft(
                Stage.LEGAL,
                draft("legal", "arbitrary_code_execution", "local", source_evidence()),
                context(),
                validate_legal_finding,
                LEGAL_DISCLAIMER,
            )
