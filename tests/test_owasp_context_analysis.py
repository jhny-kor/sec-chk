from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SHARED_PYTHON = ROOT / "platforms" / "shared" / "python"
if str(SHARED_PYTHON) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON))

from security_scanner.checks.code_patterns import check_file  # noqa: E402
from security_scanner.models import Finding, TargetConfig  # noqa: E402
from security_scanner.standards import (  # noqa: E402
    CODE_PATTERN_RULE_IDS,
    CONFIGURATION_RULE_IDS,
    DEPENDENCY_RULE_IDS,
    OWASP_ASVS_5,
    OWASP_PROACTIVE_CONTROLS,
    OWASP_TOP_10_2025,
    PREVENTION_RULE_IDS,
    SCREEN_QUALITY_RULE_IDS,
    SECRET_RULE_IDS,
    SECURITY_STANDARDS,
    SENSITIVE_COMMENT_RULE_IDS,
    WEB_VERIFIED_RULE_IDS,
)


class OwaspWholeFileContextTests(unittest.TestCase):
    def _scan(self, filename: str, content: str):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / filename
            path.write_text(content, encoding="utf-8")
            return check_file(path, TargetConfig(name="fixture", path=path.parent))

    def test_constant_variable_named_query_is_not_confirmed_as_untrusted(self) -> None:
        findings = self._scan("a.py", 'query = "SELECT 1"\ncursor.execute(query)\n')
        sql = [finding for finding in findings if finding.rule_id == "code.sql-dynamic-query"]
        self.assertTrue(all(finding.verification_status != "confirmed" for finding in sql))

    def test_unrelated_sanitizer_on_sink_line_does_not_hide_tainted_xss(self) -> None:
        findings = self._scan(
            "a.js",
            "const unsafe = location.hash;\n"
            'element.innerHTML = DOMPurify.sanitize("<b>fixed</b>") + unsafe;\n',
        )
        finding = next(item for item in findings if item.rule_id == "code.xss-dom-sink")
        self.assertEqual(finding.verification_status, "confirmed")

    def test_untrusted_deserialization_is_confirmed_from_multiline_flow(self) -> None:
        findings = self._scan(
            "a.py",
            'payload = request.get_data()\nvalue = pickle.loads(payload)\n',
        )
        finding = next(item for item in findings if item.rule_id == "code.unsafe-deserialization")
        self.assertEqual(finding.verification_status, "confirmed")

    def test_file_level_auth_and_rate_limit_controls_suppress_bootstrap_candidates(self) -> None:
        findings = self._scan(
            "a.ts",
            "const app = express();\n"
            "app.use(authenticate);\n"
            "app.use(rateLimit({ windowMs: 60000, max: 100 }));\n"
            'app.get("/api/admin/users", (req) => listUsers(req));\n',
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertNotIn("code.api-route-missing-auth", rule_ids)
        self.assertNotIn("code.api-missing-rate-limit", rule_ids)

    def test_multiline_request_body_limit_and_http_timeout_are_seen(self) -> None:
        findings = self._scan(
            "a.js",
            "app.use(express.json({\n  limit: '1mb'\n}));\n"
            "const result = axios.get(url, {\n  timeout: 5000\n});\n",
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertNotIn("code.unbounded-request-body", rule_ids)
        self.assertNotIn("code.external-api-no-timeout", rule_ids)

    def test_invalid_verification_status_fails_closed_to_review(self) -> None:
        finding = Finding(
            rule_id="code.example",
            category="code",
            severity="high",
            title="example",
            path=Path("a.py"),
            verification_status="unknown",
        )
        self.assertEqual(finding.verification_status, "needs_review")


class OwaspMappingCompletenessTests(unittest.TestCase):
    def _category(self, standard, category_id: str):
        return next(category for category in standard.categories if category.id == category_id)

    def test_top10_crypto_category_includes_source_crypto_failures(self) -> None:
        category = self._category(OWASP_TOP_10_2025, "a04-cryptographic-failures")
        expected = {
            "code.weak-hash",
            "code.insufficient-key-length",
            "code.insecure-random-security-use",
            "code.tls-certificate-verification-disabled",
            "code.password-hash-without-salt",
        }
        self.assertTrue(expected.issubset(category.rule_ids))
        self.assertIn("code", category.scanner_categories)

    def test_top10_injection_category_includes_officially_named_injection_families(self) -> None:
        category = self._category(OWASP_TOP_10_2025, "a05-injection")
        expected = {
            "code.xss-dom-sink",
            "code.sql-dynamic-query",
            "code.command-injection",
            "code.eval-user-input",
            "code.xml-injection",
            "code.ldap-injection",
            "code.http-response-splitting",
            "code.format-string-user-input",
        }
        self.assertTrue(expected.issubset(category.rule_ids))

    def test_all_source_selectable_owasp_taxonomies_remain_complete(self) -> None:
        self.assertEqual(len([c for c in OWASP_TOP_10_2025.categories if c.id != "all"]), 10)
        self.assertEqual(len([c for c in OWASP_PROACTIVE_CONTROLS.categories if c.id != "all"]), 10)
        self.assertEqual(len([c for c in OWASP_ASVS_5.categories if c.id != "all"]), 17)

    def test_every_registered_owasp_rule_id_exists_in_the_scanner_catalog(self) -> None:
        known_rule_ids = {
            *SECRET_RULE_IDS,
            *SENSITIVE_COMMENT_RULE_IDS,
            *DEPENDENCY_RULE_IDS,
            *CONFIGURATION_RULE_IDS,
            *CODE_PATTERN_RULE_IDS,
            *SCREEN_QUALITY_RULE_IDS,
            *PREVENTION_RULE_IDS,
            *WEB_VERIFIED_RULE_IDS,
        }
        unknown: list[str] = []
        for standard in SECURITY_STANDARDS:
            if not standard.id.startswith("owasp-"):
                continue
            for category in standard.categories:
                for rule_id in category.rule_ids:
                    if rule_id not in known_rule_ids:
                        unknown.append(f"{standard.id}/{category.id}: {rule_id}")
        self.assertEqual(unknown, [])


if __name__ == "__main__":
    unittest.main()
