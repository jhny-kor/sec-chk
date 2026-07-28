from __future__ import annotations

import io
import re
import sys
import tempfile
import unittest
import zipfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHARED_PYTHON = ROOT / "platforms" / "shared" / "python"
if str(SHARED_PYTHON) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON))

from security_scanner.checks import code_patterns, secrets  # noqa: E402
from security_scanner.cli import _has_failure  # noqa: E402
from security_scanner.models import DEFAULT_CATEGORIES, Finding, TargetConfig  # noqa: E402
from security_scanner.reporting import (  # noqa: E402
    build_dashboard_payload,
    render_hwpx,
    render_markdown_from_payload,
    render_xlsx,
)
from security_scanner.standards import (  # noqa: E402
    CODE_PATTERN_RULE_IDS,
    CONFIGURATION_RULE_IDS,
    DEPENDENCY_RULE_IDS,
    OWASP_TOP_10_2025,
    OWASP_PROACTIVE_CONTROLS,
    PREVENTION_RULE_IDS,
    SECRET_RULE_IDS,
    SENSITIVE_COMMENT_RULE_IDS,
    SW49_CATEGORY_EXPECTED_COUNTS,
    SW49_CONTROLS,
    SW49_STATUSES,
    SW49_SUPPORT_LEVELS,
    SW_DEV_SECURITY_49,
    WEB_VERIFIED_RULE_IDS,
    evaluate_sw49_controls,
    sw49_payload,
)

ALL_KNOWN_RULE_IDS = frozenset(
    SECRET_RULE_IDS
    + SENSITIVE_COMMENT_RULE_IDS
    + DEPENDENCY_RULE_IDS
    + CONFIGURATION_RULE_IDS
    + CODE_PATTERN_RULE_IDS
    + PREVENTION_RULE_IDS
    + WEB_VERIFIED_RULE_IDS
)

ALL_SCAN_CATEGORIES = DEFAULT_CATEGORIES

OFFICIAL_ID_RE = re.compile(r"^[ISTECPA]-\d{2}$")


def _finding(rule_id: str, category: str = "code") -> Finding:
    return Finding(
        rule_id=rule_id,
        category=category,
        severity="high",
        title="t",
        path=Path("src/app.py"),
        line=1,
        evidence="e",
    )


def _sw49_category(category_id: str):
    for category in SW_DEV_SECURITY_49.categories:
        if category.id == category_id:
            return category
    raise AssertionError(f"missing category: {category_id}")


class Sw49ControlIntegrityTests(unittest.TestCase):
    def test_sw_dev_security_has_exactly_49_controls(self) -> None:
        self.assertEqual(len(SW49_CONTROLS), 49)

    def test_source_profile_does_not_overclaim_full_automation(self) -> None:
        support_counts = Counter(control.support_level for control in SW49_CONTROLS)
        self.assertEqual(support_counts["automated"], 0)
        self.assertEqual(support_counts["partial"], 36)
        self.assertEqual(support_counts["manual-review"], 9)
        self.assertEqual(support_counts["unsupported"], 4)

    def test_sw_dev_security_category_counts(self) -> None:
        counts = Counter(control.category_id for control in SW49_CONTROLS)
        self.assertEqual(dict(counts), SW49_CATEGORY_EXPECTED_COUNTS)

    def test_official_ids_unique_and_well_formed(self) -> None:
        official_ids = [control.official_id for control in SW49_CONTROLS]
        self.assertEqual(len(official_ids), len(set(official_ids)))
        for official_id in official_ids:
            self.assertRegex(official_id, OFFICIAL_ID_RE)

    def test_control_ids_unique_and_well_formed(self) -> None:
        control_ids = [control.control_id for control in SW49_CONTROLS]
        self.assertEqual(len(control_ids), len(set(control_ids)))
        for control_id in control_ids:
            self.assertRegex(control_id, r"^sw49\.[istecpa]\d{2}$")

    def test_no_missing_official_ids(self) -> None:
        expected = {
            f"{prefix}-{index:02d}"
            for prefix, count in (("I", 17), ("S", 16), ("T", 2), ("E", 3), ("C", 5), ("P", 4), ("A", 2))
            for index in range(1, count + 1)
        }
        self.assertEqual({control.official_id for control in SW49_CONTROLS}, expected)

    def test_all_mapped_rule_ids_exist(self) -> None:
        for control in SW49_CONTROLS:
            for rule_id in control.rule_ids:
                self.assertIn(rule_id, ALL_KNOWN_RULE_IDS, f"{control.official_id} maps unknown rule {rule_id}")

    def test_support_levels_are_valid(self) -> None:
        for control in SW49_CONTROLS:
            self.assertIn(control.support_level, SW49_SUPPORT_LEVELS)

    def test_automated_and_partial_controls_have_rules(self) -> None:
        for control in SW49_CONTROLS:
            if control.support_level in ("automated", "partial"):
                self.assertTrue(control.rule_ids, f"{control.official_id} has no rules")

    def test_manual_and_unsupported_controls_have_no_local_rules(self) -> None:
        for control in SW49_CONTROLS:
            if control.support_level in ("manual-review", "unsupported"):
                self.assertFalse(control.rule_ids, f"{control.official_id} should not map rules")

    def test_titles_have_korean_and_english(self) -> None:
        for control in SW49_CONTROLS:
            self.assertTrue(control.title.get("ko"))
            self.assertTrue(control.title.get("en"))
            self.assertTrue(control.cwe_ids, f"{control.official_id} has no CWE mapping")

    def test_korean_seven_types_and_owasp_proactive_controls_are_exact_profiles(self) -> None:
        self.assertEqual(
            [category.id for category in SW_DEV_SECURITY_49.categories if category.id != "all"],
            list(SW49_CATEGORY_EXPECTED_COUNTS),
        )
        self.assertEqual(
            [category.id for category in OWASP_PROACTIVE_CONTROLS.categories if category.id != "all"],
            [f"c{index}-" + suffix for index, suffix in enumerate((
                "access-control", "cryptography", "input-exceptions", "security-start", "secure-defaults",
                "components", "digital-identity", "browser-security", "logging-monitoring", "ssrf",
            ), start=1)],
        )


class Sw49MappingCorrectionTests(unittest.TestCase):
    def test_official_guide_cwe_cross_references_are_preserved(self) -> None:
        by_id = {control.official_id: control for control in SW49_CONTROLS}
        self.assertTrue({"CWE-259", "CWE-321"}.issubset(by_id["S-06"].cwe_ids))
        self.assertIn("CWE-754", by_id["E-03"].cwe_ids)

    def test_encapsulation_no_longer_maps_unrelated_rules(self) -> None:
        rule_ids = set(_sw49_category("encapsulation").rule_ids)
        for wrong in (
            "code.wildcard-cors",
            "code.public-bind-all-interfaces",
            "code.logging-sensitive-data",
            "code.pii-logging",
        ):
            self.assertNotIn(wrong, rule_ids)

    def test_api_misuse_only_maps_official_controls(self) -> None:
        rule_ids = set(_sw49_category("api-misuse").rule_ids)
        for wrong in (
            "dependency.remote-shell-script",
            "dependency.docker-remote-shell",
            "config.docker-add-http",
            "code.eval-user-input",
            "code.unsafe-deserialization",
        ):
            self.assertNotIn(wrong, rule_ids)

    def test_unsafe_deserialization_moved_to_c05(self) -> None:
        c05 = next(control for control in SW49_CONTROLS if control.official_id == "C-05")
        self.assertIn("code.unsafe-deserialization", c05.rule_ids)
        self.assertIn("code.unsafe-deserialization", _sw49_category("code-error").rule_ids)

    def test_eval_user_input_mapped_to_i02(self) -> None:
        i02 = next(control for control in SW49_CONTROLS if control.official_id == "I-02")
        self.assertIn("code.eval-user-input", i02.rule_ids)

    def test_dangerous_c_buffer_api_mapped_to_i16_and_a02(self) -> None:
        by_id = {control.official_id: control for control in SW49_CONTROLS}
        self.assertIn("code.dangerous-c-buffer-api", by_id["I-16"].rule_ids)
        self.assertIn("code.dangerous-c-buffer-api", by_id["A-02"].rule_ids)

    def test_useful_general_rules_are_kept_in_koda(self) -> None:
        for rule_id in ("code.wildcard-cors", "code.public-bind-all-interfaces", "code.logging-sensitive-data", "code.pii-logging"):
            self.assertIn(rule_id, CODE_PATTERN_RULE_IDS)

    def test_owasp_profiles_only_absorb_rules_supported_by_official_categories(self) -> None:
        by_id = {category.id: set(category.rule_ids) for category in OWASP_TOP_10_2025.categories}
        self.assertTrue(
            {
                "code.xml-injection",
                "code.ldap-injection",
                "code.http-response-splitting",
                "code.format-string-user-input",
            }.issubset(by_id["a05-injection"])
        )
        self.assertTrue(
            {
                "code.insufficient-key-length",
                "code.insecure-random-security-use",
                "code.tls-certificate-verification-disabled",
                "code.password-hash-without-salt",
            }.issubset(by_id["a04-cryptographic-failures"])
        )
        self.assertNotIn("secret.sensitive-comment", by_id["a05-injection"])


class Sw49EvaluationTests(unittest.TestCase):
    def test_zero_findings_do_not_mark_everything_pass(self) -> None:
        results = evaluate_sw49_controls([], ALL_SCAN_CATEGORIES)
        by_id = {entry["official_id"]: entry for entry in results}
        self.assertEqual(len(results), 49)
        # unsupported controls are never PASS
        for official_id in ("C-02", "C-03", "C-04", "A-01"):
            self.assertEqual(by_id[official_id]["status"], "UNSUPPORTED")
        # manual-review controls stay NEEDS_REVIEW
        for official_id in ("S-02", "S-03", "S-09", "T-02", "P-01", "P-03", "P-04", "I-14", "I-15"):
            self.assertEqual(by_id[official_id]["status"], "NEEDS_REVIEW")
        # partial controls without findings are not PASS either
        self.assertEqual(by_id["I-16"]["status"], "NEEDS_REVIEW")

    def test_not_scanned_distinct_from_unsupported(self) -> None:
        results = evaluate_sw49_controls([], scanned_categories=())
        by_id = {entry["official_id"]: entry for entry in results}
        self.assertEqual(by_id["I-01"]["status"], "NOT_SCANNED")
        self.assertEqual(by_id["C-02"]["status"], "UNSUPPORTED")
        self.assertFalse(by_id["I-01"]["executed"])

    def test_vulnerable_when_mapped_rule_fires(self) -> None:
        findings = [_finding("code.unsafe-deserialization")]
        results = evaluate_sw49_controls(findings, ALL_SCAN_CATEGORIES)
        by_id = {entry["official_id"]: entry for entry in results}
        self.assertEqual(by_id["C-05"]["status"], "VULNERABLE")
        self.assertEqual(by_id["C-05"]["finding_count"], 1)
        self.assertEqual(by_id["C-05"]["evidence"], ["src/app.py:1"])
        # the finding must not leak into API misuse
        self.assertNotEqual(by_id["A-02"]["status"], "VULNERABLE")

    def test_null_pointer_finding_maps_to_c01(self) -> None:
        results = evaluate_sw49_controls([_finding("code.null-pointer-dereference")], ALL_SCAN_CATEGORIES)
        by_id = {entry["official_id"]: entry for entry in results}
        self.assertEqual(by_id["C-01"]["status"], "VULNERABLE")
        self.assertEqual(by_id["C-01"]["confirmed_finding_count"], 1)

    def test_review_candidate_is_not_reported_as_confirmed_violation(self) -> None:
        finding = Finding(
            rule_id="code.api-missing-rate-limit",
            category="code",
            severity="low",
            title="candidate",
            path=Path("src/app.py"),
            line=1,
            verification_status="needs_review",
            verification_note="Project-wide middleware configuration must be checked.",
        )
        by_id = {
            entry["official_id"]: entry
            for entry in evaluate_sw49_controls([finding], ALL_SCAN_CATEGORIES)
        }
        self.assertEqual(by_id["S-16"]["status"], "NEEDS_REVIEW")
        self.assertEqual(by_id["S-16"]["finding_count"], 1)
        self.assertEqual(by_id["S-16"]["confirmed_finding_count"], 0)
        self.assertEqual(by_id["S-16"]["review_finding_count"], 1)
        self.assertFalse(_has_failure([finding], "low"))

    def test_partial_control_without_confirmed_finding_stays_reviewable(self) -> None:
        results = evaluate_sw49_controls([], ALL_SCAN_CATEGORIES)
        by_id = {entry["official_id"]: entry for entry in results}
        self.assertEqual(by_id["I-01"]["status"], "NEEDS_REVIEW")
        self.assertTrue(by_id["I-01"]["executed"])

    def test_statuses_are_from_allowed_set(self) -> None:
        for entry in evaluate_sw49_controls([_finding("code.weak-hash")], ALL_SCAN_CATEGORIES):
            self.assertIn(entry["status"], SW49_STATUSES)

    def test_payload_summary_counts(self) -> None:
        payload = sw49_payload([], ALL_SCAN_CATEGORIES)
        self.assertEqual(payload["total"], 49)
        self.assertEqual(sum(payload["status_counts"].values()), 49)
        self.assertEqual(sum(payload["support_counts"].values()), 49)
        self.assertEqual(payload["status_counts"]["VULNERABLE"], 0)


class Sw49NewRuleFixtureTests(unittest.TestCase):
    def _scan(self, filename: str, content: str) -> list[Finding]:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / filename
            path.write_text(content, encoding="utf-8")
            target = TargetConfig(name="t", path=Path(tmp))
            if filename.endswith((".env",)) or content.lstrip().startswith(("#", "//")):
                return secrets.check_file(path, target) + code_patterns.check_file(path, target)
            return code_patterns.check_file(path, target) + secrets.check_file(path, target)

    def _rule_ids(self, filename: str, content: str) -> set[str]:
        return {finding.rule_id for finding in self._scan(filename, content)}

    def test_open_redirect_vulnerable_and_safe(self) -> None:
        self.assertIn("code.open-redirect-user-input", self._rule_ids("a.py", 'return redirect(request.args.get("next"))\n'))
        self.assertIn("code.open-redirect-user-input", self._rule_ids("a.js", "res.redirect(req.query.next);\n"))
        self.assertNotIn("code.open-redirect-user-input", self._rule_ids("a.py", 'return redirect(url_for("home"))\n'))
        self.assertNotIn("code.open-redirect-user-input", self._rule_ids("a.py", '# redirect(request.args.get("next"))\n'))

    def test_regex_only_candidates_are_explicitly_marked_for_review(self) -> None:
        findings = self._scan("a.py", "app = FastAPI()\n")
        finding = next(item for item in findings if item.rule_id == "code.api-missing-rate-limit")
        self.assertEqual(finding.verification_status, "needs_review")
        self.assertTrue(finding.verification_note)

    def test_rate_limit_bootstrap_is_suppressed_when_control_is_configured(self) -> None:
        content = """\
app = FastAPI()
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)
"""
        self.assertNotIn("code.api-missing-rate-limit", self._rule_ids("a.py", content))

    def test_safe_yaml_loader_and_internal_exception_logging_are_not_findings(self) -> None:
        content = """\
document = yaml.load(payload, Loader=yaml.SafeLoader)
logger.exception("request failed")
"""
        rule_ids = self._rule_ids("a.py", content)
        self.assertNotIn("code.unsafe-deserialization", rule_ids)
        self.assertNotIn("code.stack-trace-exposure", rule_ids)

    def test_multiline_sql_flow_is_confirmed_and_parameter_binding_is_safe(self) -> None:
        vulnerable = """\
user_id = request.args["id"]
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)
"""
        findings = self._scan("a.py", vulnerable)
        sql = next(item for item in findings if item.rule_id == "code.sql-dynamic-query")
        self.assertEqual(sql.line, 3)
        self.assertEqual(sql.verification_status, "confirmed")

        safe = 'cursor.execute("SELECT * FROM users WHERE id = %s", (request.args["id"],))\n'
        self.assertNotIn("code.sql-dynamic-query", self._rule_ids("a.py", safe))

    def test_multiline_xss_flow_is_confirmed_and_sanitized_flow_is_safe(self) -> None:
        vulnerable = """\
const html = location.hash;
element.innerHTML = html;
"""
        findings = self._scan("a.js", vulnerable)
        xss = next(item for item in findings if item.rule_id == "code.xss-dom-sink")
        self.assertEqual(xss.verification_status, "confirmed")

        safe = """\
const html = DOMPurify.sanitize(location.hash);
element.innerHTML = html;
"""
        self.assertNotIn("code.xss-dom-sink", self._rule_ids("a.js", safe))

        mixed = """\
const safe = DOMPurify.sanitize("<b>fixed</b>");
const tainted = location.hash;
element.innerHTML = safe + tainted;
"""
        finding = next(item for item in self._scan("a.js", mixed) if item.rule_id == "code.xss-dom-sink")
        self.assertEqual(finding.verification_status, "confirmed")

    def test_command_argument_array_without_shell_is_not_confirmed(self) -> None:
        safe = 'subprocess.run(["ping", "--", request.args["host"]], shell=False, check=True)\n'
        self.assertNotIn("code.command-injection", self._rule_ids("a.py", safe))

    def test_multiline_flows_cover_major_input_validation_controls(self) -> None:
        fixtures = {
            "code.command-injection": ("a.py", 'command = "ping " + request.args["host"]\nsubprocess.run(command, shell=True)\n'),
            "code.path-traversal": ("a.py", 'filename = request.args["file"]\nopen(filename)\n'),
            "code.eval-user-input": ("a.py", 'expression = request.args["expr"]\neval(expression)\n'),
            "code.ssrf-user-url": ("a.py", 'target_url = request.args["url"]\nrequests.get(target_url)\n'),
            "code.open-redirect-user-input": ("a.py", 'next_url = request.args["next"]\nredirect(next_url)\n'),
            "code.ldap-injection": ("a.py", 'ldap_filter = request.args["filter"]\nldap_client.search(ldap_filter)\n'),
            "code.http-response-splitting": ("a.java", 'String value = request.getParameter("value");\nresponse.setHeader("X-Value", value);\n'),
        }
        for rule_id, (filename, content) in fixtures.items():
            with self.subTest(rule_id=rule_id):
                finding = next(item for item in self._scan(filename, content) if item.rule_id == rule_id)
                self.assertEqual(finding.verification_status, "confirmed")

    def test_known_guards_stop_taint_before_major_sinks(self) -> None:
        fixtures = {
            "code.path-traversal": ("a.py", 'filename = secure_filename(request.args["file"])\nopen(filename)\n'),
            "code.ssrf-user-url": ("a.py", 'target_url = validateUrl(request.args["url"])\nrequests.get(target_url)\n'),
            "code.open-redirect-user-input": ("a.py", 'next_url = validateRedirect(request.args["next"])\nredirect(next_url)\n'),
            "code.ldap-injection": ("a.py", 'ldap_filter = escapeLdap(request.args["filter"])\nldap_client.search(ldap_filter)\n'),
            "code.http-response-splitting": ("a.java", 'String value = sanitizeHeader(request.getParameter("value"));\nresponse.setHeader("X-Value", value);\n'),
        }
        for rule_id, (filename, content) in fixtures.items():
            with self.subTest(rule_id=rule_id):
                self.assertNotIn(rule_id, self._rule_ids(filename, content))

    def test_xml_injection_vulnerable_and_safe(self) -> None:
        self.assertIn("code.xml-injection", self._rule_ids("a.py", 'doc = "<user>" + request.args.get("name")\n'))
        self.assertNotIn("code.xml-injection", self._rule_ids("a.py", 'doc = "<user>fixed</user>"\n'))

    def test_java_xxe_hardened_factory_is_not_reported(self) -> None:
        source = '''
DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
DocumentBuilder builder = dbFactory.newDocumentBuilder();
builder.parse(request.getInputStream());
'''
        self.assertNotIn("code.xml-external-entity", self._rule_ids("SafeXml.java", source))

    def test_java_xxe_full_external_entity_hardening_is_not_reported(self) -> None:
        source = '''
DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
dbFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbFactory.setXIncludeAware(false);
dbFactory.setExpandEntityReferences(false);
DocumentBuilder builder = dbFactory.newDocumentBuilder();
builder.parse(xmlInputStream);
'''
        self.assertNotIn("code.xml-external-entity", self._rule_ids("SafeXml.java", source))

    def test_java_xxe_unsafe_factory_with_untrusted_parse_is_reported(self) -> None:
        source = '''
DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = dbFactory.newDocumentBuilder();
builder.parse(request.getInputStream());
'''
        findings = [finding for finding in self._scan("UnsafeXml.java", source) if finding.rule_id == "code.xml-external-entity"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line, 4)
        self.assertIn("builder.parse", findings[0].evidence)

    def test_java_xxe_hardening_after_builder_creation_is_too_late(self) -> None:
        source = '''
DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = dbFactory.newDocumentBuilder();
dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
builder.parse(request.getInputStream());
'''
        self.assertIn("code.xml-external-entity", self._rule_ids("LateHardening.java", source))

    def test_java_xxe_ignored_configuration_failure_is_reported(self) -> None:
        source = '''
DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
try {
    dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
} catch (ParserConfigurationException ignored) {
}
DocumentBuilder builder = dbFactory.newDocumentBuilder();
builder.parse(xmlInputStream);
'''
        self.assertIn("code.xml-external-entity", self._rule_ids("IgnoredHardening.java", source))

    def test_java_xxe_fail_closed_configuration_error_is_not_reported(self) -> None:
        source = '''
DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
try {
    dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
} catch (ParserConfigurationException error) {
    throw new IllegalStateException("Secure XML parser is unavailable", error);
}
DocumentBuilder builder = dbFactory.newDocumentBuilder();
builder.parse(xmlInputStream);
'''
        self.assertNotIn("code.xml-external-entity", self._rule_ids("FailClosedHardening.java", source))

    def test_java_xxe_commented_hardening_is_not_treated_as_safe(self) -> None:
        source = '''
DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
// dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
DocumentBuilder builder = dbFactory.newDocumentBuilder();
builder.parse(request.getInputStream());
'''
        self.assertIn("code.xml-external-entity", self._rule_ids("CommentedHardening.java", source))

    def test_java_xxe_later_unsafe_override_is_reported(self) -> None:
        source = '''
DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
DocumentBuilder builder = dbFactory.newDocumentBuilder();
builder.parse(xmlInputStream);
'''
        self.assertIn("code.xml-external-entity", self._rule_ids("OverriddenHardening.java", source))

    def test_java_xxe_factory_without_parse_is_not_reported(self) -> None:
        source = "DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();\n"
        self.assertNotIn("code.xml-external-entity", self._rule_ids("FactoryOnly.java", source))

    def test_ldap_injection_vulnerable_and_safe(self) -> None:
        self.assertIn("code.ldap-injection", self._rule_ids("A.java", 'String filter = "(uid=" + userInput;\n'))
        self.assertIn("code.ldap-injection", self._rule_ids("a.py", 'conn.search_s(base, scope, "(uid=%s)" % name)\n'))
        self.assertNotIn("code.ldap-injection", self._rule_ids("A.java", 'String filter = "(uid=admin)";\n'))

    def test_http_response_splitting_vulnerable_and_safe(self) -> None:
        self.assertIn("code.http-response-splitting", self._rule_ids("A.java", 'response.setHeader("X-Name", request.getParameter("n"));\n'))
        self.assertNotIn("code.http-response-splitting", self._rule_ids("A.java", 'response.setHeader("X-Name", "fixed");\n'))

    def test_format_string_vulnerable_and_safe(self) -> None:
        self.assertIn("code.format-string-user-input", self._rule_ids("a.c", "printf(user_input);\n"))
        self.assertNotIn("code.format-string-user-input", self._rule_ids("a.c", 'printf("%s", user_input);\n'))
        self.assertNotIn("code.format-string-user-input", self._rule_ids("a.c", 'sprintf(buffer, "%d", n);\n'))
        self.assertNotIn(
            "code.format-string-user-input",
            self._rule_ids(
                "A.java",
                'private static final String KEY_PATTERN = "%s:%s";\n'
                "String key = String.format(KEY_PATTERN, serviceId, judgmentCode);\n",
            ),
        )

    def test_minified_javascript_is_not_treated_as_application_source(self) -> None:
        minified = (
            '/*! jQuery v1.9.1 */(function(e,t){var token=Math.random();'
            'try{}catch(e){};t.innerHTML=location.hash})(window,document);\n'
        )
        self.assertFalse(self._scan("jquery-1.9.1.min.js", minified))
        self.assertFalse(self._scan("jquery.min.js", minified))
        self.assertIn(
            "code.xss-dom-sink",
            self._rule_ids("bundle.min.js", "/*! React v18.3.1 */\nconst value = location.hash; target.innerHTML = value;\n"),
        )
        self.assertIn(
            "code.xss-dom-sink",
            self._rule_ids("jquery.js", "const value = location.hash; target.innerHTML = value;\n"),
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "thirdparty" / "jquery-1.9.1.js"
            path.parent.mkdir()
            path.write_text(minified, encoding="utf-8")
            self.assertFalse(code_patterns.check_file(path, TargetConfig(name="t", path=Path(tmp))))

            application_path = Path(tmp) / "thirdparty" / "application.js"
            application_path.write_text("const value = location.hash; target.innerHTML = value;\n", encoding="utf-8")
            self.assertIn(
                "code.xss-dom-sink",
                {item.rule_id for item in code_patterns.check_file(application_path, TargetConfig(name="t", path=Path(tmp)))},
            )

    def test_java_null_pointer_definite_and_nullable_candidates(self) -> None:
        definite = """\
User user = null;
user.getName();
"""
        finding = next(
            item
            for item in self._scan("NullDeref.java", definite)
            if item.rule_id == "code.null-pointer-dereference"
        )
        self.assertEqual(finding.line, 2)
        self.assertEqual(finding.verification_status, "confirmed")

        alias = """\
User user = null;
User selected = user;
selected.getName();
"""
        finding = next(
            item
            for item in self._scan("NullAlias.java", alias)
            if item.rule_id == "code.null-pointer-dereference"
        )
        self.assertEqual(finding.line, 3)
        self.assertEqual(finding.verification_status, "confirmed")

        nullable_lookup = "String name = users.get(userId).getName();\n"
        finding = next(
            item
            for item in self._scan("NullableLookup.java", nullable_lookup)
            if item.rule_id == "code.null-pointer-dereference"
        )
        self.assertEqual(finding.verification_status, "needs_review")

    def test_java_null_pointer_guards_and_non_null_wrappers_are_safe(self) -> None:
        guarded = """\
User user = null;
if (user == null) {
    return;
}
user.getName();
"""
        self.assertNotIn("code.null-pointer-dereference", self._rule_ids("Guarded.java", guarded))
        self.assertNotIn(
            "code.null-pointer-dereference",
            self._rule_ids("Required.java", "Objects.requireNonNull(users.get(userId)).getName();\n"),
        )
        self.assertNotIn(
            "code.null-pointer-dereference",
            self._rule_ids("OptionalValue.java", "users.findById(userId).orElseThrow().getName();\n"),
        )
        self.assertNotIn(
            "code.null-pointer-dereference",
            self._rule_ids(
                "NonNullBranch.java",
                "User user = users.get(userId);\nif (user != null) {\n    user.getName();\n}\n",
            ),
        )
        self.assertNotIn(
            "code.null-pointer-dereference",
            self._rule_ids(
                "SingleStatementGuard.java",
                "User user = users.get(userId);\nif (user != null)\n    user.getName();\n",
            ),
        )
        self.assertNotIn(
            "code.null-pointer-dereference",
            self._rule_ids(
                "RequiredStatement.java",
                "User user = users.get(userId);\nObjects.requireNonNull(user);\nuser.getName();\n",
            ),
        )

    def test_java_null_pointer_else_branch_and_typed_map_are_reviewed(self) -> None:
        else_branch = """\
User user = users.get(userId);
if (user != null) {
    user.getName();
} else {
    user.getName();
}
"""
        findings = [
            item for item in self._scan("ElseBranch.java", else_branch)
            if item.rule_id == "code.null-pointer-dereference"
        ]
        self.assertEqual([item.line for item in findings], [5])

        typed_map = """\
Map<String, User> entries;
User selected = entries.get(userId);
selected.getName();
"""
        finding = next(
            item for item in self._scan("TypedMap.java", typed_map)
            if item.rule_id == "code.null-pointer-dereference"
        )
        self.assertEqual(finding.line, 3)
        self.assertEqual(finding.verification_status, "needs_review")

    def test_java_null_pointer_cap_keeps_late_confirmed_finding(self) -> None:
        source = "\n".join(
            [f"users.get(id{index}).getName();" for index in range(5)]
            + ["User definite = null;", "definite.getName();"]
        )
        findings = [
            item for item in self._scan("Priority.java", source)
            if item.rule_id == "code.null-pointer-dereference"
        ]
        self.assertEqual(len(findings), 5)
        self.assertTrue(any(item.line == 7 and item.verification_status == "confirmed" for item in findings))

    def test_insufficient_key_length_vulnerable_and_safe(self) -> None:
        self.assertIn("code.insufficient-key-length", self._rule_ids("a.py", "key = RSA.generate(1024)\n"))
        self.assertNotIn("code.insufficient-key-length", self._rule_ids("a.py", "key = RSA.generate(4096)\n"))

    def test_insecure_random_vulnerable_and_safe(self) -> None:
        self.assertIn("code.insecure-random-security-use", self._rule_ids("a.js", "const token = Math.random().toString(36);\n"))
        self.assertNotIn("code.insecure-random-security-use", self._rule_ids("a.js", "const delayMs = Math.random() * 100;\n"))
        self.assertNotIn("code.insecure-random-security-use", self._rule_ids("a.py", "token = secrets.token_hex(32)\n"))

    def test_tls_verification_disabled_vulnerable_and_safe(self) -> None:
        self.assertIn("code.tls-certificate-verification-disabled", self._rule_ids("a.py", "requests.get(url, verify=False)\n"))
        self.assertIn("code.tls-certificate-verification-disabled", self._rule_ids("a.js", "https.request({ rejectUnauthorized: false });\n"))
        self.assertIn("code.tls-certificate-verification-disabled", self._rule_ids("a.go", "cfg := &tls.Config{InsecureSkipVerify: true}\n"))
        self.assertNotIn("code.tls-certificate-verification-disabled", self._rule_ids("a.py", "requests.get(url, timeout=5)\n"))

    def test_password_hash_without_salt_vulnerable_and_safe(self) -> None:
        self.assertIn("code.password-hash-without-salt", self._rule_ids("a.py", "digest = hashlib.md5(password.encode()).hexdigest()\n"))
        self.assertNotIn("code.password-hash-without-salt", self._rule_ids("a.py", "digest = hashlib.sha256(file_bytes).hexdigest()\n"))
        self.assertNotIn("code.password-hash-without-salt", self._rule_ids("a.py", "hashed = bcrypt.hashpw(password, bcrypt.gensalt())\n"))

    def test_sensitive_comment_vulnerable_safe_and_redacted(self) -> None:
        findings = self._scan("a.py", "# password = SuperSecret99Value\n")
        rule_ids = {finding.rule_id for finding in findings}
        self.assertIn("secret.sensitive-comment", rule_ids)
        for finding in findings:
            if finding.rule_id == "secret.sensitive-comment":
                self.assertNotIn("SuperSecret99Value", finding.evidence)
                self.assertEqual(finding.verification_status, "needs_review")
        # placeholder / descriptive comments do not fire
        self.assertNotIn("secret.sensitive-comment", self._rule_ids("b.py", "# password = changeme\n"))
        self.assertNotIn("secret.sensitive-comment", self._rule_ids("c.py", "# The password field is validated below.\n"))

    def test_generic_secret_assignment_is_review_only_but_provider_key_is_confirmed(self) -> None:
        generic = next(
            finding
            for finding in self._scan("a.py", 'password = "ThisMayBeOnlyFixtureData99"\n')
            if finding.rule_id == "secret.generic-assignment"
        )
        self.assertEqual(generic.verification_status, "needs_review")

        provider = next(
            finding
            for finding in self._scan("a.env", "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n")
            if finding.rule_id == "secret.aws-access-key"
        )
        self.assertEqual(provider.verification_status, "confirmed")

    def test_generic_search_api_is_not_promoted_to_ldap_injection(self) -> None:
        content = 'query = request.args["q"]\nindex.search(query)\n'
        findings = [finding for finding in self._scan("a.py", content) if finding.rule_id == "code.ldap-injection"]
        self.assertTrue(all(finding.verification_status == "needs_review" for finding in findings))

    def test_unsupported_extensions_are_skipped(self) -> None:
        self.assertFalse(self._rule_ids("a.bin", "printf(user_input);\n") & {"code.format-string-user-input"})

    def test_per_file_finding_limit_holds(self) -> None:
        content = "requests.get(url, verify=False)\n" * 10
        findings = [f for f in self._scan("a.py", content) if f.rule_id == "code.tls-certificate-verification-disabled"]
        self.assertEqual(len(findings), 5)


class Sw49ReportTests(unittest.TestCase):
    def _payload(self, findings: list[Finding]) -> dict[str, object]:
        return build_dashboard_payload(
            findings,
            ("t",),
            "ko",
            standard="sw-dev-security-49",
            scanned_categories=ALL_SCAN_CATEGORIES,
        )

    def test_markdown_includes_all_49_rows_even_with_zero_findings(self) -> None:
        report = render_markdown_from_payload(self._payload([]), "ko")
        self.assertIn("소프트웨어 개발보안 49 기준 현황", report)
        for prefix, count in (("I-", 17), ("S-", 16), ("T-", 2), ("E-", 3), ("C-", 5), ("P-", 4), ("A-", 2)):
            self.assertEqual(report.count(f"| {prefix}"), count, prefix)
        self.assertIn("전체 49개 기준의 준수를 의미하지 않습니다", report)
        self.assertIn("미지원", report)
        self.assertIn("CWE-89", report)

    def test_markdown_partial_and_unsupported_controls_are_not_shown_as_pass(self) -> None:
        report = render_markdown_from_payload(self._payload([]), "ko")
        c01_row = next(line for line in report.splitlines() if line.startswith("| C-01"))
        self.assertIn("부분 자동", c01_row)
        self.assertNotIn("통과", c01_row)
        c02_row = next(line for line in report.splitlines() if line.startswith("| C-02"))
        self.assertIn("미지원", c02_row)
        self.assertNotIn("통과", c02_row)

    def test_xlsx_and_hwpx_include_49_rows(self) -> None:
        payload = self._payload([])
        xlsx_bytes = render_xlsx(payload, "ko")
        with zipfile.ZipFile(io.BytesIO(xlsx_bytes)) as archive:
            sheet2 = archive.read("xl/worksheets/sheet2.xml").decode("utf-8")
        self.assertEqual(sheet2.count("<row "), 50)  # header + 49 controls
        self.assertIn("I-01", sheet2)
        self.assertIn("A-02", sheet2)

        hwpx_bytes = render_hwpx(payload, "ko")
        with zipfile.ZipFile(io.BytesIO(hwpx_bytes)) as archive:
            section = archive.read("Contents/section0.xml").decode("utf-8")
        for official_id in ("I-01", "S-16", "T-02", "E-03", "C-05", "P-04", "A-01"):
            self.assertIn(official_id, section)

    def test_report_formats_use_same_control_count(self) -> None:
        payload = self._payload([_finding("code.sql-dynamic-query")])
        markdown = render_markdown_from_payload(payload, "ko")
        markdown_rows = sum(1 for line in markdown.splitlines() if re.match(r"^\| [ISTECPA]-\d{2} ", line))
        xlsx_bytes = render_xlsx(payload, "ko")
        with zipfile.ZipFile(io.BytesIO(xlsx_bytes)) as archive:
            sheet2 = archive.read("xl/worksheets/sheet2.xml").decode("utf-8")
        self.assertEqual(markdown_rows, 49)
        self.assertEqual(sheet2.count("<row ") - 1, 49)

    def test_finding_counts_are_accurate_per_control(self) -> None:
        payload = self._payload([_finding("code.sql-dynamic-query"), _finding("code.sql-dynamic-query")])
        controls = payload["sw49"]["controls"]
        i01 = next(entry for entry in controls if entry["official_id"] == "I-01")
        self.assertEqual(i01["finding_count"], 2)
        self.assertEqual(i01["status"], "VULNERABLE")

    def test_other_standard_payload_has_no_sw49_table(self) -> None:
        payload = build_dashboard_payload([], (), "ko", standard="owasp-top-10-2025", scanned_categories=ALL_SCAN_CATEGORIES)
        self.assertIsNone(payload["sw49"])


if __name__ == "__main__":
    unittest.main()
