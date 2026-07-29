from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SHARED_PYTHON = ROOT / "platforms" / "shared" / "python"
if str(SHARED_PYTHON) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON))

from security_scanner.standards import (  # noqa: E402
    CWE_TOP_25_2025,
    KISA_SECURE_CODING_GUIDE,
    OWASP_ASVS_5,
    OWASP_MASVS,
    OWASP_PROACTIVE_CONTROLS,
    OWASP_SAMM_2,
    OWASP_WSTG,
    SECURITY_STANDARD_IDS,
    SOURCE_STANDARD_IDS,
    SW_DEV_SECURITY_49,
    resolve_standard_selection,
    standards_payload,
)


def _leaf_categories(standard):
    return [category for category in standard.categories if category.id != "all"]


class OfficialTaxonomyTests(unittest.TestCase):
    def test_asvs_500_uses_all_official_chapters(self) -> None:
        expected = [
            ("v1-encoding-sanitization", "V1 Encoding and Sanitization"),
            ("v2-validation-business-logic", "V2 Validation and Business Logic"),
            ("v3-web-frontend-security", "V3 Web Frontend Security"),
            ("v4-api-web-service", "V4 API and Web Service"),
            ("v5-file-handling", "V5 File Handling"),
            ("v6-authentication", "V6 Authentication"),
            ("v7-session-management", "V7 Session Management"),
            ("v8-authorization", "V8 Authorization"),
            ("v9-self-contained-tokens", "V9 Self-contained Tokens"),
            ("v10-oauth-oidc", "V10 OAuth and OIDC"),
            ("v11-cryptography", "V11 Cryptography"),
            ("v12-secure-communication", "V12 Secure Communication"),
            ("v13-configuration", "V13 Configuration"),
            ("v14-data-protection", "V14 Data Protection"),
            ("v15-secure-coding-architecture", "V15 Secure Coding and Architecture"),
            ("v16-security-logging-error-handling", "V16 Security Logging and Error Handling"),
            ("v17-webrtc", "V17 WebRTC"),
        ]
        self.assertEqual(
            [(category.id, category.labels["en"]) for category in _leaf_categories(OWASP_ASVS_5)],
            expected,
        )

    def test_wstg_42_uses_all_official_test_areas(self) -> None:
        expected_ids = [
            "information-gathering",
            "configuration-deployment-management",
            "identity-management",
            "authentication",
            "authorization",
            "session-management",
            "input-validation",
            "error-handling",
            "weak-cryptography",
            "business-logic",
            "client-side",
            "api-testing",
        ]
        self.assertEqual([category.id for category in _leaf_categories(OWASP_WSTG)], expected_ids)
        self.assertNotIn("owasp-wstg", SOURCE_STANDARD_IDS)

    def test_proactive_controls_use_official_2024_names(self) -> None:
        expected = [
            "C1 Implement Access Control",
            "C2 Use Cryptography to Protect Data",
            "C3 Validate all Input & Handle Exceptions",
            "C4 Address Security from the Start",
            "C5 Secure By Default Configurations",
            "C6 Keep your Components Secure",
            "C7 Secure Digital Identities",
            "C8 Leverage Browser Security Features",
            "C9 Implement Security Logging and Monitoring",
            "C10 Stop Server Side Request Forgery",
        ]
        self.assertEqual(
            [category.labels["en"] for category in _leaf_categories(OWASP_PROACTIVE_CONTROLS)],
            expected,
        )

    def test_samm_2_uses_five_official_business_functions(self) -> None:
        self.assertEqual(
            [(category.id, category.labels["en"]) for category in _leaf_categories(OWASP_SAMM_2)],
            [
                ("governance", "Governance"),
                ("design", "Design"),
                ("implementation", "Implementation"),
                ("verification", "Verification"),
                ("operations", "Operations"),
            ],
        )

    def test_masvs_uses_official_control_groups_without_cross_group_configuration(self) -> None:
        categories = _leaf_categories(OWASP_MASVS)
        self.assertEqual(
            [(category.id, category.labels["en"]) for category in categories],
            [
                ("masvs-storage", "MASVS-STORAGE Secure Storage"),
                ("masvs-crypto", "MASVS-CRYPTO Cryptographic Functionality"),
                ("masvs-auth", "MASVS-AUTH Authentication and Authorization"),
                ("masvs-network", "MASVS-NETWORK Network Communication"),
                ("masvs-platform", "MASVS-PLATFORM Platform Interaction"),
                ("masvs-code", "MASVS-CODE Code Security and Updates"),
                ("masvs-resilience", "MASVS-RESILIENCE Reverse Engineering and Tampering Resilience"),
                ("masvs-privacy", "MASVS-PRIVACY Privacy Controls"),
            ],
        )
        crypto = next(category for category in categories if category.id == "masvs-crypto")
        self.assertNotIn("config.android-exported-component", crypto.rule_ids)
        self.assertNotIn("config.android-debuggable", crypto.rule_ids)

class CweAuthorityTests(unittest.TestCase):
    def test_cwe_top_25_2025_order_and_official_names(self) -> None:
        expected = [
            ("79", "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"),
            ("89", "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"),
            ("352", "Cross-Site Request Forgery (CSRF)"),
            ("862", "Missing Authorization"),
            ("787", "Out-of-bounds Write"),
            ("22", "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"),
            ("416", "Use After Free"),
            ("125", "Out-of-bounds Read"),
            ("78", "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"),
            ("94", "Improper Control of Generation of Code ('Code Injection')"),
            ("120", "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')"),
            ("434", "Unrestricted Upload of File with Dangerous Type"),
            ("476", "NULL Pointer Dereference"),
            ("121", "Stack-based Buffer Overflow"),
            ("502", "Deserialization of Untrusted Data"),
            ("122", "Heap-based Buffer Overflow"),
            ("863", "Incorrect Authorization"),
            ("20", "Improper Input Validation"),
            ("284", "Improper Access Control"),
            ("200", "Exposure of Sensitive Information to an Unauthorized Actor"),
            ("306", "Missing Authentication for Critical Function"),
            ("918", "Server-Side Request Forgery (SSRF)"),
            ("77", "Improper Neutralization of Special Elements used in a Command ('Command Injection')"),
            ("639", "Authorization Bypass Through User-Controlled Key"),
            ("770", "Allocation of Resources Without Limits or Throttling"),
        ]
        categories = _leaf_categories(CWE_TOP_25_2025)
        self.assertEqual(
            [
                (category.id.split("-", 2)[1], category.labels["en"].split(" ", 1)[1])
                for category in categories
            ],
            expected,
        )

    def test_indirect_buffer_api_heuristic_is_not_claimed_as_precise_memory_analysis(self) -> None:
        by_id = {category.id: category for category in _leaf_categories(CWE_TOP_25_2025)}
        for category_id in (
            "cwe-787-out-of-bounds-write",
            "cwe-125-out-of-bounds-read",
            "cwe-121-stack-buffer-overflow",
            "cwe-122-heap-buffer-overflow",
        ):
            self.assertFalse(by_id[category_id].supported)
            self.assertEqual(by_id[category_id].rule_ids, ())
        self.assertEqual(
            by_id["cwe-120-classic-buffer-overflow"].rule_ids,
            ("code.dangerous-c-buffer-api",),
        )

class KoreanAuthorityTests(unittest.TestCase):
    def test_kisa_profile_is_the_official_2021_49_control_guide(self) -> None:
        self.assertEqual(
            [category.id for category in _leaf_categories(KISA_SECURE_CODING_GUIDE)],
            [category.id for category in _leaf_categories(SW_DEV_SECURITY_49)],
        )
        self.assertNotIn("alias", KISA_SECURE_CODING_GUIDE.labels["en"].lower())
        self.assertNotIn("별칭", KISA_SECURE_CODING_GUIDE.labels["ko"])
        self.assertEqual(KISA_SECURE_CODING_GUIDE.published_on, "2021-11-30")
        self.assertEqual(KISA_SECURE_CODING_GUIDE.version, "2021")


class CurrentStandardRegistryTests(unittest.TestCase):
    def test_legacy_aliases_and_unofficial_groupings_are_removed(self) -> None:
        removed = {
            "owasp-top-10-2021",
            "cwe-sans-top-25-2025",
            "cwe",
            "ncsc-web-8",
        }
        self.assertTrue(removed.isdisjoint(SECURITY_STANDARD_IDS))
        self.assertTrue(removed.isdisjoint(SOURCE_STANDARD_IDS))
        self.assertTrue(removed.isdisjoint({entry["id"] for entry in standards_payload()}))

    def test_old_category_aliases_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "Unsupported standard category"):
            resolve_standard_selection("owasp-asvs-5", "validation")

    def test_current_source_standards_publish_issuer_and_release(self) -> None:
        by_id = {entry["id"]: entry for entry in standards_payload()}
        for standard_id in SOURCE_STANDARD_IDS:
            if standard_id == "local":
                continue
            with self.subTest(standard_id=standard_id):
                self.assertTrue(by_id[standard_id]["issuer"])
                self.assertTrue(by_id[standard_id]["published_on"])
                self.assertTrue(by_id[standard_id]["version"])


if __name__ == "__main__":
    unittest.main()
