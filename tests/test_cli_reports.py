from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHARED_PYTHON = ROOT / "platforms" / "shared" / "python"
if str(SHARED_PYTHON) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON))

from security_scanner.cli import build_parser, main  # noqa: E402
from security_scanner.reporting import _render_html_main, _source_main_filter_markup  # noqa: E402


class CliReportTests(unittest.TestCase):
    def test_source_summary_groups_same_severity_and_rule_and_collapses_locations(self) -> None:
        findings = [
            {"severity": "high", "rule_id": "code.same-rule", "path": f"source-{index}.py", "line": index, "title": "같은 문제"}
            for index in range(1, 5)
        ]
        payload = {
            "summary": {"displayed_finding_count": 4, "by_severity": {"critical": 0, "high": 4, "medium": 0, "low": 0}},
            "scan": {"standard": "local", "standard_category": "all", "path": "src"},
            "standards": [{"id": "local", "labels": {"ko": "로컬 기준"}, "categories": []}],
            "findings_by_language": {"ko": findings},
            "rule_mappings": {"code.same-rule": {"mappings": [{"standard_labels": {"ko": "점검 기준명"}, "category_labels": {"ko": "매핑 항목"}}]}},
            "generated_display": "2026-07-27",
        }
        document = _render_html_main(payload, "ko", "source-detail.html") + _source_main_filter_markup(payload, "ko")
        self.assertEqual(document.count('<td><code>code.same-rule</code></td>'), 1)
        self.assertIn('data-finding-count="4"', document)
        self.assertIn("source-collapse-more", document)
        self.assertIn("더보기 (1)", document)
        self.assertIn('class="source-severity-details"', document)
        self.assertNotIn('class="source-severity-details" open', document)
        self.assertIn("점검 기준명\n매핑 항목", document)

    def test_report_samples_mark_external_distribution(self) -> None:
        samples = sorted((ROOT / "samples" / "report-designs").glob("*.html"))
        self.assertTrue(samples)
        for sample in samples:
            document = sample.read_text(encoding="utf-8")
            self.assertIn("대외 비인가", document, sample.name)
            self.assertRegex(document, r"border: ?2px solid #(ef4444|ff4d5e|b42318)", sample.name)

    def test_standard_is_selected_from_registered_profiles(self) -> None:
        args = build_parser().parse_args(
            ["scan", "--target", ".", "--standard", "sw-dev-security-49", "--standard-category", "code-error"]
        )
        self.assertEqual(args.standard, "sw-dev-security-49")
        with self.assertRaises(SystemExit):
            build_parser().parse_args(["scan", "--target", ".", "--standard", "cis-windows-benchmark"])
        with self.assertRaises(SystemExit):
            build_parser().parse_args(["scan", "--target", ".", "--standard", "not-a-standard"])
        for removed_standard in ("owasp-top-10-2021", "cwe-sans-top-25-2025", "cwe", "ncsc-web-8"):
            with self.assertRaises(SystemExit):
                build_parser().parse_args(["scan", "--target", ".", "--standard", removed_standard])

    def test_standard_help_lists_current_publication_information(self) -> None:
        help_text = build_parser()._subparsers._group_actions[0].choices["scan"].format_help()
        self.assertIn("owasp-asvs-5: OWASP ASVS 5.0", help_text)
        self.assertIn("v5.0.0", help_text)
        self.assertIn("published 2025-05-30", help_text)
        self.assertIn("kisa-secure-coding-guide", help_text)
        self.assertIn("published 2021-11-30", help_text)
        self.assertNotIn("owasp-top-10-2021", help_text)
        self.assertNotIn("cwe-sans-top-25-2025", help_text)

    def test_jar_scan_accepts_repeated_targets(self) -> None:
        args = build_parser().parse_args(
            ["jar-scan", "--target", "/srv/api", "--target", "/opt/apps"]
        )
        self.assertEqual(args.target, ["/srv/api", "/opt/apps"])
        help_text = build_parser()._subparsers._group_actions[0].choices["jar-scan"].format_help()
        self.assertIn("repeat for multiple roots", help_text)

    def test_scan_reports_accept_korean_language_only(self) -> None:
        parser = build_parser()
        self.assertEqual(parser.parse_args(["scan", "--target", "."]).language, "ko")
        self.assertEqual(parser.parse_args(["jar-scan", "--target", "."]).language, "ko")
        with self.assertRaises(SystemExit):
            parser.parse_args(["scan", "--target", ".", "--language", "en"])
        with self.assertRaises(SystemExit):
            parser.parse_args(["jar-scan", "--target", ".", "--language", "en"])

    def test_source_html_writes_main_and_detail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.py"
            source.write_text('cursor.execute("select * from users where id=" + user_id)\n', encoding="utf-8")
            output = root / "reports" / "source.html"
            exit_code = main(
                [
                    "scan",
                    "--target",
                    str(source),
                    "--standard",
                    "owasp-asvs-5",
                    "--standard-category",
                    "v2-validation-business-logic",
                    "--format",
                    "html",
                    "--output",
                    str(output),
                ]
            )
            self.assertEqual(exit_code, 0)
            detail = output.with_name("source-detail.html")
            self.assertTrue(output.is_file())
            self.assertTrue(detail.is_file())
            main_html = output.read_text(encoding="utf-8")
            self.assertIn('href="source-detail.html"', main_html)
            self.assertIn("상세 보고서 더보기", main_html)
            self.assertIn("전체 취약점", main_html)
            self.assertIn("치명", main_html)
            self.assertIn("우선 조치", main_html)
            self.assertIn("소스 취약점 요약", main_html)
            self.assertIn("max-width:1560px", main_html)
            self.assertIn('class="source-summary-table"', main_html)
            self.assertIn('class="column-resizer"', main_html)
            self.assertIn('data-column-index="4"', main_html)
            self.assertIn('class="source-criteria"', main_html)
            self.assertIn('class="source-severity-details"', main_html)
            self.assertNotIn('class="source-severity-details" open', main_html)
            self.assertIn('id="source-main-query"', main_html)
            self.assertIn('id="source-main-standard"', main_html)
            self.assertIn("심각도별 위치", main_html)
            self.assertIn("code.sql-dynamic-query", main_html)
            self.assertIn("source.py:1", main_html)
            self.assertIn("source-main-guide-open", main_html)
            self.assertIn("OWASP ASVS 5.0", main_html)
            self.assertIn("대외 비인가", main_html)
            self.assertIn('class="koda-main-classification-badge" style="order:2"', main_html)
            self.assertIn('class="standards-guide-button" type="button" style="order:1;', main_html)
            self.assertLess(main_html.index("source-main-guide-open"), main_html.index("대외 비인가"))
            self.assertIn('class="standards-guide-name" style="display:block">OWASP ASVS 5.0</strong>', main_html)
            self.assertIn('class="standards-guide-description" style="display:block;color:#60708a">', main_html)
            self.assertIn("border:2px solid #ef4444", main_html)
            self.assertIn("border-radius:0", main_html)
            self.assertIn("background:none", main_html)
            detail_html = detail.read_text(encoding="utf-8")
            self.assertIn("code.sql-dynamic-query", detail_html)
            self.assertNotIn('href="source.html"', detail_html)
            self.assertIn("source-detail-guide-open", detail_html)
            self.assertIn("분석 기준 안내", detail_html)
            self.assertIn("소스코드 취약점 상세", detail_html)
            self.assertIn('class="finding"', detail_html)
            self.assertIn("문제 설명", detail_html)
            self.assertIn("조치 방법", detail_html)
            self.assertNotIn('id="settings-toggle"', detail_html)
            self.assertNotIn('id="web-scan-run"', detail_html)
            self.assertIn("대외 비인가", detail_html)
            self.assertIn("external-classification-badge", detail_html)
            self.assertNotIn('id="lang-ko"', detail_html)
            self.assertNotIn('id="lang-en"', detail_html)
            self.assertIn("max-width:1560px", detail_html)
            self.assertIn("border-radius: 0", detail_html)
            self.assertIn("background: none", detail_html)
            self.assertIn('source_context', detail_html)
            self.assertIn("source-code-line", detail_html)
            self.assertIn('id="location"', detail_html)
            self.assertIn("전체 위치", detail_html)
            self.assertIn('<option value="critical">치명</option>', detail_html)
            self.assertIn('<option value="info">정보</option>', detail_html)
            self.assertNotIn('<option value="critical">Critical</option>', detail_html)

    def test_source_html_redacts_secret_context_and_embedded_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "secret.py"
            secret = "sk-123456789012345678901234"
            source.write_text(f'api_key = "{secret}"\n', encoding="utf-8")
            output = root / "reports" / "source.html"
            exit_code = main(
                [
                    "scan",
                    "--target",
                    str(source),
                    "--format",
                    "html",
                    "--output",
                    str(output),
                ]
            )
            self.assertEqual(exit_code, 0)
            detail_html = output.with_name("source-detail.html").read_text(encoding="utf-8")
            self.assertIn("<redacted sensitive source line>", detail_html)
            self.assertNotIn(secret, detail_html)


class WindowsAliasPackagingTests(unittest.TestCase):
    def test_windows_installer_stages_koda_alias_and_path(self) -> None:
        script = (ROOT / "platforms/windows/scripts/build-koda-windows-installer.ps1").read_text(encoding="utf-8")
        iss = (ROOT / "platforms/windows/packaging/KODA.iss").read_text(encoding="utf-8")
        self.assertIn('Join-Path $AppDistDir "koda.cmd"', script)
        self.assertIn('echo Run: koda --help', script)
        self.assertIn('Name: "{app}\\koda.cmd"', iss)
        self.assertIn("ChangesEnvironment=yes", iss)
        self.assertIn('ValueName: "Path"', iss)


class MacAppStorePackagingTests(unittest.TestCase):
    def test_java_helper_excludes_unused_dashboard_tk_modules(self) -> None:
        app_store_script = (
            ROOT / "platforms/macos/scripts/prepare-java-scan-assets.command"
        ).read_text(encoding="utf-8")
        legacy_script = (
            ROOT / "platforms/macos/scripts/build-koda-app.command"
        ).read_text(encoding="utf-8")

        for module in (
            "security_scanner.server",
            "security_scanner.app",
            "tkinter",
            "_tkinter",
        ):
            self.assertIn(f"--exclude-module {module}", app_store_script)

        self.assertIn("--hidden-import tkinter", legacy_script)
        self.assertNotIn("--exclude-module tkinter", legacy_script)


if __name__ == "__main__":
    unittest.main()
