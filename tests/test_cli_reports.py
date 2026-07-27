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


class CliReportTests(unittest.TestCase):
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
            self.assertNotIn("source-detail.html", main_html)
            self.assertIn("Total findings", main_html)
            self.assertIn("Critical", main_html)
            self.assertIn("Priority action", main_html)
            self.assertIn("Source finding summary", main_html)
            self.assertIn('class="source-summary-table"', main_html)
            self.assertIn("code.sql-dynamic-query", main_html)
            self.assertIn("source.py:1", main_html)
            self.assertIn("source-main-guide-open", main_html)
            self.assertIn("OWASP ASVS 5.0", main_html)
            self.assertIn("대외 비인가", main_html)
            self.assertLess(main_html.index("대외 비인가"), main_html.index("source-main-guide-open"))
            self.assertIn("border:2px solid #ef4444", main_html)
            self.assertIn("border-radius:0", main_html)
            self.assertIn("background:none", main_html)
            detail_html = detail.read_text(encoding="utf-8")
            self.assertIn("code.sql-dynamic-query", detail_html)
            self.assertNotIn('href="source.html"', detail_html)
            self.assertIn("source-detail-guide-open", detail_html)
            self.assertIn("Analysis standards guide", detail_html)
            self.assertIn("Source Code Vulnerability Detail", detail_html)
            self.assertIn('class="finding"', detail_html)
            self.assertIn("Problem description", detail_html)
            self.assertIn("Remediation", detail_html)
            self.assertNotIn('id="settings-toggle"', detail_html)
            self.assertNotIn('id="web-scan-run"', detail_html)
            self.assertIn("대외 비인가", detail_html)
            self.assertIn("external-classification-badge", detail_html)
            self.assertLess(detail_html.index("대외 비인가"), detail_html.index('id="lang-ko"'))
            self.assertIn("border-radius: 0", detail_html)
            self.assertIn("background: none", detail_html)
            self.assertIn('source_context', detail_html)
            self.assertIn("source-code-line", detail_html)
            self.assertIn('id="location"', detail_html)
            self.assertIn("All locations", detail_html)

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
