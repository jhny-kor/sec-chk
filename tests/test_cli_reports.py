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
    def test_standard_is_selected_from_registered_profiles(self) -> None:
        args = build_parser().parse_args(
            ["scan", "--target", ".", "--standard", "sw-dev-security-49", "--standard-category", "code-error"]
        )
        self.assertEqual(args.standard, "sw-dev-security-49")
        with self.assertRaises(SystemExit):
            build_parser().parse_args(["scan", "--target", ".", "--standard", "cis-windows-benchmark"])
        with self.assertRaises(SystemExit):
            build_parser().parse_args(["scan", "--target", ".", "--standard", "not-a-standard"])

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
                    "validation",
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
            self.assertIn("source-detail.html", output.read_text(encoding="utf-8"))
            self.assertIn("code.sql-dynamic-query", detail.read_text(encoding="utf-8"))


class WindowsAliasPackagingTests(unittest.TestCase):
    def test_windows_installer_stages_koda_alias_and_path(self) -> None:
        script = (ROOT / "platforms/windows/scripts/build-koda-windows-installer.ps1").read_text(encoding="utf-8")
        iss = (ROOT / "platforms/windows/packaging/KODA.iss").read_text(encoding="utf-8")
        self.assertIn('Join-Path $AppDistDir "koda.cmd"', script)
        self.assertIn('echo Run: koda --help', script)
        self.assertIn('Name: "{app}\\koda.cmd"', iss)
        self.assertIn("ChangesEnvironment=yes", iss)
        self.assertIn('ValueName: "Path"', iss)


if __name__ == "__main__":
    unittest.main()
