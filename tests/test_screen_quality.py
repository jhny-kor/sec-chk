from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHARED_PYTHON = ROOT / "platforms" / "shared" / "python"
if str(SHARED_PYTHON) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON))

from security_scanner.models import ScannerConfig, TargetConfig
from security_scanner.scanner import SecurityScanner


class ScreenQualityTests(unittest.TestCase):
    def test_screen_quality_flags_markup_accessibility_and_exposure_risks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "index.html").write_text(
                "<html>\n"
                "<head><title>KODA</title></head>\n"
                "<body>\n"
                '  <img src="/logo.png">\n'
                '  <input id="name">\n'
                "  <button>Save</button>\n"
                '  <a href="#">Placeholder</a>\n'
                '  <script>const apiKey = "secret-123456";</script>\n'
                "  <p>Error at /var/log/app.log</p>\n"
                "</body>\n"
                "</html>\n",
                encoding="utf-8",
            )

            findings = SecurityScanner(
                ScannerConfig(targets=(TargetConfig(name="screen", path=root, categories=("screen_quality",)),))
            ).scan()
            rule_ids = {finding.rule_id for finding in findings}

            self.assertTrue(all(finding.category == "screen_quality" for finding in findings))
            self.assertIn("screen.html-lang-missing", rule_ids)
            self.assertIn("screen.viewport-missing", rule_ids)
            self.assertIn("screen.image-alt-missing", rule_ids)
            self.assertIn("screen.input-label-missing", rule_ids)
            self.assertIn("screen.button-type-missing", rule_ids)
            self.assertIn("screen.link-target-empty", rule_ids)
            self.assertIn("screen.sensitive-text-exposed", rule_ids)
            self.assertIn("screen.system-path-exposed", rule_ids)

    def test_screen_quality_includes_clx_and_js_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "form.clx").write_text("<button>Save</button>\n", encoding="utf-8")
            (root / "view.js").write_text('const apiKey = "secret-123456";\n', encoding="utf-8")

            findings = SecurityScanner(
                ScannerConfig(targets=(TargetConfig(name="screen", path=root, categories=("screen_quality",)),))
            ).scan()
            rule_ids = {finding.rule_id for finding in findings}

            self.assertIn("screen.button-type-missing", rule_ids)
            self.assertIn("screen.sensitive-text-exposed", rule_ids)


if __name__ == "__main__":
    unittest.main()
