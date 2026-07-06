from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

from security_scanner.reporting import render_html
from security_scanner.server import prevention_kit_payload


class PreventionKitTest(unittest.TestCase):
    def test_toolkit_writes_guardrail_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = prevention_kit_payload("toolkit", directory)
            self.assertEqual(result["action"], "toolkit")
            self.assertTrue(any(item["status"] == "written" for item in result["results"]))

    def test_ignore_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = prevention_kit_payload("ignore", directory)
            self.assertEqual(first["results"][0]["status"], "written")
            self.assertTrue(first["results"][0]["path"].endswith("koda-ignore.yml"))
            second = prevention_kit_payload("ignore", directory)
            self.assertEqual(second["results"][0]["status"], "skipped")

    def test_hook_requires_git_repo(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                prevention_kit_payload("hook", directory)
            (Path(directory) / ".git").mkdir()
            result = prevention_kit_payload("hook", directory)
            self.assertTrue(result["results"][0]["path"].endswith("pre-commit"))

    def test_unknown_action_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                prevention_kit_payload("bogus", directory)

    def test_dashboard_renders_prevention_controls(self) -> None:
        for language in ("ko", "en"):
            html = render_html([], language=language)
            self.assertIn("prevention-apply-toolkit", html)
            self.assertNotIn("__INITIAL_PREVENTION", html)
            self.assertFalse(re.search(r"__INITIAL_[A-Z_]+__", html))


if __name__ == "__main__":
    unittest.main()
