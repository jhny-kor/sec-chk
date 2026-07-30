from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "platforms" / "shared" / "python"))

from security_scanner.standards import SW49_CONTROLS  # noqa: E402


FIXTURES = ROOT / "tests" / "fixtures" / "sw49"


class SW49AccuracyManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
        cls.rows = cls.manifest["fixtures"]

    def test_manifest_has_exactly_one_positive_negative_pair_for_each_official_control(self):
        expected = {control.official_id for control in SW49_CONTROLS}
        actual = {row["control"] for row in self.rows}
        self.assertEqual(actual, expected)
        self.assertEqual(len(self.rows), 49)
        for row in self.rows:
            self.assertTrue(row["positive"])
            self.assertTrue(row["negative"])
            self.assertIn(row["expected_positive"], {"VULNERABLE", "NEEDS_REVIEW"})
            self.assertEqual(row["expected_negative"], "clean")

    def test_manifest_fixture_paths_are_contained_and_exist(self):
        for row in self.rows:
            for key in ("positive", "negative", "context_files"):
                paths = row.get(key, []) if key == "context_files" else [row[key]]
                for relative in paths:
                    path = (FIXTURES / relative).resolve()
                    self.assertTrue(path.is_relative_to(FIXTURES.resolve()), relative)
                    self.assertTrue(path.is_file(), relative)

    def test_manifest_declares_expected_outcomes_without_claiming_measured_accuracy(self):
        self.assertNotIn("accuracy", self.manifest)
        self.assertNotIn("scorecard", self.manifest)


if __name__ == "__main__":
    unittest.main()
