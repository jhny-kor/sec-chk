from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "platforms" / "shared" / "python"))

from security_scanner.standards import SW49_CONTROLS  # noqa: E402
from security_scanner.models import ScannerConfig, TargetConfig  # noqa: E402
from security_scanner.scanner import SecurityScanner  # noqa: E402
from security_scanner.sarif_import import import_sarif, load_sarif  # noqa: E402


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
            for key in ("positive", "negative", "positive_context_files", "negative_context_files"):
                paths = row.get(key, []) if key.endswith("context_files") else [row[key]]
                for relative in paths:
                    path = (FIXTURES / relative).resolve()
                    self.assertTrue(path.is_relative_to(FIXTURES.resolve()), relative)
                    self.assertTrue(path.is_file(), relative)

    def _scan_fixture(self, row, side):
        """Scan the fixture as source, including declared cross-file context."""
        source = (FIXTURES / row[side]).resolve()
        context = [FIXTURES / relative for relative in row.get(f"{side}_context_files", ())]
        if not context:
            return SecurityScanner(ScannerConfig(
                targets=(TargetConfig(side, source),), standard="sw-dev-security-49"
            )).scan()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for path in [source, *context]:
                destination = root / path.relative_to(FIXTURES)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, destination)
            return SecurityScanner(ScannerConfig(
                targets=(TargetConfig(side, root),), standard="sw-dev-security-49"
            )).scan()

    def test_each_executable_mapping_is_exercised_by_positive_and_negative_source(self):
        """A fixture index is not coverage: execute each control's local strategy."""
        for row in self.rows:
            control = next(control for control in SW49_CONTROLS if control.official_id == row["control"])
            positive = self._scan_fixture(row, "positive")
            negative = self._scan_fixture(row, "negative")
            local_rules = {rule_id for rule_id in control.rule_ids if not rule_id.startswith("web.")}
            positive_rules = {finding.rule_id for finding in positive.findings}
            negative_rules = {finding.rule_id for finding in negative.findings}
            with self.subTest(control=row["control"]):
                if local_rules:
                    # C-01's cross-file proof is delegated to the external
                    # CodeQL strategy; a local regex must never pretend it
                    # proved the dataflow when that analyzer was not run.
                    if row["control"] == "C-01" and not (local_rules & positive_rules):
                        statuses = {
                            strategy.status
                            for strategy in positive.source_analysis.strategies
                            if strategy.official_control == row["control"]
                        }
                        self.assertIn("NOT_RUN", statuses)
                        self.assertEqual(row["expected_positive"], "VULNERABLE")
                        continue
                    self.assertTrue(
                        local_rules & positive_rules,
                        f"{row['control']} positive fixture did not exercise {sorted(local_rules)}",
                    )
                    self.assertFalse(
                        local_rules & negative_rules,
                        f"{row['control']} negative fixture triggered {sorted(local_rules & negative_rules)}",
                    )
                else:
                    self.assertEqual(row["expected_positive"], "NEEDS_REVIEW")
                    statuses = {
                        strategy.status
                        for strategy in positive.source_analysis.strategies
                        if strategy.official_control == row["control"]
                    }
                    self.assertTrue(statuses & {"NOT_RUN", "NOT_APPLICABLE", "PARTIAL"})
                    self.assertNotIn("COMPLETE", statuses)

    def test_manifest_does_not_claim_accuracy_without_execution(self):
        self.assertNotIn("accuracy", self.manifest)
        self.assertNotIn("scorecard", self.manifest)

    def test_c01_cross_file_positive_evidence_is_imported_with_trace(self):
        document = load_sarif(FIXTURES / "sarif" / "c01_cross_file_positive.sarif")
        findings, warnings = import_sarif(document, FIXTURES, {
            ("codeql", "java/null-dereference"): {
                "rule_id": "code.null-pointer-dereference",
                "verification_status": "confirmed",
                "evidence_kind": "dataflow",
                "trace_required": True,
                "analyzer_versions": ("2.26.1",),
            }
        })
        self.assertFalse(warnings)
        self.assertEqual([finding.rule_id for finding in findings], ["code.null-pointer-dereference"])
        self.assertGreaterEqual(len(findings[0].trace), 2)


if __name__ == "__main__":
    unittest.main()
