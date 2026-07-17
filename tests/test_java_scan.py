from __future__ import annotations

import json
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SHARED_PYTHON = ROOT / "platforms" / "shared" / "python"
if str(SHARED_PYTHON) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON))

from security_scanner.java_archives import scan_archives
from security_scanner.java_inventory import inventory_components
from security_scanner.java_vulnerability_scan import JavaScanOptions, run_java_scan
from security_scanner.grype_adapter import GrypeMatch, GrypeResult
from security_scanner.syft_adapter import run_syft


def _write_jar(path: Path, files: dict[str, str | bytes]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)


class JavaInventoryTests(unittest.TestCase):
    def test_manifest_only_archive_is_partial_and_requires_review(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_jar(root / "manifest.jar", {"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\nImplementation-Title: internal-lib\nImplementation-Version: 4.2\n"})
            component = inventory_components(scan_archives(root))[0]
            self.assertEqual(component.identification_source, "manifest")
            self.assertEqual(component.identity_status, "partial")
            self.assertTrue(component.manual_review_required)

    def test_maven_coordinates_and_nested_war_library_are_identified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "nested.jar"
            _write_jar(
                nested,
                {
                    "META-INF/maven/org.example/demo/pom.properties":
                    "groupId=org.example\nartifactId=demo\nversion=1.2.3\n",
                },
            )
            war = root / "service.war"
            with zipfile.ZipFile(war, "w") as archive:
                archive.writestr("WEB-INF/lib/demo-1.2.3.jar", nested.read_bytes())
            ear = root / "enterprise.ear"
            with zipfile.ZipFile(ear, "w") as archive:
                archive.writestr("lib/demo-1.2.3.jar", nested.read_bytes())

            artifacts = scan_archives(root)
            components = inventory_components(artifacts)
            purls = {component.purl for component in components}
            self.assertIn("pkg:maven/org.example/demo@1.2.3", purls)
            nested_component = next(component for component in components if component.name == "demo")
            self.assertTrue(any("service.war!/WEB-INF/lib/demo-1.2.3.jar" in location for location in nested_component.locations))
            self.assertTrue(any("enterprise.ear!/lib/demo-1.2.3.jar" in location for location in nested_component.locations))

    def test_unresolved_archive_keeps_manual_review_flag_and_duplicate_locations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "common.jar"
            _write_jar(source, {"README.txt": "no coordinates"})
            duplicate = root / "backup-common.jar"
            duplicate.write_bytes(source.read_bytes())

            components = inventory_components(scan_archives(root))
            unresolved = next(component for component in components if component.sha256)
            self.assertEqual(unresolved.identity_status, "unresolved")
            self.assertTrue(unresolved.manual_review_required)
            self.assertEqual(len(unresolved.locations), 2)

    def test_zip_path_escape_is_warned_and_not_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.jar"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("../outside.jar", b"bad")
                archive.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")

            result = scan_archives(Path(directory))
            self.assertTrue(any("unsafe ZIP path" in warning for warning in result.warnings))
            self.assertFalse((Path(directory).parent / "outside.jar").exists())

    def test_corrupt_zip_and_nested_depth_are_warnings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "corrupt.jar").write_bytes(b"not a zip")
            deep = Path(directory) / "deep.jar"
            _write_jar(deep, {"inner.txt": "x"})
            nested = Path(directory) / "nested.jar"
            with zipfile.ZipFile(nested, "w") as archive:
                archive.writestr("BOOT-INF/lib/deep.jar", deep.read_bytes())
            outer = root / "outer.jar"
            with zipfile.ZipFile(outer, "w") as archive:
                archive.writestr("BOOT-INF/lib/inner.jar", nested.read_bytes())
            result = scan_archives(root, max_depth=1)
            self.assertTrue(any("Corrupt ZIP" in warning for warning in result.warnings))
            self.assertTrue(any("Maximum nested archive depth" in warning for warning in result.warnings))

    def test_spring_boot_fat_jar_library_is_inventoried(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "spring-core.jar"
            _write_jar(nested, {"META-INF/maven/org.springframework/spring-core/pom.properties": "groupId=org.springframework\nartifactId=spring-core\nversion=6.1.0\n"})
            with zipfile.ZipFile(root / "application.jar", "w") as archive:
                archive.writestr("BOOT-INF/lib/spring-core-6.1.0.jar", nested.read_bytes())

            components = inventory_components(scan_archives(root))
            self.assertIn("pkg:maven/org.springframework/spring-core@6.1.0", {component.purl for component in components})


class JavaScanTests(unittest.TestCase):
    def test_offline_run_writes_all_reports_and_combines_local_feeds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "app"
            target.mkdir()
            jar = target / "log4j-core.jar"
            _write_jar(
                jar,
                {
                    "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties":
                    "groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n",
                },
            )
            nvd = root / "nvd.json"
            nvd.write_text(
                json.dumps(
                    {
                        "lastModifiedDate": "2026-07-15T00:00:00.000Z",
                        "vulnerabilities": [
                            {
                                "cve": {
                                    "id": "CVE-2021-44228",
                                    "published": "2021-12-10T00:00:00.000Z",
                                    "lastModified": "2026-07-15T00:00:00.000Z",
                                    "descriptions": [{"lang": "en", "value": "JNDI injection"}],
                                    "metrics": {
                                        "cvssMetricV31": [
                                            {"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL", "vectorString": "AV:N"}}
                                        ]
                                    },
                                }
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            kev = root / "kev.json"
            kev.write_text(
                json.dumps(
                    {
                        "catalogVersion": "2026.07.15",
                        "dateReleased": "2026-07-15",
                        "vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", "dueDate": "2022-01-10", "requiredAction": "Patch", "knownRansomwareCampaignUse": "Known"}],
                    }
                ),
                encoding="utf-8",
            )
            fake_grype = root / "grype"
            fake_grype.write_text("#!/bin/sh\n", encoding="utf-8")
            fake_grype.chmod(fake_grype.stat().st_mode | stat.S_IXUSR)

            grype_payload = {
                "descriptor": {"version": "0.80.0"},
                "matches": [
                    {
                        "vulnerability": {"id": "GHSA-test", "severity": "critical", "fix": {"versions": ["2.17.1"]}},
                        "relatedVulnerabilities": [{"id": "CVE-2021-44228"}],
                        "artifact": {"name": "log4j-core", "version": "2.14.1", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "locations": [{"path": str(jar)}]},
                    }
                ],
            }
            with patch("security_scanner.grype_adapter.subprocess.run") as run:
                run.side_effect = [
                    type("Completed", (), {"returncode": 0, "stdout": "grype 0.80.0", "stderr": ""})(),
                    type("Completed", (), {"returncode": 0, "stdout": json.dumps({"database": {"built": "2026-07-15T00:00:00Z"}}), "stderr": ""})(),
                    type("Completed", (), {"returncode": 0, "stdout": json.dumps(grype_payload), "stderr": ""})(),
                ]
                result = run_java_scan(
                    JavaScanOptions(
                        target=target,
                        output_dir=root / "reports",
                        grype_bin=fake_grype,
                        nvd_data=nvd,
                        cisa_kev=kev,
                        language="ko",
                        fail_on="high",
                    )
                )

            self.assertEqual(result.exit_code, 1)
            self.assertEqual(len(result.vulnerabilities), 1)
            vulnerability = result.vulnerabilities[0]
            self.assertTrue(vulnerability.known_exploited)
            self.assertEqual(vulnerability.cisa_kev["kev_date_added"], "2021-12-10")
            self.assertEqual(vulnerability.cisa_kev["kev_required_action"], "Patch")
            self.assertTrue((root / "reports/server-sbom.cdx.json").exists())
            self.assertTrue((root / "reports/server-vulnerabilities.json").exists())
            self.assertTrue((root / "reports/server-library-report.html").exists())
            self.assertTrue((root / "reports/server-library-report.md").exists())
            self.assertTrue((root / "reports/scan-metadata.json").exists())
            self.assertTrue((root / "reports/warnings.json").exists())
            metadata = json.loads((root / "reports/scan-metadata.json").read_text(encoding="utf-8"))
            self.assertEqual(set(metadata["data_sources"]), {"nvd", "cisa_kev"})
            self.assertEqual(metadata["grype_database"]["database"]["built"], "2026-07-15T00:00:00Z")
            self.assertTrue(all(len(source["files"][0]["sha256"]) == 64 for source in metadata["data_sources"].values()))
            report = json.loads((root / "reports/server-vulnerabilities.json").read_text(encoding="utf-8"))
            self.assertEqual(report["archives"][0]["archive_type"], "jar")
            self.assertEqual(report["target"], str(target.resolve()))
            self.assertNotIn("kn" + "vd", report)
            self.assertNotIn("manual_review_candidates", report)
            rendered = (root / "reports/server-library-report.html").read_text(encoding="utf-8")
            self.assertIn('<html lang="ko">', rendered)
            self.assertIn('id="report-help"', rendered)
            self.assertNotIn("KN" + "VD", rendered)

    def test_missing_explicit_grype_is_exit_two_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "app"
            target.mkdir()
            _write_jar(target / "empty.jar", {})
            result = run_java_scan(JavaScanOptions(target=target, output_dir=root / "reports", grype_bin=root / "missing-grype"))
            self.assertEqual(result.exit_code, 2)
            self.assertTrue(any("Grype" in warning for warning in result.warnings))

    def test_builtin_only_scan_does_not_open_network_connections(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "app"
            target.mkdir()
            _write_jar(target / "demo.jar", {"META-INF/maven/org.example/demo/pom.properties": "groupId=org.example\nartifactId=demo\nversion=1.2.3\n"})
            with patch.object(socket, "create_connection", side_effect=AssertionError("network access is forbidden")):
                result = run_java_scan(JavaScanOptions(target=target, output_dir=root / "reports", builtin_only=True, no_grype=True))
            self.assertEqual(result.exit_code, 0)

    def test_fail_on_kev_returns_one(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "app"
            target.mkdir()
            _write_jar(target / "demo.jar", {"META-INF/maven/org.example/demo/pom.properties": "groupId=org.example\nartifactId=demo\nversion=1.2.3\n"})
            kev = root / "kev.json"
            kev.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-0001"}]}), encoding="utf-8")
            match = GrypeMatch("CVE-2026-0001", ("CVE-2026-0001",), "demo", "1.2.3", "pkg:maven/org.example/demo@1.2.3", (), "low", (), ())
            with patch("security_scanner.java_vulnerability_scan.run_grype", return_value=GrypeResult((match,), "test", {}, "", False)):
                result = run_java_scan(JavaScanOptions(target=target, output_dir=root / "reports", cisa_kev=kev, fail_on_kev=True))
            self.assertEqual(result.exit_code, 1)

    def test_syft_timeout_is_controlled_and_does_not_raise(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "syft"
            binary.write_text("placeholder", encoding="utf-8")
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
            with patch("security_scanner.syft_adapter.subprocess.run", side_effect=subprocess.TimeoutExpired(str(binary), 1)):
                result = run_syft(root, binary, 1)
            self.assertTrue(result.fatal)
            self.assertIn("Syft failed", result.warning)

    def test_syft_json_and_missing_binary_paths_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "syft"
            binary.write_text("placeholder", encoding="utf-8")
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
            payload = {"bomFormat": "CycloneDX", "components": []}
            with patch("security_scanner.syft_adapter.subprocess.run") as run:
                run.side_effect = [
                    type("Completed", (), {"returncode": 0, "stdout": "syft 1.0.0", "stderr": ""})(),
                    type("Completed", (), {"returncode": 0, "stdout": json.dumps(payload), "stderr": ""})(),
                ]
                result = run_syft(root, binary, 1)
            self.assertFalse(result.fatal)
            self.assertEqual(result.payload, payload)
            missing = run_syft(root, root / "missing-syft", 1)
            self.assertTrue(missing.fatal)
            self.assertIn("not found", missing.warning)


if __name__ == "__main__":
    unittest.main()
