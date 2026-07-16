from __future__ import annotations

import json
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

from security_scanner.grype_adapter import run_grype
from security_scanner.java_archives import scan_archives
from security_scanner.syft_adapter import run_syft


def _write_jar(path: Path, files: dict[str, str | bytes]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)


class JavaScanRuntimeTests(unittest.TestCase):
    def test_default_scan_reads_all_archive_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "nested.jar"
            _write_jar(nested, {"META-INF/maven/org.example/demo/pom.properties": "groupId=org.example\nartifactId=demo\nversion=1.2.3\n"})
            with zipfile.ZipFile(root / "large.war", "w") as archive:
                for index in range(10_001):
                    archive.writestr(f"WEB-INF/classes/{index}.txt", b"")
                archive.writestr("WEB-INF/lib/nested.jar", nested.read_bytes())

            result = scan_archives(root)

            self.assertEqual(len(result.artifacts), 3)
            self.assertFalse(any("limit exceeded" in warning for warning in result.warnings))

    def test_external_tool_runners_request_utf8_decoding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "tool"
            binary.write_text("placeholder", encoding="utf-8")
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
            with patch("security_scanner.syft_adapter.subprocess.run") as syft_run:
                syft_run.side_effect = [
                    subprocess.CompletedProcess([str(binary)], 0, "syft 1.0.0", ""),
                    subprocess.CompletedProcess([str(binary)], 0, json.dumps({"bomFormat": "CycloneDX", "components": []}), ""),
                ]
                run_syft(root, binary, 1)
            with patch("security_scanner.grype_adapter.subprocess.run") as grype_run:
                grype_run.side_effect = [
                    subprocess.CompletedProcess([str(binary)], 0, "grype 1.0.0", ""),
                    subprocess.CompletedProcess([str(binary)], 0, json.dumps({"database": {}}), ""),
                    subprocess.CompletedProcess([str(binary)], 0, json.dumps({"matches": []}), ""),
                ]
                run_grype(root / "sbom.json", binary, 1)

            for runner in (syft_run, grype_run):
                for invocation in runner.call_args_list:
                    self.assertEqual(invocation.kwargs["encoding"], "utf-8")
                    self.assertEqual(invocation.kwargs["errors"], "replace")


if __name__ == "__main__":
    unittest.main()
