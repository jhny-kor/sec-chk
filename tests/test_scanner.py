from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from security_scanner.app import _create_available_server
from security_scanner.config import expand_path
from security_scanner.discovery import discover_projects
from security_scanner.models import ScannerConfig, TargetConfig
from security_scanner.reporting import render_html, render_json, render_sarif
from security_scanner.scanner import SecurityScanner
from security_scanner.server import _select_directory_macos, allowed_cors_origin, scan_directory_payload, select_directory


class ScannerTests(unittest.TestCase):
    def test_detects_and_redacts_secret_like_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret_value = "sk-" + "1234567890abcdefghijklmnop"
            (root / ".env").write_text(f"OPENAI_API_KEY={secret_value}\n", encoding="utf-8")

            findings = _scan(root, categories=("secrets",))

            self.assertTrue(any(finding.rule_id == "secret.openai-key" for finding in findings))
            self.assertFalse(any(secret_value in finding.evidence for finding in findings))

    def test_ignores_environment_variable_secret_references(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "settings.py").write_text(
                "api_key = os.getenv('OKX_API_KEY')\n"
                "access_token = config.get('access_token')\n",
                encoding="utf-8",
            )

            findings = _scan(root, categories=("secrets",))

            self.assertEqual(findings, [])

    def test_ignores_secret_words_inside_messages(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "client.py").write_text(
                "raise RuntimeError(f'token response did not include access_token: {decoded}')\n",
                encoding="utf-8",
            )

            findings = _scan(root, categories=("secrets",))

            self.assertEqual(findings, [])

    def test_detects_package_json_without_lockfile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps({"dependencies": {"left-pad": "latest"}}),
                encoding="utf-8",
            )

            findings = _scan(root, categories=("dependencies",))
            rule_ids = {finding.rule_id for finding in findings}

            self.assertIn("dependency.node-missing-lockfile", rule_ids)
            self.assertIn("dependency.node-unbounded-version", rule_ids)

    def test_detects_risky_configuration_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "docker-compose.yml").write_text(
                "services:\n  app:\n    privileged: true\n",
                encoding="utf-8",
            )

            findings = _scan(root, categories=("configuration",))

            self.assertTrue(any(finding.rule_id == "config.compose-privileged" for finding in findings))

    def test_excludes_configured_globs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ignored = root / "ignored"
            ignored.mkdir()
            env_line = "PASS" + "WORD=verysecretvalue\n"
            (ignored / ".env").write_text(env_line, encoding="utf-8")

            config = ScannerConfig(
                targets=(
                    TargetConfig(
                        name="tmp",
                        path=root,
                        categories=("secrets", "configuration"),
                        exclude_globs=("ignored/**",),
                    ),
                )
            )
            findings = SecurityScanner(config).scan()

            self.assertEqual(findings, [])

    def test_json_report_contains_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("requests\n", encoding="utf-8")

            findings = _scan(root, categories=("dependencies",))
            payload = json.loads(render_json(findings))

            self.assertEqual(payload["summary"]["by_category"]["dependencies"], 1)

    def test_discovers_project_roots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "app"
            project.mkdir()
            (project / "pyproject.toml").write_text("[project]\nname = 'app'\n", encoding="utf-8")

            discovered = discover_projects(root, max_depth=1)

            self.assertEqual(len(discovered), 1)
            self.assertEqual(discovered[0].name, "app")
            self.assertEqual(discovered[0].ecosystems, ("python",))

    def test_expand_path_supports_env_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            variable = "SEC_CHK_TEST_TARGET"
            previous = os.environ.pop(variable, None)
            try:
                self.assertEqual(expand_path(f"${{{variable}:-.}}", root), root.resolve())
                os.environ[variable] = str(root / "custom")
                self.assertEqual(expand_path(f"${{{variable}:-.}}", root), (root / "custom").resolve())
            finally:
                if previous is None:
                    os.environ.pop(variable, None)
                else:
                    os.environ[variable] = previous

    def test_discovery_skips_root_marker_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text("[project]\nname = 'root'\n", encoding="utf-8")
            child = root / "child"
            child.mkdir()
            (child / "package.json").write_text("{}", encoding="utf-8")

            discovered = discover_projects(root, max_depth=1)

            self.assertEqual([project.name for project in discovered], ["child"])

    def test_scanner_expands_discovered_targets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "web"
            project.mkdir()
            (project / "package.json").write_text(
                json.dumps({"dependencies": {"left-pad": "latest"}}),
                encoding="utf-8",
            )

            config = ScannerConfig(
                targets=(
                    TargetConfig(
                        name="docs",
                        path=root,
                        categories=("dependencies",),
                        discover_projects=True,
                        discovery_depth=1,
                    ),
                )
            )
            scanner = SecurityScanner(config)
            findings = scanner.scan()

            self.assertEqual([target.name for target in scanner.effective_targets], ["docs/web"])
            self.assertTrue(any(finding.target == "docs/web" for finding in findings))

    def test_html_report_contains_dashboard_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("requests\n", encoding="utf-8")

            findings = _scan(root, categories=("dependencies",))
            html = render_html(findings, target_names=("tmp",))

            self.assertIn("Local Security Dashboard", html)
            self.assertIn("findings-data", html)
            self.assertIn("dependency.python-unpinned-requirement", html)

    def test_html_report_can_render_korean_labels(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("requests\n", encoding="utf-8")

            findings = _scan(root, categories=("dependencies",))
            html = render_html(findings, target_names=("tmp",), language="ko", target_paths={"tmp": str(root)})
            payload = _html_payload(html)

            self.assertIn('<html lang="ko">', html)
            self.assertIn('id="lang-ko"', html)
            self.assertIn('id="lang-en"', html)
            self.assertIn("로컬 보안 대시보드", html)
            self.assertIn("모든 심각도", html)
            self.assertIn("고정되지 않은 Python 의존성", html)
            self.assertIn("조치 보기", html)
            self.assertIn("Local Security Dashboard", html)
            self.assertEqual(payload["summary"]["target_paths"]["tmp"], str(root))
            self.assertEqual(payload["language"], "ko")
            self.assertIn("en", payload["findings_by_language"])
            self.assertIn("ko", payload["findings_by_language"])
            self.assertRegex(payload["generated_display"], r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")
            self.assertIsNone(re.search(r"\.\d+|[+-]\d{2}:\d{2}$", payload["generated_display"]))

    def test_dashboard_payload_can_scan_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("requests\n", encoding="utf-8")

            payload = scan_directory_payload(str(root), language="ko", discover_projects=False)

            self.assertEqual(payload["language"], "ko")
            self.assertEqual(payload["scan"]["path"], str(root.resolve()))
            self.assertEqual(payload["summary"]["target_paths"][root.name], str(root.resolve()))
            self.assertEqual(payload["findings_by_language"]["ko"][0]["title"], "고정되지 않은 Python 의존성")

    def test_dashboard_payload_can_scan_standard_category(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret_value = "sk-" + "1234567890abcdefghijklmnop"
            (root / ".env").write_text(f"OPENAI_API_KEY={secret_value}\n", encoding="utf-8")
            (root / "requirements.txt").write_text("requests\n", encoding="utf-8")

            payload = scan_directory_payload(
                str(root),
                language="ko",
                discover_projects=False,
                standard="owasp-top-10-2021",
                standard_category="a06-vulnerable-outdated-components",
            )

            rule_ids = {finding["rule_id"] for finding in payload["findings_by_language"]["en"]}
            self.assertIn("dependency.python-unpinned-requirement", rule_ids)
            self.assertNotIn("secret.openai-key", rule_ids)
            self.assertEqual(payload["scan"]["standard"], "owasp-top-10-2021")
            self.assertEqual(payload["scan"]["standard_category"], "a06-vulnerable-outdated-components")

    def test_cwe_top25_profile_maps_sensitive_information_exposure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret_value = "sk-" + "1234567890abcdefghijklmnop"
            (root / ".env").write_text(f"OPENAI_API_KEY={secret_value}\n", encoding="utf-8")
            (root / "requirements.txt").write_text("requests\n", encoding="utf-8")

            payload = scan_directory_payload(
                str(root),
                discover_projects=False,
                standard="cwe-top-25-2025",
                standard_category="cwe-200-sensitive-information-exposure",
            )

            rule_ids = {finding["rule_id"] for finding in payload["findings_by_language"]["en"]}
            self.assertIn("secret.openai-key", rule_ids)
            self.assertIn("config.env-file-present", rule_ids)
            self.assertNotIn("dependency.python-unpinned-requirement", rule_ids)

    def test_isms_p_development_security_profile_maps_test_data_security(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret_value = "sk-" + "1234567890abcdefghijklmnop"
            (root / ".env").write_text(f"OPENAI_API_KEY={secret_value}\n", encoding="utf-8")
            (root / "settings.py").write_text("DEBUG=" + "true\n", encoding="utf-8")

            payload = scan_directory_payload(
                str(root),
                discover_projects=False,
                standard="isms-p-development-security",
                standard_category="2.8.4-test-data-security",
            )

            rule_ids = {finding["rule_id"] for finding in payload["findings_by_language"]["en"]}
            self.assertIn("secret.openai-key", rule_ids)
            self.assertIn("config.env-file-present", rule_ids)
            self.assertNotIn("config.debug-enabled", rule_ids)

    def test_unsupported_standard_category_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                scan_directory_payload(
                    tmp,
                    discover_projects=False,
                    standard="owasp-top-10-2021",
                    standard_category="a03-injection",
                )

    def test_select_directory_falls_back_to_macos_picker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            selected = Path(tmp).resolve()
            completed = subprocess.CompletedProcess(
                args=["osascript"],
                returncode=0,
                stdout=f"{selected}\n",
                stderr="",
            )

            with (
                patch("security_scanner.server._select_directory_tk", side_effect=RuntimeError("tk missing")),
                patch("security_scanner.server.platform.system", return_value="Darwin"),
                patch("security_scanner.server.subprocess.run", return_value=completed) as run_picker,
            ):
                self.assertEqual(select_directory(), str(selected))
                self.assertTrue(run_picker.called)

    def test_macos_picker_retries_without_default_location_pattern_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            selected = Path(tmp).resolve()
            failed = subprocess.CompletedProcess(
                args=["osascript"],
                returncode=1,
                stdout="",
                stderr="The string did not match the expected pattern.",
            )
            completed = subprocess.CompletedProcess(
                args=["osascript"],
                returncode=0,
                stdout=f"{selected}\n",
                stderr="",
            )

            with patch("security_scanner.server.subprocess.run", side_effect=(failed, completed)) as run_picker:
                self.assertEqual(_select_directory_macos(Path(tmp)), str(selected))
                self.assertEqual(run_picker.call_count, 2)

    def test_local_cors_allows_static_file_reports_only_for_local_server(self) -> None:
        self.assertEqual(allowed_cors_origin("null"), "null")
        self.assertEqual(allowed_cors_origin("http://127.0.0.1:8765"), "http://127.0.0.1:8765")
        self.assertEqual(allowed_cors_origin("http://localhost:8765"), "http://localhost:8765")
        self.assertIsNone(allowed_cors_origin("https://example.com"))
        self.assertIsNone(allowed_cors_origin(None))

    def test_app_server_uses_next_available_port(self) -> None:
        fake_server = object()

        def create_server(host: str, port: int, language: str) -> object:
            if port == 8765:
                raise OSError("address already in use")
            return fake_server

        with patch("security_scanner.app.create_dashboard_server", side_effect=create_server):
            port, server = _create_available_server("127.0.0.1", 8765, "ko", 5)

        self.assertEqual(port, 8766)
        self.assertIs(server, fake_server)

    def test_platform_launchers_start_app_mode(self) -> None:
        root = Path(__file__).resolve().parents[1]
        mac_launcher = root / "scripts" / "sec-chk.command"
        windows_launcher = root / "scripts" / "sec-chk.bat"

        self.assertIn("-m security_scanner app", mac_launcher.read_text(encoding="utf-8"))
        self.assertIn("-m security_scanner app", windows_launcher.read_text(encoding="utf-8"))
        self.assertIn("py -3", windows_launcher.read_text(encoding="utf-8"))

    def test_html_report_contains_scan_controls(self) -> None:
        html = render_html([], language="ko")

        self.assertIn('id="scan-path"', html)
        self.assertIn('readonly aria-readonly="true"', html)
        self.assertIn('id="scan-choose"', html)
        self.assertIn('id="scan-standard"', html)
        self.assertIn('id="scan-standard-category"', html)
        self.assertIn('id="scan-run"', html)
        self.assertIn('apiEndpoint("/api/select-directory")', html)
        self.assertIn("http://127.0.0.1:8765", html)
        self.assertIn("점검 경로", html)
        self.assertIn("폴더 선택", html)
        self.assertIn("보안 기준", html)
        self.assertIn("기준 카테고리", html)
        self.assertIn("OWASP Top 10:2025", html)
        self.assertIn("OWASP Top 10:2021", html)
        self.assertIn("CWE Top 25:2025", html)
        self.assertIn("OWASP API Security Top 10:2023", html)
        self.assertIn("OWASP Mobile Top 10:2024", html)
        self.assertIn("소프트웨어 개발보안 49", html)
        self.assertIn("ISMS-P 2.8 개발보안", html)
        self.assertIn("점검 실행", html)

    def test_sarif_report_contains_rule_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("requests\n", encoding="utf-8")

            findings = _scan(root, categories=("dependencies",))
            payload = json.loads(render_sarif(findings))

            self.assertEqual(payload["version"], "2.1.0")
            self.assertEqual(payload["runs"][0]["results"][0]["ruleId"], "dependency.python-unpinned-requirement")


def _scan(root: Path, categories: tuple[str, ...]):
    config = ScannerConfig(targets=(TargetConfig(name="tmp", path=root, categories=categories),))
    return SecurityScanner(config).scan()


def _html_payload(content: str) -> dict[str, object]:
    marker = '<script id="findings-data" type="application/json">'
    start = content.index(marker) + len(marker)
    end = content.index("</script>", start)
    return json.loads(content[start:end])


if __name__ == "__main__":
    unittest.main()
