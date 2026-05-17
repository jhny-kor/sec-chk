from __future__ import annotations

import io
import json
import os
import re
import subprocess
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from security_scanner.app import _create_available_server, run_app
from security_scanner.cli import main as cli_main
from security_scanner.config import expand_path
from security_scanner.dast import findings_from_zap_json, run_zap_baseline
from security_scanner.dependency_inventory import queryable_osv_components
from security_scanner.diffing import diff_reports, render_diff_markdown
from security_scanner.discovery import discover_projects
from security_scanner.evidence import render_evidence_checklist
from security_scanner.integrations import upload_sbom_to_dependency_track
from security_scanner.models import DependencyComponent, Finding, ScannerConfig, TargetConfig
from security_scanner.osv_vulnerabilities import _finding_from_vulnerability
from security_scanner.release import build_release_security_package
from security_scanner.reporting import render_html, render_json, render_report, render_sarif
from security_scanner.scanner import SecurityScanner
from security_scanner.server import _select_directory_macos, allowed_cors_origin, scan_directory_payload, select_directory
from security_scanner.standards import standards_payload
from security_scanner.toolkit import write_security_template_files
from security_scanner.vex import render_cyclonedx_vex
from security_scanner.vuln_intel import VulnerabilityIntel


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

    def test_ignores_argument_secret_references(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "cli.py").write_text(
                "api_key = args.api_key or api_key_from_env(args.api_key_env)\n",
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

    def test_development_environment_flags_config_not_templates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env").write_text("APP_ENV=development\n", encoding="utf-8")
            (root / ".env.example").write_text("APP_ENV=development\n", encoding="utf-8")
            (root / "templates.py").write_text('"APP_ENV=development"\n', encoding="utf-8")

            findings = _scan(root, categories=("configuration",))
            matching_paths = {finding.path.name for finding in findings if finding.rule_id == "config.development-environment"}

            self.assertEqual(matching_paths, {".env"})

    def test_detects_kubernetes_terraform_and_github_workflow_risks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            k8s_dir = root / "k8s"
            workflow_dir = root / ".github" / "workflows"
            k8s_dir.mkdir()
            workflow_dir.mkdir(parents=True)
            (k8s_dir / "deployment.yaml").write_text(
                "apiVersion: apps/v1\n"
                "kind: Deployment\n"
                "spec:\n"
                "  template:\n"
                "    spec:\n"
                "      hostNetwork: true\n"
                "      volumes:\n"
                "        - hostPath:\n"
                "            path: /var/run\n"
                "      containers:\n"
                "        - securityContext:\n"
                "            privileged: true\n"
                "            allowPrivilegeEscalation: true\n",
                encoding="utf-8",
            )
            (root / "main.tf").write_text(
                'resource "aws_security_group_rule" "ssh" {\n'
                '  from_port = 22\n'
                '  to_port = 22\n'
                '  cidr_blocks = ["0.0.0.0/0"]\n'
                '}\n'
                'resource "aws_s3_bucket" "public" {\n'
                '  acl = "public-read"\n'
                '}\n',
                encoding="utf-8",
            )
            (workflow_dir / "ci.yml").write_text(
                "on:\n"
                "  pull_request_target:\n"
                "jobs:\n"
                "  test:\n"
                "    steps:\n"
                "      - run: echo ${{ github.event.pull_request.title }}\n",
                encoding="utf-8",
            )

            rule_ids = {finding.rule_id for finding in _scan(root, categories=("configuration",))}

            for rule_id in {
                "config.k8s-privileged-container",
                "config.k8s-allow-privilege-escalation",
                "config.k8s-host-network",
                "config.k8s-hostpath-volume",
                "config.terraform-open-admin-port",
                "config.terraform-public-storage",
                "config.github-pull-request-target",
                "config.github-untrusted-event-in-run",
            }:
                self.assertIn(rule_id, rule_ids)

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

    def test_excludes_build_cache_directories_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_cache = root / ".build"
            build_cache.mkdir()
            (build_cache / ".env").write_text("OPENAI_API_KEY=sk-1234567890abcdefghijklmnop\n", encoding="utf-8")

            findings = _scan(root, categories=("secrets",))

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
            self.assertIn('id="help-toggle"', html)
            self.assertIn("보안 점검 기준 도움말", html)
            self.assertIn("국정원 웹 8대 보안취약점", html)
            self.assertIn("전자금융감독규정 8대 취약점", html)
            self.assertIn("OWASP ASVS 5.0", html)
            self.assertIn("OWASP SAMM 2", html)
            self.assertIn("NIST SSDF SP 800-218", html)
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

    def test_standards_payload_contains_help_metadata_and_new_profiles(self) -> None:
        payload = standards_payload()
        standards = {standard["id"]: standard for standard in payload}

        for standard_id in (
            "cwe-sans-top-25-2025",
            "cwe",
            "kisa-secure-coding-guide",
            "sw-dev-security-7-types",
            "ncsc-web-8",
            "electronic-financial-supervision-8",
            "owasp-asvs-5",
            "owasp-wstg",
            "nist-ssdf-sp800-218",
            "owasp-samm-2",
            "owasp-dependency-check-baseline",
            "owasp-dependency-track-baseline",
            "openssf-scorecard-baseline",
            "cisa-kev-epss-priority",
            "slsa-sigstore-baseline",
        ):
            self.assertIn(standard_id, standards)
            self.assertTrue(standards[standard_id]["description"]["ko"])
            self.assertTrue(standards[standard_id]["coverage"]["ko"])
            self.assertTrue(standards[standard_id]["references"])
            self.assertTrue(any(category["supported"] for category in standards[standard_id]["categories"]))

        self.assertEqual(
            standards["ncsc-web-8"]["references"][0]["url"],
            "https://www.ncsc.go.kr/",
        )
        self.assertEqual(standards["owasp-asvs-5"]["coverage_level"], "evidence")
        self.assertEqual(standards["owasp-wstg"]["coverage_level"], "external")

    def test_dashboard_payload_can_scan_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("requests\n", encoding="utf-8")

            payload = scan_directory_payload(str(root), language="ko", discover_projects=False)

            self.assertEqual(payload["language"], "ko")
            self.assertEqual(payload["scan"]["path"], str(root.resolve()))
            self.assertEqual(payload["summary"]["target_paths"][root.name], str(root.resolve()))
            self.assertEqual(payload["findings_by_language"]["ko"][0]["title"], "고정되지 않은 Python 의존성")

    def test_dashboard_payload_includes_dependency_components_and_sbom(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("jinja2==2.4.1\n", encoding="utf-8")

            payload = scan_directory_payload(str(root), language="ko", discover_projects=False)

            self.assertEqual(payload["components"][0]["name"], "jinja2")
            self.assertEqual(payload["components"][0]["ecosystem"], "PyPI")
            self.assertEqual(payload["sbom"]["bomFormat"], "CycloneDX")
            self.assertEqual(payload["sbom"]["specVersion"], "1.6")
            self.assertEqual(payload["sbom"]["components"][0]["purl"], "pkg:pypi/jinja2@2.4.1")

    def test_prevention_guardrails_detect_missing_project_controls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            (root / "package.json").write_text(json.dumps({"dependencies": {"left-pad": "1.3.0"}}), encoding="utf-8")
            (root / ".env").write_text("TOKEN=placeholder\n", encoding="utf-8")
            (root / ".gitignore").write_text("dist/\n", encoding="utf-8")
            (root / "Dockerfile").write_text("FROM python:3.12\n", encoding="utf-8")
            (workflows / "build.yml").write_text("name: build\non: [push]\n", encoding="utf-8")

            findings = _scan(root, categories=("prevention",))
            rule_ids = {finding.rule_id for finding in findings}

            self.assertIn("prevention.security-policy-missing", rule_ids)
            self.assertIn("prevention.dependency-update-automation-missing", rule_ids)
            self.assertIn("prevention.ci-security-scan-missing", rule_ids)
            self.assertIn("prevention.env-not-gitignored", rule_ids)
            self.assertIn("prevention.env-example-missing", rule_ids)
            self.assertIn("prevention.dockerignore-missing", rule_ids)
            self.assertIn("prevention.sbom-missing", rule_ids)

    def test_prevention_guardrails_accept_configured_controls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflows = root / ".github" / "workflows"
            dependabot = root / ".github"
            workflows.mkdir(parents=True)
            (root / "package.json").write_text(json.dumps({"dependencies": {"left-pad": "1.3.0"}}), encoding="utf-8")
            (root / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
            (root / ".env").write_text("TOKEN=placeholder\n", encoding="utf-8")
            (root / ".env.example").write_text("TOKEN=\n", encoding="utf-8")
            (root / ".gitignore").write_text(".env\n.env.*\n", encoding="utf-8")
            (root / "Dockerfile").write_text("FROM python:3.12\n", encoding="utf-8")
            (root / ".dockerignore").write_text(".env\n.git\n", encoding="utf-8")
            (root / "sbom.cdx.json").write_text("{}", encoding="utf-8")
            (root / "vex.cdx.json").write_text("{}", encoding="utf-8")
            (dependabot / "dependabot.yml").write_text("version: 2\nupdates: []\n", encoding="utf-8")
            (workflows / "security.yml").write_text(
                "name: security\n"
                "permissions:\n"
                "  contents: read\n"
                "jobs:\n"
                "  security:\n"
                "    steps:\n"
                "      - run: koda scan\n"
                "      - run: semgrep ci\n"
                "      - run: scorecard\n"
                "      - run: cosign sign artifact\n"
                "      - run: zap-baseline.py -t https://example.com\n"
                "      - run: curl https://dependency-track.example.com/api/v1/bom\n",
                encoding="utf-8",
            )

            findings = _scan(root, categories=("prevention",))

            self.assertEqual(findings, [])

    def test_koda_ignore_file_suppresses_matching_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env").write_text("OPENAI_API_KEY=sk-1234567890abcdefghijklmnop\n", encoding="utf-8")
            (root / "koda-ignore.yml").write_text(
                """
ignore:
  - rule: secret.openai-key
    path: .env
    reason: local development placeholder
    until: 2099-12-31
""",
                encoding="utf-8",
            )

            findings = _scan(root, categories=("secrets",))

            self.assertEqual(findings, [])

    def test_zap_dry_run_and_json_parser(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = run_zap_baseline("https://example.com", output_dir=root / "zap", dry_run=True)

            self.assertIn("zap-baseline.py", result.command)
            self.assertEqual(result.exit_code, 0)

            zap_json = root / "zap-baseline.json"
            zap_json.write_text(
                json.dumps(
                    {
                        "site": [
                            {
                                "alerts": [
                                    {
                                        "pluginid": "10020",
                                        "riskdesc": "Low (Medium)",
                                        "name": "Missing header",
                                        "desc": "<p>header missing</p>",
                                        "solution": "Set the header",
                                        "instances": [{"uri": "https://example.com/"}],
                                    }
                                ]
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            findings = findings_from_zap_json(zap_json, target_url="https://example.com")

            self.assertEqual(findings[0].rule_id, "dast.zap.10020")
            self.assertEqual(findings[0].severity, "low")

    def test_evidence_checklist_contains_evidence_review_items(self) -> None:
        checklist = render_evidence_checklist(project_name="demo", language="ko")

        self.assertIn("KODA 수동 증적 체크리스트", checklist)
        self.assertIn("OWASP ASVS", checklist)
        self.assertIn("ISMS-P", checklist)

    def test_diff_reports_identifies_added_and_resolved_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline = root / "baseline.json"
            current = root / "current.json"
            baseline.write_text(
                json.dumps({"findings": [{"rule_id": "a", "target": "t", "path": "old.py", "line": 1}]}),
                encoding="utf-8",
            )
            current.write_text(
                json.dumps({"findings": [{"rule_id": "b", "target": "t", "path": "new.py", "line": 2}]}),
                encoding="utf-8",
            )

            diff = diff_reports(baseline, current)
            markdown = render_diff_markdown(diff, language="ko")

            self.assertEqual(diff["summary"]["added"], 1)
            self.assertEqual(diff["summary"]["resolved"], 1)
            self.assertIn("새로 발생", markdown)

    def test_release_security_package_contains_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            output = Path(tmp) / "release"
            root.mkdir()
            (root / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")

            manifest = build_release_security_package(target=root, output_dir=output, project_name="demo")

            self.assertEqual(manifest["project"], "demo")
            self.assertTrue((output / "koda-sbom.cdx.json").exists())
            self.assertTrue((output / "koda-vex.cdx.json").exists())
            self.assertTrue((output / "manual-evidence-checklist.md").exists())
            self.assertTrue((output / "checksums.txt").exists())

    def test_cyclonedx_report_uses_collected_dependency_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package-lock.json").write_text(
                json.dumps({"packages": {"node_modules/lodash": {"version": "4.17.21"}}}),
                encoding="utf-8",
            )
            scanner = SecurityScanner(ScannerConfig(targets=(TargetConfig(name="tmp", path=root, categories=("dependencies",)),)))
            scanner.scan()

            payload = json.loads(render_report([], "cyclonedx", components=scanner.components))
            component = payload["components"][0]

            self.assertEqual(payload["bomFormat"], "CycloneDX")
            self.assertEqual(component["name"], "lodash")
            self.assertEqual(component["version"], "4.17.21")
            self.assertEqual(component["purl"], "pkg:npm/lodash@4.17.21")

    def test_dependency_inventory_reads_common_lockfiles_for_osv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text(
                """
[project]
dependencies = ["requests==2.31.0"]

[tool.poetry.dependencies]
python = "^3.11"
click = "8.1.7"
""",
                encoding="utf-8",
            )
            (root / "poetry.lock").write_text(
                """
[[package]]
name = "django"
version = "4.2.11"
category = "main"

[[package]]
name = "pytest"
version = "8.2.0"
category = "dev"
""",
                encoding="utf-8",
            )
            (root / "Pipfile.lock").write_text(
                json.dumps(
                    {
                        "default": {"flask": {"version": "==3.0.2"}},
                        "develop": {"black": {"version": "==24.4.2"}},
                    }
                ),
                encoding="utf-8",
            )
            (root / "yarn.lock").write_text(
                """
left-pad@^1.3.0:
  version "1.3.0"
"@scope/pkg@npm:^2.0.0":
  version: 2.0.1
""",
                encoding="utf-8",
            )
            (root / "pnpm-lock.yaml").write_text(
                """
lockfileVersion: '9.0'
packages:
  /lodash@4.17.21:
    resolution: {integrity: sha512-test}
  /@scope/thing@1.2.3:
    resolution: {integrity: sha512-test}
""",
                encoding="utf-8",
            )

            scanner = SecurityScanner(ScannerConfig(targets=(TargetConfig(name="tmp", path=root, categories=("dependencies",)),)))
            scanner.scan()
            components = queryable_osv_components(scanner.components)
            names = {(component.ecosystem, component.name, component.version, component.source, component.scope) for component in components}

            self.assertIn(("PyPI", "requests", "2.31.0", "project.dependencies", "required"), names)
            self.assertIn(("PyPI", "click", "8.1.7", "tool.poetry.dependencies", "required"), names)
            self.assertIn(("PyPI", "django", "4.2.11", "poetry.lock", "required"), names)
            self.assertIn(("PyPI", "pytest", "8.2.0", "poetry.lock", "excluded"), names)
            self.assertIn(("PyPI", "flask", "3.0.2", "Pipfile.lock", "required"), names)
            self.assertIn(("PyPI", "black", "24.4.2", "Pipfile.lock", "excluded"), names)
            self.assertIn(("npm", "left-pad", "1.3.0", "yarn.lock", "required"), names)
            self.assertIn(("npm", "@scope/pkg", "2.0.1", "yarn.lock", "required"), names)
            self.assertIn(("npm", "lodash", "4.17.21", "pnpm-lock", "required"), names)
            self.assertIn(("npm", "@scope/thing", "1.2.3", "pnpm-lock", "required"), names)

    def test_scan_command_accepts_multiple_files_and_zip_archives(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env_file = root / ".env"
            requirements = root / "requirements.txt"
            archive_path = root / "upload.zip"
            output = root / "report.json"
            secret_value = "sk-" + "1234567890abcdefghijklmnop"
            env_file.write_text(f"OPENAI_API_KEY={secret_value}\n", encoding="utf-8")
            requirements.write_text("requests\n", encoding="utf-8")
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("web/views.js", "document.body.innerHTML = location.hash\n")

            exit_code = cli_main(
                [
                    "scan",
                    "--target",
                    str(env_file),
                    "--target",
                    str(requirements),
                    "--target",
                    str(archive_path),
                    "--format",
                    "json",
                    "--output",
                    str(output),
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            rule_ids = {finding["rule_id"] for finding in payload["findings"]}
            self.assertIn("secret.openai-key", rule_ids)
            self.assertIn("dependency.python-unpinned-requirement", rule_ids)
            self.assertIn("code.xss-dom-sink", rule_ids)

    def test_osv_lookup_can_be_enabled_for_exact_dependency_versions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            requirements = root / "requirements.txt"
            requirements.write_text("jinja2==2.4.1\nrequests\n", encoding="utf-8")

            def fake_query(components, **kwargs):
                self.assertEqual([component.name for component in components], ["jinja2"])
                return (
                    [
                        Finding(
                            rule_id="dependency.osv-known-vulnerability",
                            category="dependencies",
                            severity="high",
                            title="Known vulnerable dependency reported by OSV",
                            path=requirements,
                            target="tmp",
                            line=1,
                            evidence="PyPI jinja2@2.4.1: GHSA-test",
                        )
                    ],
                    [],
                )

            config = ScannerConfig(
                targets=(TargetConfig(name="tmp", path=root, categories=("dependencies",)),),
                enable_osv=True,
            )
            with patch("security_scanner.scanner.query_osv_findings", side_effect=fake_query) as query:
                scanner = SecurityScanner(config)
                findings = scanner.scan()

            self.assertTrue(query.called)
            self.assertIn("dependency.osv-known-vulnerability", {finding.rule_id for finding in findings})
            self.assertEqual([component.name for component in queryable_osv_components(scanner.components)], ["jinja2"])

    def test_osv_vulnerability_details_preserve_severity_and_aliases(self) -> None:
        dependency = DependencyComponent("jinja2", "PyPI", "2.4.1", Path("requirements.txt"), target="tmp", line=1)

        finding = _finding_from_vulnerability(
            dependency,
            {
                "id": "GHSA-test",
                "summary": "Template sandbox escape",
                "aliases": ["CVE-2026-0001"],
                "database_specific": {"severity": "CRITICAL"},
                "published": "2026-01-02T00:00:00Z",
                "modified": "2026-01-03T00:00:00Z",
            },
        )

        self.assertEqual(finding.severity, "critical")
        self.assertEqual(finding.title, "Template sandbox escape")
        self.assertIn("CVE-2026-0001", finding.evidence)
        self.assertIn("published 2026-01-02", finding.description)

    def test_osv_finding_can_include_kev_epss_priority(self) -> None:
        dependency = DependencyComponent("jinja2", "PyPI", "2.4.1", Path("requirements.txt"), target="tmp", line=1)

        finding = _finding_from_vulnerability(
            dependency,
            {
                "id": "GHSA-test",
                "summary": "Template sandbox escape",
                "aliases": ["CVE-2026-0002"],
                "database_specific": {"severity": "LOW"},
            },
            intel={
                "CVE-2026-0002": VulnerabilityIntel(
                    cve="CVE-2026-0002",
                    kev=True,
                    kev_due_date="2026-06-01",
                    epss=0.91,
                    percentile=0.99,
                )
            },
            cve_ids=("CVE-2026-0002",),
        )

        self.assertEqual(finding.severity, "critical")
        self.assertIn("CISA KEV", finding.evidence)
        self.assertIn("Prioritize", finding.recommendation)

    def test_cyclonedx_vex_report_uses_osv_findings(self) -> None:
        finding = Finding(
            rule_id="dependency.osv-known-vulnerability",
            category="dependencies",
            severity="high",
            title="Known vulnerable dependency",
            path=Path("requirements.txt"),
            target="tmp",
            evidence="PyPI jinja2@2.4.1: GHSA-test (CVE-2026-0003)",
        )

        payload = json.loads(render_cyclonedx_vex([finding]))

        self.assertEqual(payload["bomFormat"], "CycloneDX")
        self.assertEqual(payload["vulnerabilities"][0]["id"], "CVE-2026-0003")
        self.assertEqual(payload["vulnerabilities"][0]["analysis"]["state"], "in_triage")

    def test_security_toolkit_writes_templates_without_overwriting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SECURITY.md").write_text("custom\n", encoding="utf-8")

            results = write_security_template_files(root, project_name="Example")
            resolved_root = root.resolve()
            statuses = {result.path.relative_to(resolved_root).as_posix(): result.status for result in results}

            self.assertEqual(statuses["SECURITY.md"], "skipped")
            self.assertEqual(statuses[".github/dependabot.yml"], "written")
            self.assertEqual(statuses[".github/workflows/koda-security.yml"], "written")
            self.assertEqual(statuses["docs/security/VEX.md"], "written")
            self.assertEqual(statuses["docs/security/SLSA_SIGSTORE.md"], "written")
            self.assertEqual((root / "SECURITY.md").read_text(encoding="utf-8"), "custom\n")

    def test_cli_prints_external_security_integration_commands(self) -> None:
        zap_output = io.StringIO()
        with redirect_stdout(zap_output):
            zap_code = cli_main(["zap-command", "--url", "https://example.com", "--output-dir", "reports/zap"])

        dependency_track_output = io.StringIO()
        with redirect_stdout(dependency_track_output):
            dependency_track_code = cli_main(
                [
                    "dependency-track-command",
                    "--server-url",
                    "https://dependency-track.example.com",
                    "--project-name",
                    "Example",
                    "--project-version",
                    "main",
                    "--sbom",
                    "reports/sbom.cdx.json",
                ]
            )

        self.assertEqual(zap_code, 0)
        self.assertIn("ghcr.io/zaproxy/zaproxy:stable", zap_output.getvalue())
        self.assertIn("zap-baseline.py", zap_output.getvalue())
        self.assertEqual(dependency_track_code, 0)
        self.assertIn("/api/v1/bom", dependency_track_output.getvalue())
        self.assertIn("projectName=Example", dependency_track_output.getvalue())

    def test_prevention_checks_supply_chain_super_app_guardrails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(json.dumps({"dependencies": {"left-pad": "1.3.0"}}), encoding="utf-8")
            workflow = root / ".github" / "workflows"
            workflow.mkdir(parents=True)
            (workflow / "build.yml").write_text(
                "name: build\non: [push]\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@main\n",
                encoding="utf-8",
            )

            findings = _scan(root, categories=("prevention",))
            rule_ids = {finding.rule_id for finding in findings}

            self.assertIn("prevention.openssf-scorecard-missing", rule_ids)
            self.assertIn("prevention.github-token-permissions-not-readonly", rule_ids)
            self.assertIn("prevention.github-actions-unpinned", rule_ids)
            self.assertIn("prevention.slsa-sigstore-missing", rule_ids)
            self.assertIn("prevention.dependency-track-integration-missing", rule_ids)
            self.assertIn("prevention.vex-missing", rule_ids)

    def test_dependency_track_upload_posts_multipart_sbom(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sbom = root / "sbom.cdx.json"
            sbom.write_text('{"bomFormat":"CycloneDX"}', encoding="utf-8")
            received: dict[str, object] = {}

            class FakeResponse:
                status = 200

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return b'{"token":"processing-token"}'

            def fake_urlopen(request, timeout=0):
                received["url"] = request.full_url
                received["api_key"] = request.headers.get("X-api-key")
                received["content_type"] = request.headers.get("Content-type")
                received["body"] = request.data
                received["timeout"] = timeout
                return FakeResponse()

            with patch("security_scanner.integrations.urllib.request.urlopen", side_effect=fake_urlopen):
                payload = upload_sbom_to_dependency_track(
                    server_url="https://dependency-track.example.com",
                    api_key="secret",
                    project_name="Example",
                    project_version="main",
                    sbom_path=sbom,
                )

            self.assertEqual(payload["token"], "processing-token")
            self.assertEqual(received["url"], "https://dependency-track.example.com/api/v1/bom")
            self.assertEqual(received["api_key"], "secret")
            self.assertIn("multipart/form-data", str(received["content_type"]))
            self.assertIn(b'projectName', received["body"])  # type: ignore[operator]
            self.assertIn(b'CycloneDX', received["body"])  # type: ignore[operator]

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

    def test_injection_standard_profile_runs_code_pattern_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "views.js").write_text(
                "document.body.innerHTML = location.hash\n",
                encoding="utf-8",
            )
            query_line = (
                "cursor."
                'execute(f"'
                "SELECT * FROM users WHERE id = {request.args['id']}"
                '")\n'
            )
            (root / "users.py").write_text(query_line, encoding="utf-8")

            payload = scan_directory_payload(
                str(root),
                discover_projects=False,
                standard="owasp-top-10-2021",
                standard_category="a03-injection",
            )

            rule_ids = {finding["rule_id"] for finding in payload["findings_by_language"]["en"]}
            self.assertIn("code.xss-dom-sink", rule_ids)
            self.assertIn("code.sql-dynamic-query", rule_ids)
            self.assertEqual(payload["scan"]["standard_category"], "a03-injection")

    def test_cwe_path_traversal_profile_runs_code_pattern_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path_line = (
                "return "
                "send_file("
                'request.args["path"])\n'
            )
            (root / "app.py").write_text(path_line, encoding="utf-8")

            payload = scan_directory_payload(
                str(root),
                discover_projects=False,
                standard="cwe-top-25-2025",
                standard_category="cwe-22-path-traversal",
            )

            rule_ids = {finding["rule_id"] for finding in payload["findings_by_language"]["en"]}
            self.assertEqual(rule_ids, {"code.path-traversal"})

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

    def test_logging_monitoring_profile_runs_code_pattern_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log_line = (
                "logger."
                "info("
                '"pass'
                'word=%s", request.args["pass'
                'word"])\n'
            )
            handler_line = (
                "try:\n"
                "    run_job()\n"
                "except Exception: "
                "pass\n"
            )
            trace_line = (
                "traceback."
                "print_exc()\n"
            )
            (root / "audit.py").write_text(log_line, encoding="utf-8")
            (root / "worker.py").write_text(handler_line + trace_line, encoding="utf-8")

            payload = scan_directory_payload(
                str(root),
                discover_projects=False,
                standard="owasp-top-10-2021",
                standard_category="a09-security-logging-monitoring-failures",
            )

            rule_ids = {finding["rule_id"] for finding in payload["findings_by_language"]["en"]}
            self.assertIn("code.logging-sensitive-data", rule_ids)
            self.assertIn("code.empty-exception-handler", rule_ids)
            self.assertIn("code.stack-trace-exposure", rule_ids)

    def test_api_inventory_profile_runs_unversioned_route_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            route_line = (
                "app."
                "get("
                '"/api/users", handler)\n'
            )
            (root / "routes.js").write_text(route_line, encoding="utf-8")

            payload = scan_directory_payload(
                str(root),
                discover_projects=False,
                standard="owasp-api-security-2023",
                standard_category="api9-improper-inventory-management",
            )

            rule_ids = {finding["rule_id"] for finding in payload["findings_by_language"]["en"]}
            self.assertEqual(rule_ids, {"code.unversioned-api-route"})

    def test_sw_security_time_state_and_encapsulation_profiles_run_code_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            temp_line = (
                "path = tempfile."
                "mk"
                "temp()\n"
            )
            cors_line = (
                "CORS(app, "
                "origins="
                '"*")\n'
            )
            bind_line = (
                "app."
                "run(host="
                '"0.0.0.0")\n'
            )
            (root / "files.py").write_text(temp_line, encoding="utf-8")
            (root / "server.py").write_text(cors_line + bind_line, encoding="utf-8")

            time_payload = scan_directory_payload(
                str(root),
                discover_projects=False,
                standard="sw-dev-security-49",
                standard_category="time-state",
            )
            encapsulation_payload = scan_directory_payload(
                str(root),
                discover_projects=False,
                standard="sw-dev-security-49",
                standard_category="encapsulation",
            )

            time_rule_ids = {finding["rule_id"] for finding in time_payload["findings_by_language"]["en"]}
            encapsulation_rule_ids = {finding["rule_id"] for finding in encapsulation_payload["findings_by_language"]["en"]}
            self.assertEqual(time_rule_ids, {"code.insecure-temp-file"})
            self.assertIn("code.wildcard-cors", encapsulation_rule_ids)
            self.assertIn("code.public-bind-all-interfaces", encapsulation_rule_ids)

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

    def test_ncsc_web_8_profile_runs_server_config_file_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".htaccess").write_text("Options Indexes\n", encoding="utf-8")
            (root / "web.config").write_text("<add name=\"WebDAVModule\" />\n", encoding="utf-8")

            listing_payload = scan_directory_payload(
                str(root),
                discover_projects=False,
                standard="ncsc-web-8",
                standard_category="directory-listing",
            )
            webdav_payload = scan_directory_payload(
                str(root),
                discover_projects=False,
                standard="ncsc-web-8",
                standard_category="webdav",
            )

            listing_rule_ids = {finding["rule_id"] for finding in listing_payload["findings_by_language"]["en"]}
            webdav_rule_ids = {finding["rule_id"] for finding in webdav_payload["findings_by_language"]["en"]}
            self.assertEqual(listing_rule_ids, {"code.directory-listing-enabled"})
            self.assertEqual(webdav_rule_ids, {"code.webdav-enabled"})

    def test_electronic_finance_cookie_session_profile_runs_cookie_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cookie_line = (
                "session({ cookie: { "
                "se"
                "cure: fal"
                "se, http"
                "Only: fal"
                "se } })\n"
            )
            (root / "server.js").write_text(cookie_line, encoding="utf-8")

            payload = scan_directory_payload(
                str(root),
                discover_projects=False,
                standard="electronic-financial-supervision-8",
                standard_category="cookie-session",
            )

            rule_ids = {finding["rule_id"] for finding in payload["findings_by_language"]["en"]}
            self.assertIn("code.insecure-cookie-settings", rule_ids)

    def test_asvs_data_protection_profile_runs_weak_hash_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hash_line = (
                "digest = hashlib."
                "md"
                "5(data).hexdigest()\n"
            )
            (root / "hashing.py").write_text(hash_line, encoding="utf-8")

            payload = scan_directory_payload(
                str(root),
                discover_projects=False,
                standard="owasp-asvs-5",
                standard_category="data-protection",
            )

            rule_ids = {finding["rule_id"] for finding in payload["findings_by_language"]["en"]}
            self.assertEqual(rule_ids, {"code.weak-hash"})

    def test_unsupported_standard_category_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                scan_directory_payload(
                    tmp,
                    discover_projects=False,
                    standard="cwe-top-25-2025",
                    standard_category="cwe-416-use-after-free",
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

    def test_app_schedules_browser_without_blocking_server_loop(self) -> None:
        events: list[str] = []

        class FakeTimer:
            cancelled = False

            def cancel(self) -> None:
                self.cancelled = True

        class FakeServer:
            def serve_forever(self) -> None:
                events.append("serve")
                raise KeyboardInterrupt()

            def server_close(self) -> None:
                events.append("close")

        timer = FakeTimer()

        def schedule_browser(url: str) -> FakeTimer:
            events.append(f"schedule:{url}")
            return timer

        with (
            patch("builtins.print"),
            patch("security_scanner.app._create_available_server", return_value=(8765, FakeServer())),
            patch("security_scanner.app._schedule_browser_open", side_effect=schedule_browser),
        ):
            self.assertEqual(run_app(open_browser=True), 0)

        self.assertEqual(
            events,
            [
                "schedule:http://127.0.0.1:8765/security-dashboard.html",
                "serve",
                "close",
            ],
        )
        self.assertTrue(timer.cancelled)

    def test_platform_launchers_start_app_mode(self) -> None:
        root = Path(__file__).resolve().parents[1]
        mac_launcher = root / "scripts" / "sec-chk.command"
        mac_installer = root / "scripts" / "install-macos.command"
        mac_uninstaller = root / "scripts" / "uninstall-macos.command"
        windows_launcher = root / "scripts" / "sec-chk.bat"
        windows_installer = root / "scripts" / "install-windows.ps1"
        windows_installer_bat = root / "scripts" / "install-windows.bat"
        windows_uninstaller = root / "scripts" / "uninstall-windows.ps1"
        windows_builder = root / "scripts" / "build-windows-installer.ps1"
        windows_inno = root / "packaging" / "windows" / "SecChk.iss"
        mac_app_builder = root / "packaging" / "macos" / "build-koda-app.command"
        mac_xcode_builder = root / "packaging" / "macos" / "build-koda-xcode-app.command"
        mac_entitlements = root / "packaging" / "macos" / "KODA.entitlements"
        mac_icon = root / "packaging" / "macos" / "assets" / "KODA.icns"
        mac_packaging_readme = root / "packaging" / "macos" / "README.md"
        koda_project = root / "platforms" / "macos" / "KODA" / "KODA.xcodeproj" / "project.pbxproj"
        koda_scheme = (
            root
            / "platforms"
            / "macos"
            / "KODA"
            / "KODA.xcodeproj"
            / "xcshareddata"
            / "xcschemes"
            / "KODA.xcscheme"
        )
        koda_content_view = root / "platforms" / "macos" / "KODA" / "KODA" / "ContentView.swift"
        koda_standards_view = root / "platforms" / "macos" / "KODA" / "KODA" / "SecurityStandardsView.swift"
        koda_bridge = root / "platforms" / "macos" / "KODA" / "KODA" / "ScannerBridge.swift"
        koda_app = root / "platforms" / "macos" / "KODA" / "KODA" / "KODAApp.swift"
        koda_native_scanner = root / "platforms" / "macos" / "KODA" / "KODA" / "NativeSecurityScanner.swift"
        store_release_notes = root / "docs" / "store-release.md"
        readme = (root / "README.md").read_text(encoding="utf-8")

        self.assertIn("-m security_scanner app", mac_launcher.read_text(encoding="utf-8"))
        self.assertTrue(os.access(mac_installer, os.X_OK))
        self.assertTrue(os.access(mac_uninstaller, os.X_OK))
        self.assertIn("Library/Application Support/SecChk", mac_installer.read_text(encoding="utf-8"))
        self.assertIn("SecChk.command", mac_installer.read_text(encoding="utf-8"))
        self.assertIn("-m security_scanner app", mac_installer.read_text(encoding="utf-8"))
        self.assertIn("rm -rf", mac_uninstaller.read_text(encoding="utf-8"))
        self.assertIn("-m security_scanner app", windows_launcher.read_text(encoding="utf-8"))
        self.assertIn("py -3", windows_launcher.read_text(encoding="utf-8"))
        self.assertIn("install-windows.ps1", windows_installer_bat.read_text(encoding="utf-8"))
        self.assertIn("LOCALAPPDATA", windows_installer.read_text(encoding="utf-8"))
        self.assertIn("SecChk.bat", windows_installer.read_text(encoding="utf-8"))
        self.assertIn("security_scanner", windows_installer.read_text(encoding="utf-8"))
        self.assertIn("Remove-Item -Path $InstallRoot", windows_uninstaller.read_text(encoding="utf-8"))
        self.assertIn('InstallerOutDir = Join-Path $DistDir "Windows"', windows_builder.read_text(encoding="utf-8"))
        self.assertIn("OutputDir=..\\..\\dist\\Windows", windows_inno.read_text(encoding="utf-8"))
        self.assertTrue(os.access(mac_app_builder, os.X_OK))
        self.assertIn("APP_NAME=\"${APP_NAME:-KODA}\"", mac_app_builder.read_text(encoding="utf-8"))
        self.assertTrue(os.access(mac_xcode_builder, os.X_OK))
        self.assertIn("platforms/macos/KODA/KODA.xcodeproj", mac_xcode_builder.read_text(encoding="utf-8"))
        self.assertIn("dist/macos", mac_xcode_builder.read_text(encoding="utf-8"))
        self.assertIn("com.apple.security.app-sandbox", mac_entitlements.read_text(encoding="utf-8"))
        self.assertIn("com.apple.security.files.user-selected.read-write", mac_entitlements.read_text(encoding="utf-8"))
        self.assertEqual(mac_icon.read_bytes()[:4], b"icns")
        self.assertIn("KODA macOS App Store Packaging", mac_packaging_readme.read_text(encoding="utf-8"))
        self.assertIn("productType = \"com.apple.product-type.application\"", koda_project.read_text(encoding="utf-8"))
        self.assertIn("PRODUCT_BUNDLE_IDENTIFIER = com.jhnykor.koda", koda_project.read_text(encoding="utf-8"))
        self.assertIn("CODE_SIGN_ENTITLEMENTS = ../../../packaging/macos/KODA.entitlements", koda_project.read_text(encoding="utf-8"))
        self.assertIn("NativeSecurityScanner.swift in Sources", koda_project.read_text(encoding="utf-8"))
        self.assertIn("SecurityStandardsView.swift in Sources", koda_project.read_text(encoding="utf-8"))
        self.assertNotIn("security_scanner in Resources", koda_project.read_text(encoding="utf-8"))
        self.assertNotIn("KODA_SCANNER_ROOT", koda_scheme.read_text(encoding="utf-8"))
        self.assertIn("NSOpenPanel", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("allowsMultipleSelection = true", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("canChooseDirectories = true", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("canChooseFiles = true", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("zip, jar, war, tar, tar.gz, tgz, gz", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("NativeSecurityScanner", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("startAccessingSecurityScopedResource", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("func removeTarget", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("reportItems", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("buildReportItems", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("ReportExportFormat", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("exportSecurityToolkit", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("applySecurityToolkit", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("buildSecurityFixPlans", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("applySecurityFixPlans", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("exportSBOM", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("runOSVLookup", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("createIgnoreTemplate", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("scoreHistory", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("SecurityAutoFixer", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("SecurityScoreStore", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("KODAIgnoreTemplateWriter", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("NativeDependencyInventory", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("NativeOSVClient", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("NativeVulnerabilityIntelClient", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("NativeVEXDocument", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("koda-ignore.yml", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("pyprojectComponents", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("poetryLockComponents", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("pipfileLockComponents", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("yarnLockComponents", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("pnpmLockComponents", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("poetry.lock", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("Pipfile.lock", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("yarn.lock", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("pnpm-lock.yaml", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("SecurityPreventionTemplateWrite", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("SecurityPreventionToolkit", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("NSSavePanel", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("allowedContentTypes", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("GeneratedReportFiles", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("writeMarkdownReport", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("writePDFReport", koda_bridge.read_text(encoding="utf-8"))
        self.assertNotIn("python3", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("WKWebView", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("ReportWebView", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("loadFileURL", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("@Environment(\\.colorScheme)", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("webView.appearance", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("LanguageToggle(language: $language)", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.exportSecurityToolkit", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.applySecurityToolkit", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.buildSecurityFixPlans", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.applySecurityFixPlans", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.exportSBOM", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.runOSVLookup", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.exportVEX", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.exportZAPBaselinePlan", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.runZAPBaseline", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.exportEvidenceChecklist", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.exportReleaseSecurityPackage", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.exportScoreDiff", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.createIgnoreTemplate", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("SecurityFixWizardSheet", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("SecurityScoreHistorySheet", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("shield.lefthalf.filled", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("folder.badge.gearshape", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("wand.and.sparkles", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("shippingbox", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("chart.line.uptrend.xyaxis", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.export", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("square.and.arrow.down", koda_content_view.read_text(encoding="utf-8"))
        self.assertNotIn("scanner.openReport", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("showMainHelp", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("MainHelpScreen", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("HelpSummaryBlock", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("preventionKitUsageItems", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("GeometryReader", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn('@AppStorage("koda.dashboard.topFraction.v2")', koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("dashboardTopFraction = 0.25", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("minTopHeight: CGFloat = 160", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("@State private var liveTopFraction", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("DashboardSplitView", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("DragGesture", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("return min(140", koda_content_view.read_text(encoding="utf-8"))
        self.assertNotIn("VSplitView", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("removeTarget(target)", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("ScanResultsGroupedView", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("ScanReportDetailScreen", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("SecurityStandardDetailScreen", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("HelpGuideScreen", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("SecurityStandardCatalog.all", koda_content_view.read_text(encoding="utf-8"))
        self.assertNotIn("RiskScoreOverviewPanel", koda_content_view.read_text(encoding="utf-8"))
        self.assertNotIn("SeverityDistributionChart", koda_content_view.read_text(encoding="utf-8"))
        self.assertNotIn("Picker(\"하단 화면\"", koda_content_view.read_text(encoding="utf-8"))
        self.assertNotIn("Picker(\"Language\"", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("도움말", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("전체 조회", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("보안기준별 점검결과", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("ScanResultsGroupedView", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("HelpGuideRoute", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("HelpGuideScreen", koda_standards_view.read_text(encoding="utf-8"))
        self.assertNotIn("DetailHelpPanel", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("LanguageToggle", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("KODAScreenTopBar", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("자동 점검", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("외부 연동 필요", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("증적 확인 필요", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("예방 키트", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("보안 예방 키트 파일로 저장", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("선택 폴더에 예방 설정 적용", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("자동 수정 마법사", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("SBOM 생성", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("OSV/CVE + KEV/EPSS 조회", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("VEX 문서 생성", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("ZAP DAST 계획 생성", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("ZAP DAST 실행", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("수동 증적 체크리스트", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("릴리스 보안 패키지 생성", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("점검 변경 리포트", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("예외 파일 생성", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("보안 점수 추적", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("파일 기반 정적 점검", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("KO", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("EN", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("Local Project Security Scan", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("Results by Security Standard", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("Download", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("점검 가이드", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("이 기준에서 확인하는 항목", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("세부 확인 항목", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("detailItems(language:", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("KODATheme.cardBackground", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("OWASP Top 10:2025", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("국정원 웹 8대 보안취약점", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("전자금융감독규정 8대 취약점", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("OWASP ASVS 5.0", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("NIST SSDF SP 800-218", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("KODA_SCAN_TARGETS", koda_app.read_text(encoding="utf-8"))
        self.assertIn("KODA_SCAN_OUTPUT_MARKDOWN", koda_app.read_text(encoding="utf-8"))
        self.assertIn("KODA_SCAN_OUTPUT_PDF", koda_app.read_text(encoding="utf-8"))
        self.assertIn("KODA_SCAN_LANGUAGE", koda_app.read_text(encoding="utf-8"))
        self.assertIn("koda-ignore.yml", koda_native_scanner.read_text(encoding="utf-8"))
        self.assertIn("NativeIgnoreRules", koda_native_scanner.read_text(encoding="utf-8"))
        self.assertIn("extractZip", koda_native_scanner.read_text(encoding="utf-8"))
        self.assertIn("gunzip", koda_native_scanner.read_text(encoding="utf-8"))
        self.assertIn("writeMarkdownReport", koda_native_scanner.read_text(encoding="utf-8"))
        self.assertIn("writePDFReport", koda_native_scanner.read_text(encoding="utf-8"))
        self.assertIn("KODA Security Scan Report", koda_native_scanner.read_text(encoding="utf-8"))
        self.assertIn("위험점수 계산", koda_native_scanner.read_text(encoding="utf-8"))
        self.assertIn("위험군별 분포", koda_native_scanner.read_text(encoding="utf-8"))
        self.assertIn("drawPDFSummaryPage", koda_native_scanner.read_text(encoding="utf-8"))
        self.assertIn("drawPDFSeverityBars", koda_native_scanner.read_text(encoding="utf-8"))
        self.assertIn("drawPDFFindingTablePages", koda_native_scanner.read_text(encoding="utf-8"))
        self.assertIn("drawPDFTableHeader", koda_native_scanner.read_text(encoding="utf-8"))
        self.assertIn("drawPDFTableCell", koda_native_scanner.read_text(encoding="utf-8"))
        self.assertIn("color-scheme: light dark", koda_native_scanner.read_text(encoding="utf-8"))
        self.assertIn("prefers-color-scheme: dark", koda_native_scanner.read_text(encoding="utf-8"))
        self.assertIn("NativeRegexCache", koda_native_scanner.read_text(encoding="utf-8"))
        for rule_id in (
            "secret.aws-access-key",
            "secret.github-token",
            "secret.slack-token",
            "dependency.package-json-invalid",
            "dependency.node-insecure-url",
            "dependency.remote-shell-script",
            "dependency.python-insecure-url",
            "dependency.python-wildcard-version",
            "dependency.docker-unpinned-base",
            "dependency.docker-remote-shell",
            "config.private-key-like-file",
            "config.development-environment",
            "config.docker-root-user",
            "config.docker-add-http",
            "config.docker-no-user",
            "config.compose-host-network",
            "config.compose-docker-sock",
            "config.k8s-privileged-container",
            "config.k8s-allow-privilege-escalation",
            "config.k8s-host-network",
            "config.k8s-hostpath-volume",
            "config.terraform-public-storage",
            "config.terraform-public-access-block-disabled",
            "config.terraform-open-admin-port",
            "config.github-pull-request-target",
            "config.github-untrusted-event-in-run",
            "code.csrf-disabled",
            "code.auth-disabled-endpoint",
            "code.eval-user-input",
            "code.ssrf-user-url",
            "code.unrestricted-file-upload",
            "code.dangerous-c-buffer-api",
            "code.unbounded-request-body",
            "code.logging-sensitive-data",
            "code.empty-exception-handler",
            "code.stack-trace-exposure",
            "code.unversioned-api-route",
            "code.legacy-board-software",
            "code.xml-external-entity",
            "prevention.security-policy-missing",
            "prevention.dependency-update-automation-missing",
            "prevention.ci-security-scan-missing",
            "prevention.env-not-gitignored",
            "prevention.env-example-missing",
            "prevention.dockerignore-missing",
            "prevention.sbom-missing",
            "prevention.sast-workflow-missing",
            "prevention.openssf-scorecard-missing",
            "prevention.github-token-permissions-not-readonly",
            "prevention.github-actions-unpinned",
            "prevention.slsa-sigstore-missing",
            "prevention.zap-baseline-missing",
            "prevention.dependency-track-integration-missing",
            "prevention.vex-missing",
            "prevention.binary-artifact-committed",
        ):
            self.assertIn(rule_id, koda_native_scanner.read_text(encoding="utf-8"))
        self.assertNotIn("scaleBy(x: 1, y: -1)", koda_native_scanner.read_text(encoding="utf-8"))
        self.assertIn(".msixupload", (root / "packaging" / "windows" / "README.md").read_text(encoding="utf-8"))
        self.assertIn("Microsoft Store", store_release_notes.read_text(encoding="utf-8"))
        self.assertIn("App Store Connect", store_release_notes.read_text(encoding="utf-8"))
        self.assertIn("native Swift scanner", store_release_notes.read_text(encoding="utf-8"))
        self.assertIn("Install quickly", readme)
        self.assertIn("설치 방법 요약", readme)
        self.assertIn("scripts/install-macos.command", readme)
        self.assertIn("scripts/install-windows.bat", readme)
        self.assertIn("KODA", readme)
        self.assertIn("auto-fix wizard", readme)
        self.assertIn("koda-ignore.yml", readme)
        self.assertIn("score history", readme)
        self.assertIn("자동 수정 마법사", readme)
        self.assertIn("poetry.lock", readme)
        self.assertIn("Pipfile.lock", readme)
        self.assertIn("yarn.lock", readme)
        self.assertIn("pnpm-lock.yaml", readme)
        self.assertIn("MSIX", readme)
        self.assertIn("init-security", readme)
        self.assertIn("zap-command", readme)
        self.assertIn("upload-sbom", readme)

    def test_html_report_contains_scan_controls(self) -> None:
        html = render_html([], language="ko")

        self.assertIn('id="scan-path"', html)
        self.assertIn('readonly aria-readonly="true"', html)
        self.assertIn('id="scan-choose"', html)
        self.assertIn('id="scan-standard"', html)
        self.assertIn('id="scan-standard-category"', html)
        self.assertIn('id="scan-run"', html)
        self.assertIn('id="scan-osv"', html)
        self.assertIn('id="sbom-download"', html)
        self.assertIn('id="coverage-matrix"', html)
        self.assertIn('id="scan-depth" type="number" min="0" max="20" value="2"', html)
        self.assertIn('apiEndpoint("/api/select-directory")', html)
        self.assertIn("http://127.0.0.1:8765", html)
        self.assertIn("아직 미지원", html)
        self.assertIn("코드 패턴", html)
        self.assertIn("점검 경로", html)
        self.assertIn("폴더 선택", html)
        self.assertIn("보안 기준", html)
        self.assertIn("기준 카테고리", html)
        self.assertIn("OSV/CVE + KEV/EPSS 조회", html)
        self.assertIn("SBOM 다운로드", html)
        self.assertIn("커버리지 매트릭스", html)
        self.assertIn("예방 가드레일", html)
        self.assertIn("치명 100점", html)
        self.assertIn('id="risk-score-note"', html)
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
