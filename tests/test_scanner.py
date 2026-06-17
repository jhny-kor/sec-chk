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
from security_scanner.reachability import (
    ImportIndex,
    annotate_reachability,
    imported_names_from_lines,
    package_import_candidates,
)
from security_scanner.ai import provider as ai_provider
from security_scanner.ai import triage as ai_triage
from security_scanner.ai.provider import LLMResult, LLMUnavailable
from security_scanner.fixes import apply as fixes_apply
from security_scanner.fixes import deterministic as fixes_deterministic
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

    def test_detects_mobile_iac_and_llm_security_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            k8s_dir = root / "manifests"
            k8s_dir.mkdir()
            (root / "docker-compose.yml").write_text(
                "services:\n"
                "  app:\n"
                "    cap_add:\n"
                "      - SYS_ADMIN\n"
                "    pid: host\n",
                encoding="utf-8",
            )
            (k8s_dir / "pod.yaml").write_text(
                "apiVersion: v1\n"
                "kind: Pod\n"
                "spec:\n"
                "  automountServiceAccountToken: true\n"
                "  containers:\n"
                "    - image: nginx\n"
                "      securityContext:\n"
                "        runAsNonRoot: false\n",
                encoding="utf-8",
            )
            (root / "iam.tf").write_text(
                'resource "aws_iam_policy_document" "wide" {\n'
                '  statement {\n'
                '    actions = ["*"]\n'
                '    principals { identifiers = ["*"] }\n'
                '  }\n'
                '}\n',
                encoding="utf-8",
            )
            (root / "AndroidManifest.xml").write_text(
                '<manifest><application android:debuggable="true" android:allowBackup="true" '
                'android:usesCleartextTraffic="true"><activity android:exported="true" /></application></manifest>\n',
                encoding="utf-8",
            )
            (root / "Info.plist").write_text(
                "<plist><dict><key>NSAllowsArbitraryLoads</key><true/>"
                "<key>UIFileSharingEnabled</key><true/>"
                "<key>LSSupportsOpeningDocumentsInPlace</key><true/></dict></plist>\n",
                encoding="utf-8",
            )
            (root / "llm.py").write_text(
                'prompt = system + request.args["q"]\n'
                'client.responses.create(input={"token": token})\n'
                'tools = [{"name": "shell_exec"}]\n'
                'tool_choice = "auto"\n',
                encoding="utf-8",
            )

            rule_ids = {finding.rule_id for finding in _scan(root, categories=("configuration", "code"))}

            for rule_id in {
                "config.compose-dangerous-capability",
                "config.compose-host-pid",
                "config.k8s-run-as-root",
                "config.k8s-service-account-token",
                "config.k8s-unpinned-image",
                "config.terraform-wildcard-iam-action",
                "config.terraform-wildcard-principal",
                "config.android-debuggable",
                "config.android-allow-backup",
                "config.android-cleartext-traffic",
                "config.android-exported-component",
                "config.ios-ats-arbitrary-loads",
                "config.ios-file-sharing-enabled",
                "config.ios-open-documents-in-place",
                "code.llm-prompt-user-concat",
                "code.llm-tool-unrestricted",
                "code.llm-sensitive-data-in-prompt",
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
            "owasp-masvs",
            "owasp-llm-top-10-2025",
            "ncsc-web-8",
            "electronic-financial-supervision-8",
            "owasp-asvs-5",
            "owasp-wstg",
            "nist-ssdf-sp800-218",
            "nist-csf-2",
            "owasp-samm-2",
            "cisa-secure-by-design",
            "cisa-secure-software-attestation",
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
            self.assertIn("prevention.codeowners-missing", rule_ids)
            self.assertIn("prevention.repository-security-settings-missing", rule_ids)
            self.assertIn("prevention.release-provenance-automation-missing", rule_ids)
            self.assertIn("prevention.ssdf-workflow-missing", rule_ids)
            self.assertIn("prevention.secure-by-design-program-missing", rule_ids)
            self.assertIn("prevention.threat-model-missing", rule_ids)
            self.assertIn("prevention.secret-rotation-runbook-missing", rule_ids)
            self.assertIn("prevention.nist-csf-profile-missing", rule_ids)
            self.assertIn("prevention.cisa-attestation-missing", rule_ids)

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
            (dependabot / "CODEOWNERS").write_text("* @security-team\n", encoding="utf-8")
            (dependabot / "dependabot.yml").write_text("version: 2\nupdates: []\n", encoding="utf-8")
            docs = root / "docs" / "security"
            docs.mkdir(parents=True)
            (docs / "GITHUB_REPOSITORY_SECURITY.md").write_text("# GitHub Repository Security\n", encoding="utf-8")
            (docs / "NIST_SSDF_WORKFLOW.md").write_text("# NIST SSDF\n", encoding="utf-8")
            (docs / "SECURE_BY_DESIGN.md").write_text("# Secure by Design\n", encoding="utf-8")
            (docs / "THREAT_MODEL.md").write_text("# Threat Model\n", encoding="utf-8")
            (docs / "SECRET_ROTATION.md").write_text("# Secret Rotation\n", encoding="utf-8")
            (docs / "NIST_CSF_2_PROFILE.md").write_text("# NIST CSF\n", encoding="utf-8")
            (docs / "CISA_SECURE_SOFTWARE_ATTESTATION.md").write_text("# CISA Attestation\n", encoding="utf-8")
            (docs / "SCVS_PLAN.md").write_text("# SCVS\n", encoding="utf-8")
            (docs / "PRIVACY_DATA_MAP.md").write_text("# Privacy Data Map\n", encoding="utf-8")
            (docs / "SECURITY_ROADMAP.md").write_text("# Security Roadmap\n", encoding="utf-8")
            (docs / "EVIDENCE_REGISTER.md").write_text("# Evidence Register\n", encoding="utf-8")
            (docs / "SECURITY_HEADERS.md").write_text("# Security Headers\n", encoding="utf-8")
            (docs / "CONTAINER_HARDENING.md").write_text("# Container Hardening\n", encoding="utf-8")
            (docs / "CLOUD_IAC_SECURITY.md").write_text("# Cloud IaC Security\n", encoding="utf-8")
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

    def test_dependency_inventory_reads_additional_osv_ecosystems(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "go.mod").write_text(
                """
module example.com/app

require (
    golang.org/x/crypto v0.22.0
)
""",
                encoding="utf-8",
            )
            (root / "Cargo.lock").write_text(
                """
[[package]]
name = "regex"
version = "1.10.4"
""",
                encoding="utf-8",
            )
            (root / "Gemfile.lock").write_text(
                """
GEM
  remote: https://rubygems.org/
  specs:
    rack (2.2.8)
""",
                encoding="utf-8",
            )
            (root / "composer.lock").write_text(
                json.dumps(
                    {
                        "packages": [{"name": "symfony/http-foundation", "version": "v6.4.7"}],
                        "packages-dev": [{"name": "phpunit/phpunit", "version": "10.5.20"}],
                    }
                ),
                encoding="utf-8",
            )
            (root / "pom.xml").write_text(
                """
<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>6.1.6</version>
    </dependency>
  </dependencies>
</project>
""",
                encoding="utf-8",
            )
            (root / "app.csproj").write_text(
                """
<Project>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
  </ItemGroup>
</Project>
""",
                encoding="utf-8",
            )

            scanner = SecurityScanner(ScannerConfig(targets=(TargetConfig(name="tmp", path=root, categories=("dependencies",)),)))
            scanner.scan()
            components = queryable_osv_components(scanner.components)
            names = {(component.ecosystem, component.name, component.version, component.source, component.scope, component.purl) for component in components}

            self.assertIn(("Go", "golang.org/x/crypto", "v0.22.0", "go.mod", "required", "pkg:golang/golang.org/x/crypto@v0.22.0"), names)
            self.assertIn(("crates.io", "regex", "1.10.4", "Cargo.lock", "required", "pkg:cargo/regex@1.10.4"), names)
            self.assertIn(("RubyGems", "rack", "2.2.8", "Gemfile.lock", "required", "pkg:gem/rack@2.2.8"), names)
            self.assertIn(("Packagist", "symfony/http-foundation", "6.4.7", "packages", "required", "pkg:composer/symfony/http-foundation@6.4.7"), names)
            self.assertIn(("Packagist", "phpunit/phpunit", "10.5.20", "packages-dev", "excluded", "pkg:composer/phpunit/phpunit@10.5.20"), names)
            self.assertIn(("Maven", "org.springframework:spring-core", "6.1.6", "pom.xml", "required", "pkg:maven/org.springframework/spring-core@6.1.6"), names)
            self.assertIn(("NuGet", "Newtonsoft.Json", "13.0.3", "app.csproj", "required", "pkg:nuget/Newtonsoft.Json@13.0.3"), names)

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
            self.assertEqual(statuses[".github/workflows/koda-release-provenance.yml"], "written")
            self.assertEqual(statuses[".github/CODEOWNERS"], "written")
            self.assertEqual(statuses["docs/security/PRE_COMMIT.md"], "written")
            self.assertEqual(statuses["docs/security/GITHUB_REPOSITORY_SECURITY.md"], "written")
            self.assertEqual(statuses["docs/security/VEX.md"], "written")
            self.assertEqual(statuses["docs/security/SLSA_SIGSTORE.md"], "written")
            self.assertEqual(statuses["docs/security/NIST_SSDF_WORKFLOW.md"], "written")
            self.assertEqual(statuses["docs/security/SECURE_BY_DESIGN.md"], "written")
            self.assertEqual((root / "SECURITY.md").read_text(encoding="utf-8"), "custom\n")

    def test_cli_writes_prevention_workflow_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".git").mkdir()
            hook_output = io.StringIO()
            with redirect_stdout(hook_output):
                hook_code = cli_main(["install-hook", "--target", str(root), "--fail-on", "medium"])
            hook = root / ".git" / "hooks" / "pre-commit"

            checklist = root / "repo-security.md"
            ssdf = root / "ssdf.md"
            secure_by_design = root / "secure-by-design.md"
            sigstore = root / "sigstore.md"

            self.assertEqual(hook_code, 0)
            self.assertTrue(hook.exists())
            self.assertTrue(os.access(hook, os.X_OK))
            self.assertIn("KODA_PRE_COMMIT_FAIL_ON:-medium", hook.read_text(encoding="utf-8"))
            self.assertIn("written", hook_output.getvalue())

            self.assertEqual(
                cli_main(["repo-security-checklist", "--target", str(root), "--project-name", "Example", "--output", str(checklist)]),
                0,
            )
            self.assertEqual(cli_main(["ssdf-plan", "--target", str(root), "--output", str(ssdf)]), 0)
            self.assertEqual(cli_main(["secure-by-design-plan", "--target", str(root), "--output", str(secure_by_design)]), 0)
            self.assertEqual(cli_main(["sigstore-plan", "--target", str(root), "--artifact", "dist/example.tar.gz", "--output", str(sigstore)]), 0)

            self.assertIn("GitHub Repository Security Checklist", checklist.read_text(encoding="utf-8"))
            self.assertIn("NIST SSDF Workflow", ssdf.read_text(encoding="utf-8"))
            self.assertIn("CISA Secure by Design Plan", secure_by_design.read_text(encoding="utf-8"))
            self.assertIn("dist/example.tar.gz", sigstore.read_text(encoding="utf-8"))

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

    def test_detects_api_auth_privacy_and_cloud_iac_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "api.js").write_text(
                "const app = express()\n"
                "app.post('/api/admin/users', (req) => User.update(req.body))\n"
                "axios.get(endpoint)\n"
                "console.log('email', user.email)\n"
                "jwt.decode(token, options={verify_signature: False})\n"
                "const algorithms = ['none']\n",
                encoding="utf-8",
            )
            (root / "main.tf").write_text(
                'cidr_blocks = ["0.0.0.0/0"]\n'
                'encrypted = false\n'
                'output "db_password" {\n'
                '  sensitive = false\n'
                '}\n',
                encoding="utf-8",
            )
            (root / "docker-compose.yml").write_text(
                "services:\n  app:\n    environment:\n      DB_PASSWORD=secret\n",
                encoding="utf-8",
            )
            k8s = root / "k8s"
            k8s.mkdir()
            (k8s / "deployment.yaml").write_text(
                "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n      - image: nginx\n        securityContext:\n          seccompProfile: unconfined\n          capabilities:\n            add: [SYS_ADMIN]\n",
                encoding="utf-8",
            )

            findings = _scan(root, categories=("configuration", "code"))
            rule_ids = {finding.rule_id for finding in findings}

            for rule_id in {
                "code.api-route-missing-auth",
                "code.api-mass-assignment",
                "code.api-missing-rate-limit",
                "code.external-api-no-timeout",
                "code.pii-logging",
                "code.jwt-verification-disabled",
                "code.jwt-none-algorithm",
                "config.terraform-public-ingress",
                "config.terraform-unencrypted-storage",
                "config.terraform-sensitive-output",
                "config.compose-secret-in-environment",
                "config.k8s-seccomp-unconfined",
                "config.k8s-dangerous-capability",
            }:
                self.assertIn(rule_id, rule_ids)

    def test_prevention_checks_exception_governance_and_super_app_plans(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(json.dumps({"dependencies": {"left-pad": "1.3.0"}}), encoding="utf-8")
            (root / "api.py").write_text("app = FastAPI()\n@app.get('/api/users')\ndef users(): pass\n", encoding="utf-8")
            (root / "main.tf").write_text('cidr_blocks = ["0.0.0.0/0"]\n', encoding="utf-8")
            k8s = root / "k8s"
            k8s.mkdir()
            (k8s / "deployment.yaml").write_text("kind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n      - image: nginx\n", encoding="utf-8")
            (root / "koda-ignore.yml").write_text(
                "ignore:\n"
                "  - rule: code.xss-dom-sink\n"
                "    path: web.js\n"
                "    until: 2000-01-01\n",
                encoding="utf-8",
            )

            findings = _scan(root, categories=("prevention",))
            rule_ids = {finding.rule_id for finding in findings}

            for rule_id in {
                "prevention.api-security-plan-missing",
                "prevention.scvs-plan-missing",
                "prevention.privacy-data-map-missing",
                "prevention.security-roadmap-missing",
                "prevention.evidence-register-missing",
                "prevention.exception-reason-missing",
                "prevention.exception-owner-missing",
                "prevention.exception-expired",
                "prevention.k8s-network-policy-missing",
                "prevention.security-headers-guide-missing",
                "prevention.container-hardening-guide-missing",
                "prevention.cloud-iac-security-plan-missing",
            }:
                self.assertIn(rule_id, rule_ids)

    def test_owasp_scvs_standard_profile_maps_supply_chain_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("requests\n", encoding="utf-8")

            payload = scan_directory_payload(
                str(root),
                discover_projects=False,
                min_severity="info",
                standard="owasp-scvs",
                standard_category="v2-sbom",
            )

            rule_ids = {finding["rule_id"] for finding in payload["findings_by_language"]["en"]}
            self.assertEqual(rule_ids, {"prevention.sbom-missing", "prevention.dependency-track-integration-missing"})

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
        koda_windows_inno = root / "packaging" / "windows" / "KODA.iss"
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
        self.assertIn("--browser", koda_windows_inno.read_text(encoding="utf-8"))
        self.assertIn("KODA (Browser Mode)", koda_windows_inno.read_text(encoding="utf-8"))
        self.assertTrue(os.access(mac_app_builder, os.X_OK))
        self.assertIn("APP_NAME=\"${APP_NAME:-KODA}\"", mac_app_builder.read_text(encoding="utf-8"))
        self.assertTrue(os.access(mac_xcode_builder, os.X_OK))
        self.assertIn("platforms/macos/KODA/KODA.xcodeproj", mac_xcode_builder.read_text(encoding="utf-8"))
        self.assertIn("dist/macos", mac_xcode_builder.read_text(encoding="utf-8"))
        self.assertIn("com.apple.security.app-sandbox", mac_entitlements.read_text(encoding="utf-8"))
        self.assertIn("com.apple.security.files.user-selected.read-write", mac_entitlements.read_text(encoding="utf-8"))
        self.assertNotIn("com.apple.security.network.server", mac_entitlements.read_text(encoding="utf-8"))
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
        self.assertIn("goModuleComponents", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("cargoLockComponents", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("gemfileLockComponents", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("composerLockComponents", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("pomComponents", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("nugetComponents", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("supportedOSVEcosystems", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("NativeReportSanitizer", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("writeSanitizedReport", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("poetry.lock", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("Pipfile.lock", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("yarn.lock", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("pnpm-lock.yaml", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("Cargo.lock", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("Gemfile.lock", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("composer.lock", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("pom.xml", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("packages.config", koda_bridge.read_text(encoding="utf-8"))
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
        self.assertIn("scanner.installPreCommitHook", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.buildSecurityFixPlans", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.applySecurityFixPlans", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.exportSBOM", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.runOSVLookup", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.exportVEX", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.exportZAPBaselinePlan", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.runZAPBaseline", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.exportEvidenceChecklist", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.exportReleaseSecurityPackage", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.exportReleaseSigningPlan", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.exportScoreDiff", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.createIgnoreTemplate", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.exportRepositorySecurityChecklist", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.exportSSDFWorkflowPlan", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.exportSecureByDesignPlan", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.exportSecretResponseChecklist", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.exportAILLMSecurityPlan", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.exportMobileSecurityPlan", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.exportNISTCSFProfile", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.exportCISAAttestationChecklist", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("SecurityFixWizardSheet", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("SecurityScoreHistorySheet", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("ThreatModelWizardSheet", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("ComplianceDashboardSheet", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("shield.lefthalf.filled", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("folder.badge.gearshape", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("wand.and.sparkles", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("shippingbox", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("chart.line.uptrend.xyaxis", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("scanner.export", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("square.and.arrow.down", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("maskReportExports", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("maskReportExportTitle", koda_content_view.read_text(encoding="utf-8"))
        self.assertNotIn("scanner.openReport", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("showMainHelp", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("MainHelpScreen", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("HelpSummaryBlock", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("preventionKitGroups", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("preventionKitUsageItems", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("threatModelWizardTitle", koda_content_view.read_text(encoding="utf-8"))
        self.assertIn("complianceDashboardTitle", koda_content_view.read_text(encoding="utf-8"))
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
        self.assertIn("예방 키트에 포함된 항목", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("Apply Guardrails to Folders", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("release provenance workflow", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("KODA_PRE_COMMIT_FAIL_ON", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("선택 폴더에 예방 설정 적용", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("커밋 전 보안 차단 설치", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("자동 수정 마법사", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("SBOM 생성", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("OSV/CVE + KEV/EPSS 조회", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("VEX 문서 생성", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("ZAP DAST 계획 생성", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("ZAP DAST 실행", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("수동 증적 체크리스트", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("릴리스 보안 패키지 생성", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("릴리스 서명 계획 생성", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("점검 변경 리포트", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("예외 파일 생성", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("저장소 보안 설정 체크리스트", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("NIST SSDF 워크플로 계획", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("Secure by Design 예방 계획", koda_standards_view.read_text(encoding="utf-8"))
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
        self.assertIn("CISA Secure by Design", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("OWASP MASVS", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("OWASP LLM Top 10:2025", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("NIST CSF 2.0", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("CISA 보안 소프트웨어 개발 확인서", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("국제 원칙", koda_standards_view.read_text(encoding="utf-8"))
        self.assertIn("KODA_SCAN_TARGETS", koda_app.read_text(encoding="utf-8"))
        self.assertIn("KODA_SCAN_OUTPUT_MARKDOWN", koda_app.read_text(encoding="utf-8"))
        self.assertIn("KODA_SCAN_OUTPUT_PDF", koda_app.read_text(encoding="utf-8"))
        self.assertIn("KODA_SCAN_FAIL_ON", koda_app.read_text(encoding="utf-8"))
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
            "config.compose-dangerous-capability",
            "config.compose-host-pid",
            "config.k8s-privileged-container",
            "config.k8s-allow-privilege-escalation",
            "config.k8s-host-network",
            "config.k8s-hostpath-volume",
            "config.k8s-run-as-root",
            "config.k8s-service-account-token",
            "config.k8s-unpinned-image",
            "config.terraform-public-storage",
            "config.terraform-public-access-block-disabled",
            "config.terraform-open-admin-port",
            "config.terraform-wildcard-iam-action",
            "config.terraform-wildcard-principal",
            "config.github-pull-request-target",
            "config.github-untrusted-event-in-run",
            "config.android-debuggable",
            "config.android-allow-backup",
            "config.android-cleartext-traffic",
            "config.android-exported-component",
            "config.ios-ats-arbitrary-loads",
            "config.ios-file-sharing-enabled",
            "config.ios-open-documents-in-place",
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
            "code.llm-prompt-user-concat",
            "code.llm-tool-unrestricted",
            "code.llm-sensitive-data-in-prompt",
            "prevention.security-policy-missing",
            "prevention.pre-commit-hook-missing",
            "prevention.dependency-update-automation-missing",
            "prevention.codeowners-missing",
            "prevention.repository-security-settings-missing",
            "prevention.ci-security-scan-missing",
            "prevention.release-provenance-automation-missing",
            "prevention.env-not-gitignored",
            "prevention.env-example-missing",
            "prevention.dockerignore-missing",
            "prevention.sbom-missing",
            "prevention.sast-workflow-missing",
            "prevention.ssdf-workflow-missing",
            "prevention.secure-by-design-program-missing",
            "prevention.openssf-scorecard-missing",
            "prevention.github-token-permissions-not-readonly",
            "prevention.github-actions-unpinned",
            "prevention.slsa-sigstore-missing",
            "prevention.zap-baseline-missing",
            "prevention.dependency-track-integration-missing",
            "prevention.vex-missing",
            "prevention.binary-artifact-committed",
            "prevention.threat-model-missing",
            "prevention.secret-rotation-runbook-missing",
            "prevention.ai-llm-security-plan-missing",
            "prevention.mobile-security-plan-missing",
            "prevention.nist-csf-profile-missing",
            "prevention.cisa-attestation-missing",
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
        self.assertIn("THREAT_MODEL.md", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("AI_LLM_SECURITY.md", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("MOBILE_SECURITY.md", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("NIST_CSF_2_PROFILE.md", koda_bridge.read_text(encoding="utf-8"))
        self.assertIn("CISA_SECURE_SOFTWARE_ATTESTATION.md", koda_bridge.read_text(encoding="utf-8"))

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
        self.assertIn("OWASP MASVS", html)
        self.assertIn("OWASP LLM Top 10:2025", html)
        self.assertIn("NIST CSF 2.0", html)
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


class HostCheckTests(unittest.TestCase):
    def test_current_platform_normalizes(self) -> None:
        from security_scanner.checks.host.common import current_platform

        self.assertIn(current_platform(), {"macos", "windows", "linux", "other"})

    def test_runner_rejects_non_allowlisted_command(self) -> None:
        from security_scanner.checks.host.runner import run_command

        result = run_command(["rm", "-rf", "/"])
        self.assertFalse(result.ok)
        self.assertIn("not allowlisted", result.error)

    def test_runner_rejects_allowlist_bypass_via_path(self) -> None:
        from security_scanner.checks.host.runner import run_command

        result = run_command(["/bin/rm", "-rf", "/"])
        self.assertFalse(result.ok)
        self.assertIn("not allowlisted", result.error)

    def test_check_host_unsupported_platform_warns(self) -> None:
        from security_scanner.checks.host import check_host

        findings, warnings = check_host(platform="other")
        self.assertEqual(findings, [])
        self.assertTrue(any("not supported" in warning for warning in warnings))

    def test_macos_filevault_off_is_high(self) -> None:
        from security_scanner.checks.host import host_macos
        from security_scanner.checks.host.runner import CommandResult

        fake = CommandResult(command="fdesetup status", ok=True, returncode=0, stdout="FileVault is Off.\n")
        with patch.object(host_macos, "run_command", return_value=fake):
            findings = host_macos.check_filevault()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "host.macos.filevault-off")
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[0].category, "host")
        self.assertEqual(findings[0].resource, "macos/filevault")

    def test_macos_automatic_login_enabled_is_high(self) -> None:
        from security_scanner.checks.host import host_macos
        from security_scanner.checks.host.runner import CommandResult

        fake = CommandResult(command="defaults", ok=True, returncode=0, stdout="admin\n")
        with patch.object(host_macos, "run_command", return_value=fake):
            findings = host_macos.check_automatic_login()
        self.assertEqual(findings[0].rule_id, "host.macos.auto-login-enabled")
        self.assertEqual(findings[0].severity, "high")

    def test_windows_guest_account_enabled_is_medium(self) -> None:
        from security_scanner.checks.host import host_windows
        from security_scanner.checks.host.runner import CommandResult

        fake = CommandResult(command="powershell", ok=True, returncode=0, stdout="True\n")
        with patch.object(host_windows, "powershell", return_value=fake):
            findings = host_windows.check_guest_account()
        self.assertEqual(findings[0].rule_id, "host.windows.guest-account-enabled")
        self.assertEqual(findings[0].severity, "medium")

    def test_drift_regression_and_improvement(self) -> None:
        from security_scanner.checks import host as host_pkg
        from security_scanner.checks.host.common import host_finding

        baseline = {"macos/filevault": "info", "macos/firewall": "high"}
        current = [
            host_finding("host.macos.filevault-off", "high", "FileVault off", "macos/filevault"),
            host_finding("host.macos.firewall-enabled", "info", "Firewall on", "macos/firewall"),
        ]
        with patch.object(host_pkg, "_load_baseline", return_value=baseline):
            drift = host_pkg._drift_findings(current)
        kinds = {f.rule_id for f in drift}
        self.assertIn("host.drift.regressed", kinds)
        self.assertIn("host.drift.improved", kinds)

    def test_drift_empty_baseline_no_findings(self) -> None:
        from security_scanner.checks import host as host_pkg
        from security_scanner.checks.host.common import host_finding

        current = [host_finding("host.macos.filevault-off", "high", "FileVault off", "macos/filevault")]
        with patch.object(host_pkg, "_load_baseline", return_value={}):
            self.assertEqual(host_pkg._drift_findings(current), [])

    def test_macos_sip_failure_yields_no_finding(self) -> None:
        from security_scanner.checks.host import host_macos
        from security_scanner.checks.host.runner import CommandResult

        fake = CommandResult(command="csrutil status", ok=False, returncode=1, error="command not found")
        with patch.object(host_macos, "run_command", return_value=fake):
            self.assertEqual(host_macos.check_system_integrity_protection(), [])

    def test_check_host_isolates_failing_probe(self) -> None:
        from security_scanner.checks.host import check_host

        def boom() -> list:
            raise RuntimeError("probe blew up")

        with patch("security_scanner.checks.host._platform_checks", return_value=(boom,)):
            findings, warnings = check_host(platform="macos")
        self.assertEqual(findings, [])
        self.assertTrue(any("probe blew up" in warning for warning in warnings))

    def test_scanner_skips_host_by_default(self) -> None:
        from security_scanner.checks.host.common import host_finding

        sentinel = [host_finding("host.test", "high", "t", "test/resource")]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.py").write_text("x = 1\n", encoding="utf-8")
            with patch("security_scanner.scanner.check_host", return_value=(sentinel, [])) as mocked:
                findings = _scan(root, categories=("code",))
        mocked.assert_not_called()
        self.assertFalse(any(f.category == "host" for f in findings))

    def test_macos_stealth_mode_off_is_low(self) -> None:
        from security_scanner.checks.host import host_macos
        from security_scanner.checks.host.runner import CommandResult

        fake = CommandResult(command="...", ok=True, returncode=0, stdout="Firewall stealth mode is off\n")
        with patch.object(host_macos, "run_command", return_value=fake):
            findings = host_macos.check_firewall_stealth_mode()
        self.assertEqual([f.rule_id for f in findings], ["host.macos.firewall-stealth-disabled"])
        self.assertEqual(findings[0].severity, "low")

    def test_macos_security_updates_requires_both_keys(self) -> None:
        from security_scanner.checks.host import host_macos
        from security_scanner.checks.host.runner import CommandResult

        def fake_run(args, **kwargs):
            key = args[-1]
            value = "1" if key == "ConfigDataInstall" else "0"
            return CommandResult(command="defaults", ok=True, returncode=0, stdout=value + "\n")

        with patch.object(host_macos, "run_command", side_effect=fake_run):
            findings = host_macos.check_automatic_security_updates()
        # ConfigDataInstall on but CriticalUpdateInstall off -> not fully enabled
        self.assertEqual([f.rule_id for f in findings], ["host.macos.auto-security-updates-disabled"])
        self.assertEqual(findings[0].severity, "medium")

    def test_cis_benchmark_standards_registered(self) -> None:
        from security_scanner.standards import resolve_standard_selection, standards_payload

        ids = {s["id"] for s in standards_payload()}
        self.assertIn("cis-macos-benchmark", ids)
        self.assertIn("cis-windows-benchmark", ids)

        selection = resolve_standard_selection("cis-macos-benchmark", "all")
        self.assertEqual(selection.scanner_categories, ("host",))
        self.assertIn("host.macos.filevault-off", selection.rule_ids)

    def test_cis_benchmark_filters_to_host_findings(self) -> None:
        from security_scanner.checks.host.common import host_finding
        from security_scanner.standards import filter_findings_by_standard, resolve_standard_selection

        selection = resolve_standard_selection("cis-macos-benchmark", "network")
        findings = [
            host_finding("host.macos.firewall-disabled", "medium", "fw", "macos/application-firewall"),
            host_finding("host.macos.sip-enabled", "info", "sip", "macos/system-integrity-protection"),
        ]
        filtered = filter_findings_by_standard(findings, selection)
        self.assertEqual([f.rule_id for f in filtered], ["host.macos.firewall-disabled"])

    def test_scanner_runs_host_when_requested(self) -> None:
        from security_scanner.checks.host.common import host_finding

        sentinel = [host_finding("host.test", "high", "t", "test/resource")]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch("security_scanner.scanner.check_host", return_value=(sentinel, [])) as mocked:
                findings = _scan(root, categories=("host",))
        mocked.assert_called_once()
        host_findings = [f for f in findings if f.category == "host"]
        self.assertEqual(len(host_findings), 1)
        self.assertEqual(host_findings[0].target, "tmp")


class Phase2InventoryTests(unittest.TestCase):
    def test_macos_inventory_parses_system_profiler(self) -> None:
        from security_scanner import inventory
        from security_scanner.checks.host.runner import CommandResult

        sp_json = json.dumps(
            {"SPApplicationsDataType": [
                {"_name": "Safari", "version": "17.0", "obtained_from": "apple"},
                {"_name": "Safari", "version": "17.0", "obtained_from": "apple"},
                {"_name": "Foo", "version": "", "obtained_from": "identified_developer"},
            ]}
        )
        fake = CommandResult(command="system_profiler", ok=True, returncode=0, stdout=sp_json)
        with patch.object(inventory, "run_command", return_value=fake):
            apps, warnings = inventory.collect_installed_apps(platform="macos")
        self.assertEqual(warnings, [])
        self.assertEqual(len(apps), 2)  # deduped Safari + Foo
        self.assertEqual(apps[0].name, "Foo")

    def test_inventory_unsupported_platform(self) -> None:
        from security_scanner import inventory

        apps, warnings = inventory.collect_installed_apps(platform="linux")
        self.assertEqual(apps, [])
        self.assertTrue(any("not supported" in w for w in warnings))

    def test_eol_result_past_date_is_eol(self) -> None:
        from datetime import date
        from security_scanner.eol_data import _result_from_payload

        result = _result_from_payload("macos", "12", {"eol": "2020-01-01", "latest": "12.7"}, date(2026, 1, 1))
        self.assertTrue(result.is_eol)
        self.assertFalse(result.support_unknown)

    def test_eol_result_future_date_supported(self) -> None:
        from datetime import date
        from security_scanner.eol_data import _result_from_payload

        result = _result_from_payload("macos", "26", {"eol": "2030-01-01"}, date(2026, 1, 1))
        self.assertFalse(result.is_eol)

    def test_eol_result_bool_and_unknown(self) -> None:
        from datetime import date
        from security_scanner.eol_data import _result_from_payload

        self.assertTrue(_result_from_payload("p", "1", {"eol": True}, date(2026, 1, 1)).is_eol)
        self.assertTrue(_result_from_payload("p", "1", {}, date(2026, 1, 1)).support_unknown)

    def test_cpe_version_matching(self) -> None:
        from security_scanner.cpe_lookup import _version_applies

        cve = {"configurations": [{"nodes": [{"cpeMatch": [
            {"criteria": "cpe:2.3:a:v:p:*:*", "versionStartIncluding": "1.0", "versionEndExcluding": "2.0"}
        ]}]}]}
        self.assertTrue(_version_applies("1.5", cve))
        self.assertFalse(_version_applies("2.0", cve))
        self.assertFalse(_version_applies("0.9", cve))

    def test_cpe_no_bounded_node_drops_cve(self) -> None:
        from security_scanner.cpe_lookup import _version_applies

        cve = {"configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:v:p:*:*"}]}]}]}
        self.assertFalse(_version_applies("1.5", cve))

    def test_cpe_exact_version_match(self) -> None:
        from security_scanner.cpe_lookup import _version_applies

        cve = {"configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:v:p:1.2.3:*"}]}]}]}
        self.assertTrue(_version_applies("1.2.3", cve))
        self.assertFalse(_version_applies("1.2.4", cve))

    def test_os_eol_finding_high_when_eol(self) -> None:
        from security_scanner.checks.host import inventory_checks
        from security_scanner.eol_data import EolResult

        result = EolResult(product="macos", cycle="12", eol_date="2020-01-01", is_eol=True)
        with patch.object(inventory_checks, "os_release", return_value=("macos", "12.7", "12")), patch(
            "security_scanner.eol_data.query_cycle_eol", return_value=(result, [])
        ):
            findings, _ = inventory_checks.os_eol_finding()
        self.assertEqual([f.rule_id for f in findings], ["host.eol.os-end-of-life"])
        self.assertEqual(findings[0].severity, "high")

    def test_dashboard_include_host_toggle(self) -> None:
        from security_scanner.checks.host.common import host_finding

        with patch(
            "security_scanner.scanner.check_host",
            return_value=([host_finding("host.x", "high", "t", "r")], []),
        ):
            with tempfile.TemporaryDirectory() as tmp:
                on = scan_directory_payload(
                    tmp, standard="local", standard_category="all", min_severity="info", include_host=True
                )
                off = scan_directory_payload(
                    tmp, standard="local", standard_category="all", min_severity="info", include_host=False
                )
        on_host = [f for f in on["findings_by_language"]["en"] if f["category"] == "host"]
        off_host = [f for f in off["findings_by_language"]["en"] if f["category"] == "host"]
        self.assertEqual(len(on_host), 1)
        self.assertEqual(len(off_host), 0)


class ReachabilityTests(unittest.TestCase):
    def test_python_import_extraction_ignores_relative(self) -> None:
        index = imported_names_from_lines(
            [
                "import os",
                "import requests",
                "from yaml import safe_load",
                "from . import local",
                "from .pkg import thing",
                "import google.protobuf",
            ],
            ".py",
        )
        self.assertEqual(index.python, frozenset({"os", "requests", "yaml", "google"}))
        self.assertEqual(index.js, frozenset())

    def test_js_import_extraction(self) -> None:
        index = imported_names_from_lines(
            [
                "import x from 'lodash';",
                'const y = require("express");',
                "import './local';",
                "import foo from '@scope/pkg';",
                "await import('axios');",
            ],
            ".ts",
        )
        self.assertEqual(index.js, frozenset({"lodash", "express", "@scope/pkg", "axios"}))
        self.assertEqual(index.python, frozenset())

    def test_pypi_import_aliases(self) -> None:
        self.assertIn("yaml", package_import_candidates("PyYAML", "PyPI"))
        self.assertIn("bs4", package_import_candidates("beautifulsoup4", "PyPI"))
        self.assertIn("dateutil", package_import_candidates("python-dateutil", "PyPI"))

    def test_annotate_marks_reachable_and_unreachable(self) -> None:
        component = DependencyComponent("jinja2", "PyPI", "2.4.1", Path("requirements.txt"), target="t", line=1)
        finding = Finding(
            rule_id="dependency.osv-known-vulnerability",
            category="dependencies",
            severity="high",
            title="vuln",
            path=Path("requirements.txt"),
            target="t",
            line=1,
        )
        reachable = annotate_reachability([finding], (component,), ImportIndex(python=frozenset({"jinja2"})))
        self.assertEqual(reachable[0].reachable, "reachable")
        unreachable = annotate_reachability([finding], (component,), ImportIndex(python=frozenset({"os"})))
        self.assertEqual(unreachable[0].reachable, "unreachable")

    def test_annotate_unknown_when_language_not_analyzed(self) -> None:
        component = DependencyComponent("jinja2", "PyPI", "2.4.1", Path("requirements.txt"), target="t", line=1)
        finding = Finding(
            rule_id="dependency.osv-known-vulnerability",
            category="dependencies",
            severity="high",
            title="vuln",
            path=Path("requirements.txt"),
            target="t",
            line=1,
        )
        # Only JS imports were collected, so the Python verdict stays unknown (never downgraded).
        result = annotate_reachability([finding], (component,), ImportIndex(js=frozenset({"lodash"})))
        self.assertEqual(result[0].reachable, "unknown")

    def test_annotate_leaves_non_osv_findings_untouched(self) -> None:
        finding = Finding(
            rule_id="dependency.missing-lockfile",
            category="dependencies",
            severity="low",
            title="x",
            path=Path("package.json"),
            target="t",
            line=1,
        )
        result = annotate_reachability([finding], (), ImportIndex(python=frozenset({"os"})))
        self.assertEqual(result[0].reachable, "")

    def test_scanner_labels_unreachable_dependency(self) -> None:
        reachable = self._scan_osv_with_app("import os\nprint(os.getcwd())\n")
        self.assertEqual(reachable, "unreachable")

    def test_scanner_labels_reachable_dependency(self) -> None:
        reachable = self._scan_osv_with_app("import jinja2\nprint(jinja2.__version__)\n")
        self.assertEqual(reachable, "reachable")

    def test_reachability_off_leaves_findings_unlabelled(self) -> None:
        reachable = self._scan_osv_with_app("import os\n", enable_reachability=False)
        self.assertEqual(reachable, "")

    def test_reachable_only_gate_excludes_unreachable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("jinja2==2.4.1\n", encoding="utf-8")
            (root / "app.py").write_text("import os\n", encoding="utf-8")

            with patch("security_scanner.scanner.query_osv_findings", side_effect=_fake_osv_high_jinja2):
                with redirect_stdout(io.StringIO()):
                    blocked = cli_main(
                        ["scan", "--target", str(root), "--category", "dependencies",
                         "--enable-osv", "--reachability", "--fail-on", "high"]
                    )
                    allowed = cli_main(
                        ["scan", "--target", str(root), "--category", "dependencies",
                         "--enable-osv", "--reachability", "--reachable-only", "--fail-on", "high"]
                    )
        self.assertEqual(blocked, 1)
        self.assertEqual(allowed, 0)

    def _scan_osv_with_app(self, app_source: str, *, enable_reachability: bool = True) -> str:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("jinja2==2.4.1\n", encoding="utf-8")
            (root / "app.py").write_text(app_source, encoding="utf-8")
            config = ScannerConfig(
                targets=(TargetConfig(name="t", path=root, categories=("dependencies",)),),
                enable_osv=True,
                enable_reachability=enable_reachability,
            )
            with patch("security_scanner.scanner.query_osv_findings", side_effect=_fake_osv_high_jinja2):
                findings = SecurityScanner(config).scan()
        osv = [finding for finding in findings if finding.rule_id == "dependency.osv-known-vulnerability"]
        self.assertEqual(len(osv), 1)
        return osv[0].reachable


def _fake_osv_high_jinja2(components, **kwargs):
    component = next(component for component in components if component.name == "jinja2")
    return (
        [
            Finding(
                rule_id="dependency.osv-known-vulnerability",
                category="dependencies",
                severity="high",
                title="Known vulnerable dependency reported by OSV",
                path=Path(component.path),
                target=component.target,
                line=component.line,
                evidence="PyPI jinja2@2.4.1: GHSA-test",
            )
        ],
        [],
    )


class _FakeHTTPResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._payload

    def __enter__(self) -> "_FakeHTTPResponse":
        return self

    def __exit__(self, *args) -> bool:
        return False


class AIProviderTests(unittest.TestCase):
    def test_resolve_model_requires_configuration(self) -> None:
        with patch.dict(os.environ, {"KODA_LLM": ""}, clear=False):
            with self.assertRaises(LLMUnavailable):
                ai_provider.resolve_model()

    def test_complete_rejects_unsupported_backend(self) -> None:
        with self.assertRaises(LLMUnavailable):
            ai_provider.complete("hello", model="madeup/model-x")

    def test_complete_rejects_spec_without_model_name(self) -> None:
        with self.assertRaises(LLMUnavailable):
            ai_provider.complete("hello", model="ollama")

    def test_ollama_backend_uses_local_urllib_without_external_transfer(self) -> None:
        with patch(
            "security_scanner.ai.provider.urllib.request.urlopen",
            return_value=_FakeHTTPResponse({"response": "hello"}),
        ):
            result = ai_provider.complete("hi", model="ollama/qwen2.5-coder:7b")
        self.assertEqual(result.text, "hello")
        self.assertEqual(result.backend, "ollama")
        self.assertFalse(result.sent_externally)

    def test_ollama_backend_failure_raises_unavailable(self) -> None:
        with patch(
            "security_scanner.ai.provider.urllib.request.urlopen",
            side_effect=OSError("connection refused"),
        ):
            with self.assertRaises(LLMUnavailable):
                ai_provider.complete("hi", model="ollama/qwen2.5-coder:7b")


class AITriageTests(unittest.TestCase):
    def _finding(self, **overrides) -> Finding:
        base = dict(
            rule_id="code.eval-usage",
            category="code",
            severity="high",
            title="Use of eval",
            path=Path("does-not-exist.py"),
            target="t",
            line=1,
        )
        base.update(overrides)
        return Finding(**base)

    def test_triage_annotates_and_preserves_severity(self) -> None:
        def fake_complete(prompt, **kwargs):
            return LLMResult(
                text='{"verdict": "likely_true", "confidence": 0.9, "note": "reaches eval"}',
                backend="ollama",
                sent_externally=False,
            )

        out, warnings = ai_triage.triage_findings([self._finding()], complete=fake_complete)
        self.assertEqual(out[0].triage_verdict, "likely_true")
        self.assertEqual(out[0].triage_confidence, 0.9)
        self.assertEqual(out[0].triage_note, "reaches eval")
        self.assertEqual(out[0].severity, "high")
        self.assertEqual(warnings, [])

    def test_triage_warns_once_on_external_backend(self) -> None:
        def fake_complete(prompt, **kwargs):
            return LLMResult(
                text='{"verdict": "likely_false", "confidence": 0.1, "note": "test stub"}',
                backend="anthropic",
                sent_externally=True,
            )

        _, warnings = ai_triage.triage_findings(
            [self._finding(), self._finding(rule_id="code.other")], complete=fake_complete
        )
        external = [warning for warning in warnings if "external network call" in warning]
        self.assertEqual(len(external), 1)

    def test_triage_does_not_send_raw_secret_material(self) -> None:
        captured: dict[str, str] = {}

        def fake_complete(prompt, **kwargs):
            captured["prompt"] = prompt
            return LLMResult(
                text='{"verdict": "likely_false", "confidence": 0.2, "note": "placeholder"}',
                backend="ollama",
                sent_externally=False,
            )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret_value = "sk-" + "abcdefghijklmnopqrstuvwxyz0123"
            env_file = root / ".env"
            env_file.write_text(f"OPENAI_API_KEY={secret_value}\n", encoding="utf-8")
            finding = self._finding(
                rule_id="secret.openai-key",
                category="secrets",
                path=env_file,
                evidence="OPENAI_API_KEY=<redacted>",
            )
            ai_triage.triage_findings([finding], complete=fake_complete)

        self.assertIn("prompt", captured)
        self.assertNotIn(secret_value, captured["prompt"])

    def test_triage_stops_and_warns_when_backend_unavailable(self) -> None:
        def fake_complete(prompt, **kwargs):
            raise LLMUnavailable("ollama is not running")

        out, warnings = ai_triage.triage_findings([self._finding()], complete=fake_complete)
        self.assertEqual(out[0].triage_verdict, "")
        self.assertTrue(any("AI triage skipped" in warning for warning in warnings))

    def test_triage_handles_unparseable_response(self) -> None:
        def fake_complete(prompt, **kwargs):
            return LLMResult(text="sorry, I cannot help", backend="ollama", sent_externally=False)

        out, warnings = ai_triage.triage_findings([self._finding()], complete=fake_complete)
        self.assertEqual(out[0].triage_verdict, "")
        self.assertTrue(any("could not parse" in warning for warning in warnings))

    def test_scanner_ai_triage_labels_findings(self) -> None:
        def fake_complete(prompt, **kwargs):
            return LLMResult(
                text='{"verdict": "likely_true", "confidence": 0.8, "note": "real key"}',
                backend="ollama",
                sent_externally=False,
            )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env").write_text("OPENAI_API_KEY=sk-" + "x" * 30 + "\n", encoding="utf-8")
            config = ScannerConfig(
                targets=(TargetConfig(name="t", path=root, categories=("secrets",)),),
                enable_ai_triage=True,
            )
            with patch("security_scanner.ai.provider.complete", side_effect=fake_complete):
                findings = SecurityScanner(config).scan()

        secrets = [finding for finding in findings if finding.category == "secrets"]
        self.assertTrue(secrets)
        self.assertTrue(all(finding.triage_verdict == "likely_true" for finding in secrets))
        self.assertTrue(all(finding.severity != "" for finding in secrets))

    def test_scanner_ai_triage_off_leaves_findings_unlabelled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env").write_text("OPENAI_API_KEY=sk-" + "x" * 30 + "\n", encoding="utf-8")
            config = ScannerConfig(
                targets=(TargetConfig(name="t", path=root, categories=("secrets",)),),
            )
            findings = SecurityScanner(config).scan()

        secrets = [finding for finding in findings if finding.category == "secrets"]
        self.assertTrue(secrets)
        self.assertTrue(all(finding.triage_verdict == "" for finding in secrets))


class AutoFixTests(unittest.TestCase):
    def test_fix_weak_hash_rewrites_qualified_calls_only(self) -> None:
        self.assertEqual(fixes_deterministic.fix_weak_hash("h = hashlib.md5(d)"), "h = hashlib.sha256(d)")
        self.assertEqual(fixes_deterministic.fix_weak_hash("h = digest.sha1(d)"), "h = digest.sha256(d)")
        self.assertIsNone(fixes_deterministic.fix_weak_hash("h = sha256(d)"))
        self.assertIsNone(fixes_deterministic.fix_weak_hash("value = 1"))

    def test_fix_yaml_load_respects_existing_loader(self) -> None:
        self.assertEqual(fixes_deterministic.fix_yaml_load("c = yaml.load(s)"), "c = yaml.safe_load(s)")
        self.assertIsNone(fixes_deterministic.fix_yaml_load("c = yaml.load(s, Loader=yaml.SafeLoader)"))
        self.assertIsNone(fixes_deterministic.fix_yaml_load("c = yaml.safe_load(s)"))

    def test_plan_render_and_apply_with_backup_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "app.py"
            src.write_text(
                "import hashlib, yaml\n"
                "h = hashlib.md5(b'x').hexdigest()\n"
                "c = yaml.load('a: 1')\n",
                encoding="utf-8",
            )
            plans, warnings = fixes_apply.plan_fixes(_scan(root, categories=("code",)))
            self.assertEqual(warnings, [])
            self.assertEqual(len(plans), 1)
            self.assertEqual(len(plans[0].fixes), 2)

            diff = fixes_apply.render_diff(plans)
            self.assertIn("hashlib.sha256(", diff)
            self.assertIn("yaml.safe_load(", diff)
            # Planning/rendering must not modify the file.
            self.assertIn("hashlib.md5(", src.read_text(encoding="utf-8"))

            result = fixes_apply.apply_plans(plans)
            self.assertEqual(result.skipped, [])
            self.assertEqual(len(result.applied), 1)
            updated = src.read_text(encoding="utf-8")
            self.assertIn("hashlib.sha256(", updated)
            self.assertIn("yaml.safe_load(", updated)
            self.assertNotIn("hashlib.md5(", updated)
            self.assertTrue((root / "app.py.bak").exists())

            # Re-scanning the fixed tree yields nothing more to fix.
            plans_again, _ = fixes_apply.plan_fixes(_scan(root, categories=("code",)))
            self.assertEqual(plans_again, [])

    def test_apply_skips_when_fix_would_break_python_syntax(self) -> None:
        from security_scanner.fixes.apply import FilePlan, LineFix, apply_plans

        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "broken.py"
            src.write_text("x = 1\n", encoding="utf-8")
            plan = FilePlan(
                path=src,
                fixes=[LineFix(line=1, rule_id="x", original="x = 1", fixed="x = (")],
                original_text="x = 1\n",
                fixed_text="x = (\n",
            )
            result = apply_plans([plan])

            self.assertIn(src, result.skipped)
            self.assertEqual(result.applied, [])
            self.assertEqual(src.read_text(encoding="utf-8"), "x = 1\n")
            self.assertTrue(any("syntax" in warning for warning in result.warnings))

    def test_cli_fix_dry_run_does_not_write_then_apply_does(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "app.py"
            src.write_text("import hashlib\nh = hashlib.md5(b'x')\n", encoding="utf-8")

            with redirect_stdout(io.StringIO()):
                dry_code = cli_main(["fix", "--target", str(root)])
            self.assertEqual(dry_code, 0)
            self.assertIn("hashlib.md5(", src.read_text(encoding="utf-8"))

            with redirect_stdout(io.StringIO()):
                apply_code = cli_main(["fix", "--target", str(root), "--apply"])
            self.assertEqual(apply_code, 0)
            self.assertIn("hashlib.sha256(", src.read_text(encoding="utf-8"))


def _git(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=str(root), capture_output=True, text=True, check=True)


def _init_git_repo(root: Path) -> None:
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "test@example.com")
    _git(root, "config", "user.name", "Test")
    _git(root, "config", "commit.gpgsign", "false")


class DiffScopeTests(unittest.TestCase):
    def test_changed_files_lists_modified_and_excludes_unchanged(self) -> None:
        from security_scanner.git_changes import changed_files

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _init_git_repo(root)
            (root / "a.py").write_text("x = 1\n", encoding="utf-8")
            (root / "b.py").write_text("y = 2\n", encoding="utf-8")
            _git(root, "add", "-A")
            _git(root, "commit", "-q", "-m", "base")
            base = _git(root, "rev-parse", "HEAD").stdout.strip()
            (root / "a.py").write_text("x = 99\n", encoding="utf-8")
            _git(root, "add", "-A")
            _git(root, "commit", "-q", "-m", "change a")

            changed, warnings = changed_files(base, root)

        self.assertIsNotNone(changed)
        self.assertIn((root / "a.py").resolve(), changed)
        self.assertNotIn((root / "b.py").resolve(), changed)
        self.assertEqual(warnings, [])

    def test_changed_files_requires_base(self) -> None:
        from security_scanner.git_changes import changed_files

        with tempfile.TemporaryDirectory() as tmp:
            changed, warnings = changed_files("", Path(tmp))
        self.assertIsNone(changed)
        self.assertTrue(any("requires --base" in warning for warning in warnings))

    def test_changed_files_outside_git_repo_returns_none(self) -> None:
        from security_scanner.git_changes import changed_files

        with tempfile.TemporaryDirectory() as tmp:
            changed, warnings = changed_files("main", Path(tmp))
        self.assertIsNone(changed)
        self.assertTrue(any("git repository" in warning for warning in warnings))

    def test_scanner_changed_only_scopes_to_changed_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.env").write_text("OPENAI_API_KEY=sk-" + "x" * 30 + "\n", encoding="utf-8")
            (root / "b.env").write_text("OPENAI_API_KEY=sk-" + "y" * 30 + "\n", encoding="utf-8")
            changed = {(root / "a.env").resolve()}
            config = ScannerConfig(
                targets=(TargetConfig(name="t", path=root, categories=("secrets",)),),
                changed_only=True,
                diff_base="origin/main",
            )
            with patch("security_scanner.git_changes.changed_files", return_value=(changed, [])):
                findings = SecurityScanner(config).scan()

        scanned = {finding.path.resolve() for finding in findings}
        self.assertIn((root / "a.env").resolve(), scanned)
        self.assertNotIn((root / "b.env").resolve(), scanned)

    def test_scanner_changed_only_falls_back_when_git_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.env").write_text("OPENAI_API_KEY=sk-" + "x" * 30 + "\n", encoding="utf-8")
            (root / "b.env").write_text("OPENAI_API_KEY=sk-" + "y" * 30 + "\n", encoding="utf-8")
            config = ScannerConfig(
                targets=(TargetConfig(name="t", path=root, categories=("secrets",)),),
                changed_only=True,
                diff_base="origin/main",
            )
            with patch(
                "security_scanner.git_changes.changed_files",
                return_value=(None, ["git diff failed; scanning all files instead."]),
            ):
                scanner = SecurityScanner(config)
                findings = scanner.scan()

        scanned = {finding.path.resolve() for finding in findings}
        self.assertIn((root / "a.env").resolve(), scanned)
        self.assertIn((root / "b.env").resolve(), scanned)
        self.assertTrue(any("scanning all files" in warning for warning in scanner.warnings))


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
