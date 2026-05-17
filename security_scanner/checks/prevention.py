from __future__ import annotations

from pathlib import Path
from typing import Iterable

from ..models import Finding, TargetConfig
from .common import normalized_relpath, read_text_lines


DEPENDENCY_MANIFEST_NAMES = {
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "requirements.txt",
    "requirements.in",
    "pyproject.toml",
    "poetry.lock",
    "Pipfile",
    "Pipfile.lock",
    "Gemfile",
    "Gemfile.lock",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "composer.json",
    "composer.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
}

SECURITY_POLICY_PATHS = {
    "SECURITY.md",
    ".github/SECURITY.md",
    "docs/SECURITY.md",
}

DEPENDENCY_AUTOMATION_PATHS = {
    ".github/dependabot.yml",
    ".github/dependabot.yaml",
    "dependabot.yml",
    "dependabot.yaml",
    "renovate.json",
    ".renovaterc",
    ".renovaterc.json",
    ".github/renovate.json",
}

SECURITY_WORKFLOW_KEYWORDS = (
    "sec-chk",
    "koda",
    "osv",
    "dependency-check",
    "dependency-track",
    "trivy",
    "grype",
    "snyk",
    "semgrep",
    "codeql",
    "gitleaks",
    "trufflehog",
    "zap",
    "bandit",
    "safety",
    "pip-audit",
    "npm audit",
)

SAST_WORKFLOW_KEYWORDS = ("codeql", "semgrep", "sonar", "bandit", "brakeman", "gosec")
SCORECARD_WORKFLOW_KEYWORDS = ("scorecard-action", "openssf/scorecard", "scorecard")
DAST_WORKFLOW_KEYWORDS = ("zap-baseline", "zaproxy", "owasp/zap", "ghcr.io/zaproxy")
DEPENDENCY_TRACK_KEYWORDS = ("dependency-track", "/api/v1/bom")
SLSA_SIGSTORE_KEYWORDS = ("slsa", "sigstore", "cosign", "provenance", "attestation", "attest")
VEX_NAMES = {"vex.json", "vex.cdx.json", "cyclonedx-vex.json", "openvex.json"}
VEX_SUFFIXES = {".json"}
BINARY_ARTIFACT_SUFFIXES = {
    ".app",
    ".apk",
    ".dmg",
    ".dll",
    ".dylib",
    ".ear",
    ".exe",
    ".msi",
    ".pkg",
    ".so",
    ".war",
}

ENV_EXAMPLE_NAMES = {
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.local.example",
    ".env.development.example",
    ".env.production.example",
}

SBOM_SUFFIXES = {".json", ".xml"}


def check_file(path: Path, target: TargetConfig) -> list[Finding]:
    del path, target
    return []


def check_project(root: Path, files: Iterable[Path], target: TargetConfig) -> list[Finding]:
    file_list = tuple(files)
    rel_paths = {normalized_relpath(path, root) for path in file_list}
    basenames = {path.name for path in file_list}
    lower_rel_paths = {rel.lower() for rel in rel_paths}
    lower_basenames = {name.lower() for name in basenames}

    findings: list[Finding] = []
    has_dependency_manifest = bool(DEPENDENCY_MANIFEST_NAMES & basenames)
    has_source_code = any(path.suffix.lower() in {".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rb", ".php", ".cs", ".swift", ".rs"} for path in file_list)
    dockerfiles = [path for path in file_list if path.name == "Dockerfile" or path.name.startswith("Dockerfile.")]
    env_files = [
        path
        for path in file_list
        if path.name == ".env" or (path.name.startswith(".env.") and not path.name.endswith((".example", ".sample", ".template")))
    ]
    workflow_files = [path for path in file_list if normalized_relpath(path, root).startswith(".github/workflows/")]
    workflow_texts = _workflow_texts(workflow_files, target)
    combined_workflow_text = "\n".join(workflow_texts)

    if (has_source_code or has_dependency_manifest) and not (SECURITY_POLICY_PATHS & rel_paths):
        findings.append(
            _finding(
                "prevention.security-policy-missing",
                "info",
                root,
                "Security policy is not documented",
                "SECURITY.md",
                "No SECURITY.md found",
                "Add SECURITY.md with supported versions, vulnerability reporting contact, and disclosure expectations.",
            )
        )

    if has_dependency_manifest and not (DEPENDENCY_AUTOMATION_PATHS & rel_paths):
        findings.append(
            _finding(
                "prevention.dependency-update-automation-missing",
                "low",
                root,
                "Dependency update automation is not configured",
                "dependency automation",
                "No Dependabot or Renovate configuration found",
                "Add Dependabot or Renovate so vulnerable and outdated dependencies are surfaced continuously.",
            )
        )

    if (has_dependency_manifest or has_source_code) and not _has_security_workflow(workflow_files, target):
        findings.append(
            _finding(
                "prevention.ci-security-scan-missing",
                "info",
                root,
                "CI security scan is not configured",
                ".github/workflows",
                "No recognized security scan workflow found",
                "Add a CI job for KODA/SecChk, CodeQL, Semgrep, OSV, Trivy, Gitleaks, ZAP baseline, or a similar security scanner.",
            )
        )

    if (has_source_code or has_dependency_manifest) and not _contains_any(combined_workflow_text, SAST_WORKFLOW_KEYWORDS):
        findings.append(
            _finding(
                "prevention.sast-workflow-missing",
                "info",
                root,
                "SAST workflow is not configured",
                ".github/workflows",
                "No CodeQL, Semgrep, or similar static analysis workflow found",
                "Add a SAST workflow such as CodeQL or Semgrep so code-level security checks run on pull requests.",
            )
        )

    if (has_source_code or has_dependency_manifest) and not _contains_any(combined_workflow_text, SCORECARD_WORKFLOW_KEYWORDS):
        findings.append(
            _finding(
                "prevention.openssf-scorecard-missing",
                "info",
                root,
                "OpenSSF Scorecard workflow is not configured",
                ".github/workflows",
                "No OpenSSF Scorecard workflow found",
                "Run OpenSSF Scorecard in CI to monitor supply-chain posture such as token permissions, pinned actions, SAST, and dependency-update automation.",
            )
        )

    if workflow_files and not _has_readonly_token_permissions(combined_workflow_text):
        findings.append(
            _finding(
                "prevention.github-token-permissions-not-readonly",
                "low",
                root,
                "GitHub Actions token permissions are not locked down",
                ".github/workflows permissions",
                "No read-only workflow token baseline found",
                "Set top-level workflow permissions to contents: read and grant write permissions only to jobs that need them.",
            )
        )

    floating_actions = _floating_github_actions(workflow_texts)
    if floating_actions:
        findings.append(
            _finding(
                "prevention.github-actions-unpinned",
                "medium",
                root,
                "GitHub Actions references are not pinned tightly",
                ".github/workflows uses",
                ", ".join(floating_actions[:5]),
                "Pin third-party GitHub Actions to immutable commit SHAs or reviewed version tags, and avoid main/master/latest references.",
            )
        )

    if (
        (has_dependency_manifest or has_source_code)
        and not _contains_any(combined_workflow_text, SLSA_SIGSTORE_KEYWORDS)
        and "docs/security/slsa_sigstore.md" not in lower_rel_paths
    ):
        findings.append(
            _finding(
                "prevention.slsa-sigstore-missing",
                "info",
                root,
                "Release signing or provenance is not configured",
                "SLSA/Sigstore",
                "No SLSA provenance, Sigstore, cosign, or attestation workflow found",
                "Add artifact signing and provenance generation for releases using Sigstore/cosign or SLSA generators.",
            )
        )

    if (
        _looks_like_web_project(file_list, basenames)
        and not _contains_any(combined_workflow_text, DAST_WORKFLOW_KEYWORDS)
        and "docs/security/zap_baseline.md" not in lower_rel_paths
    ):
        findings.append(
            _finding(
                "prevention.zap-baseline-missing",
                "info",
                root,
                "DAST baseline is not configured",
                "OWASP ZAP",
                "No OWASP ZAP baseline workflow or guide found",
                "For authorized staging URLs, add an OWASP ZAP baseline check or document the DAST handoff process.",
            )
        )

    if (
        has_dependency_manifest
        and not _contains_any(combined_workflow_text, DEPENDENCY_TRACK_KEYWORDS)
        and "docs/security/dependency_track.md" not in lower_rel_paths
    ):
        findings.append(
            _finding(
                "prevention.dependency-track-integration-missing",
                "info",
                root,
                "Dependency-Track SBOM upload is not configured",
                "Dependency-Track",
                "No Dependency-Track SBOM upload workflow found",
                "Upload release SBOMs to Dependency-Track or another SBOM analysis backend when the project has dependency manifests.",
            )
        )

    if has_dependency_manifest and not _has_vex(lower_rel_paths, lower_basenames):
        findings.append(
            _finding(
                "prevention.vex-missing",
                "info",
                root,
                "VEX document is not present",
                "VEX",
                "Dependency manifests exist but no local VEX artifact was found",
                "Generate a VEX document for reviewed dependency vulnerabilities so exploitable, fixed, and not-affected decisions are traceable.",
            )
        )

    binary_artifacts = _binary_artifacts(file_list, root)
    if binary_artifacts:
        findings.append(
            _finding(
                "prevention.binary-artifact-committed",
                "low",
                root,
                "Binary release artifact is committed",
                "binary artifacts",
                ", ".join(binary_artifacts[:5]),
                "Keep build artifacts out of source control unless they are intentionally vendored and covered by provenance, checksums, or signatures.",
            )
        )

    if env_files and not _gitignore_ignores_env(root, target):
        findings.append(
            _finding(
                "prevention.env-not-gitignored",
                "low",
                root,
                ".env files are not ignored",
                ".gitignore",
                "Environment files exist but .gitignore does not exclude them",
                "Add .env, .env.*, or an equivalent pattern to .gitignore before committing real environment files.",
            )
        )

    if env_files and not (ENV_EXAMPLE_NAMES & basenames):
        findings.append(
            _finding(
                "prevention.env-example-missing",
                "low",
                root,
                "Sanitized environment example is missing",
                ".env.example",
                "Environment files exist without a sanitized example",
                "Commit a sanitized .env.example or .env.sample and keep real values outside the repository.",
            )
        )

    if dockerfiles and ".dockerignore" not in basenames:
        findings.append(
            _finding(
                "prevention.dockerignore-missing",
                "low",
                root,
                ".dockerignore is missing",
                ".dockerignore",
                "Dockerfile exists without .dockerignore",
                "Add .dockerignore to keep secrets, VCS metadata, build output, and local files out of Docker build contexts.",
            )
        )

    if has_dependency_manifest and not _has_sbom(lower_rel_paths, lower_basenames):
        findings.append(
            _finding(
                "prevention.sbom-missing",
                "info",
                root,
                "SBOM artifact is not present",
                "sbom",
                "Dependency manifests exist but no local SBOM artifact was found",
                "Generate and retain a CycloneDX or SPDX SBOM for release builds or CI artifacts.",
            )
        )

    return findings


def _finding(
    rule_id: str,
    severity: str,
    root: Path,
    title: str,
    evidence: str,
    description: str,
    recommendation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        category="prevention",
        severity=severity,
        title=title,
        path=root,
        evidence=evidence,
        description=description,
        recommendation=recommendation,
    )


def _has_security_workflow(workflow_files: Iterable[Path], target: TargetConfig) -> bool:
    for workflow in workflow_files:
        lines = read_text_lines(workflow, target.max_file_size_bytes)
        if not lines:
            continue
        text = "\n".join(lines).lower()
        if any(keyword in text for keyword in SECURITY_WORKFLOW_KEYWORDS):
            return True
    return False


def _workflow_texts(workflow_files: Iterable[Path], target: TargetConfig) -> list[str]:
    texts: list[str] = []
    for workflow in workflow_files:
        lines = read_text_lines(workflow, target.max_file_size_bytes)
        if lines:
            texts.append("\n".join(lines).lower())
    return texts


def _contains_any(text: str, keywords: tuple[str, ...]) -> bool:
    return any(keyword in text for keyword in keywords)


def _has_readonly_token_permissions(workflow_text: str) -> bool:
    if "permissions: read-all" in workflow_text:
        return True
    if "permissions:" not in workflow_text:
        return False
    return "contents: read" in workflow_text and "write-all" not in workflow_text


def _floating_github_actions(workflow_texts: Iterable[str]) -> list[str]:
    floating: list[str] = []
    for text in workflow_texts:
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("- uses:"):
                reference = stripped.split("- uses:", 1)[1].strip().strip("'\"")
            elif stripped.startswith("uses:"):
                reference = stripped.split("uses:", 1)[1].strip().strip("'\"")
            else:
                continue
            if _is_floating_action_reference(reference):
                floating.append(reference)
    return sorted(set(floating))


def _is_floating_action_reference(reference: str) -> bool:
    if reference.startswith("./"):
        return False
    if "@" not in reference:
        return True
    ref = reference.rsplit("@", 1)[1].strip().lower()
    if ref in {"main", "master", "latest", "head"}:
        return True
    return False


def _gitignore_ignores_env(root: Path, target: TargetConfig) -> bool:
    lines = read_text_lines(root / ".gitignore", target.max_file_size_bytes)
    if not lines:
        return False
    patterns = {line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")}
    env_patterns = {".env", ".env*", ".env.*", "*.env", "**/.env", "**/.env.*"}
    return bool(patterns & env_patterns)


def _has_sbom(lower_rel_paths: set[str], lower_basenames: set[str]) -> bool:
    known_names = {"sbom.cdx.json", "bom.json", "bom.xml", "cyclonedx.json", "cyclonedx.xml", "spdx.json", "spdx.xml"}
    if known_names & lower_basenames:
        return True
    return any("sbom" in rel and Path(rel).suffix.lower() in SBOM_SUFFIXES for rel in lower_rel_paths)


def _has_vex(lower_rel_paths: set[str], lower_basenames: set[str]) -> bool:
    if VEX_NAMES & lower_basenames:
        return True
    return any("vex" in rel and Path(rel).suffix.lower() in VEX_SUFFIXES for rel in lower_rel_paths)


def _looks_like_web_project(file_list: tuple[Path, ...], basenames: set[str]) -> bool:
    if {"package.json", "vite.config.js", "next.config.js", "next.config.mjs"} & basenames:
        return True
    web_suffixes = {".html", ".jsx", ".tsx", ".php", ".vue", ".svelte"}
    web_config_names = {"nginx.conf", "httpd.conf", "apache2.conf", "web.config"}
    return any(path.suffix.lower() in web_suffixes or path.name.lower() in web_config_names for path in file_list)


def _binary_artifacts(file_list: tuple[Path, ...], root: Path) -> list[str]:
    artifacts: list[str] = []
    for path in file_list:
        if path.suffix.lower() in BINARY_ARTIFACT_SUFFIXES:
            artifacts.append(normalized_relpath(path, root))
    return sorted(artifacts)
