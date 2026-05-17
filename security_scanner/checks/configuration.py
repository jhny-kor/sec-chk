from __future__ import annotations

import re
from pathlib import Path

from ..models import Finding, TargetConfig
from .common import is_text_candidate, read_text_lines


ENV_FILE_RE = re.compile(r"^\.env($|\.)")
PRIVATE_KEY_FILENAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
PRIVATE_KEY_SUFFIXES = {".pem", ".p12", ".pfx", ".key"}
DEBUG_RE = re.compile(
    r"(?i)\b(DEBUG|DJANGO_DEBUG|FLASK_DEBUG|APP_DEBUG)\b\s*[:=]\s*['\"]?(true|1|yes|on)['\"]?"
)
DEV_ENV_RE = re.compile(r"(?i)\b(NODE_ENV|FLASK_ENV|APP_ENV)\b\s*[:=]\s*['\"]?development['\"]?")
DEV_ENV_CONFIG_SUFFIXES = {".cfg", ".conf", ".config", ".env", ".ini", ".json", ".properties", ".toml", ".yaml", ".yml"}
DEV_ENV_CONFIG_NAMES = {"Dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
K8S_FILE_NAMES = {
    "deployment.yml",
    "deployment.yaml",
    "pod.yml",
    "pod.yaml",
    "daemonset.yml",
    "daemonset.yaml",
    "statefulset.yml",
    "statefulset.yaml",
}
WORKFLOW_PARTS = (".github", "workflows")


def check_file(path: Path, target: TargetConfig) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_check_sensitive_filenames(path))

    if is_text_candidate(path):
        lines = read_text_lines(path, target.max_file_size_bytes)
        if lines:
            findings.extend(_check_text_config(path, lines))

    if path.name == "Dockerfile" or path.name.startswith("Dockerfile."):
        findings.extend(_check_dockerfile(path, target))
    if path.name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
        findings.extend(_check_compose(path, target))
    if _looks_like_kubernetes_manifest(path):
        findings.extend(_check_kubernetes_manifest(path, target))
    if path.suffix.lower() in {".tf", ".tfvars"}:
        findings.extend(_check_terraform(path, target))
    if _looks_like_github_workflow(path):
        findings.extend(_check_github_workflow(path, target))
    return findings


def _check_sensitive_filenames(path: Path) -> list[Finding]:
    name = path.name
    lower_name = name.lower()
    findings: list[Finding] = []
    if ENV_FILE_RE.match(name) and not lower_name.endswith((".example", ".sample", ".template")):
        findings.append(
            Finding(
                rule_id="config.env-file-present",
                category="configuration",
                severity="medium",
                title="Environment file present in project tree",
                path=path,
                description="Local environment files often contain credentials or production-only settings.",
                recommendation="Keep real environment files outside repositories and commit only sanitized examples.",
            )
        )
    if name in PRIVATE_KEY_FILENAMES or path.suffix.lower() in PRIVATE_KEY_SUFFIXES:
        findings.append(
            Finding(
                rule_id="config.private-key-like-file",
                category="configuration",
                severity="high",
                title="Private-key-like file present",
                path=path,
                description="Private key material should not live inside project folders unless intentionally test-only.",
                recommendation="Move private keys to a secret store and rotate them if they were used.",
            )
        )
    return findings


def _check_text_config(path: Path, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if DEBUG_RE.search(line):
            findings.append(
                Finding(
                    rule_id="config.debug-enabled",
                    category="configuration",
                    severity="medium",
                    title="Debug mode appears enabled",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Debug mode can expose internals, stack traces, or unsafe endpoints when deployed.",
                    recommendation="Disable debug mode in shared, staging, and production configurations.",
                )
            )
        if _should_check_development_environment(path) and DEV_ENV_RE.search(line):
            findings.append(
                Finding(
                    rule_id="config.development-environment",
                    category="configuration",
                    severity="low",
                    title="Development environment flag present",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Development environment settings can weaken runtime assumptions if reused for deployment.",
                    recommendation="Separate local development configuration from deployment configuration.",
                )
            )
    return findings


def _should_check_development_environment(path: Path) -> bool:
    lower_name = path.name.lower()
    if lower_name.endswith((".example", ".sample", ".template")):
        return False
    if path.name in DEV_ENV_CONFIG_NAMES:
        return True
    if lower_name.startswith(".env"):
        return True
    return path.suffix.lower() in DEV_ENV_CONFIG_SUFFIXES


def _check_dockerfile(path: Path, target: TargetConfig) -> list[Finding]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []

    has_user = False
    findings: list[Finding] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        upper = line.upper()
        if upper.startswith("USER "):
            has_user = True
            if line.split(maxsplit=1)[1].strip() in {"0", "root"}:
                findings.append(
                    Finding(
                        rule_id="config.docker-root-user",
                        category="configuration",
                        severity="medium",
                        title="Docker image explicitly runs as root",
                        path=path,
                        line=line_number,
                        evidence=line,
                        description="Root containers increase impact when a process is compromised.",
                        recommendation="Create and run as a least-privileged user unless root is required.",
                    )
                )
        if upper.startswith("ADD ") and "http://" in line.lower():
            findings.append(
                Finding(
                    rule_id="config.docker-add-http",
                    category="configuration",
                    severity="medium",
                    title="Dockerfile ADD fetches over HTTP",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="HTTP downloads can be modified in transit during image builds.",
                    recommendation="Use HTTPS and verify artifact checksums.",
                )
            )

    if not has_user:
        findings.append(
            Finding(
                rule_id="config.docker-no-user",
                category="configuration",
                severity="low",
                title="Dockerfile does not set a non-root user",
                path=path,
                description="Images without a USER directive usually run as root by default.",
                recommendation="Add a non-root USER for runtime stages when possible.",
            )
        )
    return findings


def _check_compose(path: Path, target: TargetConfig) -> list[Finding]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []

    findings: list[Finding] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        lowered = line.lower()
        if lowered == "privileged: true":
            findings.append(
                Finding(
                    rule_id="config.compose-privileged",
                    category="configuration",
                    severity="high",
                    title="Compose service enables privileged mode",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Privileged containers have broad host access.",
                    recommendation="Remove privileged mode and grant only the specific capabilities required.",
                )
            )
        if lowered == "network_mode: host":
            findings.append(
                Finding(
                    rule_id="config.compose-host-network",
                    category="configuration",
                    severity="medium",
                    title="Compose service uses host networking",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Host networking weakens isolation and can expose local services.",
                    recommendation="Use explicit port mappings unless host networking is required.",
                )
            )
        if "/var/run/docker.sock" in lowered:
            findings.append(
                Finding(
                    rule_id="config.compose-docker-sock",
                    category="configuration",
                    severity="high",
                    title="Compose service mounts the Docker socket",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Docker socket access is effectively host-level control.",
                    recommendation="Avoid mounting the Docker socket or isolate it behind a purpose-built proxy.",
                )
            )
    return findings


def _looks_like_kubernetes_manifest(path: Path) -> bool:
    lower_name = path.name.lower()
    if lower_name in K8S_FILE_NAMES:
        return True
    if path.suffix.lower() not in {".yaml", ".yml"}:
        return False
    lowered_parts = {part.lower() for part in path.parts}
    return bool({"k8s", "kubernetes", "manifests", "helm"} & lowered_parts)


def _check_kubernetes_manifest(path: Path, target: TargetConfig) -> list[Finding]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []

    findings: list[Finding] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        lowered = line.lower()
        if lowered == "privileged: true":
            findings.append(
                Finding(
                    rule_id="config.k8s-privileged-container",
                    category="configuration",
                    severity="high",
                    title="Kubernetes container enables privileged mode",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Privileged Kubernetes containers can obtain broad host-level access.",
                    recommendation="Remove privileged mode and grant only the specific Linux capabilities that are required.",
                )
            )
        if lowered == "allowprivilegeescalation: true":
            findings.append(
                Finding(
                    rule_id="config.k8s-allow-privilege-escalation",
                    category="configuration",
                    severity="medium",
                    title="Kubernetes container allows privilege escalation",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Privilege escalation weakens container isolation.",
                    recommendation="Set allowPrivilegeEscalation: false unless a documented workload requirement exists.",
                )
            )
        if lowered == "hostnetwork: true":
            findings.append(
                Finding(
                    rule_id="config.k8s-host-network",
                    category="configuration",
                    severity="medium",
                    title="Kubernetes workload uses host networking",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Host networking bypasses normal pod network isolation.",
                    recommendation="Use pod networking and explicit Services or NetworkPolicies unless host networking is required.",
                )
            )
        if lowered == "hostpath:" or lowered.endswith(" hostpath:") or lowered.endswith("- hostpath:"):
            findings.append(
                Finding(
                    rule_id="config.k8s-hostpath-volume",
                    category="configuration",
                    severity="medium",
                    title="Kubernetes workload mounts a hostPath volume",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="hostPath volumes expose host filesystem paths to a container.",
                    recommendation="Replace hostPath with scoped PersistentVolumes or document why host access is unavoidable.",
                )
            )
    return findings


def _check_terraform(path: Path, target: TargetConfig) -> list[Finding]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []

    findings: list[Finding] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        lowered = line.lower()
        if re.search(r'\bacl\s*=\s*"(public-read|public-read-write|website)"', lowered):
            findings.append(
                Finding(
                    rule_id="config.terraform-public-storage",
                    category="configuration",
                    severity="high",
                    title="Terraform storage ACL is public",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Public storage buckets can expose data unintentionally.",
                    recommendation="Use private ACLs and explicit, reviewed public access policies only when required.",
                )
            )
        if re.search(r"\b(block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false\b", lowered):
            findings.append(
                Finding(
                    rule_id="config.terraform-public-access-block-disabled",
                    category="configuration",
                    severity="medium",
                    title="Terraform public access block is disabled",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Disabling public access block controls increases the chance of accidental exposure.",
                    recommendation="Keep public access block controls enabled unless a documented public bucket design exists.",
                )
            )
        if "0.0.0.0/0" in lowered and _nearby_admin_port(lines, line_number):
            findings.append(
                Finding(
                    rule_id="config.terraform-open-admin-port",
                    category="configuration",
                    severity="high",
                    title="Terraform security group opens admin access to the internet",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="SSH or RDP exposed to 0.0.0.0/0 is a common initial access path.",
                    recommendation="Restrict admin ports to VPN, bastion, or approved source CIDRs.",
                )
            )
    return findings


def _nearby_admin_port(lines: list[str], line_number: int) -> bool:
    start = max(0, line_number - 8)
    end = min(len(lines), line_number + 7)
    window = "\n".join(lines[start:end]).lower()
    return bool(re.search(r"\b(from_port|to_port|port)\s*=\s*(22|3389)\b", window))


def _looks_like_github_workflow(path: Path) -> bool:
    normalized = "/".join(part.lower() for part in path.parts)
    return all(part in normalized for part in WORKFLOW_PARTS) and path.suffix.lower() in {".yml", ".yaml"}


def _check_github_workflow(path: Path, target: TargetConfig) -> list[Finding]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []

    findings: list[Finding] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        lowered = line.lower()
        if lowered.startswith("pull_request_target:"):
            findings.append(
                Finding(
                    rule_id="config.github-pull-request-target",
                    category="configuration",
                    severity="medium",
                    title="GitHub Actions uses pull_request_target",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="pull_request_target runs with privileged repository context and is risky with untrusted PR code.",
                    recommendation="Use pull_request for untrusted code or strictly separate checkout/build steps from privileged operations.",
                )
            )
        if (lowered.startswith("run:") or lowered.startswith("- run:")) and "${{ github.event." in lowered:
            findings.append(
                Finding(
                    rule_id="config.github-untrusted-event-in-run",
                    category="configuration",
                    severity="medium",
                    title="GitHub Actions run step interpolates untrusted event data",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="GitHub event fields can contain attacker-controlled text in pull request workflows.",
                    recommendation="Pass event values through environment variables and quote/validate them before shell use.",
                )
            )
    return findings
