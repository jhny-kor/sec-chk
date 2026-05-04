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
        if DEV_ENV_RE.search(line):
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
