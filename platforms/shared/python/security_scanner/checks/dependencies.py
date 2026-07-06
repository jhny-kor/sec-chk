from __future__ import annotations

import json
import re
from pathlib import Path

from ..models import Finding, TargetConfig
from .common import find_line_containing, read_text_lines


LOCKFILES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lockb",
}

SHELL_PIPE_RE = re.compile(r"\b(curl|wget)\b.+\|\s*(sh|bash|zsh|python|ruby|node)\b", re.IGNORECASE)


def check_file(path: Path, target: TargetConfig) -> list[Finding]:
    if path.name == "package.json":
        return _check_package_json(path, target)
    if path.name in {"requirements.txt", "requirements.in"} or path.name.endswith("-requirements.txt"):
        return _check_requirements(path, target)
    if path.name == "pyproject.toml":
        return _check_pyproject(path, target)
    if path.name == "Dockerfile" or path.name.startswith("Dockerfile."):
        return _check_dockerfile(path, target)
    return []


def _check_package_json(path: Path, target: TargetConfig) -> list[Finding]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []

    try:
        data = json.loads("\n".join(lines))
    except json.JSONDecodeError as exc:
        return [
            Finding(
                rule_id="dependency.package-json-invalid",
                category="dependencies",
                severity="medium",
                title="Invalid package.json",
                path=path,
                line=exc.lineno,
                evidence=str(exc),
                description="Invalid dependency manifests can hide dependency review issues and break reproducible installs.",
                recommendation="Fix package.json syntax so dependency tooling can inspect it reliably.",
            )
        ]

    findings: list[Finding] = []
    dependency_sections = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
    has_dependencies = any(isinstance(data.get(section), dict) and data[section] for section in dependency_sections)
    if has_dependencies and not any((path.parent / lockfile).exists() for lockfile in LOCKFILES):
        findings.append(
            Finding(
                rule_id="dependency.node-missing-lockfile",
                category="dependencies",
                severity="medium",
                title="Node project has dependencies but no lockfile",
                path=path,
                description="Installs are not reproducible without a lockfile, which increases supply-chain drift risk.",
                recommendation="Commit the package manager lockfile used by this project.",
            )
        )

    for section in dependency_sections:
        deps = data.get(section, {})
        if not isinstance(deps, dict):
            continue
        for package, version in deps.items():
            if not isinstance(version, str):
                continue
            line = find_line_containing(lines, f'"{package}"')
            if version.strip() in {"*", "latest"}:
                findings.append(
                    Finding(
                        rule_id="dependency.node-unbounded-version",
                        category="dependencies",
                        severity="medium",
                        title="Unbounded Node dependency version",
                        path=path,
                        line=line,
                        evidence=f"{package}: {version}",
                        description="Unbounded dependency versions can pull unexpected code during install.",
                        recommendation="Pin the dependency to a reviewed semver range and keep the lockfile updated.",
                    )
                )
            if version.startswith("http://") or " http://" in version:
                findings.append(
                    Finding(
                        rule_id="dependency.node-insecure-url",
                        category="dependencies",
                        severity="high",
                        title="Dependency fetched over insecure HTTP",
                        path=path,
                        line=line,
                        evidence=f"{package}: {version}",
                        description="HTTP dependency sources can be modified in transit.",
                        recommendation="Use HTTPS or a trusted package registry source.",
                    )
                )

    scripts = data.get("scripts", {})
    if isinstance(scripts, dict):
        for name, command in scripts.items():
            if isinstance(command, str) and SHELL_PIPE_RE.search(command):
                findings.append(
                    Finding(
                        rule_id="dependency.remote-shell-script",
                        category="dependencies",
                        severity="high",
                        title="Package script pipes remote content into a shell",
                        path=path,
                        line=find_line_containing(lines, f'"{name}"'),
                        evidence=f"{name}: {command}",
                        description="Remote shell execution during package scripts is difficult to audit and can change without review.",
                        recommendation="Vendor the installer, verify checksums, or replace the script with explicit reviewed steps.",
                    )
                )

    return findings


def _check_requirements(path: Path, target: TargetConfig) -> list[Finding]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []

    findings: list[Finding] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(("-", "--")):
            continue
        if line.startswith("http://") or " http://" in line:
            findings.append(
                Finding(
                    rule_id="dependency.python-insecure-url",
                    category="dependencies",
                    severity="high",
                    title="Python dependency fetched over insecure HTTP",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="HTTP dependency sources can be modified in transit.",
                    recommendation="Use HTTPS or a trusted package index.",
                )
            )
        if "==" not in line and " @ " not in line and not line.startswith(("-e ", "git+")):
            findings.append(
                Finding(
                    rule_id="dependency.python-unpinned-requirement",
                    category="dependencies",
                    severity="low",
                    title="Unpinned Python requirement",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Unpinned requirements can change across installs and make dependency review less reliable.",
                    recommendation="Pin runtime dependencies in deployment requirements or use a generated lockfile.",
                )
            )
    return findings


def _check_pyproject(path: Path, target: TargetConfig) -> list[Finding]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []

    findings: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if re.search(r'=\s*["\']\*["\']', stripped):
            findings.append(
                Finding(
                    rule_id="dependency.python-wildcard-version",
                    category="dependencies",
                    severity="medium",
                    title="Wildcard Python dependency version",
                    path=path,
                    line=line_number,
                    evidence=stripped,
                    description="Wildcard dependency versions can pull unexpected code during install.",
                    recommendation="Use a reviewed version range or lockfile.",
                )
            )
    return findings


def _check_dockerfile(path: Path, target: TargetConfig) -> list[Finding]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []

    findings: list[Finding] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        upper = line.upper()
        if upper.startswith("FROM "):
            image = line.split(maxsplit=1)[1].split(" AS ", maxsplit=1)[0].strip()
            if image.endswith(":latest") or (":" not in image and "@" not in image):
                findings.append(
                    Finding(
                        rule_id="dependency.docker-unpinned-base",
                        category="dependencies",
                        severity="medium",
                        title="Docker base image is not pinned",
                        path=path,
                        line=line_number,
                        evidence=line,
                        description="Floating base image tags can change without review.",
                        recommendation="Pin to a reviewed tag or digest.",
                    )
                )
        if SHELL_PIPE_RE.search(line):
            findings.append(
                Finding(
                    rule_id="dependency.docker-remote-shell",
                    category="dependencies",
                    severity="high",
                    title="Docker build pipes remote content into a shell",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Remote shell execution in builds is difficult to audit and can change without review.",
                    recommendation="Download verified artifacts and check signatures or checksums before execution.",
                )
            )
    return findings
