from __future__ import annotations

import fnmatch
import os
from dataclasses import replace
from pathlib import Path
from typing import Callable

from .checks import configuration, dependencies, secrets
from .checks.common import normalized_relpath
from .discovery import discover_projects
from .models import Finding, ScannerConfig, TargetConfig


DEFAULT_EXCLUDE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".cache",
    ".mypy_cache",
    ".next",
    ".omx",
    ".playwright-cli",
    ".pytest_cache",
    ".terraform",
    ".venv",
    "DerivedData",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "output",
    "reports",
    "target",
    "venv",
}

DEFAULT_EXCLUDE_GLOBS = (
    "**/.git/**",
    "**/node_modules/**",
    "**/.venv/**",
    "**/venv/**",
    "**/dist/**",
    "**/build/**",
    "**/reports/**",
    "**/.omx/**",
    "**/.playwright-cli/**",
    "**/output/**",
)

CHECKS: dict[str, Callable[[Path, TargetConfig], list[Finding]]] = {
    "secrets": secrets.check_file,
    "dependencies": dependencies.check_file,
    "configuration": configuration.check_file,
}


class SecurityScanner:
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.warnings: list[str] = []
        self.effective_targets: tuple[TargetConfig, ...] = ()

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        self.effective_targets = self._expand_targets()
        for target in self.effective_targets:
            findings.extend(self._scan_target(target))
        return sorted(findings, key=lambda finding: finding.sort_key())

    def _expand_targets(self) -> tuple[TargetConfig, ...]:
        targets: list[TargetConfig] = []
        for target in self.config.targets:
            if not target.discover_projects:
                targets.append(target)
                continue

            discovered = discover_projects(target.path, target.discovery_depth)
            if not discovered:
                self.warnings.append(f"No project markers found under: {target.path}")
                targets.append(replace(target, discover_projects=False))
                continue

            for project in discovered:
                targets.append(
                    replace(
                        target,
                        name=f"{target.name}/{project.name}",
                        path=project.path,
                        discover_projects=False,
                    )
                )
        return tuple(targets)

    def _scan_target(self, target: TargetConfig) -> list[Finding]:
        if not target.path.exists():
            self.warnings.append(f"Target does not exist: {target.path}")
            return []
        if target.path.is_file():
            return self._scan_file(target.path, target)

        findings: list[Finding] = []
        for file_path in self._iter_files(target):
            findings.extend(self._scan_file(file_path, target))
        return findings

    def _scan_file(self, path: Path, target: TargetConfig) -> list[Finding]:
        findings: list[Finding] = []
        for category in target.categories:
            check = CHECKS[category]
            findings.extend(
                replace(finding, target=target.name) if not finding.target else finding
                for finding in check(path, target)
            )
        return findings

    def _iter_files(self, target: TargetConfig):
        exclude_globs = DEFAULT_EXCLUDE_GLOBS + target.exclude_globs

        def on_error(error: OSError) -> None:
            self.warnings.append(f"Could not read {error.filename}: {error.strerror}")

        for root, dirs, files in os.walk(target.path, onerror=on_error):
            root_path = Path(root)
            dirs[:] = [
                dirname
                for dirname in dirs
                if dirname not in DEFAULT_EXCLUDE_DIRS
                and not self._matches_exclude(root_path / dirname, target.path, exclude_globs)
            ]
            for filename in files:
                file_path = root_path / filename
                if self._matches_exclude(file_path, target.path, exclude_globs):
                    continue
                yield file_path

    @staticmethod
    def _matches_exclude(path: Path, root: Path, patterns: tuple[str, ...]) -> bool:
        rel = normalized_relpath(path, root)
        name = path.name
        return any(fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(name, pattern) for pattern in patterns)
