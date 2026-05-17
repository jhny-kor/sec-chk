from __future__ import annotations

import fnmatch
import os
from dataclasses import replace
from pathlib import Path
from typing import Callable

from .checks import code_patterns, configuration, dependencies, prevention, secrets
from .checks.common import clear_read_text_cache, normalized_relpath
from .dependency_inventory import components_from_file, queryable_osv_components, unique_components
from .discovery import discover_projects
from .ignore import filter_ignored_findings
from .models import DependencyComponent, Finding, ScannerConfig, TargetConfig
from .osv_vulnerabilities import query_osv_findings


DEFAULT_EXCLUDE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".cache",
    ".build",
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
    "**/.build/**",
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
    "code": code_patterns.check_file,
    "prevention": prevention.check_file,
}


class SecurityScanner:
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.warnings: list[str] = []
        self.effective_targets: tuple[TargetConfig, ...] = ()
        self.components: tuple[DependencyComponent, ...] = ()

    def scan(self) -> list[Finding]:
        clear_read_text_cache()
        findings: list[Finding] = []
        components: list[DependencyComponent] = []
        self.effective_targets = self._expand_targets()
        for target in self.effective_targets:
            target_findings, target_components = self._scan_target(target)
            components.extend(target_components)
            findings.extend(target_findings)
        self.components = unique_components(components)
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

    def _scan_target(self, target: TargetConfig) -> tuple[list[Finding], list[DependencyComponent]]:
        if not target.path.exists():
            self.warnings.append(f"Target does not exist: {target.path}")
            return [], []
        if target.path.is_file():
            components = self._components_from_file(target.path, target)
            findings = self._scan_file(target.path, target)
            findings.extend(self._osv_findings(components))
            filtered, ignored = filter_ignored_findings(findings, target.path.parent)
            if ignored:
                self.warnings.append(f"Ignored {ignored} finding(s) using KODA ignore rules for: {target.path.parent}")
            return filtered, components

        findings: list[Finding] = []
        components: list[DependencyComponent] = []
        scanned_files: list[Path] = []
        for file_path in self._iter_files(target):
            scanned_files.append(file_path)
            file_components = self._components_from_file(file_path, target)
            components.extend(file_components)
            findings.extend(self._scan_file(file_path, target))
        if "prevention" in target.categories:
            findings.extend(
                replace(finding, target=target.name) if not finding.target else finding
                for finding in prevention.check_project(target.path, scanned_files, target)
            )
        findings.extend(self._osv_findings(components))
        filtered, ignored = filter_ignored_findings(findings, target.path)
        if ignored:
            self.warnings.append(f"Ignored {ignored} finding(s) using KODA ignore rules for: {target.path}")
        return filtered, components

    def _scan_file(self, path: Path, target: TargetConfig) -> list[Finding]:
        findings: list[Finding] = []
        for category in target.categories:
            check = CHECKS[category]
            findings.extend(
                replace(finding, target=target.name) if not finding.target else finding
                for finding in check(path, target)
            )
        return findings

    def _components_from_file(self, path: Path, target: TargetConfig) -> list[DependencyComponent]:
        if "dependencies" not in target.categories:
            return []
        return components_from_file(path, target)

    def _osv_findings(self, components: list[DependencyComponent]) -> list[Finding]:
        if not (self.config.enable_osv or self.config.enable_vuln_intel):
            return []
        queryable_components = queryable_osv_components(tuple(components))
        if not queryable_components:
            return []
        findings, warnings = query_osv_findings(queryable_components, enable_vuln_intel=self.config.enable_vuln_intel)
        self.warnings.extend(warnings)
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
