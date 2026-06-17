from __future__ import annotations

import fnmatch
import os
from dataclasses import replace
from pathlib import Path
from typing import Callable

from . import git_changes, reachability
from .checks import code_patterns, configuration, dependencies, prevention, secrets
from .checks.common import clear_read_text_cache, normalized_relpath, read_text_lines
from .checks.host import HostScanOptions, check_host
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
        self._python_imports: set[str] = set()
        self._js_imports: set[str] = set()

    def scan(self) -> list[Finding]:
        clear_read_text_cache()
        findings: list[Finding] = []
        components: list[DependencyComponent] = []
        self.effective_targets = self._expand_targets()
        for target in self.effective_targets:
            target_findings, target_components = self._scan_target(target)
            components.extend(target_components)
            findings.extend(target_findings)
        findings.extend(self._scan_host())
        self.components = unique_components(components)
        if self.config.enable_reachability:
            index = reachability.ImportIndex(
                python=frozenset(self._python_imports),
                js=frozenset(self._js_imports),
            )
            findings = reachability.annotate_reachability(findings, tuple(components), index)
        if self.config.enable_ai_triage:
            from .ai import triage as ai_triage

            findings, triage_warnings = ai_triage.triage_findings(
                findings,
                model=self.config.llm_model,
                language=self.config.report.language,
            )
            self.warnings.extend(triage_warnings)
        return sorted(findings, key=lambda finding: finding.sort_key())

    def _changed_files(self, target: TargetConfig) -> set[Path] | None:
        if not self.config.changed_only:
            return None
        changed, warnings = git_changes.changed_files(self.config.diff_base, target.path)
        self.warnings.extend(warnings)
        return changed

    def _collect_imports(self, path: Path, target: TargetConfig) -> None:
        if not self.config.enable_reachability or not reachability.is_analyzable(path.suffix):
            return
        lines = read_text_lines(path, target.max_file_size_bytes)
        if lines is None:
            return
        index = reachability.imported_names_from_lines(lines, path.suffix)
        self._python_imports |= index.python
        self._js_imports |= index.js

    def _scan_host(self) -> list[Finding]:
        host_targets = [target for target in self.effective_targets if "host" in target.categories]
        if not host_targets:
            return []
        options = HostScanOptions(
            enable_inventory=self.config.enable_host_inventory,
            enable_eol=self.config.enable_host_eol,
            enable_cve=self.config.enable_host_cve,
            nvd_api_key=self.config.nvd_api_key,
        )
        host_findings, warnings = check_host(options=options)
        self.warnings.extend(warnings)
        if not host_findings:
            return []
        target_name = host_targets[0].name
        tagged = [
            replace(finding, target=target_name) if not finding.target else finding
            for finding in host_findings
        ]
        filtered, ignored = filter_ignored_findings(tagged, host_targets[0].path)
        if ignored:
            self.warnings.append(f"Ignored {ignored} host finding(s) using KODA ignore rules")
        return filtered

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
            self._collect_imports(target.path, target)
            findings.extend(self._osv_findings(components))
            filtered, ignored = filter_ignored_findings(findings, target.path.parent)
            if ignored:
                self.warnings.append(f"Ignored {ignored} finding(s) using KODA ignore rules for: {target.path.parent}")
            return filtered, components

        findings: list[Finding] = []
        components: list[DependencyComponent] = []
        scanned_files: list[Path] = []
        changed = self._changed_files(target)
        filtering = self.config.changed_only and changed is not None
        for file_path in self._iter_files(target):
            if filtering and file_path.resolve() not in changed:
                continue
            scanned_files.append(file_path)
            file_components = self._components_from_file(file_path, target)
            components.extend(file_components)
            findings.extend(self._scan_file(file_path, target))
            self._collect_imports(file_path, target)
        # Project-level prevention reasons over the whole project; skip it while diff-scoping
        # so a partial file list does not produce spurious "missing control" findings.
        if "prevention" in target.categories and not filtering:
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
            check = CHECKS.get(category)
            if check is None:  # e.g. "host" is not file-based; handled in _scan_host
                continue
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
