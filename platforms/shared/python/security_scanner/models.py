from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


SECURITY_CATEGORIES = ("secrets", "dependencies", "configuration", "code", "prevention")
FILE_CATEGORIES = SECURITY_CATEGORIES + ("screen_quality",)
HOST_CATEGORIES = ("host",)
CATEGORIES = FILE_CATEGORIES + HOST_CATEGORIES
DEFAULT_CATEGORIES = SECURITY_CATEGORIES
SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {severity: index for index, severity in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    severity: str
    title: str
    path: Path
    target: str = ""
    line: int | None = None
    evidence: str = ""
    description: str = ""
    recommendation: str = ""
    # For host/endpoint findings that are not tied to a file: a stable resource
    # identifier such as "macos/system-integrity-protection". Empty for file findings.
    resource: str = ""
    # Optional reachability label for dependency findings (see reachability.py).
    # "" when not analyzed; otherwise "reachable" / "unreachable" / "unknown".
    reachable: str = ""
    # Optional AI triage labels (see ai/triage.py). Severity is never derived from these.
    # verdict: "" when not triaged; otherwise "likely_true" / "likely_false" / "uncertain".
    triage_verdict: str = ""
    triage_confidence: float | None = None
    triage_note: str = ""

    def sort_key(self) -> tuple[int, str, str, int]:
        return (
            -SEVERITY_RANK[self.severity],
            self.target,
            self.category,
            str(self.path),
            self.line or 0,
        )


@dataclass(frozen=True)
class DependencyComponent:
    name: str
    ecosystem: str
    version: str
    path: Path
    target: str = ""
    line: int | None = None
    scope: str = "required"
    source: str = ""
    purl: str = ""

    def key(self) -> tuple[str, str, str, str]:
        return (self.ecosystem.lower(), self.name.lower(), self.version, self.target)


@dataclass(frozen=True)
class TargetConfig:
    name: str
    path: Path
    categories: tuple[str, ...] = DEFAULT_CATEGORIES
    exclude_globs: tuple[str, ...] = ()
    max_file_size_bytes: int = 524288
    discover_projects: bool = False
    discovery_depth: int | None = None


@dataclass(frozen=True)
class ReportConfig:
    format: str = "markdown"
    output: Path | None = None
    min_severity: str = "low"
    language: str = "en"


@dataclass(frozen=True)
class ScannerConfig:
    targets: tuple[TargetConfig, ...]
    report: ReportConfig = ReportConfig()
    enable_osv: bool = False
    enable_vuln_intel: bool = False
    # Opt-in host inventory checks (only used when a target includes the "host" category).
    enable_host_inventory: bool = False
    enable_host_eol: bool = False
    enable_host_cve: bool = False
    nvd_api_key: str | None = None
    # Opt-in reachability analysis: annotate OSV dependency findings with whether the
    # vulnerable package is actually imported by the scanned source (see reachability.py).
    enable_reachability: bool = False
    # Opt-in AI triage of findings (see ai/triage.py). llm_model overrides the KODA_LLM
    # environment variable when set (e.g. "ollama/qwen2.5-coder:7b").
    enable_ai_triage: bool = False
    llm_model: str | None = None
    # Opt-in CI diff-scope: scan only files changed versus diff_base (see git_changes.py).
    changed_only: bool = False
    diff_base: str | None = None
