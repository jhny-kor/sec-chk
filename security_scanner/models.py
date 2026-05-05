from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


CATEGORIES = ("secrets", "dependencies", "configuration", "code")
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

    def sort_key(self) -> tuple[int, str, str, int]:
        return (
            -SEVERITY_RANK[self.severity],
            self.target,
            self.category,
            str(self.path),
            self.line or 0,
        )


@dataclass(frozen=True)
class TargetConfig:
    name: str
    path: Path
    categories: tuple[str, ...] = CATEGORIES
    exclude_globs: tuple[str, ...] = ()
    max_file_size_bytes: int = 524288
    discover_projects: bool = False
    discovery_depth: int = 2


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
