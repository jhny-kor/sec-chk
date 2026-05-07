from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from .models import CATEGORIES, SEVERITIES, ReportConfig, ScannerConfig, TargetConfig


SUPPORTED_LANGUAGES = {"en", "ko"}


class ConfigError(ValueError):
    """Raised when scanner configuration is invalid."""


def load_config(path: Path) -> ScannerConfig:
    config_path = path.expanduser().resolve()
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON config {config_path}: {exc}") from exc
    return config_from_dict(raw, base_dir=config_path.parent)


def config_from_dict(raw: dict[str, Any], base_dir: Path | None = None) -> ScannerConfig:
    base = base_dir or Path.cwd()
    targets_raw = raw.get("targets")
    if not isinstance(targets_raw, list) or not targets_raw:
        raise ConfigError("Config must define a non-empty 'targets' list.")

    targets = tuple(_target_from_dict(item, base) for item in targets_raw)
    report = _report_from_dict(raw.get("report", {}), base)
    enable_osv = bool(raw.get("enable_osv", False))
    return ScannerConfig(targets=targets, report=report, enable_osv=enable_osv)


def _target_from_dict(raw: dict[str, Any], base_dir: Path) -> TargetConfig:
    if not isinstance(raw, dict):
        raise ConfigError("Each target must be an object.")

    path_value = raw.get("path")
    if not isinstance(path_value, str) or not path_value.strip():
        raise ConfigError("Each target requires a non-empty string 'path'.")

    target_path = expand_path(path_value, base_dir)
    name = raw.get("name") or target_path.name or str(target_path)
    categories = _normalize_categories(raw.get("categories", CATEGORIES))
    exclude_globs = tuple(str(item) for item in raw.get("exclude_globs", ()))
    max_file_size_bytes = int(raw.get("max_file_size_bytes", 524288))
    if max_file_size_bytes <= 0:
        raise ConfigError("max_file_size_bytes must be positive.")
    discover_projects = bool(raw.get("discover_projects", False))
    discovery_depth = int(raw.get("discovery_depth", 2))
    if discovery_depth < 0:
        raise ConfigError("discovery_depth must be zero or greater.")

    return TargetConfig(
        name=str(name),
        path=target_path,
        categories=categories,
        exclude_globs=exclude_globs,
        max_file_size_bytes=max_file_size_bytes,
        discover_projects=discover_projects,
        discovery_depth=discovery_depth,
    )


def _report_from_dict(raw: dict[str, Any], base_dir: Path) -> ReportConfig:
    if not isinstance(raw, dict):
        raise ConfigError("'report' must be an object when present.")

    report_format = str(raw.get("format", "markdown")).lower()
    if report_format not in {"markdown", "json", "html", "sarif", "cyclonedx"}:
        raise ConfigError("report.format must be 'markdown', 'json', 'html', 'sarif', or 'cyclonedx'.")

    min_severity = str(raw.get("min_severity", "low")).lower()
    if min_severity not in SEVERITIES:
        raise ConfigError(f"Unknown min_severity: {min_severity}")

    language = str(raw.get("language", "en")).lower()
    if language not in SUPPORTED_LANGUAGES:
        raise ConfigError("report.language must be 'en' or 'ko'.")

    output_raw = raw.get("output")
    output = expand_path(output_raw, base_dir) if isinstance(output_raw, str) else None
    return ReportConfig(format=report_format, output=output, min_severity=min_severity, language=language)


def _normalize_categories(raw: Any) -> tuple[str, ...]:
    if raw == "all":
        return CATEGORIES
    if not isinstance(raw, list | tuple):
        raise ConfigError("categories must be a list or 'all'.")

    normalized = tuple(str(item).lower() for item in raw)
    unknown = sorted(set(normalized) - set(CATEGORIES))
    if unknown:
        raise ConfigError(f"Unknown categories: {', '.join(unknown)}")
    if not normalized:
        raise ConfigError("categories must not be empty.")
    return normalized


def expand_path(value: str, base_dir: Path) -> Path:
    expanded = os.path.expandvars(os.path.expanduser(_expand_env_defaults(value)))
    path = Path(expanded)
    if not path.is_absolute():
        path = base_dir / path
    return path.resolve()


def _expand_env_defaults(value: str) -> str:
    pattern = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*):-([^}]*)\}")

    def replace(match: re.Match[str]) -> str:
        env_value = os.environ.get(match.group(1))
        return env_value if env_value else match.group(2)

    return pattern.sub(replace, value)
