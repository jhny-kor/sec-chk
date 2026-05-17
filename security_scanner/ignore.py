from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from .checks.common import normalized_relpath
from .models import Finding


IGNORE_FILENAMES = ("koda-ignore.yml", ".koda-ignore.yml")


@dataclass(frozen=True)
class IgnoreRule:
    rule: str = "*"
    path: str = "*"
    reason: str = ""
    until: str = ""

    @property
    def expired(self) -> bool:
        if not self.until:
            return False
        try:
            return date.fromisoformat(self.until) < date.today()
        except ValueError:
            return False

    def matches(self, finding: Finding, root: Path) -> bool:
        if self.expired:
            return False
        if self.rule not in {"*", finding.rule_id, finding.category}:
            return False

        raw_path = finding.path
        path_text = str(raw_path)
        try:
            path_text = normalized_relpath(raw_path, root)
        except ValueError:
            pass
        return fnmatch.fnmatch(path_text, self.path) or fnmatch.fnmatch(Path(path_text).name, self.path)


def load_ignore_rules(root: Path) -> tuple[IgnoreRule, ...]:
    for filename in IGNORE_FILENAMES:
        path = root / filename
        if path.exists():
            return tuple(_parse_ignore_rules(path.read_text(encoding="utf-8")))
    return ()


def filter_ignored_findings(findings: list[Finding], root: Path) -> tuple[list[Finding], int]:
    rules = load_ignore_rules(root)
    if not rules:
        return findings, 0

    kept: list[Finding] = []
    ignored = 0
    for finding in findings:
        if any(rule.matches(finding, root) for rule in rules):
            ignored += 1
        else:
            kept.append(finding)
    return kept, ignored


def _parse_ignore_rules(text: str) -> list[IgnoreRule]:
    rules: list[IgnoreRule] = []
    current: dict[str, str] = {}

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        stripped = line.strip()
        if not stripped or stripped == "ignore:":
            continue
        if stripped.startswith("- "):
            if current:
                rules.append(_rule_from_mapping(current))
            current = {}
            stripped = stripped[2:].strip()
            if ":" in stripped:
                key, value = stripped.split(":", 1)
                current[key.strip()] = _clean_value(value)
            continue
        if ":" in stripped and current is not None:
            key, value = stripped.split(":", 1)
            current[key.strip()] = _clean_value(value)

    if current:
        rules.append(_rule_from_mapping(current))
    return rules


def _rule_from_mapping(mapping: dict[str, str]) -> IgnoreRule:
    return IgnoreRule(
        rule=mapping.get("rule", mapping.get("rule_id", "*")) or "*",
        path=mapping.get("path", "*") or "*",
        reason=mapping.get("reason", ""),
        until=mapping.get("until", ""),
    )


def _clean_value(value: str) -> str:
    return value.strip().strip("'\"")
