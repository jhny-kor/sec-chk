"""Plan, preview, and apply deterministic fixes.

Flow: ``plan_fixes`` turns fixable findings into per-file plans (read-only); ``render_diff``
shows a unified diff for a dry run; ``apply_plans`` writes the changes only when explicitly
requested, backing up each file as ``*.bak`` and re-parsing Python to guarantee the fix did
not break syntax (rolling that file back if it would).
"""

from __future__ import annotations

import ast
import difflib
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Finding
from . import fixer_for


@dataclass(frozen=True)
class LineFix:
    line: int  # 1-based line number
    rule_id: str
    original: str
    fixed: str


@dataclass
class FilePlan:
    path: Path
    fixes: list[LineFix] = field(default_factory=list)
    original_text: str = ""
    fixed_text: str = ""


@dataclass
class ApplyResult:
    applied: list[Path] = field(default_factory=list)
    skipped: list[Path] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def plan_fixes(
    findings: list[Finding],
    *,
    rule: str | None = None,
) -> tuple[list[FilePlan], list[str]]:
    """Build per-file fix plans from fixable findings without modifying any file."""
    warnings: list[str] = []
    grouped: dict[Path, list[Finding]] = {}
    for finding in findings:
        if finding.line is None or fixer_for(finding.rule_id) is None:
            continue
        if rule and finding.rule_id != rule:
            continue
        grouped.setdefault(finding.path, []).append(finding)

    plans: list[FilePlan] = []
    for path, file_findings in sorted(grouped.items(), key=lambda item: str(item[0])):
        try:
            original = path.read_text(encoding="utf-8")
        except OSError as exc:
            warnings.append(f"Could not read {path}: {exc}")
            continue
        lines = original.splitlines(keepends=True)
        applied: list[LineFix] = []
        fixed_line_numbers: set[int] = set()
        for finding in sorted(file_findings, key=lambda item: item.line or 0):
            index = (finding.line or 0) - 1
            if index < 0 or index >= len(lines) or finding.line in fixed_line_numbers:
                continue
            fixer = fixer_for(finding.rule_id)
            if fixer is None:
                continue
            raw = lines[index]
            stripped = raw.rstrip("\n")
            newline = raw[len(stripped):]
            fixed = fixer(stripped)
            if fixed is None or fixed == stripped:
                continue
            lines[index] = fixed + newline
            applied.append(LineFix(line=finding.line, rule_id=finding.rule_id, original=stripped, fixed=fixed))
            fixed_line_numbers.add(finding.line)
        if applied:
            plans.append(
                FilePlan(path=path, fixes=applied, original_text=original, fixed_text="".join(lines))
            )
    return plans, warnings


def render_diff(plans: list[FilePlan]) -> str:
    chunks: list[str] = []
    for plan in plans:
        name = str(plan.path)
        diff = difflib.unified_diff(
            plan.original_text.splitlines(keepends=True),
            plan.fixed_text.splitlines(keepends=True),
            fromfile=f"a/{name}",
            tofile=f"b/{name}",
        )
        chunks.append("".join(diff))
    return "".join(chunks)


def apply_plans(plans: list[FilePlan], *, make_backup: bool = True) -> ApplyResult:
    result = ApplyResult()
    for plan in plans:
        if plan.path.suffix == ".py":
            try:
                ast.parse(plan.fixed_text)
            except SyntaxError as exc:
                result.warnings.append(f"Skipped {plan.path}: applying the fix would break Python syntax ({exc}).")
                result.skipped.append(plan.path)
                continue
        try:
            if make_backup:
                backup = plan.path.with_name(plan.path.name + ".bak")
                backup.write_text(plan.original_text, encoding="utf-8")
            plan.path.write_text(plan.fixed_text, encoding="utf-8")
        except OSError as exc:
            result.warnings.append(f"Could not write {plan.path}: {exc}")
            result.skipped.append(plan.path)
            continue
        result.applied.append(plan.path)
    return result
