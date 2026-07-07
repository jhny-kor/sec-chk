from __future__ import annotations

import re
from pathlib import Path

from ..models import Finding, TargetConfig
from .common import read_text_lines


SCREEN_FILE_SUFFIXES = {".html", ".htm", ".jsp", ".jspx", ".vue", ".jsx", ".tsx"}
HTML_LIKE_SUFFIXES = {".html", ".htm", ".jsp", ".jspx"}
IMG_TAG_RE = re.compile(r"<img\b[^>]*>", re.IGNORECASE)
INPUT_TAG_RE = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
BUTTON_TAG_RE = re.compile(r"<button\b[^>]*>", re.IGNORECASE)
ANCHOR_TAG_RE = re.compile(r"<a\b[^>]*>", re.IGNORECASE)
ATTR_RE = re.compile(
    r"([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*(['\"])(.*?)\2",
    re.DOTALL,
)
LABEL_FOR_RE = re.compile(
    r"<label\b[^>]*\bfor\s*=\s*(['\"])(.*?)\1",
    re.IGNORECASE | re.DOTALL,
)
SENSITIVE_TEXT_RE = re.compile(
    r"(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*['\"][^'\"]{6,}"
)
SYSTEM_PATH_RE = re.compile(
    r"(?i)(/var/(log|www|lib)|/etc/[A-Za-z0-9_.-]+|[A-Z]:\\(?:Users|Windows|Program Files)\\)"
)


def check_file(path: Path, target: TargetConfig) -> list[Finding]:
    if path.suffix.lower() not in SCREEN_FILE_SUFFIXES:
        return []
    lines = read_text_lines(path, target.max_file_size_bytes)
    if not lines:
        return []
    text = "\n".join(lines)
    findings = _check_document(path, text)
    findings.extend(_check_lines(path, lines))
    return findings


def _check_document(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    lower = text.lower()
    if (
        path.suffix.lower() in HTML_LIKE_SUFFIXES
        and "<html" in lower
        and not re.search(r"<html\b[^>]*\blang\s*=", text, re.IGNORECASE)
    ):
        findings.append(
            _finding(
                "screen.html-lang-missing",
                "medium",
                "HTML language is not declared",
                path,
                "Add a lang attribute to the html element.",
            )
        )
    if "<head" in lower and "name=\"viewport\"" not in lower and "name='viewport'" not in lower:
        findings.append(
            _finding(
                "screen.viewport-missing",
                "medium",
                "Responsive viewport meta tag is missing",
                path,
                "Add a viewport meta tag for responsive layouts.",
            )
        )

    label_targets = {match.group(2) for match in LABEL_FOR_RE.finditer(text)}
    for match in IMG_TAG_RE.finditer(text):
        attrs = _attrs(match.group(0))
        if "alt" not in attrs:
            findings.append(
                _finding(
                    "screen.image-alt-missing",
                    "medium",
                    "Image is missing alt text",
                    path,
                    "Add meaningful alt text or alt=\"\" for decorative images.",
                )
            )
    for match in INPUT_TAG_RE.finditer(text):
        attrs = _attrs(match.group(0))
        input_type = attrs.get("type", "text").lower()
        if input_type in {"hidden", "submit", "button", "reset"}:
            continue
        has_accessible_name = (
            attrs.get("aria-label")
            or attrs.get("aria-labelledby")
            or attrs.get("title")
            or (attrs.get("id") and attrs["id"] in label_targets)
        )
        if not has_accessible_name:
            findings.append(
                _finding(
                    "screen.input-label-missing",
                    "medium",
                    "Input has no accessible label",
                    path,
                    "Connect the input to a label or add aria-label.",
                )
            )
    for match in BUTTON_TAG_RE.finditer(text):
        attrs = _attrs(match.group(0))
        if "type" not in attrs:
            findings.append(
                _finding(
                    "screen.button-type-missing",
                    "low",
                    "Button type is not explicit",
                    path,
                    "Set button type to button, submit, or reset.",
                )
            )
    for match in ANCHOR_TAG_RE.finditer(text):
        attrs = _attrs(match.group(0))
        if attrs.get("href", "").strip() in {"", "#", "javascript:void(0)"}:
            findings.append(
                _finding(
                    "screen.link-target-empty",
                    "low",
                    "Link target is empty or placeholder",
                    path,
                    "Use a real href or a button for actions.",
                )
            )
    return findings


def _check_lines(path: Path, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for index, line in enumerate(lines, start=1):
        if SENSITIVE_TEXT_RE.search(line):
            findings.append(
                _finding(
                    "screen.sensitive-text-exposed",
                    "high",
                    "Screen source appears to expose sensitive text",
                    path,
                    "Remove secrets and sensitive values from client-rendered source.",
                    index,
                )
            )
        if SYSTEM_PATH_RE.search(line):
            findings.append(
                _finding(
                    "screen.system-path-exposed",
                    "medium",
                    "Screen source exposes a system path",
                    path,
                    "Replace internal system paths with user-safe messages.",
                    index,
                )
            )
    return findings


def _attrs(tag: str) -> dict[str, str]:
    return {match.group(1).lower(): match.group(3).strip() for match in ATTR_RE.finditer(tag)}


def _finding(
    rule_id: str,
    severity: str,
    title: str,
    path: Path,
    recommendation: str,
    line: int | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        category="screen_quality",
        severity=severity,
        title=title,
        path=path,
        line=line,
        description=(
            "Screen quality checks flag markup that can break accessibility, "
            "responsive behavior, or safe public error display."
        ),
        recommendation=recommendation,
    )
