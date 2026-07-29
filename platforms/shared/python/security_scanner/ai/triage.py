"""AI-assisted triage of findings (opt-in).

This is the "beyond static scanner" noise filter: an LLM labels each finding as a likely
true/false positive with a confidence and a one-line reason. Safety rules (see
docs/spec-beyond-static-scanner.md) are enforced here, not left to the model:

- **Severity is never changed.** The model only adds ``triage_*`` labels; the original
  severity (and therefore the ``--fail-on`` gate) is untouched.
- **Secrets are not sent verbatim.** For ``secrets`` findings no source snippet is built,
  so a raw key is never forwarded to a cloud backend (the redacted evidence is used).
- **Graceful degradation.** If the backend is unavailable the scan continues unlabelled;
  the first external call surfaces a one-time privacy warning.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace

from ..checks.common import read_text_lines
from ..models import Finding
from . import provider

# Cap how many findings we send per scan to bound latency and (for cloud backends) cost
# and data egress. The most severe findings are triaged first (findings arrive sorted).
DEFAULT_MAX_FINDINGS = 40
_SNIPPET_BEFORE = 3
_SNIPPET_AFTER = 3
_SNIPPET_HEAD = 10
_MAX_FILE_BYTES = 524288

_VALID_VERDICTS = {"likely_true", "likely_false", "uncertain"}

_FALSE_POSITIVE_PROMPT = (
    "You are the false-positive gate for a static-analysis finding. Look only for "
    "evidence that this finding is noise. You must NOT change the severity. Reply ONLY "
    'with JSON: {"verdict": "likely_false|uncertain", "confidence": 0.0-1.0, "note": "<=20 words"}.'
)
_TRUE_POSITIVE_PROMPT = (
    "You are the true-positive explainer for a static-analysis finding. Look only for "
    "evidence that this finding is real and exploitable. You must NOT change the severity. "
    'Reply ONLY with JSON: {"verdict": "likely_true|uncertain", "confidence": 0.0-1.0, "note": "<=20 words"}.'
)


@dataclass(frozen=True)
class _Verdict:
    verdict: str
    confidence: float | None
    note: str


def triage_findings(
    findings: list[Finding],
    *,
    complete=None,
    model: str | None = None,
    language: str = "en",
    max_findings: int = DEFAULT_MAX_FINDINGS,
    timeout_seconds: float = 30.0,
) -> tuple[list[Finding], list[str]]:
    """Return findings annotated with triage labels plus any warnings.

    ``complete`` is injectable for testing; by default it dispatches through
    :func:`security_scanner.ai.provider.complete`.
    """
    warnings: list[str] = []
    if not findings:
        return findings, warnings

    complete_fn = complete or provider.complete
    annotated = list(findings)
    budget = max_findings
    external_warned = False

    for index, finding in enumerate(annotated):
        if budget <= 0:
            break
        if not _should_triage(finding):
            continue
        prompt = _build_prompt(finding, language)
        try:
            false_positive_result = complete_fn(
                prompt,
                system=_FALSE_POSITIVE_PROMPT,
                json_mode=True,
                model=model,
                timeout_seconds=timeout_seconds,
            )
            true_positive_result = complete_fn(
                prompt,
                system=_TRUE_POSITIVE_PROMPT,
                json_mode=True,
                model=model,
                timeout_seconds=timeout_seconds,
            )
        except provider.LLMUnavailable as exc:
            warnings.append(f"AI triage skipped: {exc}")
            return annotated, warnings
        budget -= 1
        if (false_positive_result.sent_externally or true_positive_result.sent_externally) and not external_warned:
            warnings.append(
                f"AI triage sent finding context to the '{false_positive_result.backend}' backend (external network call)."
            )
            external_warned = True
        false_positive = _parse_verdict(false_positive_result.text)
        true_positive = _parse_verdict(true_positive_result.text)
        if false_positive is None or true_positive is None:
            warnings.append(f"AI triage could not parse the model response for {finding.rule_id}.")
            continue
        verdict = _combine_verdicts(false_positive, true_positive)
        annotated[index] = replace(
            finding,
            triage_verdict=verdict.verdict,
            triage_confidence=verdict.confidence,
            triage_note=verdict.note,
        )
    return annotated, warnings


def _combine_verdicts(false_positive: _Verdict, true_positive: _Verdict) -> _Verdict:
    if false_positive.verdict == "likely_false" and true_positive.verdict == "likely_true":
        confidence_values = [
            value for value in (false_positive.confidence, true_positive.confidence) if value is not None
        ]
        confidence = min(confidence_values) if confidence_values else None
        return _Verdict(verdict="uncertain", confidence=confidence, note="FP and TP chains disagree")
    if false_positive.verdict == "likely_false":
        return false_positive
    if true_positive.verdict == "likely_true":
        return true_positive
    confidence_values = [value for value in (false_positive.confidence, true_positive.confidence) if value is not None]
    confidence = max(confidence_values) if confidence_values else None
    note = false_positive.note or true_positive.note
    return _Verdict(verdict="uncertain", confidence=confidence, note=note)


def _should_triage(finding: Finding) -> bool:
    # Host posture findings are deterministic OS-state checks; triage adds little there.
    if finding.category == "host":
        return False
    return not finding.triage_verdict


def _build_prompt(finding: Finding, language: str) -> str:
    lang_line = "Answer the note in Korean." if language == "ko" else "Answer the note in English."
    parts = [
        f"Rule: {finding.rule_id}",
        f"Category: {finding.category}",
        f"Severity (do not change): {finding.severity}",
        f"Title: {finding.title}",
    ]
    if finding.evidence:
        parts.append(f"Evidence: {finding.evidence}")
    if finding.description:
        parts.append(f"Description: {finding.description[:500]}")
    snippet = _code_snippet(finding)
    if snippet:
        parts.append("Source context:\n" + snippet)
    parts.append(lang_line)
    parts.append(
        'Return JSON only: {"verdict": "likely_true|likely_false|uncertain", '
        '"confidence": 0.0-1.0, "note": "short reason"}.'
    )
    return "\n".join(parts)


def _code_snippet(finding: Finding) -> str:
    # Never forward raw secret material to a backend; the redacted evidence is enough.
    if finding.category == "secrets":
        return ""
    if finding.line is None or finding.resource:
        return ""
    path = finding.path
    try:
        if not path.is_file():
            return ""
    except OSError:
        return ""
    lines = read_text_lines(path, _MAX_FILE_BYTES)
    if not lines:
        return ""
    head = lines[:_SNIPPET_HEAD]
    start = max(0, finding.line - 1 - _SNIPPET_BEFORE)
    end = min(len(lines), finding.line + _SNIPPET_AFTER)
    window = lines[start:end]
    collected: list[str] = []
    seen: set[int] = set()
    for offset, text in enumerate(head, start=1):
        if offset not in seen:
            seen.add(offset)
            collected.append(f"{offset}: {text}")
    for position, text in enumerate(window, start=start + 1):
        if position not in seen:
            seen.add(position)
            collected.append(f"{position}: {text}")
    return "\n".join(collected)


def _parse_verdict(text: str) -> _Verdict | None:
    if not text:
        return None
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        return None
    try:
        data = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    verdict = str(data.get("verdict", "")).strip().lower()
    if verdict not in _VALID_VERDICTS:
        return None
    confidence: float | None
    try:
        confidence = max(0.0, min(1.0, float(data.get("confidence"))))
    except (TypeError, ValueError):
        confidence = None
    note = str(data.get("note", "")).strip()[:200]
    return _Verdict(verdict=verdict, confidence=confidence, note=note)
