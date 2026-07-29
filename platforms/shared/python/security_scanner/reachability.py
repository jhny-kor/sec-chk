"""Reachability analysis for dependency findings.

KODA stays a read-only, offline-first scanner, so this module is a *pre-computed*
reachability pass (Endor-style, manifest/import based) that needs no build step and
no extra dependencies — only the standard library ``ast`` for Python and a small
regular expression for JavaScript/TypeScript.

The goal is to reduce dependency-CVE noise: if a vulnerable package is never imported
by the scanned source, the finding is labelled ``unreachable`` so it can be
deprioritised. The finding itself is never deleted — labelling is conservative and the
optional ``--reachable-only`` gate is the only place an ``unreachable`` finding is
dropped, and only when the user explicitly asks for it.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, replace

from .models import DependencyComponent, Finding


# OSV dependency findings carry this rule id (see osv_vulnerabilities.py). Only these
# package-specific findings are annotated; generic dependency hygiene findings are left
# untouched because they are not tied to a single importable package.
OSV_RULE_ID = "dependency.osv-known-vulnerability"

# Ecosystems whose import graph this module can analyse. For anything else the verdict
# stays "unknown" so we never wrongly downgrade a finding we cannot reason about.
_PYTHON_ECOSYSTEMS = {"pypi", "python"}
_JS_ECOSYSTEMS = {"npm", "node", "nodejs"}

_PY_SUFFIXES = {".py"}
_JS_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".vue", ".mjs", ".cjs"}

# Common PyPI distribution name -> import name mismatches. Keys are normalised
# (lowercase, hyphenated) distribution names; values are the modules they expose.
_PYPI_IMPORT_ALIASES: dict[str, set[str]] = {
    "pyyaml": {"yaml"},
    "beautifulsoup4": {"bs4"},
    "pillow": {"pil"},
    "scikit-learn": {"sklearn"},
    "scikit-image": {"skimage"},
    "python-dateutil": {"dateutil"},
    "python-dotenv": {"dotenv"},
    "msgpack-python": {"msgpack"},
    "pycryptodome": {"crypto"},
    "pycryptodomex": {"cryptodome"},
    "opencv-python": {"cv2"},
    "protobuf": {"google"},
    "setuptools": {"setuptools", "pkg_resources"},
    "pyjwt": {"jwt"},
    "pillow-simd": {"pil"},
    "memcached": {"memcache"},
    "websocket-client": {"websocket"},
}

# Matches the quoted module specifier after `from`, `require(`, `import(`, or a bare
# `import '...'`. Captures the specifier so we can take its top-level package name.
_JS_IMPORT_RE = re.compile(
    r"""(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(\s*|\bimport\s+)['"]([^'"\n]+)['"]"""
)


@dataclass(frozen=True)
class ImportIndex:
    """Set of top-level package names imported by the scanned source, per language."""

    python: frozenset[str] = frozenset()
    js: frozenset[str] = frozenset()

    @property
    def empty(self) -> bool:
        return not self.python and not self.js


def is_analyzable(suffix: str) -> bool:
    """Whether a file suffix carries imports this module can extract."""
    lowered = suffix.lower()
    return lowered in _PY_SUFFIXES or lowered in _JS_SUFFIXES


def imported_names_from_lines(lines: list[str], suffix: str) -> ImportIndex:
    """Extract imported top-level package names from one file's lines."""
    lowered = suffix.lower()
    if lowered in _PY_SUFFIXES:
        return ImportIndex(python=frozenset(_python_imports("\n".join(lines))))
    if lowered in _JS_SUFFIXES:
        return ImportIndex(js=frozenset(_js_imports(lines)))
    return ImportIndex()


def annotate_reachability(
    findings: list[Finding],
    components: tuple[DependencyComponent, ...] | list[DependencyComponent],
    index: ImportIndex,
) -> list[Finding]:
    """Return findings with a ``reachable`` label on dependency-CVE findings.

    Matching uses the component's (path, line) which the OSV finding mirrors, so we do
    not parse evidence strings. Findings that already carry a label, or that are not
    OSV dependency findings, are returned unchanged.
    """
    component_by_location: dict[tuple[str, int | None], DependencyComponent] = {}
    for component in components:
        component_by_location[(str(component.path), component.line)] = component

    annotated: list[Finding] = []
    for finding in findings:
        if not _is_dependency_cve(finding) or finding.reachable:
            annotated.append(finding)
            continue
        component = component_by_location.get((str(finding.path), finding.line))
        annotated.append(replace(finding, reachable=_reachable_status(component, index)))
    return annotated


def package_import_candidates(name: str, ecosystem: str) -> set[str]:
    """Candidate import names a package could expose, for membership testing."""
    raw = name.strip().lower()
    if not raw:
        return set()
    eco = ecosystem.strip().lower()
    candidates = {raw}
    if eco in _PYTHON_ECOSYSTEMS:
        normalized = raw.replace("_", "-")
        candidates.update(_PYPI_IMPORT_ALIASES.get(normalized, set()))
        candidates.add(raw.replace("-", "_"))
        candidates.add(raw.replace("-", ""))
        candidates.add(normalized.replace("-", "_"))
    elif eco in _JS_ECOSYSTEMS:
        # npm import specifiers normally equal the package name (including @scope/name).
        candidates.add(raw)
    return {candidate for candidate in candidates if candidate}


def _reachable_status(component: DependencyComponent | None, index: ImportIndex) -> str:
    if component is None:
        return "unknown"
    eco = component.ecosystem.strip().lower()
    candidates = package_import_candidates(component.name, component.ecosystem)
    if eco in _PYTHON_ECOSYSTEMS:
        if not index.python:
            return "unknown"
        return "reachable" if candidates & index.python else "unreachable"
    if eco in _JS_ECOSYSTEMS:
        if not index.js:
            return "unknown"
        return "reachable" if candidates & index.js else "unreachable"
    return "unknown"


def _is_dependency_cve(finding: Finding) -> bool:
    return finding.category == "dependencies" and finding.rule_id == OSV_RULE_ID


def _python_imports(source: str) -> set[str]:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return _python_imports_regex(source)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".", 1)[0].strip().lower()
                if top:
                    names.add(top)
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative import -> first-party code, not a dependency
                continue
            if node.module:
                top = node.module.split(".", 1)[0].strip().lower()
                if top:
                    names.add(top)
    return names


def _python_imports_regex(source: str) -> set[str]:
    names: set[str] = set()
    pattern = re.compile(r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))", re.MULTILINE)
    for module, plain in pattern.findall(source):
        target = module or plain
        if not target or target.startswith("."):
            continue
        top = target.split(".", 1)[0].strip().lower()
        if top:
            names.add(top)
    return names


def _js_imports(lines: list[str]) -> set[str]:
    names: set[str] = set()
    for match in _JS_IMPORT_RE.finditer("\n".join(lines)):
        spec = match.group(1).strip()
        if not spec or spec.startswith("."):  # relative path -> first-party module
            continue
        if spec.startswith("@"):
            parts = spec.split("/")
            names.add("/".join(parts[:2]).lower())
        else:
            names.add(spec.split("/", 1)[0].lower())
    return names
