"""Git diff-scope helpers for CI (opt-in).

When ``--changed-only --base <ref>`` is used, KODA scans only the files changed versus a
base ref instead of the whole tree — the common pattern for fast per-pull-request checks.

This uses only the standard library (``subprocess`` calling ``git``). Any problem
(no git, base ref missing, shallow checkout) returns ``None`` so the caller falls back to a
normal full scan rather than silently hiding findings.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


def _run_git(args: list[str], cwd: Path, timeout_seconds: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )


def repo_root(target: Path, *, timeout_seconds: float = 30.0) -> Path | None:
    try:
        result = _run_git(["rev-parse", "--show-toplevel"], target, timeout_seconds)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    top = result.stdout.strip()
    return Path(top) if top else None


def changed_files(
    base_ref: str | None,
    target: Path,
    *,
    timeout_seconds: float = 30.0,
) -> tuple[set[Path] | None, list[str]]:
    """Return resolved absolute paths changed since ``base_ref`` (excluding deletions).

    ``None`` signals "could not determine a diff" so the caller scans everything; an empty
    set is a valid "nothing changed" result.
    """
    base = (base_ref or "").strip()
    if not base:
        return None, ["--changed-only requires --base <ref>; scanning all files instead."]

    root = repo_root(target, timeout_seconds=timeout_seconds)
    if root is None:
        return None, [f"Could not find a git repository for {target}; scanning all files instead."]

    try:
        result = _run_git(
            ["diff", "--name-only", "--diff-filter=d", f"{base}...HEAD"],
            root,
            timeout_seconds,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return None, [f"git diff failed ({exc}); scanning all files instead."]

    if result.returncode != 0:
        message = result.stderr.strip() or "unknown error"
        return None, [f"git diff against '{base}' failed ({message}); scanning all files instead."]

    changed: set[Path] = set()
    for line in result.stdout.splitlines():
        relative = line.strip()
        if relative:
            changed.add((root / relative).resolve())
    return changed, []
