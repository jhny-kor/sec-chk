from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class SyftResult:
    payload: dict[str, object] | None
    version: str
    warning: str
    fatal: bool


def run_syft(target: Path, binary: Path | None, timeout: float) -> SyftResult:
    if binary is None:
        return SyftResult(None, "", "Syft is not configured; using the built-in Java inventory.", False)
    validation = _validate_binary(binary)
    if validation:
        return SyftResult(None, "", validation, True)
    version_result = _run(binary, ("--version",), timeout, {})
    version = version_result.stdout.strip() if version_result.returncode == 0 else ""
    if version_result.returncode != 0:
        version_warning = f"Syft version check failed: {version_result.stderr.strip() or 'unknown error'}"
    else:
        version_warning = ""
    scan = _run(binary, (f"dir:{target}", "-o", "cyclonedx-json"), timeout, {})
    if scan.returncode != 0:
        warning = f"Syft failed; using the built-in Java inventory: {scan.stderr.strip() or 'unknown error'}"
        return SyftResult(None, version, warning, True)
    try:
        payload = json.loads(scan.stdout)
    except json.JSONDecodeError as exc:
        return SyftResult(None, version, f"Syft returned invalid JSON: {exc}", True)
    if not isinstance(payload, dict) or payload.get("bomFormat") != "CycloneDX" or not isinstance(payload.get("components"), list):
        return SyftResult(None, version, "Syft returned an invalid CycloneDX document.", True)
    return SyftResult(payload, version, version_warning, False)


def _validate_binary(binary: Path) -> str:
    if not binary.is_file():
        return f"Syft executable not found: {binary}"
    if not os.access(binary, os.X_OK):
        return f"Syft executable is not executable: {binary}"
    return ""


def _run(binary: Path, arguments: tuple[str, ...], timeout: float, extra_env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update(extra_env)
    try:
        return subprocess.run(
            [str(binary), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except FileNotFoundError:
        return subprocess.CompletedProcess([str(binary), *arguments], 127, "", f"executable not found: {binary}")
    except PermissionError:
        return subprocess.CompletedProcess([str(binary), *arguments], 126, "", f"permission denied: {binary}")
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess([str(binary), *arguments], 124, "", f"timed out after {timeout:g}s")
    except OSError as exc:
        return subprocess.CompletedProcess([str(binary), *arguments], 125, "", str(exc))
