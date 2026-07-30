"""CodeQL 2.26.1 profile contract; runtime execution is fail-closed."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .source_analysis import AnalyzerRun

PROFILE_ID = "codeql-java-none-2.26.1"
CODEQL_VERSION = "2.26.1"


@dataclass(frozen=True, slots=True)
class SandboxCapability:
    status: str = "UNVERIFIED"
    wrapper: Path | None = None
    config: Path | None = None
    reason: str = "sandbox_capability_unverified"


def preflight(
    binary: Path | None,
    *,
    sandbox: SandboxCapability | None = None,
    license_attested: bool = False,
    target: Path | None = None,
) -> AnalyzerRun:
    """Record availability without executing untrusted analyzer code.

    KODA does not currently possess a nonce-bound, process-tree and network
    confinement verifier, so runtime CodeQL execution is always refused.
    Administrators may import separately generated SARIF as positive evidence.
    """
    sandbox = sandbox or SandboxCapability()
    if not license_attested:
        return AnalyzerRun("codeql", CODEQL_VERSION, PROFILE_ID, status="SKIPPED", target=str(target or ""), failure_reason="license_not_attested")
    if sandbox.status != "VERIFIED":
        return AnalyzerRun("codeql", CODEQL_VERSION, PROFILE_ID, status="SKIPPED", target=str(target or ""), failure_reason=sandbox.reason or "sandbox_capability_unverified")
    if binary is None or not binary.is_file():
        return AnalyzerRun("codeql", CODEQL_VERSION, PROFILE_ID, status="MISSING", target=str(target or ""), failure_reason="codeql_missing")
    if not os.access(binary, os.X_OK):
        return AnalyzerRun("codeql", CODEQL_VERSION, PROFILE_ID, status="MISSING", target=str(target or ""), failure_reason="codeql_not_executable")
    return AnalyzerRun("codeql", CODEQL_VERSION, PROFILE_ID, status="SKIPPED", target=str(target or ""), failure_reason="sandbox_runtime_verifier_unavailable")


def build_command(binary: Path, wrapper: Path, wrapper_config: Path, operation: str, *args: str) -> tuple[str, ...]:
    """Pure command builder retained for administrator-side integration tests."""
    if operation not in {"version", "resolve", "database_create", "database_analyze"}:
        raise ValueError("unsupported_codeql_operation")
    return (str(wrapper), f"--config={wrapper_config}", "--", str(binary), *args)
