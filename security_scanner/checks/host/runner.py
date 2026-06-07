"""Safe, read-only OS command runner for host/endpoint security checks.

Host checks must never run arbitrary commands. Every invocation goes through
``run_command`` which enforces an allowlist on the executable name, a timeout,
and isolates failures so a missing tool or a hung process degrades to a warning
instead of crashing the scan.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Sequence


# Allowlisted executables. Only read-only/status commands belong here. Keyed by
# the executable basename (no path) so callers cannot smuggle in a full path.
ALLOWED_COMMANDS: frozenset[str] = frozenset(
    {
        # macOS
        "csrutil",
        "fdesetup",
        "spctl",
        "socketfilterfw",
        "system_profiler",
        "softwareupdate",
        "sw_vers",
        "defaults",
        "scutil",
        # Windows
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
        # cross-platform
        "sysctl",
    }
)

DEFAULT_TIMEOUT_SECONDS = 15.0


@dataclass(frozen=True)
class CommandResult:
    """Outcome of a single command invocation."""

    command: str
    ok: bool
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    error: str = ""

    @property
    def text(self) -> str:
        """stdout stripped of trailing whitespace (convenience for parsers)."""
        return self.stdout.strip()


def run_command(
    args: Sequence[str],
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    allow: frozenset[str] | None = None,
) -> CommandResult:
    """Run an allowlisted, read-only command and capture its output.

    Never raises for expected failures (missing binary, timeout, non-zero exit);
    callers inspect ``CommandResult.ok`` / ``error`` instead.
    """

    if not args:
        return CommandResult(command="", ok=False, returncode=-1, error="empty command")

    executable = str(args[0])
    basename = executable.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
    allowlist = allow if allow is not None else ALLOWED_COMMANDS
    if basename not in allowlist:
        return CommandResult(
            command=executable,
            ok=False,
            returncode=-1,
            error=f"command not allowlisted: {basename}",
        )

    printable = " ".join(str(part) for part in args)
    try:
        completed = subprocess.run(  # noqa: S603 - args are allowlisted, shell disabled
            [str(part) for part in args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return CommandResult(command=printable, ok=False, returncode=-1, error="command not found")
    except subprocess.TimeoutExpired:
        return CommandResult(
            command=printable, ok=False, returncode=-1, timed_out=True, error="command timed out"
        )
    except OSError as exc:  # pragma: no cover - environment specific
        return CommandResult(command=printable, ok=False, returncode=-1, error=str(exc))

    return CommandResult(
        command=printable,
        ok=completed.returncode == 0,
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )


def powershell(script: str, *, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> CommandResult:
    """Run a read-only PowerShell snippet with no profile and bypass policy."""

    return run_command(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        timeout=timeout,
    )
