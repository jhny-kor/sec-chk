"""PyInstaller entry point for the SecChk browser launcher.

This wrapper makes the packaged executable behave the same as:
    python -m security_scanner app
"""
from __future__ import annotations

import sys
from pathlib import Path

shared_engine = Path(__file__).resolve().parents[3] / "platforms" / "shared" / "python"
if shared_engine.exists():
    sys.path.insert(0, str(shared_engine))

from security_scanner.cli import main


def _set_safe_working_directory() -> None:
    """Start from the user's home folder instead of the installer directory."""
    try:
        Path.home().resolve()
    except Exception:
        return

    try:
        # The dashboard uses the current working directory as a fallback scan
        # base. Starting from the user's home folder is safer than starting from
        # Program Files or the PyInstaller extraction folder.
        import os

        os.chdir(Path.home())
    except Exception:
        return


if __name__ == "__main__":
    _set_safe_working_directory()
    raise SystemExit(main(["app", *sys.argv[1:]]))
