"""PyInstaller entry point for the KODA Windows browser launcher.

This wrapper packages the existing dashboard runtime with the KODA product name.
It behaves like:
    python -m security_scanner app
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

shared_engine = Path(__file__).resolve().parents[3] / "platforms" / "shared" / "python"
if shared_engine.exists():
    sys.path.insert(0, str(shared_engine))

from security_scanner.cli import main


def _set_safe_working_directory() -> None:
    """Start from the user's home folder instead of the installer directory."""
    try:
        home = Path.home().resolve()
    except Exception:
        return

    try:
        os.chdir(home)
    except Exception:
        return


if __name__ == "__main__":
    os.environ.setdefault("KODA_DISPLAY_NAME", "KODA")
    _set_safe_working_directory()
    raise SystemExit(main(["app", *sys.argv[1:]]))
