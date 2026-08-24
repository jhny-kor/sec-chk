#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
REPO_DIR="${SCRIPT_DIR:h:h:h}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

cd "$REPO_DIR"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "python3 was not found. Install Python 3.10 or newer and run this launcher again."
  read -r "?Press Enter to close."
  exit 1
fi

export PYTHONPATH="$REPO_DIR/platforms/shared/python${PYTHONPATH:+:$PYTHONPATH}"
exec "$PYTHON_BIN" -m security_scanner app "$@"
