#!/bin/zsh
set -euo pipefail

INSTALL_ROOT="${SEC_CHK_INSTALL_ROOT:-$HOME/Library/Application Support/SecChk}"
LAUNCHER_DIR="${SEC_CHK_LAUNCHER_DIR:-$HOME/Applications}"
LAUNCHER_PATH="$LAUNCHER_DIR/SecChk.command"
CLI_LAUNCHER_PATH="$LAUNCHER_DIR/SecChk-CLI.command"

echo "Removing SecChk shortcuts and install files."

rm -f "$LAUNCHER_PATH" "$CLI_LAUNCHER_PATH"
rm -rf "$INSTALL_ROOT"

echo "SecChk was removed."
read -r "?Press Enter to close." || true
