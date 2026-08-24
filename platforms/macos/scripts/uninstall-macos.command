#!/bin/zsh
set -euo pipefail

INSTALL_ROOT="${KODA_INSTALL_ROOT:-${SEC_CHK_INSTALL_ROOT:-$HOME/Library/Application Support/KODA}}"
LEGACY_INSTALL_ROOT="$HOME/Library/Application Support/SecChk"
LAUNCHER_DIR="${KODA_LAUNCHER_DIR:-${SEC_CHK_LAUNCHER_DIR:-$HOME/Applications}}"
LAUNCHER_PATH="$LAUNCHER_DIR/KODA.command"
CLI_LAUNCHER_PATH="$LAUNCHER_DIR/KODA-CLI.command"
LEGACY_LAUNCHER_PATH="$LAUNCHER_DIR/SecChk.command"
LEGACY_CLI_LAUNCHER_PATH="$LAUNCHER_DIR/SecChk-CLI.command"

echo "Removing KODA shortcuts and install files."

rm -f "$LAUNCHER_PATH" "$CLI_LAUNCHER_PATH" "$LEGACY_LAUNCHER_PATH" "$LEGACY_CLI_LAUNCHER_PATH"
rm -rf "$INSTALL_ROOT" "$LEGACY_INSTALL_ROOT"

echo "KODA was removed."
read -r "?Press Enter to close." || true
