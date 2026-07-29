#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
REPO_DIR="${SCRIPT_DIR:h:h:h}"
INSTALL_ROOT="${SEC_CHK_INSTALL_ROOT:-$HOME/Library/Application Support/SecChk}"
APP_DIR="$INSTALL_ROOT/app"
VENV_DIR="$INSTALL_ROOT/.venv"
LAUNCHER_DIR="${SEC_CHK_LAUNCHER_DIR:-$HOME/Applications}"
LAUNCHER_PATH="$LAUNCHER_DIR/SecChk.command"
CLI_LAUNCHER_PATH="$LAUNCHER_DIR/SecChk-CLI.command"
UNINSTALL_PATH="$INSTALL_ROOT/Uninstall-SecChk.command"

find_python() {
  local candidates=()
  if [[ -n "${PYTHON_BIN:-}" ]]; then
    candidates+=("$PYTHON_BIN")
  fi
  candidates+=(python3 python)

  local candidate
  for candidate in "${candidates[@]}"; do
    if ! command -v "$candidate" >/dev/null 2>&1; then
      continue
    fi
    if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
      print -r -- "$candidate"
      return 0
    fi
  done
  return 1
}

PYTHON_CMD="$(find_python || true)"
if [[ -z "$PYTHON_CMD" ]]; then
  echo "Python 3.10 or newer was not found."
  echo "Install Python from https://www.python.org/downloads/macos/ and run this installer again."
  read -r "?Press Enter to close."
  exit 1
fi

echo "Installing SecChk to $INSTALL_ROOT"
mkdir -p "$INSTALL_ROOT" "$LAUNCHER_DIR"

if [[ ! -x "$VENV_DIR/bin/python" ]]; then
  "$PYTHON_CMD" -m venv "$VENV_DIR"
fi

rm -rf "$APP_DIR"
mkdir -p "$APP_DIR"

mkdir -p "$APP_DIR/security_scanner"
/usr/bin/rsync -a --delete \
  --exclude ".DS_Store" \
  --exclude "__pycache__/" \
  --exclude "*.pyc" \
  "$REPO_DIR/platforms/shared/python/security_scanner/" "$APP_DIR/security_scanner/"
for file_name in README.md pyproject.toml scanner_config.example.json scanner_config.documents.example.json; do
  if [[ -f "$REPO_DIR/platforms/shared/python/$file_name" ]]; then
    cp "$REPO_DIR/platforms/shared/python/$file_name" "$APP_DIR/$file_name"
  elif [[ -f "$REPO_DIR/$file_name" ]]; then
    cp "$REPO_DIR/$file_name" "$APP_DIR/$file_name"
  fi
done
if [[ -d "$REPO_DIR/docs" ]]; then
  mkdir -p "$APP_DIR/docs"
  /usr/bin/rsync -a --delete \
    --exclude ".DS_Store" \
    "$REPO_DIR/docs/" "$APP_DIR/docs/"
fi
cp "$SCRIPT_DIR/uninstall-macos.command" "$UNINSTALL_PATH"
chmod +x "$UNINSTALL_PATH"

cat > "$LAUNCHER_PATH" <<EOF
#!/bin/zsh
set -u

SEC_CHK_ROOT="$INSTALL_ROOT"
SEC_CHK_APP="$APP_DIR"
SEC_CHK_PY="$VENV_DIR/bin/python"

if [[ ! -x "\$SEC_CHK_PY" ]]; then
  echo "SecChk Python environment was not found."
  echo "Run install-macos.command again."
  read -r "?Press Enter to close."
  exit 1
fi

export PYTHONPATH="\$SEC_CHK_APP\${PYTHONPATH:+:\$PYTHONPATH}"
cd "\$HOME"
"\$SEC_CHK_PY" -m security_scanner app "\$@"
status=\$?
if [[ "\$status" -ne 0 ]]; then
  echo
  echo "SecChk stopped with exit code \$status."
  read -r "?Press Enter to close."
fi
exit "\$status"
EOF
chmod +x "$LAUNCHER_PATH"

cat > "$CLI_LAUNCHER_PATH" <<EOF
#!/bin/zsh
set -u

SEC_CHK_APP="$APP_DIR"
SEC_CHK_PY="$VENV_DIR/bin/python"

if [[ ! -x "\$SEC_CHK_PY" ]]; then
  echo "SecChk Python environment was not found."
  echo "Run install-macos.command again."
  exit 1
fi

export PYTHONPATH="\$SEC_CHK_APP\${PYTHONPATH:+:\$PYTHONPATH}"
"\$SEC_CHK_PY" -m security_scanner "\$@"
exit \$?
EOF
chmod +x "$CLI_LAUNCHER_PATH"

echo
echo "SecChk was installed successfully."
echo "Run it from:"
echo "  $LAUNCHER_PATH"
echo
echo "CLI launcher:"
echo "  $CLI_LAUNCHER_PATH"
echo
echo "Uninstall:"
echo "  $UNINSTALL_PATH"
echo
read -r "?Press Enter to close." || true
