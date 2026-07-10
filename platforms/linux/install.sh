#!/usr/bin/env bash
set -euo pipefail

prefix="${KODA_PREFIX:-$HOME/.local/share/koda-linux}"
bin_dir="${KODA_BIN_DIR:-$HOME/.local/bin}"
link_command=1

usage() {
  cat <<'EOF'
Usage: install.sh [--prefix DIR] [--bin-dir DIR] [--no-link]

Installs the Linux KODA wrapper and shared scanner source without requiring root.
Environment:
  KODA_PREFIX   install root, default ~/.local/share/koda-linux
  KODA_BIN_DIR  command link directory, default ~/.local/bin
  KODA_PYTHON   Python interpreter used by bin/koda, default python3
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --prefix)
      prefix="$2"
      shift 2
      ;;
    --bin-dir)
      bin_dir="$2"
      shift 2
      ;;
    --no-link)
      link_command=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

select_python() {
  if [ -n "${KODA_PYTHON:-}" ]; then
    printf '%s\n' "$KODA_PYTHON"
    return
  fi
  for candidate in python3.14 python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return
    fi
  done
  printf '%s\n' python3
}

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
python_bin="$(select_python)"

"$python_bin" - <<'PY'
import sys

if sys.version_info < (3, 10):
    raise SystemExit("KODA requires Python 3.10 or newer.")
PY

mkdir -p "$prefix/bin" "$prefix/app" "$prefix/examples"
cp "$script_dir/bin/koda" "$prefix/bin/koda"
chmod 0755 "$prefix/bin/koda"

if [ -d "$script_dir/app/security_scanner" ]; then
  cp -R "$script_dir/app/." "$prefix/app/"
else
  repo_root="$(CDPATH= cd -- "$script_dir/../.." && pwd)"
  shared_python="$repo_root/platforms/shared/python"
  cp -R "$shared_python/security_scanner" "$prefix/app/security_scanner"
  for file in README.md pyproject.toml scanner_config.example.json scanner_config.documents.example.json LICENSE SECURITY.md PRIVACY.md koda-ignore.yml; do
    if [ -f "$shared_python/$file" ]; then
      cp "$shared_python/$file" "$prefix/app/$file"
    elif [ -f "$repo_root/$file" ]; then
      cp "$repo_root/$file" "$prefix/app/$file"
    fi
  done
fi

if [ -d "$script_dir/examples" ]; then
  cp -R "$script_dir/examples/." "$prefix/examples/"
fi
if [ -f "$script_dir/README-offline.md" ]; then
  cp "$script_dir/README-offline.md" "$prefix/README-offline.md"
fi

# A pre-bundled Chromium (staged by package.sh) makes SPA rendering fully
# offline; copy it into place so setup_render below reuses it instead of
# downloading.
if [ -d "$script_dir/ms-playwright" ]; then
  rm -rf "$prefix/ms-playwright"
  cp -R "$script_dir/ms-playwright" "$prefix/ms-playwright"
fi

# Optional headless-render setup for the SPA web crawl. Installs the pinned
# Playwright into a dedicated venv the koda launcher prefers, and provisions
# Chromium. Never fatal: any failure leaves KODA working with the standard-
# library crawler (non-rendered). Skip with KODA_SKIP_RENDER=1.
setup_render() {
  if [ "${KODA_SKIP_RENDER:-0}" = "1" ]; then
    echo "Skipping SPA-render setup (KODA_SKIP_RENDER=1)."
    return 0
  fi
  local venv="$prefix/render-venv"
  local wheels="$prefix/app/render-wheels"
  if ! "$python_bin" -m venv "$venv" 2>/dev/null; then
    echo "warning: could not create render venv; SPA rendering disabled." >&2
    return 0
  fi
  if [ -d "$wheels" ]; then
    "$venv/bin/pip" install --quiet --no-index --find-links "$wheels" "playwright==1.61.0" \
      || { echo "warning: offline playwright install failed; SPA rendering disabled." >&2; return 0; }
  else
    "$venv/bin/pip" install --quiet "playwright==1.61.0" \
      || { echo "warning: playwright install failed (offline without bundled wheels?); SPA rendering disabled." >&2; return 0; }
  fi
  if [ ! -d "$prefix/ms-playwright" ]; then
    PLAYWRIGHT_BROWSERS_PATH="$prefix/ms-playwright" "$venv/bin/python" -m playwright install chromium \
      || echo "warning: Chromium download failed; run 'PLAYWRIGHT_BROWSERS_PATH=$prefix/ms-playwright $venv/bin/python -m playwright install chromium' later." >&2
  fi
  echo "SPA-render support installed: $venv"
}
setup_render

if [ "$link_command" -eq 1 ]; then
  mkdir -p "$bin_dir"
  ln -sfn "$prefix/bin/koda" "$bin_dir/koda"
  echo "Installed koda command: $bin_dir/koda"
else
  echo "Installed koda command: $prefix/bin/koda"
fi

echo "Run: koda list-categories"
