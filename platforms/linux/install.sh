#!/usr/bin/env bash
set -euo pipefail

prefix="${KODA_PREFIX:-/home/user0/koda}"
bin_dir="${KODA_BIN_DIR:-$prefix}"
link_command=1

usage() {
  cat <<'EOF'
Usage: install.sh [--prefix DIR] [--bin-dir DIR] [--no-link]

Installs the Linux KODA wrapper and shared scanner source without requiring root.
Environment:
  KODA_PREFIX   install root, default /home/user0/koda
  KODA_BIN_DIR  command link directory, default $KODA_PREFIX
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
printf '%s\n' "$python_bin" > "$prefix/python-interpreter"

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

verify_offline_manifest() {
  if [ ! -f "$script_dir/manifest.sha256" ]; then
    return 0
  fi
  "$python_bin" - "$script_dir/manifest.sha256" "$script_dir" <<'PY'
import hashlib
import pathlib
import sys

manifest = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2]).resolve()
for line in manifest.read_text(encoding="utf-8").splitlines():
    expected, relative = line.split(maxsplit=1)
    path = (root / relative.strip()).resolve()
    if root not in path.parents or not path.is_file():
        raise SystemExit(f"offline bundle file is missing: {relative}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != expected:
        raise SystemExit(f"offline bundle checksum mismatch: {relative}")
PY
}
verify_offline_manifest

install_offline_assets() {
  local asset
  for asset in tools grype-db vuln-data; do
    if [ -e "$script_dir/$asset" ]; then
      rm -rf "$prefix/$asset"
      cp -R "$script_dir/$asset" "$prefix/$asset"
    fi
  done
  for metadata in manifest.sha256 versions.txt; do
    if [ -f "$script_dir/$metadata" ]; then
      cp "$script_dir/$metadata" "$prefix/$metadata"
    fi
  done

  local db_archive
  db_archive="$(find "$prefix/grype-db/incoming" -type f -name '*.tar.zst' -print -quit 2>/dev/null || true)"
  if [ -n "$db_archive" ]; then
    if [ ! -x "$prefix/tools/grype" ]; then
      echo "error: bundled Grype DB exists but bundled Grype executable is missing." >&2
      return 1
    fi
    mkdir -p "$prefix/grype-db/db"
    GRYPE_DB_CACHE_DIR="$prefix/grype-db/db" \
      GRYPE_DB_AUTO_UPDATE=false \
      GRYPE_DB_VALIDATE_AGE=false \
      "$prefix/tools/grype" db import "$db_archive" \
      || { echo "error: bundled Grype DB import failed." >&2; return 1; }
  fi
}
install_offline_assets

setup_render() {
  local wheels="$prefix/app/render-wheels"
  if [ ! -d "$wheels" ] && [ -f "$script_dir/manifest.sha256" ]; then
    echo "error: offline bundle is missing app/render-wheels; refusing network install." >&2
    return 1
  fi
  if [ ! -d "$wheels" ]; then
    "$python_bin" -m pip install --quiet --target "$prefix/render-lib" "playwright==1.61.0" \
      || { echo "error: PDF renderer install failed; build or use the offline bundle." >&2; return 1; }
  else
    rm -rf "$prefix/render-lib"
    mkdir -p "$prefix/render-lib"
    "$python_bin" - "$wheels" "$prefix/render-lib" <<'PY'
import pathlib
import sys
import zipfile

wheels = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
python_tag = f"cp{sys.version_info.major}{sys.version_info.minor}"
selected = []
required = {"playwright-", "pyee-", "typing_extensions-", "greenlet-"}
for wheel in sorted(wheels.glob("*.whl")):
    name = wheel.name
    if name.startswith("greenlet-") and f"-{python_tag}-{python_tag}-" not in name:
        continue
    if any(name.startswith(prefix) for prefix in required):
        selected.append(wheel)

if not any(path.name.startswith("playwright-") for path in selected):
    raise SystemExit(f"no Playwright wheel for Python {python_tag}")
if not any(path.name.startswith("greenlet-") for path in selected):
    raise SystemExit(f"no greenlet wheel for Python {python_tag}")

for wheel in selected:
    with zipfile.ZipFile(wheel) as archive:
        for member in archive.infolist():
            relative = pathlib.PurePosixPath(member.filename)
            if relative.is_absolute() or ".." in relative.parts:
                raise SystemExit(f"unsafe wheel member: {member.filename}")
        for member in archive.infolist():
            archive.extract(member, destination)
            # zipfile drops POSIX modes; restore them so bundled executables
            # (e.g. playwright/driver/node) stay runnable.
            mode = (member.external_attr >> 16) & 0o7777
            if mode and not member.is_dir():
                (destination / member.filename).chmod(mode)
PY
  fi

  if [ ! -d "$prefix/ms-playwright" ]; then
    if [ -f "$script_dir/manifest.sha256" ]; then
      echo "error: offline bundle is missing ms-playwright; refusing browser download." >&2
      return 1
    fi
    PYTHONPATH="$prefix/render-lib${PYTHONPATH:+:$PYTHONPATH}" \
      PLAYWRIGHT_BROWSERS_PATH="$prefix/ms-playwright" \
      "$python_bin" -m playwright install chromium \
      || { echo "error: Chromium download failed; dashboard PDF export requires it." >&2; return 1; }
  fi
  echo "Dashboard PDF renderer installed: $prefix/render-lib"
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
