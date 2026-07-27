#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/../.." && pwd)"
shared_python="$repo_root/platforms/shared/python"
dist_dir="${KODA_LINUX_DIST_DIR:-$repo_root/dist/linux}"
offline_asset_dir="${KODA_OFFLINE_ASSET_DIR:-}"
version="$(awk -F'"' '/^version =/ { print $2; exit }' "$shared_python/pyproject.toml")"
version="${version:-0.1.0}"
case "${KODA_LINUX_ARCH:-$(uname -m)}" in
  x86_64|amd64) linux_arch="x86_64" ;;
  aarch64|arm64) linux_arch="arm64" ;;
  *) echo "error: unsupported Linux architecture: $(uname -m)" >&2; exit 1 ;;
esac
package_name="koda-linux-$linux_arch-$version"
stage_parent="$(mktemp -d)"
stage="$stage_parent/$package_name"

cleanup() {
  rm -rf "$stage_parent"
}
trap cleanup EXIT

mkdir -p "$stage/bin" "$stage/app" "$stage/examples" "$dist_dir"
cp "$script_dir/bin/koda" "$stage/bin/koda"
cp "$script_dir/install.sh" "$stage/install.sh"
cp "$script_dir/README-offline.md" "$stage/README-offline.md"
cp -R "$script_dir/examples/." "$stage/examples/"
chmod 0755 "$stage/bin/koda" "$stage/install.sh"

cp -R "$shared_python/security_scanner" "$stage/app/security_scanner"
for file in README.md pyproject.toml scanner_config.example.json scanner_config.documents.example.json LICENSE NOTICE SECURITY.md PRIVACY.md koda-ignore.yml; do
  if [ -f "$shared_python/$file" ]; then
    cp "$shared_python/$file" "$stage/app/$file"
  elif [ -f "$repo_root/$file" ]; then
    cp "$repo_root/$file" "$stage/app/$file"
  fi
done

if [ -n "$offline_asset_dir" ]; then
  if [ "$linux_arch" != "x86_64" ]; then
    echo "error: offline Java tooling is currently packaged for Linux x86_64 only." >&2
    exit 1
  fi
  for required in \
    "$offline_asset_dir/tools/syft" \
    "$offline_asset_dir/tools/grype" \
    "$offline_asset_dir/grype-db/incoming" \
    "$offline_asset_dir/vuln-data/nvd" \
    "$offline_asset_dir/vuln-data/known_exploited_vulnerabilities.json"; do
    if [ ! -e "$required" ]; then
      echo "error: incomplete offline asset directory; missing $required" >&2
      exit 1
    fi
  done
  if ! find "$offline_asset_dir/grype-db/incoming" -type f -name '*.tar.zst' -print -quit | grep -q .; then
    echo "error: offline asset directory has no Grype DB .tar.zst archive." >&2
    exit 1
  fi
  if ! find "$offline_asset_dir/vuln-data/nvd" -type f \( -name '*.json' -o -name '*.json.gz' \) -print -quit | grep -q .; then
    echo "error: offline asset directory has no NVD JSON feed." >&2
    exit 1
  fi
  cp -R "$offline_asset_dir/tools" "$stage/tools"
  cp -R "$offline_asset_dir/grype-db" "$stage/grype-db"
  cp -R "$offline_asset_dir/vuln-data" "$stage/vuln-data"
  if [ -f "$offline_asset_dir/manifest.sha256" ]; then
    cp "$offline_asset_dir/manifest.sha256" "$stage/manifest.sha256"
  fi
  if [ -f "$offline_asset_dir/versions.txt" ]; then
    cp "$offline_asset_dir/versions.txt" "$stage/versions.txt"
  fi
  chmod 0755 "$stage/tools/syft" "$stage/tools/grype"
fi

render_wheels="$stage/app/render-wheels"
mkdir -p "$render_wheels"
for python_version in 310 311 312 313 314; do
  python_minor="3.${python_version:1:2}"
  if ! python3 -m pip download \
    --only-binary=:all: \
    --platform manylinux1_x86_64 \
    --platform manylinux_2_24_x86_64 \
    --platform manylinux_2_28_x86_64 \
    --implementation cp \
    --abi "cp$python_version" \
    --python-version "$python_minor" \
    "playwright==1.61.0" \
    -d "$render_wheels" >/dev/null 2>&1; then
    echo "error: could not download Playwright wheels for Python $python_minor." >&2
    exit 1
  fi
done
tmp_root="$(mktemp -d)"
tmp_venv="$tmp_root/venv"
if ! python3 -m venv "$tmp_venv" \
   || ! "$tmp_venv/bin/pip" install --quiet --no-index --find-links "$render_wheels" "playwright==1.61.0" \
   || ! PLAYWRIGHT_BROWSERS_PATH="$stage/ms-playwright" "$tmp_venv/bin/python" -m playwright install chromium >/dev/null 2>&1; then
  echo "error: could not stage Chromium for dashboard PDF export." >&2
  rm -rf "$tmp_root"
  exit 1
fi
rm -rf "$tmp_root"
echo "Bundled Playwright wheels + Chromium for dashboard PDF export." >&2

tarball="$dist_dir/$package_name.tar.gz"
tar -C "$stage_parent" -czf "$tarball" "$package_name"
echo "$tarball"
