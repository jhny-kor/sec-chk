#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/../.." && pwd)"
shared_python="$repo_root/platforms/shared/python"
dist_dir="${KODA_LINUX_DIST_DIR:-$repo_root/dist/linux}"
version="$(awk -F'"' '/^version =/ { print $2; exit }' "$shared_python/pyproject.toml")"
version="${version:-0.1.0}"
package_name="koda-linux-x86_64-$version"
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
for file in README.md pyproject.toml scanner_config.example.json scanner_config.documents.example.json LICENSE SECURITY.md PRIVACY.md koda-ignore.yml; do
  if [ -f "$shared_python/$file" ]; then
    cp "$shared_python/$file" "$stage/app/$file"
  elif [ -f "$repo_root/$file" ]; then
    cp "$repo_root/$file" "$stage/app/$file"
  fi
done

# Bundle the SPA-render dependencies for an offline install: the pinned
# Playwright wheels plus a Chromium build. Best-effort — on failure the package
# is leaner and install.sh fetches these online instead. Skip with
# KODA_SKIP_RENDER=1.
if [ "${KODA_SKIP_RENDER:-0}" != "1" ]; then
  render_wheels="$stage/app/render-wheels"
  mkdir -p "$render_wheels"
  if python3 -m pip download "playwright==1.61.0" -d "$render_wheels" >/dev/null 2>&1; then
    tmp_root="$(mktemp -d)"
    tmp_venv="$tmp_root/venv"
    if python3 -m venv "$tmp_venv" \
       && "$tmp_venv/bin/pip" install --quiet --no-index --find-links "$render_wheels" "playwright==1.61.0" \
       && PLAYWRIGHT_BROWSERS_PATH="$stage/ms-playwright" "$tmp_venv/bin/python" -m playwright install chromium >/dev/null 2>&1; then
      echo "Bundled Playwright wheels + Chromium for offline SPA render." >&2
    else
      echo "warning: could not stage Chromium; package will fetch render deps at install time." >&2
      rm -rf "$stage/ms-playwright"
    fi
    rm -rf "$tmp_root"
  else
    echo "warning: could not download Playwright wheels; package omits bundled render deps." >&2
    rm -rf "$render_wheels"
  fi
fi

tarball="$dist_dir/$package_name.tar.gz"
tar -C "$stage_parent" -czf "$tarball" "$package_name"
echo "$tarball"
