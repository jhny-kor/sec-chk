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

tarball="$dist_dir/$package_name.tar.gz"
tar -C "$stage_parent" -czf "$tarball" "$package_name"
echo "$tarball"
