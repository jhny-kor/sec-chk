#!/usr/bin/env bash
set -euo pipefail

deploy_dir="${DEPLOY_DIR:-/deploy/app}"
report_dir="${KODA_REPORT_DIR:-reports/koda}"
fail_on="${KODA_FAIL_ON:-high}"

mkdir -p "$report_dir"

gate_status=0
koda deploy-check \
  --target "$deploy_dir" \
  --output-dir "$report_dir" \
  --fail-on "$fail_on" || gate_status=$?

koda scan \
  --target "$deploy_dir" \
  --format html \
  --output "$report_dir/koda-security.html" \
  --min-severity low

if [ "$gate_status" -ne 0 ]; then
  echo "KODA deployment gate failed at severity: $fail_on" >&2
  exit "$gate_status"
fi

echo "KODA deployment gate passed."
