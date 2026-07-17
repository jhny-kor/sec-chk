#!/usr/bin/env bash
# KODA closed-network Docker wrapper. Runs the koda-offline image with
# network none, read-only rootfs, no capabilities, resource limits, and
# ro/rw mounts derived from the CLI arguments. Exit codes: container exit
# code passes through; wrapper errors exit 2.
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

image="${KODA_IMAGE:-}"
if [ -z "$image" ] && [ -f "$script_dir/image-ref.txt" ]; then
  IFS= read -r image < "$script_dir/image-ref.txt" || true
fi
if [ -z "$image" ]; then
  echo "error: image reference not found; set KODA_IMAGE or provide image-ref.txt" >&2
  exit 2
fi

dashboard_name="koda-dashboard"
dashboard_network="koda-dashboard"

usage() {
  cat <<'EOF'
Usage:
  koda-docker <koda subcommand> [args...]     e.g. jar-scan, sbom-verify, list-categories
  koda-docker audit --target DIR --baseline SBOM --reports DIR [extra jar-scan args]
  koda-docker dashboard start [--reports DIR] | status | logs [-f] | stop

Path arguments (--target/--sbom/--baseline-sbom read-only, --output-dir/--output
read-write) are bind-mounted automatically at the same absolute path.

Environment:
  KODA_IMAGE            image reference, default from image-ref.txt
  KODA_CPUS             default 2
  KODA_MEMORY           default 4g
  KODA_PIDS_LIMIT       default 256
  KODA_TMPFS_SIZE       default 512m
  KODA_ALLOW_CONCURRENT set 1 to allow parallel scans
  KODA_PORT             dashboard host port, default 8765
  KODA_DASHBOARD_BIND   dashboard bind address, default 127.0.0.1
  KODA_DOCKER_EXTRA_ARGS extra docker run options, whitespace-separated
EOF
}

# Extra docker options come from a whitespace-split env var; never eval.
extra_args=()
if [ -n "${KODA_DOCKER_EXTRA_ARGS:-}" ]; then
  read -r -a extra_args <<<"$KODA_DOCKER_EXTRA_ARGS"
fi

base_run_opts() {
  printf '%s\n' \
    --rm \
    --platform linux/amd64 \
    --pull never \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --pids-limit "${KODA_PIDS_LIMIT:-256}" \
    --memory "${KODA_MEMORY:-4g}" \
    --cpus "${KODA_CPUS:-2}" \
    --tmpfs "/tmp:rw,noexec,nosuid,size=${KODA_TMPFS_SIZE:-512m}" \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp/koda-home \
    -e XDG_CACHE_HOME=/tmp/koda-cache
}

declare -A mount_mode=()

add_mount() {
  local path="$1" mode="$2"
  # rw wins when the same path is requested both ways.
  if [ "${mount_mode[$path]:-}" != "rw" ]; then
    mount_mode[$path]="$mode"
  fi
}

require_path() {
  local flag="$1" path="$2"
  if [ ! -e "$path" ]; then
    echo "error: $flag path does not exist: $path" >&2
    exit 2
  fi
}

run_cli() {
  local args=() flag value
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --target|--sbom|--baseline-sbom|--target=*|--sbom=*|--baseline-sbom=*)
        case "$1" in
          *=*) flag="${1%%=*}"; value="${1#*=}"; shift ;;
          *) flag="$1"; value="${2:-}"; shift 2 ;;
        esac
        require_path "$flag" "$value"
        value="$(realpath "$value")"
        add_mount "$value" ro
        args+=("$flag" "$value")
        ;;
      --output-dir|--output-dir=*)
        case "$1" in
          *=*) value="${1#*=}"; shift ;;
          *) value="${2:-}"; shift 2 ;;
        esac
        mkdir -p "$value"
        value="$(realpath "$value")"
        add_mount "$value" rw
        args+=(--output-dir "$value")
        ;;
      --output|--output=*)
        case "$1" in
          *=*) value="${1#*=}"; shift ;;
          *) value="${2:-}"; shift 2 ;;
        esac
        mkdir -p "$(dirname -- "$value")"
        value="$(realpath "$(dirname -- "$value")")/$(basename -- "$value")"
        add_mount "$(dirname -- "$value")" rw
        args+=(--output "$value")
        ;;
      *)
        args+=("$1")
        shift
        ;;
    esac
  done

  # ponytail: one scan at a time by default; the JEUS host shares its I/O.
  if [ "${KODA_ALLOW_CONCURRENT:-0}" != "1" ]; then
    exec 9>"$script_dir/.koda-docker-scan.lock"
    if ! flock -n 9; then
      echo "error: another koda-docker run holds the scan lock; set KODA_ALLOW_CONCURRENT=1 to override." >&2
      exit 2
    fi
  fi

  local run_opts=() path
  while IFS= read -r line; do run_opts+=("$line"); done < <(base_run_opts)
  run_opts+=(--network none)
  for path in "${!mount_mode[@]}"; do
    run_opts+=(-v "$path:$path:${mount_mode[$path]}")
  done
  exec docker run "${run_opts[@]}" "${extra_args[@]}" "$image" "${args[@]}"
}

run_audit() {
  local target="" baseline="" reports="" rest=()
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --target) target="${2:-}"; shift 2 ;;
      --baseline) baseline="${2:-}"; shift 2 ;;
      --reports) reports="${2:-}"; shift 2 ;;
      *) rest+=("$1"); shift ;;
    esac
  done
  if [ -z "$target" ] || [ -z "$baseline" ] || [ -z "$reports" ]; then
    echo "error: audit requires --target, --baseline, and --reports." >&2
    exit 2
  fi
  run_cli jar-scan \
    --target "$target" \
    --output-dir "$reports" \
    --verify-sbom \
    --baseline-sbom "$baseline" \
    --strict-hash \
    --fail-on-mismatch \
    --fail-on-version-conflict \
    --fail-on-untracked \
    --fail-on high \
    --fail-on-kev \
    ${rest[@]+"${rest[@]}"}
}

dashboard_start() {
  local reports=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --reports) reports="${2:-}"; shift 2 ;;
      *) echo "error: unknown dashboard start option: $1" >&2; exit 2 ;;
    esac
  done
  local bind="${KODA_DASHBOARD_BIND:-127.0.0.1}"
  local port="${KODA_PORT:-8765}"
  if docker ps --format '{{.Names}}' | grep -qx "$dashboard_name"; then
    echo "dashboard already running: http://$bind:$port/security-dashboard.html"
    return 0
  fi
  docker rm -f "$dashboard_name" >/dev/null 2>&1 || true
  # A dedicated bridge with IP masquerade disabled: the published port keeps
  # working (DNAT+conntrack) while container-originated egress is unroutable.
  # A --internal network would also disable the published port, so it is not
  # usable here.
  if ! docker network inspect "$dashboard_network" >/dev/null 2>&1; then
    docker network create \
      -o com.docker.network.bridge.enable_ip_masquerade=false \
      "$dashboard_network" >/dev/null
  fi
  local run_opts=(-d --name "$dashboard_name" --network "$dashboard_network")
  while IFS= read -r line; do run_opts+=("$line"); done < <(base_run_opts)
  # -d and --rm conflict with container inspection after exit; drop --rm.
  local filtered=() opt
  for opt in "${run_opts[@]}"; do
    [ "$opt" = "--rm" ] || filtered+=("$opt")
  done
  filtered+=(-p "$bind:$port:8765")
  if [ -n "$reports" ]; then
    mkdir -p "$reports"
    reports="$(realpath "$reports")"
    filtered+=(-v "$reports:$reports:rw")
  fi
  docker run "${filtered[@]}" "${extra_args[@]}" "$image" \
    serve --host 0.0.0.0 --port 8765 >/dev/null
  echo "dashboard started: http://$bind:$port/security-dashboard.html"
  echo "remote access: ssh -L $port:127.0.0.1:$port <user>@<server>"
}

case "${1:-}" in
  -h|--help|"")
    usage
    exit 0
    ;;
  audit)
    shift
    run_audit "$@"
    ;;
  dashboard)
    shift
    case "${1:-}" in
      start) shift; dashboard_start "$@" ;;
      status)
        docker ps --all --filter "name=^${dashboard_name}\$" \
          --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
        ;;
      logs) shift; docker logs ${1:+"$1"} "$dashboard_name" ;;
      stop) docker rm -f "$dashboard_name" >/dev/null 2>&1 && echo "dashboard stopped" || echo "dashboard not running" ;;
      *) echo "Usage: koda-docker dashboard start|status|logs|stop" >&2; exit 2 ;;
    esac
    ;;
  serve)
    echo "error: use 'koda-docker dashboard start' instead of 'serve'." >&2
    exit 2
    ;;
  *)
    run_cli "$@"
    ;;
esac
