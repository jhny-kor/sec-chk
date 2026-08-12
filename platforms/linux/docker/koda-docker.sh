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
  koda-docker dashboard start [--reports DIR] [--port PORT] [--bind ADDRESS]
  koda-docker dashboard status | logs [-f] | stop
  koda-docker dashboard bootstrap --tracker-user-id UUID

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
  KODA_PORTAL_DATA_DIR  durable portal database/input directory
  KODA_PUBLISH_DASHBOARD set 0 when a gateway reaches the private Docker network
  KODA_SSBOM_TRACKER_URL optional http(s) URL shown as an SBOM Tracker button
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

mount_paths=()
mount_modes=()

add_mount() {
  local path="$1" mode="$2" index
  for index in "${!mount_paths[@]}"; do
    if [ "${mount_paths[$index]}" = "$path" ]; then
      # rw wins when the same path is requested both ways.
      [ "${mount_modes[$index]}" = "rw" ] || mount_modes[$index]="$mode"
      return
    fi
  done
  mount_paths+=("$path")
  mount_modes+=("$mode")
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

  local run_opts=() path index
  while IFS= read -r line; do run_opts+=("$line"); done < <(base_run_opts)
  run_opts+=(--network none)
  for index in "${!mount_paths[@]}"; do
    path="${mount_paths[$index]}"
    run_opts+=(-v "$path:$path:${mount_modes[$index]}")
  done
  local docker_opts=("${run_opts[@]}")
  if [ "${#extra_args[@]}" -gt 0 ]; then
    docker_opts+=("${extra_args[@]}")
  fi
  exec docker run "${docker_opts[@]}" "$image" "${args[@]}"
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
  local bind="${KODA_DASHBOARD_BIND:-127.0.0.1}"
  local port="${KODA_PORT:-8765}"
  local portal_data="${KODA_PORTAL_DATA_DIR:-$script_dir/data/portal}"
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --reports) reports="${2:-}"; shift 2 ;;
      --port) port="${2:-}"; shift 2 ;;
      --bind) bind="${2:-}"; shift 2 ;;
      *) echo "error: unknown dashboard start option: $1" >&2; exit 2 ;;
    esac
  done
  case "$port" in
    ''|*[!0-9]*) echo "error: dashboard port must be an integer from 1 to 65535: $port" >&2; exit 2 ;;
  esac
  if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    echo "error: dashboard port must be an integer from 1 to 65535: $port" >&2
    exit 2
  fi
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
  if [ "${KODA_PUBLISH_DASHBOARD:-1}" = 1 ]; then
    filtered+=(-p "$bind:$port:8765")
  fi
  mkdir -p "$portal_data"
  portal_data="$(realpath "$portal_data")"
  filtered+=(
    -v "$portal_data:/var/lib/koda:rw"
    -e KODA_PORTAL_DB=/var/lib/koda/portal.sqlite3
    -e KODA_PORTAL_INPUT_DIR=/var/lib/koda/inputs
  )
  if [ -n "${KODA_SSBOM_TRACKER_URL:-}" ]; then
    filtered+=(-e "KODA_SSBOM_TRACKER_URL=${KODA_SSBOM_TRACKER_URL}")
  fi
  if [ -n "$reports" ]; then
    mkdir -p "$reports"
    reports="$(realpath "$reports")"
    filtered+=(-v "$reports:$reports:rw")
  fi
  local docker_opts=("${filtered[@]}")
  if [ "${#extra_args[@]}" -gt 0 ]; then
    docker_opts+=("${extra_args[@]}")
  fi
  docker run "${docker_opts[@]}" "$image" \
    serve --host 0.0.0.0 --port 8765 >/dev/null
  if [ "${KODA_PUBLISH_DASHBOARD:-1}" = 1 ]; then
    echo "dashboard started: http://$bind:$port/koda/"
  else
    echo "dashboard started on private Docker network: $dashboard_network"
  fi
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
      bootstrap)
        shift
        [[ "${1:-}" == --tracker-user-id && -n "${2:-}" && $# == 2 ]] \
          || { echo "Usage: koda-docker dashboard bootstrap --tracker-user-id UUID" >&2; exit 2; }
        docker exec "$dashboard_name" /opt/koda/bin/koda portal-bootstrap \
          --tracker-user-id "$2" --db /var/lib/koda/portal.sqlite3
        ;;
      stop) docker rm -f "$dashboard_name" >/dev/null 2>&1 && echo "dashboard stopped" || echo "dashboard not running" ;;
      *) echo "Usage: koda-docker dashboard start|status|logs|bootstrap|stop" >&2; exit 2 ;;
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
