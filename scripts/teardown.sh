#!/usr/bin/env bash
# Tear the lab down. Safe to run repeatedly; only touches lab-named resources.
#
#   scripts/teardown.sh --dry-run   show what would happen, change nothing
#   scripts/teardown.sh             ask for confirmation, then tear down
#   scripts/teardown.sh --yes       no prompt (for scripts)
#   scripts/teardown.sh --yes --purge-data
#                                  also delete generated runtime dirs
#                                  (endpoint home/logs and clinic-ehr/data)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

DRY_RUN=0
ASSUME_YES=0
PURGE_DATA=0

usage() {
  cat <<'USAGE'
Usage: scripts/teardown.sh [--dry-run] [--yes] [--purge-data]

  --dry-run      show what would be removed, change nothing
  --yes, -y      do not prompt for confirmation
  --purge-data   also delete generated runtime directories
                 (endpoint home/logs and clinic-ehr/data)
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --purge-data) PURGE_DATA=1 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

run() {
  if [ "$DRY_RUN" = "1" ]; then
    printf '[dry-run] %s\n' "$*"
  else
    "$@"
  fi
}

COMPOSE_DIRS=(workstation-01 frontdesk-01 msp-jump-01 clinic-ehr samba-dc)

if [ "$DRY_RUN" = "0" ] && [ "$ASSUME_YES" = "0" ]; then
  printf 'This removes all lab containers, the mills-lab network and the\n'
  printf 'mills-lab-shares volume. Runtime data directories are kept.\n'
  printf 'Continue? [y/N] '
  read -r answer || answer=""
  case "$answer" in
    y|Y|yes|YES) ;;
    *) echo "aborted"; exit 1 ;;
  esac
fi

for d in "${COMPOSE_DIRS[@]}"; do
  if [ -f "$d/docker-compose.yml" ]; then
    run docker compose -f "$d/docker-compose.yml" down -v --remove-orphans
  fi
done

if [ "$DRY_RUN" = "1" ]; then
  printf '[dry-run] docker network rm mills-lab  (only if it exists)\n'
  printf '[dry-run] docker volume rm mills-lab-shares  (only if it exists)\n'
else
  if docker network inspect mills-lab >/dev/null 2>&1; then
    docker network rm mills-lab >/dev/null
  fi
  if docker volume inspect mills-lab-shares >/dev/null 2>&1; then
    docker volume rm mills-lab-shares >/dev/null
  fi
fi

if [ "$PURGE_DATA" = "1" ]; then
  for path in clinic-ehr/data workstation-01/home workstation-01/logs \
              frontdesk-01/home frontdesk-01/logs msp-jump-01/home msp-jump-01/logs; do
    if [ -e "$path" ]; then
      run rm -rf "$path"
    fi
  done
fi

if [ "$DRY_RUN" = "1" ]; then
  printf '[dry-run] done; nothing was changed\n'
else
  printf '\nLab torn down. '
  if [ "$PURGE_DATA" = "1" ]; then
    printf 'Runtime data directories removed; samba-dc/.env kept.\n'
  else
    printf 'Runtime data directories kept (use --purge-data to delete).\n'
  fi
  printf 'Remaining lab containers (should be empty):\n'
  docker ps -a --filter "name=samba-dc" --filter "name=clinic-ehr" \
    --filter "name=ws-clinical-01" --filter "name=fd-frontdesk-01" \
    --filter "name=msp-jump-01" --format '  {{.Names}}'
fi
