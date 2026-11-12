#!/usr/bin/env bash
# Bootstrap the practice lab from a fresh clone.
# Creates the shared network + volume, generates credentials, starts services,
# seeds the domain, and joins the endpoints.
#
# Safe to re-run: every step checks for existing state first.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

info() { printf '\n==> %s\n' "$*"; }
warn() { printf '\n!! %s\n' "$*" >&2; }
die() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null || die "docker is required"
docker info >/dev/null 2>&1 || die "docker daemon is not running"
docker compose version >/dev/null 2>&1 || die "docker compose v2 is required (docker-compose v1 is not supported)"

info "Creating shared network and volume (idempotent)"
docker network inspect mills-lab >/dev/null 2>&1 || \
  docker network create --subnet 172.31.13.0/24 mills-lab
docker volume inspect mills-lab-shares >/dev/null 2>&1 || \
  docker volume create mills-lab-shares >/dev/null

# Bind-mounted runtime dirs must exist before compose starts, otherwise Docker
# creates them root-owned (annoying to clean up and harder for the host user to
# read). Create them owned by the user running bootstrap.
info "Creating runtime data directories"
mkdir -p clinic-ehr/data \
  workstation-01/home workstation-01/logs \
  frontdesk-01/home frontdesk-01/logs \
  msp-jump-01/home msp-jump-01/logs

info "Generating credentials"
if [ ! -f samba-dc/.env ]; then
  command -v openssl >/dev/null || die "openssl is required to generate credentials"
  rand() { openssl rand -base64 18 | tr -d '/+=' | cut -c1-18; }
  umask 077
  cat > samba-dc/.env <<EOF
SAMBA_ADMIN_PASS=$(rand)
USER_TEMP_PASS=$(rand)
TECH_PASS=$(rand)
LAB_BIND_IP=127.0.0.1
LAB_UID=$(id -u)
LAB_GID=$(id -g)
EOF
  umask 022
  echo "created samba-dc/.env (mode 0600)"
else
  echo "samba-dc/.env already exists"
fi
chmod 600 samba-dc/.env

if ! grep -q '^LAB_UID=' samba-dc/.env; then
  printf 'LAB_UID=%s\n' "$(id -u)" >> samba-dc/.env
fi
if ! grep -q '^LAB_GID=' samba-dc/.env; then
  printf 'LAB_GID=%s\n' "$(id -g)" >> samba-dc/.env
fi

# shellcheck disable=SC1091
set -a; . samba-dc/.env; set +a

for required in SAMBA_ADMIN_PASS USER_TEMP_PASS TECH_PASS LAB_BIND_IP; do
  [ -n "${!required:-}" ] || die "$required is missing from samba-dc/.env"
done

case "$LAB_BIND_IP" in
  127.*) ;;
  *)
    warn "LAB_BIND_IP=$LAB_BIND_IP is NOT loopback. This lab has no authentication on"
    warn "the mock EHR and anonymous LDAP bind is possible. Only do this on a trusted,"
    warn "throwaway network. See docs/LAB-SECURITY.md."
    ;;
esac

if [ -n "$(find clinic-ehr/data -maxdepth 1 ! -uid "$LAB_UID" -print -quit 2>/dev/null)" ]; then
  warn "clinic-ehr/data contains files not owned by $(id -un) (likely from an older"
  warn "rootful run). The EHR container runs as your uid and will not be able to write."
  warn "Fix with: sudo chown -R $(id -u):$(id -g) clinic-ehr/data"
fi

# Endpoint and EHR compose files read the same credentials / bind IP.
for d in workstation-01 frontdesk-01 msp-jump-01 clinic-ehr; do
  if [ ! -e "$d/.env" ] && [ ! -L "$d/.env" ]; then
    ln -s ../samba-dc/.env "$d/.env"
  fi
done

info "Building and starting the domain controller"
if ! (cd samba-dc && docker compose up -d --build --wait --wait-timeout 180); then
  die "domain controller did not become healthy; inspect: docker logs samba-dc"
fi

info "Seeding OUs, groups, users, and lockout policy"
docker exec -i samba-dc bash -s < samba-dc/populate-domain.sh | tail -5

info "Provisioning shares and synthetic clinic files"
docker exec -i samba-dc bash -s < samba-dc/provision-shares.sh | tail -5

info "Building and starting the mock EHR"
if ! (cd clinic-ehr && docker compose up -d --build --wait --wait-timeout 90); then
  die "mock EHR did not become healthy; inspect: docker logs clinic-ehr"
fi

info "Building and starting the endpoints"
for d in workstation-01 frontdesk-01 msp-jump-01; do
  if ! (cd "$d" && docker compose up -d --build --wait --wait-timeout 180); then
    die "$d did not become healthy; inspect: docker logs $d"
  fi
done

info "Done"
cat <<'EOF'

Next steps:
  scripts/seed-scenario.sh       plant the shadow-IT app (supply-chain demo finding)
  scripts/verify-boundaries.sh   assert the documented access boundaries
  scripts/run-evidence.sh        collect an evidence snapshot + render the packet

Then open: evidence/latest.html
Tear down:  scripts/teardown.sh (add --dry-run to preview)
EOF
