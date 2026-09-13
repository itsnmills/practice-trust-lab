#!/usr/bin/env bash
# Bootstrap the practice lab from a fresh clone.
# Creates the shared network + volume, generates credentials, starts services,
# seeds the domain, and joins the endpoints.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

info() { printf '\n==> %s\n' "$*"; }

command -v docker >/dev/null || { echo "docker is required"; exit 1; }
docker info >/dev/null 2>&1 || { echo "docker daemon is not running"; exit 1; }

info "Creating shared network and volume (idempotent)"
docker network inspect mills-lab >/dev/null 2>&1 || \
  docker network create --subnet 172.31.13.0/24 mills-lab
docker volume inspect mills-lab-shares >/dev/null 2>&1 || \
  docker volume create mills-lab-shares >/dev/null

info "Generating credentials"
if [ ! -f samba-dc/.env ]; then
  rand() { openssl rand -base64 18 | tr -d '/+=' | cut -c1-18; }
  cat > samba-dc/.env <<EOF
SAMBA_ADMIN_PASS=$(rand)
USER_TEMP_PASS=$(rand)
TECH_PASS=$(rand)
LAB_BIND_IP=127.0.0.1
EOF
  echo "created samba-dc/.env"
else
  echo "samba-dc/.env already exists"
fi

# Endpoint compose files read the same credentials.
for d in workstation-01 frontdesk-01 msp-jump-01; do
  [ -e "$d/.env" ] || ln -s ../samba-dc/.env "$d/.env"
done

# shellcheck disable=SC1091
set -a; . samba-dc/.env; set +a

info "Building and starting the domain controller"
(cd samba-dc && docker compose up -d --build)
echo "waiting for the DC..."
for _ in $(seq 1 60); do
  if docker exec samba-dc samba-tool domain info 127.0.0.1 >/dev/null 2>&1; then break; fi
  sleep 2
done

info "Seeding OUs, groups, users, and lockout policy"
docker exec -i samba-dc bash -s "$USER_TEMP_PASS" "$TECH_PASS" < samba-dc/populate-domain.sh | tail -3

info "Provisioning shares and synthetic clinic files"
docker exec -i samba-dc bash -s < samba-dc/provision-shares.sh | tail -3

info "Building and starting the mock EHR"
(cd clinic-ehr && docker compose up -d --build)

info "Building and starting the endpoints"
for d in workstation-01 frontdesk-01 msp-jump-01; do
  (cd "$d" && docker compose up -d --build)
done

info "Done"
cat <<'EOF'

Next steps:
  scripts/seed-scenario.sh   plant the shadow-IT app (supply-chain demo finding)
  scripts/run-evidence.sh    collect an evidence snapshot + render the packet

Then open: evidence/latest.html
EOF
