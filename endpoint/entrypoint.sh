#!/bin/bash
# Generic lab endpoint: joins the domain, then runs a staff sync loop that
# pulls share files to a local desktop, like a real clinic machine would.
#
# Configured entirely by env:
#   ENDPOINT_NAME   ws-clinical-01 | fd-frontdesk-01 | msp-jump-01
#   ENDPOINT_ROLE   human label for audit lines
#   SYNC_USER       domain user this endpoint acts as
#   SYNC_PASS       that user's password (from compose env, never persisted)
#   SYNC_SHARES     space-separated share names
#   SYNC_PATTERN    smbclient mget pattern (default *)
set -euo pipefail

REALM=MILLSLAB.INTERNAL
DOMAIN=MILLSLAB
# Passwords arrive through the read-only lab env secret, not the container
# environment. Endpoints all sync as a "known password" lab account.
if [ -r /run/secrets/lab_env ]; then
  set -a
  # shellcheck disable=SC1091
  . /run/secrets/lab_env
  set +a
fi
SYNC_PASS=${SYNC_PASS:-${TECH_PASS:-}}
DC_IP=${DC_IP:-172.31.13.10}
SHARE_HOST=${SHARE_HOST:-dc1.millslab.internal}
EP_NAME=${ENDPOINT_NAME:-ws-clinical-01}
EP_ROLE=${ENDPOINT_ROLE:-Clinic workstation}
SYNC_USER=${SYNC_USER:-jchen}
SYNC_PASS=${SYNC_PASS:?SYNC_PASS (or TECH_PASS via /run/secrets/lab_env) is required}
SYNC_SHARES=${SYNC_SHARES:-ClinicalShare}
SYNC_PATTERN=${SYNC_PATTERN:-*}
LOCAL_HOME=/home/staff
LOGDIR=/var/log/endpoint
MARKER=/var/lib/samba/.joined
JOIN_CREDS=/tmp/.joincreds

cleanup() { rm -f "$JOIN_CREDS"; }
trap cleanup EXIT INT TERM

mkdir -p "$LOCAL_HOME/Desktop/incoming" "$LOGDIR" /var/lib/samba

cat > /etc/krb5.conf <<KRB
[libdefaults]
    default_realm = $REALM
    dns_lookup_realm = false
    dns_lookup_kdc = false
[realms]
    $REALM = {
        kdc = $DC_IP
        admin_server = $DC_IP
    }
KRB

json_escape() {
  local text=$1
  text=${text//\\/\\\\}
  text=${text//\"/\\\"}
  text=$(printf '%s' "$text" | tr -d '\n\r')
  printf '%s' "$text"
}

audit() {
  printf '{"ts":"%s","endpoint":"%s","event":"%s","detail":"%s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "$(json_escape "$EP_NAME")" \
    "$(json_escape "$1")" \
    "$(json_escape "$2")" >> "$LOGDIR/activity.jsonl"
}

echo "[$EP_NAME] waiting for DC DNS..."
dns_ready=0
for _ in $(seq 1 60); do
  if getent hosts "$SHARE_HOST" >/dev/null 2>&1; then dns_ready=1; break; fi
  sleep 2
done
if [ "$dns_ready" != "1" ]; then
  echo "[$EP_NAME] DC did not resolve as $SHARE_HOST after 120s; is the lab up?" >&2
  exit 1
fi

cat > /etc/samba/smb.conf <<SMB
[global]
    workgroup = $DOMAIN
    realm = $REALM
    security = ADS
    server string = $EP_NAME (synthetic lab endpoint)
    log file = $LOGDIR/samba.log
    log level = 1 auth_audit:3
    idmap config * : backend = tdb

[homes]
    comment = Home Directories
    browseable = no
    read only = no
SMB

if [ -f "$MARKER" ] && ! net ads testjoin >/dev/null 2>&1; then
  echo "[$EP_NAME] join marker exists but the trust is gone; rejoining" >&2
  rm -f "$MARKER"
fi

if [ ! -f "$MARKER" ]; then
  echo "[$EP_NAME] joining domain $REALM"
  umask 077
  cat > "$JOIN_CREDS" <<CRED
username=Administrator
password=${SAMBA_ADMIN_PASS}
domain=$DOMAIN
CRED
  joined=0
  for attempt in 1 2 3 4 5; do
    if net ads join -A "$JOIN_CREDS" --no-dns-updates createcomputer="MillsLab/Workstations"; then
      joined=1
      break
    fi
    echo "[$EP_NAME] join attempt $attempt failed; retrying in 10s" >&2
    sleep 10
  done
  cleanup
  if [ "$joined" != "1" ]; then
    echo "[$EP_NAME] could not join the domain after 5 attempts" >&2
    exit 1
  fi
  touch "$MARKER"
  echo "[$EP_NAME] join complete"
fi

winbindd -D -s /etc/samba/smb.conf 2>/dev/null || echo "[$EP_NAME] winbindd did not start" >&2

umask 077
cat > /root/.smbcred <<CRED
username=$SYNC_USER
password=$SYNC_PASS
domain=$DOMAIN
CRED
umask 022
touch "$LOGDIR/activity.jsonl" && chmod 644 "$LOGDIR/activity.jsonl"

audit "endpoint_start" "$EP_ROLE online (sync user: $SYNC_USER)"

while true; do
  for share in $SYNC_SHARES; do
    smbclient "//$SHARE_HOST/$share" -A /root/.smbcred \
      -c "prompt OFF; recurse ON; lcd $LOCAL_HOME/Desktop/incoming; mget $SYNC_PATTERN" >/dev/null 2>&1 || true
  done
  chmod 644 "$LOCAL_HOME/Desktop/incoming/"* 2>/dev/null || true
  count=$(find "$LOCAL_HOME/Desktop/incoming" -type f | wc -l | tr -d ' ')
  audit "share_sync" "$EP_ROLE working copy refreshed: $count file(s) on $EP_NAME desktop"
  sleep 300
done
