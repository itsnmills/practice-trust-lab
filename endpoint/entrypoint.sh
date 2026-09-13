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
DC_IP=${DC_IP:-172.31.13.10}
SHARE_HOST=${SHARE_HOST:-dc1.millslab.internal}
EP_NAME=${ENDPOINT_NAME:-ws-clinical-01}
EP_ROLE=${ENDPOINT_ROLE:-Clinic workstation}
SYNC_USER=${SYNC_USER:-jchen}
SYNC_PASS=${SYNC_PASS:?SYNC_PASS required}
SYNC_SHARES=${SYNC_SHARES:-ClinicalShare}
SYNC_PATTERN=${SYNC_PATTERN:-*}
LOCAL_HOME=/home/staff
LOGDIR=/var/log/endpoint
MARKER=/var/lib/samba/.joined

mkdir -p "$LOCAL_HOME/Desktop/incoming" "$LOGDIR"

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

echo "[$EP_NAME] waiting for DC DNS..."
for i in $(seq 1 60); do
  if getent hosts "$SHARE_HOST" >/dev/null 2>&1; then break; fi
  sleep 2
done

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

if [ ! -f "$MARKER" ]; then
  echo "[$EP_NAME] joining domain $REALM"
  umask 077
  cat > /tmp/.joincreds <<CRED
username=Administrator
password=${SAMBA_ADMIN_PASS}
domain=$DOMAIN
CRED
  net ads join -A /tmp/.joincreds --no-dns-updates \
    createcomputer="MillsLab/Workstations" || true
  rm -f /tmp/.joincreds
  touch "$MARKER"
  echo "[$EP_NAME] join complete"
fi

winbindd -D -s /etc/samba/smb.conf 2>/dev/null || true

audit() {
  printf '{"ts":"%s","endpoint":"%s","event":"%s","detail":"%s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$EP_NAME" "$1" "$2" >> "$LOGDIR/activity.jsonl"
}

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
