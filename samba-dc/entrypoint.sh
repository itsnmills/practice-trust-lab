#!/bin/bash
# Provision the domain on first run, then run samba in the foreground.
set -euo pipefail

# The lab env file is mounted as a read-only secret by compose, so passwords
# are not part of the container environment (`docker inspect`).
if [ -r /run/secrets/lab_env ]; then
  set -a
  # shellcheck disable=SC1091
  . /run/secrets/lab_env
  set +a
fi

REALM="${REALM:-MILLSLAB.INTERNAL}"
DOMAIN="${DOMAIN:-MILLSLAB}"
SAMBA_ADMIN_PASS="${SAMBA_ADMIN_PASS:?SAMBA_ADMIN_PASS is required (env or /run/secrets/lab_env)}"

if [ ! -f /var/lib/samba/private/sam.ldb ]; then
  echo "[entrypoint] first run: provisioning $REALM"
  rm -f /etc/samba/smb.conf
  samba-tool domain provision \
    --use-rfc2307 \
    --realm="$REALM" \
    --domain="$DOMAIN" \
    --server-role=dc \
    --dns-backend=SAMBA_INTERNAL \
    --adminpass="$SAMBA_ADMIN_PASS"
  # auth audit trail: JSON records of every auth attempt, visible in docker logs
  sed -i '/\[global\]/a\\tlog level = 1 auth_audit:3' /etc/samba/smb.conf
  echo "[entrypoint] provision complete"
fi

# krb5.conf must survive container rebuilds, and DNS-based KDC discovery
# does not work behind Docker's embedded resolver, so pin the KDC.
cat > /etc/krb5.conf <<KRB
[libdefaults]
    default_realm = $REALM
    dns_lookup_realm = false
    dns_lookup_kdc = false
[realms]
    $REALM = {
        kdc = 127.0.0.1
        admin_server = 127.0.0.1
    }
KRB

exec samba -i
