#!/usr/bin/env bash
# Assert the access boundaries the README claims, against the running lab.
# Exits non-zero if any boundary deviates; prints one line per check.
#
#   scripts/verify-boundaries.sh
#
# Expected:
#   * clinical user (jchen) can read ClinicalShare
#   * IT user (nmills) is denied ClinicalShare but can read ITShare
#   * a temporary-password user (malvarez) cannot authenticate at all
#   * anonymous access is denied
#   * no lab password is visible in `docker inspect` container config
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

pass=0
fail=0

ok() { printf '  ok    %s\n' "$*"; pass=$((pass + 1)); }
bad() { printf '  FAIL  %s\n' "$*" >&2; fail=$((fail + 1)); }

if ! docker inspect samba-dc >/dev/null 2>&1; then
  printf 'samba-dc is not running; start the lab with scripts/bootstrap.sh\n' >&2
  exit 2
fi

# --- expected containers exist -------------------------------------------
for container in samba-dc clinic-ehr ws-clinical-01 fd-frontdesk-01 msp-jump-01; do
  if docker inspect "$container" >/dev/null 2>&1; then
    ok "container present: $container"
  else
    bad "container missing: $container (lab not fully started)"
  fi
done

# --- container config must not expose passwords ---------------------------
if [ -f samba-dc/.env ]; then
  # shellcheck disable=SC1091
  set -a; . samba-dc/.env; set +a
  leaked=0
  for container in samba-dc clinic-ehr ws-clinical-01 fd-frontdesk-01 msp-jump-01; do
    docker inspect "$container" >/dev/null 2>&1 || continue
    inspect_env=$(docker inspect "$container" --format '{{json .Config.Env}}')
    for secret in "${SAMBA_ADMIN_PASS:-}" "${USER_TEMP_PASS:-}" "${TECH_PASS:-}"; do
      [ -n "$secret" ] || continue
      if printf '%s' "$inspect_env" | grep -Fq -- "$secret"; then
        bad "$container: a lab password appears in docker inspect env"
        leaked=1
      fi
    done
  done
  if [ "$leaked" = "0" ]; then
    ok "container config: no lab password in any lab container's docker inspect env"
  fi
else
  bad "samba-dc/.env missing; cannot verify credential handling"
fi

# --- SMB boundary probes, run inside the DC -------------------------------
probe_output=$(docker exec -i samba-dc bash -s <<'EOS'
set -u
if [ -r /run/secrets/lab_env ]; then
  set -a
  . /run/secrets/lab_env
  set +a
fi
TECH=${TECH_PASS:-}
TEMP=${USER_TEMP_PASS:-}
if [ -z "$TECH" ] || [ -z "$TEMP" ]; then
  echo "PROBE_ERROR|credentials unavailable in container"
  exit 0
fi

probe() {
  label=$1
  user=$2
  password=$3
  share=$4
  cred=$(mktemp) || { echo "PROBE_ERROR|mktemp failed"; return 0; }
  chmod 600 "$cred"
  printf 'username=%s\npassword=%s\ndomain=MILLSLAB\n' "$user" "$password" > "$cred"
  out=$(smbclient "//dc1.millslab.internal/$share" -A "$cred" -c 'ls' 2>&1)
  rc=$?
  rm -f "$cred"
  reason=ok
  if [ "$rc" -ne 0 ]; then
    reason=$(printf '%s\n' "$out" | grep -o 'NT_STATUS_[A-Z_]*' | head -n1)
    [ -n "$reason" ] || reason=$(printf '%s\n' "$out" | head -n1 | tr -d '\r')
  fi
  printf 'RESULT|%s|%s|%s\n' "$label" "$rc" "$reason"
}

probe clinical_allow jchen "$TECH" ClinicalShare
probe it_deny nmills "$TECH" ClinicalShare
probe it_allow nmills "$TECH" ITShare
probe temp_deny malvarez "$TEMP" ClinicalShare

out=$(smbclient -N "//dc1.millslab.internal/ClinicalShare" -c 'ls' 2>&1)
rc=$?
reason=ok
if [ "$rc" -ne 0 ]; then
  reason=$(printf '%s\n' "$out" | grep -o 'NT_STATUS_[A-Z_]*' | head -n1)
  [ -n "$reason" ] || reason=$(printf '%s\n' "$out" | head -n1 | tr -d '\r')
fi
printf 'RESULT|anon_deny|%s|%s\n' "$rc" "$reason"
EOS
)

if printf '%s\n' "$probe_output" | grep -q '^PROBE_ERROR|'; then
  bad "probe: $(printf '%s\n' "$probe_output" | grep '^PROBE_ERROR|' | cut -d'|' -f2-)"
else
  while IFS='|' read -r tag label rc reason; do
    [ "$tag" = "RESULT" ] || continue
    case "$label" in
      clinical_allow)
        if [ "$rc" = "0" ]; then ok "clinical user can read ClinicalShare"; else bad "clinical user denied ClinicalShare ($reason)"; fi
        ;;
      it_deny)
        if [ "$rc" != "0" ] && printf '%s' "$reason" | grep -q 'ACCESS_DENIED'; then
          ok "IT user denied ClinicalShare ($reason)"
        else
          bad "IT user expected ACCESS_DENIED on ClinicalShare, got rc=$rc $reason"
        fi
        ;;
      it_allow)
        if [ "$rc" = "0" ]; then ok "IT user can read ITShare"; else bad "IT user denied ITShare ($reason)"; fi
        ;;
      temp_deny)
        if [ "$rc" != "0" ] && printf '%s' "$reason" | grep -q 'NT_STATUS_'; then
          ok "temporary-password user cannot authenticate ($reason)"
        else
          bad "temporary-password user expected auth failure, got rc=$rc $reason"
        fi
        ;;
      anon_deny)
        if [ "$rc" != "0" ] && printf '%s' "$reason" | grep -q 'NT_STATUS_'; then
          ok "anonymous access denied ($reason)"
        else
          bad "anonymous access expected denial, got rc=$rc $reason"
        fi
        ;;
      *)
        bad "unknown probe result: $label"
        ;;
    esac
  done <<< "$probe_output"
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
