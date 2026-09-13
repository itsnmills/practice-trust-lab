#!/bin/bash
# populate-domain.sh - build the lab org inside the samba-dc container:
# OUs, groups (AGDLP), synthetic users, account lockout policy.
#
# Everyone here is synthetic. The org chart is a small fictional clinic
# office because that is the environment this lab practices for.
#
# Run from the docker host:
#   source .env
#   docker exec -i samba-dc bash -s "$USER_TEMP_PASS" "$TECH_PASS" < populate-domain.sh

set -euo pipefail
TEMP_PW="${1:?usage: populate-domain.sh <temp-pw> <tech-pw>}"
TECH_PW="${2:?usage: populate-domain.sh <temp-pw> <tech-pw>}"
BASE="DC=millslab,DC=internal"

# --- OUs (parents first) --------------------------------------------------
for ou in \
  "OU=MillsLab,$BASE" \
  "OU=Staff,OU=MillsLab,$BASE" \
  "OU=Clinical,OU=Staff,OU=MillsLab,$BASE" \
  "OU=Front Office,OU=Staff,OU=MillsLab,$BASE" \
  "OU=IT,OU=Staff,OU=MillsLab,$BASE" \
  "OU=Groups,OU=MillsLab,$BASE" \
  "OU=Service Accounts,OU=MillsLab,$BASE" \
  "OU=Workstations,OU=MillsLab,$BASE" \
  "OU=Disabled Users,OU=MillsLab,$BASE"
do
  out=$(samba-tool ou create "$ou" 2>&1) && echo "OU created: $ou" || {
    if echo "$out" | grep -qi "already exists"; then echo "OU exists:  $ou"
    else echo "OU FAILED:  $ou -> $out"; exit 1; fi
  }
done

# --- Groups: global role groups + one domain-local resource group ---------
for g in SG-Clinical SG-FrontOffice SG-IT; do
  out=$(samba-tool group add "$g" --group-scope=Global --groupou="OU=Groups,OU=MillsLab" 2>&1) \
    && echo "Group created: $g" || {
      if echo "$out" | grep -qi "already exists"; then echo "Group exists:  $g"
      else echo "Group FAILED: $g -> $out"; exit 1; fi
    }
done
out=$(samba-tool group add DL-ClinicalShare-RW --group-scope=Domain --groupou="OU=Groups,OU=MillsLab" 2>&1) \
  && { echo "Group created: DL-ClinicalShare-RW"; samba-tool group addmembers DL-ClinicalShare-RW SG-Clinical; } \
  || { echo "$out" | grep -qi "already exists" && echo "Group exists:  DL-ClinicalShare-RW" || { echo "FAILED: $out"; exit 1; }; }

# --- Users ----------------------------------------------------------------
# sam;first;last;ou;group;known  (known=tech password, no forced change:
# those accounts get used interactively in demos)
USERS='
malvarez;Maria;Alvarez;Clinical;SG-Clinical;no
jchen;James;Chen;Clinical;SG-Clinical;yes
sokafor;Sarah;Okafor;Clinical;SG-Clinical;no
etran;Emily;Tran;Clinical;SG-Clinical;no
kwhite;Karen;White;Clinical;SG-Clinical;no
dpark;David;Park;Front Office;SG-FrontOffice;no
lnguyen;Lisa;Nguyen;Front Office;SG-FrontOffice;no
rhayes;Robert;Hayes;Front Office;SG-FrontOffice;no
aruiz;Angela;Ruiz;Front Office;SG-FrontOffice;no
nmills;Noah;Mills;IT;SG-IT;yes
'
echo "$USERS" | while IFS=';' read -r sam first last ou group known; do
  [ -z "$sam" ] && continue
  if samba-tool user show "$sam" >/dev/null 2>&1; then echo "User exists:  $sam"; continue; fi
  pw="$TEMP_PW"; extra="--must-change-at-next-login"
  if [ "$known" = "yes" ]; then pw="$TECH_PW"; extra=""; fi
  samba-tool user create "$sam" "$pw" \
    --given-name="$first" --surname="$last" \
    --userou="OU=$ou,OU=Staff,OU=MillsLab" \
    --mail-address="$sam@millslab.internal" $extra >/dev/null
  samba-tool group addmembers "$group" "$sam" >/dev/null
  echo "User created: $sam ($first $last) -> $ou / $group"
done

if ! samba-tool user show svc-backup >/dev/null 2>&1; then
  samba-tool user create svc-backup "$TECH_PW" \
    --userou="OU=Service Accounts,OU=MillsLab" \
    --description="Backup service account (placeholder, disabled)" >/dev/null
  samba-tool user disable svc-backup
  echo "Service account created (disabled): svc-backup"
fi

# --- Lockout policy: 5 bad tries, 15 minute lockout -----------------------
samba-tool domain passwordsettings set \
  --complexity=on --min-pwd-length=10 \
  --account-lockout-threshold=5 \
  --account-lockout-duration=15 \
  --reset-account-lockout-after=10 >/dev/null
echo "Lockout policy set: 5 attempts / 15 min"

# --- Summary --------------------------------------------------------------
echo; echo "=== OUs ===";    samba-tool ou list | sort
echo; echo "=== Groups (in OU=Groups) ==="
samba-tool group list | grep -E '^(SG|DL)-' | sort
echo; echo "=== Users ==="; samba-tool user list | sort
echo; echo "=== Password / lockout policy ==="
samba-tool domain passwordsettings show
