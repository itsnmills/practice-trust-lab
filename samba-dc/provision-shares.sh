#!/bin/bash
# provision-shares.sh - build the file-share footprint inside samba-dc:
# shared folders, AD-group based access, and synthetic clinic files.
#
# Everything here is synthetic. These shares exist so the lab can practice
# the exact thing Velari reviews in real clinics: where patient-adjacent
# data lives outside the EHR, who can reach it, and what evidence that
# leaves behind.
#
# Run from the docker host:
#   docker exec -i samba-dc bash -s < provision-shares.sh

set -euo pipefail
ROOT=/srv/samba/shares
CONF=/etc/samba/smb.conf

# --- Share definitions (idempotent append) --------------------------------
add_share() {
  local name="$1"
  if grep -q "^\[$name\]" "$CONF"; then
    echo "Share exists:  $name"
    return 0
  fi
  cat >> "$CONF" <<EOF

[$name]
	path = $ROOT/$2
	read only = No
	browseable = Yes
	valid users = $3
	force group = $4
	create mask = 0660
	directory mask = 0770
EOF
  echo "Share created: $name"
}

mkdir -p "$ROOT"/clinical "$ROOT"/frontoffice "$ROOT"/it
# NOTE: filesystem access is set with NT ACLs (see apply_acls below). An earlier
# version ran `chgrp "MILLSLAB\\DL-ClinicalShare-RW"`, which always failed (the name
# does not resolve to a gid here) and was hidden by `|| true`, leaving every share
# directory world-readable (0755 root) with access gated only by smb.conf.

add_share "ClinicalShare"     clinical     "@DL-ClinicalShare-RW" "DL-ClinicalShare-RW"
add_share "FrontOfficeShare"  frontoffice  "@SG-FrontOffice @SG-IT" "SG-FrontOffice"
add_share "ITShare"           it           "@SG-IT" "SG-IT"

# --- Synthetic data -------------------------------------------------------
seed() { # seed <path> <content-file-marker>
  if [ ! -f "$1" ]; then cat > "$1"; echo "Seeded: $1"; else echo "Exists: $1"; fi
}

seed "$ROOT/clinical/patient-schedule-export-2026-09.csv" <<'EOF'
# SYNTHETIC LAB DATA - not real patients
mrn,patient_name,dob,appt_date,provider,reason
SYN-1001,Maria Alvarez,1974-02-11,2026-09-14 09:00,Dr. Chen,Diabetes follow-up
SYN-1002,James Chen,1988-07-23,2026-09-14 09:30,Dr. Okafor,Annual physical
SYN-1003,Sarah Okafor,1965-11-02,2026-09-14 10:00,Dr. Chen,Hypertension check
SYN-1004,Emily Tran,1992-03-18,2026-09-15 08:30,PA White,Med refill
EOF

seed "$ROOT/clinical/insurance-verification-2026-09.csv" <<'EOF'
# SYNTHETIC LAB DATA - not real patients
mrn,payer,policy_id,verified_by,verified_on,status
SYN-1001,Acme Health Plan,SYN-POL-88121,dpark,2026-09-08,active
SYN-1002,Acme Health Plan,SYN-POL-88122,lnguyen,2026-09-08,active
SYN-1003,Beacon Mutual,SYN-POL-45110,dpark,2026-09-09,pending
SYN-1004,Beacon Mutual,SYN-POL-45111,aruiz,2026-09-09,active
EOF

seed "$ROOT/clinical/scribe-pilot-notes.txt" <<'EOF'
SYNTHETIC LAB DATA - not real patients
AI scribe pilot - week 1 observations
- Two providers testing vendor scribe on 4 visits/day
- Consent script read at check-in (see intake form v3)
- Transcripts land in vendor cloud; BAA status: UNVERIFIED as of 2026-09-08
- Action: ask vendor for signed BAA + subprocessor list before expanding
EOF

seed "$ROOT/frontoffice/intake-form-responses-2026-09.csv" <<'EOF'
# SYNTHETIC LAB DATA - not real patients
name,dob,phone,insurance,reason_for_visit
Maria Alvarez,1974-02-11,555-0101,Acme Health Plan,Diabetes follow-up
James Chen,1988-07-23,555-0102,Acme Health Plan,Annual physical
EOF

seed "$ROOT/frontoffice/front-desk-runbook.md" <<'EOF'
# SYNTHETIC LAB DATA
Front desk runbook (draft)
1. Verify insurance before visit, log in tracker CSV
2. Read AI scribe consent script (v3) at check-in
3. Route faxes to provider folder, not the shared drive
EOF

seed "$ROOT/it/backup-runbook.md" <<'EOF'
# SYNTHETIC LAB DATA
Backup runbook (draft)
- Nightly backup service account: svc-backup (currently disabled)
- TODO: verify restore test evidence quarterly
EOF

# --- Filesystem ACLs (least privilege, AGDLP) --------------------------------
# Defense in depth: the smb.conf `valid users` gate is not the only control. Each
# share directory grants full control to the local Administrator and
# read/write/delete (no change-permissions) to the groups in its model; a
# "group:r" argument grants read/execute only (SG-IT on the front-office share).
# Re-running replaces the ACL with the same value, so this is idempotent.
group_sid() {
  samba-tool group show "$1" --attributes=objectSid 2>/dev/null | awk '/^objectSid/ {print $2}'
}

apply_acls() {
  local dir="$1"; shift
  local rw="0x1301bf" ro="0x1200a9" sddl_dir="O:LAG:LAD:PAI(A;OICI;FA;;;LA)" sddl_file="O:LAG:LAD:PAI(A;;FA;;;LA)"
  local spec g mask sid
  for spec in "$@"; do
    g="${spec%%:*}"; mask="$rw"
    [ "$spec" != "$g:r" ] || mask="$ro"
    sid="$(group_sid "$g")"
    [ -n "$sid" ] || { echo "ACL skipped: cannot resolve SID for group $g" >&2; return 1; }
    sddl_dir="${sddl_dir}(A;OICI;${mask};;;${sid})"
    sddl_file="${sddl_file}(A;;${mask};;;${sid})"
  done
  samba-tool ntacl set "$sddl_dir" "$dir"
  find "$dir" -mindepth 1 -type d | while IFS= read -r d; do samba-tool ntacl set "$sddl_dir" "$d"; done
  find "$dir" -type f | while IFS= read -r f; do samba-tool ntacl set "$sddl_file" "$f"; done
  echo "ACL applied: $dir -> $*"
}

apply_acls "$ROOT/clinical"    DL-ClinicalShare-RW
# SG-IT is granted read/write here on purpose, not read-only: the share's
# `force group = SG-FrontOffice` adds that group to every connecting user's token,
# so IT users get the front-office group's write access regardless of an IT:r entry
# (verified live: an SG-IT user wrote to the share under an SG-IT read-only ACL).
# Making IT genuinely read-only means dropping `force group` and relying on ACL
# inheritance. The collector reports this as ACL-UNDOCUMENTED-WRITE.
apply_acls "$ROOT/frontoffice" SG-FrontOffice SG-IT
apply_acls "$ROOT/it"          SG-IT

# --- Reload samba ---------------------------------------------------------
smbcontrol all reload-config >/dev/null
echo
echo "=== Shares ==="
grep -E '^\[' "$CONF"
echo
echo "=== File inventory ==="
find "$ROOT" -type f | sort
