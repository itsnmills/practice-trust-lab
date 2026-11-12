"""Paths and tunables shared across the collector."""

from __future__ import annotations

import os
from pathlib import Path

EVIDENCE_DIR = Path(__file__).resolve().parent.parent
LAB_ROOT = EVIDENCE_DIR.parent
ARTIFACTS = EVIDENCE_DIR / "artifacts"
LEDGER = EVIDENCE_DIR / "ledger.jsonl"

DC = "samba-dc"
EHR_CONTAINER = "clinic-ehr"
EHR_LOG = LAB_ROOT / "clinic-ehr" / "data" / "access.jsonl"
EHR_HEALTH_URL = os.environ.get("EHR_URL", "http://127.0.0.1:8095/healthz")

PRIVILEGED_GROUPS = ["Domain Admins", "Enterprise Admins", "SG-IT"]
STALE_DAYS = 45

# Role groups expanded (including nesting) by the privilege section.
ROLE_GROUPS = ["Domain Admins", "Enterprise Admins", "Schema Admins", "SG-IT"]

# Documented least-privilege model for the shares in provision-shares.sh.
# Each share lists the principals allowed to read and to write.  ACLs granting
# anything outside these sets are reported.
SHARE_ACCESS_MODEL = {
    "ClinicalShare": {"allow": {"DL-ClinicalShare-RW"}, "write": {"DL-ClinicalShare-RW"}},
    "FrontOfficeShare": {"allow": {"SG-FrontOffice", "SG-IT"}, "write": {"SG-FrontOffice"}},
    "ITShare": {"allow": {"SG-IT"}, "write": {"SG-IT"}},
}

# Domain hygiene baselines.  Samba AD caps the functional level at 2008 R2, so
# the lab is expected to report this one by design.
MIN_DOMAIN_FUNCTION_LEVEL = "2016"
KRBTOG_MAX_AGE_DAYS = 180

ENDPOINTS = [
    {"name": "ws-clinical-01", "dir": "workstation-01", "role": "Clinical workstation"},
    {"name": "fd-frontdesk-01", "dir": "frontdesk-01", "role": "Front office workstation"},
    {"name": "msp-jump-01", "dir": "msp-jump-01", "role": "MSP admin jump box"},
]
LAB_CONTAINERS = {DC, EHR_CONTAINER} | {e["name"] for e in ENDPOINTS}

BUMBLEBEE_DIR = Path(os.environ.get("BUMBLEBEE_DIR", Path.home() / "bumblebee"))
SCAN_ROOTS = [LAB_ROOT / e["dir"] / "home" for e in ENDPOINTS]
