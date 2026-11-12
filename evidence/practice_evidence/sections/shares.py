"""File shares: smb.conf inventory, file hashes, patient-adjacent detection."""

from __future__ import annotations

import re
from typing import Any

from ..models import Finding, dump_findings
from ..runner import dexec

SYSTEM_SHARES = ("global", "sysvol", "netlogon")
PATIENT_ADJACENT = re.compile(r"patient|intake|insurance|schedule", re.I)


def parse_smb_conf(conf: str) -> list[dict[str, str]]:
    """Return one dict per non-system share section, with its key = value options."""
    shares: list[dict[str, str]] = []
    in_share = False
    for line in conf.splitlines():
        m = re.match(r"^\[(.+)\]$", line.strip())
        if m:
            name = m.group(1)
            in_share = name not in SYSTEM_SHARES
            if in_share:
                shares.append({"name": name})
        elif in_share and "=" in line:
            key, _, val = line.partition("=")
            shares[-1][key.strip()] = val.strip()
    return shares


def share_findings(files: list[dict[str, Any]]) -> list[Finding]:
    return [
        Finding(
            "high",
            f"patient-adjacent data on file share: {f['path']}",
            rule_id="SHR-PATIENT-ADJACENT",
            subject=f["path"],
        )
        for f in files
        if PATIENT_ADJACENT.search(f["path"])
    ]


def collect() -> dict[str, Any]:
    shares = parse_smb_conf(dexec(["cat", "/etc/samba/smb.conf"]))
    files = []
    for p in [x.strip() for x in dexec(["find", "/srv/samba/shares", "-type", "f"]).splitlines() if x.strip()]:
        files.append({"path": p, "sha256_16": dexec(["sha256sum", p]).split(" ")[0][:16]})
    return {"shares": shares, "files": files, "findings": dump_findings(share_findings(files))}
