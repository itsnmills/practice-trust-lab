"""Endpoints: local copies of share files, hash-matched, plus activity counts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..config import ENDPOINTS, LAB_ROOT
from ..models import Finding, dump_findings
from .shares import PATIENT_ADJACENT


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def scan_copies(desktop: Path) -> list[dict[str, Any]]:
    copies: list[dict[str, Any]] = []
    if not desktop.exists():
        return copies
    for p in sorted(desktop.glob("*")):
        if not p.is_file():
            continue
        try:
            digest, readable = hashlib.sha256(p.read_bytes()).hexdigest()[:16], True
        except PermissionError:
            digest, readable = None, False
        copies.append({"file": p.name, "sha256_16": digest, "readable": readable})
    return copies


def count_activity(path: Path) -> dict[str, int]:
    activity: dict[str, int] = {}
    if not path.exists():
        return activity
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        key = ev.get("event", "unknown") if isinstance(ev, dict) else "unknown"
        activity[key] = activity.get(key, 0) + 1
    return activity


def host_findings(spec: dict[str, str], copies: list[dict[str, Any]]) -> list[Finding]:
    name, role = spec["name"], spec["role"]
    out = [
        Finding(
            "low",
            f"{name}: copy not readable by evidence collector: {c['file']}",
            rule_id="EP-UNREADABLE-COPY",
            subject=f"{name}:{c['file']}",
        )
        for c in copies
        if not c["readable"]
    ]
    if not copies:
        return out
    adjacent = [c for c in copies if PATIENT_ADJACENT.search(c["file"])]
    if adjacent:
        out.append(
            Finding(
                "high",
                f"{name} ({role}): {_plural(len(adjacent), 'patient-adjacent file')} on local desktop",
                rule_id="EP-ADJACENT-EXPORT",
                subject=name,
                ref_key=f"endpoint-{name}",
            )
        )
    else:
        out.append(
            Finding(
                "info",
                f"{name} ({role}): {_plural(len(copies), 'share file')} cached locally",
                rule_id="EP-CACHED-SHARE-FILE",
                subject=name,
            )
        )
    return out


def collect() -> dict[str, Any]:
    hosts, findings = [], []
    for spec in ENDPOINTS:
        copies = scan_copies(LAB_ROOT / spec["dir"] / "home" / "Desktop" / "incoming")
        hosts.append(
            {
                "name": spec["name"],
                "role": spec["role"],
                "local_copies": copies,
                "activity": count_activity(LAB_ROOT / spec["dir"] / "logs" / "activity.jsonl"),
            }
        )
        findings += host_findings(spec, copies)
    return {"hosts": hosts, "findings": dump_findings(findings)}
