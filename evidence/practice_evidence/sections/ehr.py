"""Mock EHR surface: portal health, intake submissions, AI-scribe egress events."""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path
from typing import Any

from ..config import EHR_HEALTH_URL, EHR_LOG
from ..models import Finding, dump_findings


def count_events(log_path: Path) -> dict[str, int]:
    events: dict[str, int] = {}
    if not log_path.exists():
        return events
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            name = json.loads(line)["event"]
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
        events[name] = events.get(name, 0) + 1
    return events


def event_findings(events: dict[str, int]) -> list[Finding]:
    out = []
    scribe = events.get("scribe_transmission", 0)
    intake = events.get("intake_submitted", 0)
    if scribe:
        out.append(
            Finding(
                "high",
                f"{scribe} scribe transmission events; verify signed BAA per vendor",
                rule_id="EHR-SCRIBE-NO-BAA",
                subject="scribe-vendor",
            )
        )
    if intake:
        out.append(
            Finding(
                "medium",
                f"{intake} public web intake submission{'s' if intake != 1 else ''}; "
                "confirm TLS + retention + access control",
                rule_id="EHR-PUBLIC-INTAKE",
                subject="web-intake",
                ref_key="ehr-intake",
            )
        )
    return out


def collect() -> dict[str, Any]:
    findings: list[Finding] = []
    try:
        with urllib.request.urlopen(EHR_HEALTH_URL, timeout=5) as resp:
            health = json.loads(resp.read().decode())
    except Exception as exc:  # noqa: BLE001
        health = {"error": str(exc)}
        findings.append(
            Finding(
                "medium",
                f"clinic portal unreachable: {exc}",
                rule_id="EHR-PORTAL-UNREACHABLE",
                subject="clinic-ehr",
            )
        )

    events = count_events(EHR_LOG)
    findings += event_findings(events)
    return {
        "health": health,
        "events": events,
        "scribe_transmissions": events.get("scribe_transmission", 0),
        "intake_submissions": events.get("intake_submitted", 0),
        "findings": dump_findings(findings),
    }
