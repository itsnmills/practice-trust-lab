"""Derive reviewer-facing rows, decisions, and owner lanes from a snapshot."""

from __future__ import annotations

from typing import Any

from .rules import (
    CONSOLIDATED_GROUPS,
    GROUP_ORDER,
    SEVERITY_ORDER,
    SEVERITY_TAG,
    Rule,
    rule_for_finding,
)
from .text import due_date, extract_item

DECISION_TEMPLATES = [
    {
        "match_groups": ["supply"],
        "state": "block",
        "title": "Do not deploy the flagged package.",
        "body": "The front-desk billing helper carries a known-compromised dependency. Keep it off any other machine until the package is removed or replaced.",
        "proof": "Clean re-scan receipt",
    },
    {
        "match_groups": ["scribe"],
        "state": "review",
        "title": "Hold AI scribe expansion.",
        "body": "Encounter data is leaving the EHR to a vendor with no verified BAA. Do not expand the pilot until BAA evidence is on file.",
        "proof": "Signed BAA + subprocessor list",
    },
    {
        "match_groups": ["endpoint"],
        "state": "review",
        "title": "Stop desktop copies of clinical exports.",
        "body": "Patient-adjacent exports sit on local desktops outside the managed share. Stop the copy workflow and document the replacement.",
        "proof": "Endpoint cleanup confirmation",
    },
    {
        "match_groups": ["shares"],
        "state": "review",
        "title": "Confirm business need for share exports.",
        "body": "Schedule and insurance exports live on a share that clinical staff can reach. Confirm each export is required, then restrict to the minimum lane.",
        "proof": "Owner signoff per export",
    },
]

LANE_ORDER = ["practice owner", "msp", "scribe vendor", "web vendor", "front office"]
LANE_LABELS = {
    "practice owner": "Practice owner",
    "msp": "MSP",
    "scribe vendor": "Scribe vendor",
    "web vendor": "Web vendor",
    "front office": "Front office",
}


def _row(rule: Rule, severity: str, detail: str, items: list[str], collected_iso: str) -> dict[str, Any]:
    # A titled rule that is not consolidated still needs the concrete detail
    # (observed value, principal, path) visible in the packet.
    if not items and rule.title:
        items = [detail]
    return {
        "rule_id": rule.rule_id,
        "group": rule.group,
        "title": rule.title or detail,
        "severity": severity,
        "lane": rule.lane,
        "confidence": rule.confidence,
        "ask": rule.ask,
        "proof": rule.proof,
        "due": due_date(collected_iso, rule.due),
        "items": items,
        "hipaa": rule.hipaa,
    }


def build_rows(snap: dict[str, Any], collected_iso: str) -> list[dict[str, Any]]:
    findings = sorted(
        snap.get("findings", []),
        key=lambda x: (SEVERITY_ORDER.get(x.get("severity", "info"), 9), x.get("section", "")),
    )
    consolidated: dict[str, dict[str, Any]] = {}
    rows: list[dict[str, Any]] = []
    for finding in findings:
        detail = finding.get("detail", "")
        rule = rule_for_finding(finding)
        group = rule.group or "other"
        severity = finding.get("severity") or rule.severity
        if severity not in SEVERITY_ORDER:
            severity = "info"
        if group in CONSOLIDATED_GROUPS:
            if group in consolidated:
                row = consolidated[group]
                row["items"].append(extract_item(group, detail))
                if SEVERITY_ORDER.get(severity, 9) < SEVERITY_ORDER.get(row["severity"], 9):
                    row["severity"] = severity
                continue
            row = _row(rule, severity, detail, [extract_item(group, detail)], collected_iso)
            consolidated[group] = row
            rows.append(row)
        else:
            rows.append(_row(rule, severity, detail, [], collected_iso))
    rows.sort(
        key=lambda r: (
            SEVERITY_ORDER.get(r["severity"], 9),
            GROUP_ORDER.index(r["group"]) if r["group"] in GROUP_ORDER else 99,
        )
    )
    for i, row in enumerate(rows, 1):
        row["ref"] = f"E-{i:02d}"
    return rows


def build_decisions(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    decisions = []
    for template in DECISION_TEMPLATES:
        refs = [row["ref"] for row in rows if row["group"] in template["match_groups"]]
        if refs:
            decision = dict(template)
            decision["refs"] = refs
            decisions.append(decision)
    if not decisions:
        decisions.append(
            {
                "state": "allow",
                "title": "No blocking conditions in this pass.",
                "body": "No high-severity gaps were found. Proceed with the owner review and standard maintenance cycle.",
                "proof": "Owner review note",
                "refs": [],
            }
        )
    return decisions[:4]


def build_lanes(rows: list[dict[str, Any]]) -> list[dict[str, str]]:
    lanes: dict[str, dict[str, Any]] = {}
    for row in rows:
        for raw in [part.strip() for part in row["lane"].split("+")]:
            key = raw.lower()
            entry = lanes.setdefault(key, {"recipient": LANE_LABELS.get(key, raw.title()), "pairs": []})
            entry["pairs"].append((int(row["ref"].split("-")[1]), row["due"], row["ref"]))
    ordered = sorted(lanes.items(), key=lambda kv: LANE_ORDER.index(kv[0]) if kv[0] in LANE_ORDER else 99)
    result = []
    for _key, lane in ordered[:5]:
        collapsed: list[list[Any]] = []
        for num, due, _ref in sorted(lane["pairs"]):
            if collapsed and collapsed[-1][1] == due and collapsed[-1][2] + 1 == num:
                collapsed[-1][2] = num
            else:
                collapsed.append([num, due, num])
        parts = []
        for start, due, end in collapsed:
            label = f"E-{start:02d}" if start == end else f"E-{start:02d}\u2013E-{end:02d}"
            parts.append(f"{label} ({due})")
        result.append({"recipient": lane["recipient"], "refs": "; ".join(parts)})
    return result


__all__ = [
    "DECISION_TEMPLATES",
    "LANE_LABELS",
    "LANE_ORDER",
    "SEVERITY_TAG",
    "build_decisions",
    "build_lanes",
    "build_rows",
]
