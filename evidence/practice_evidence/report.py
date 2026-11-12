"""Markdown rendering of a snapshot."""

from __future__ import annotations

import json
from typing import Any

DRIFT_SECTIONS = [
    ("findings_new", "New findings"),
    ("findings_resolved", "Resolved findings"),
    ("findings_changed", "Changed findings"),
    ("user_changes", "Identity changes"),
    ("group_changes", "Group changes"),
    ("share_changes", "Share changes"),
    ("endpoint_changes", "Endpoint changes"),
]


def _drift_lines(drift: dict[str, Any]) -> list[str]:
    if drift["status"] == "baseline":
        return ["## Changes since last run", "", "_Baseline snapshot - no previous run to compare._", ""]
    total = sum(len(drift.get(k, [])) for k, _ in DRIFT_SECTIONS)
    lines = ["## Changes since last run", "", f"Compared to: {drift['compared_to']} | {total} change(s)", ""]
    any_changes = False
    for key, label in DRIFT_SECTIONS:
        if drift.get(key):
            any_changes = True
            lines += [f"**{label}**", *[f"- {item}" for item in drift[key]], ""]
    if drift["counter_deltas"]:
        any_changes = True
        lines += ["**Activity deltas**"]
        lines += [f"- {m}: {'+' if d >= 0 else ''}{d}" for m, d in drift["counter_deltas"].items()]
        lines.append("")
    if not any_changes:
        lines += ["_No changes since last run._", ""]
    return lines


def render_markdown(snapshot: dict[str, Any], day: str) -> str:
    counts = snapshot["finding_counts"]
    ident, ehr, auth = snapshot["identity"], snapshot["ehr"], snapshot["auth"]
    lines = [
        f"# Practice Snapshot - {day}",
        "",
        f"Collected: {snapshot['collected_at']} | Lab: `{snapshot['lab']}` | Findings: "
        + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())),
        "",
        *_drift_lines(snapshot["drift"]),
        "## Findings",
        "",
        *[f"- **[{f['severity'].upper()}]** ({f['section']}) {f['detail']}" for f in snapshot["findings"]],
        "",
        "## Identity",
        "",
        f"- Password policy: {json.dumps(ident['password_policy'])}",
        f"- Enabled users: {sum(1 for u in ident['users'] if u['enabled'])}"
        f" / disabled: {sum(1 for u in ident['users'] if not u['enabled'])}",
        *[f"- {g}: {', '.join(m) if m else '(empty)'}" for g, m in ident["privileged_groups"].items()],
        "",
        "## File shares (patient-adjacent data outside the EHR)",
        "",
        *[f"- `{f['path']}` (sha256:{f['sha256_16']}...)" for f in snapshot["shares"]["files"]],
        "",
        "## Auth activity",
        "",
        f"- Success: {auth['success']} | Failures: {auth['failures']} (window {auth['window_hours']}h)",
        *[f"- {reason}: {n}" for reason, n in auth["failure_reasons"].items()],
        "",
        "## EHR surface",
        "",
        f"- Portal health: {ehr['health']}",
        f"- Public intake submissions (all time): {ehr['intake_submissions']}",
        f"- Scribe transmission events (all time): {ehr['scribe_transmissions']}",
        "",
        "## Endpoint exposure (unmanaged workstations)",
        "",
    ]
    for host in snapshot["endpoints"]["hosts"]:
        if host["local_copies"]:
            for c in host["local_copies"]:
                digest = f"sha256:{c['sha256_16']}..." if c.get("sha256_16") else "hash unavailable (root-only)"
                lines.append(f"- {host['name']} ({host['role']}): `{c['file']}` ({digest})")
        else:
            lines.append(f"- {host['name']} ({host['role']}): no local copies detected")
        if host["activity"]:
            lines.append(f"  - activity events: {json.dumps(host['activity'])}")
    sc = snapshot["supply_chain"]
    lines += [
        "",
        "## Supply chain (Bumblebee scan)",
        "",
        f"- Scanner status: {sc.get('status')}" + (f" - {sc.get('detail')}" if sc.get("detail") else ""),
        *[f"- **[{f['severity'].upper()}]** {f['detail']}" for f in sc.get("findings", [])],
        "",
        "---",
        "",
        "_Synthetic lab data. No real patient information. Metadata-only evidence._",
    ]
    return "\n".join(lines) + "\n"
