#!/usr/bin/env python3
"""render_practice_snapshot.py - render a practice-lab evidence JSON as a
self-contained, no-PHI review packet (HTML).

Design: statutory-memorandum form. Numbered sections, evidence schedule with
stable refs (E-01...), audit-style clauses, hairlines only. Gold appears in
exactly two places (masthead rule, attestation rule); red only for P1 and
BLOCK. No cards, no pills, no colored status words.

Usage:
  python3 render_practice_snapshot.py [snapshot.json]
  python3 render_practice_snapshot.py --latest
"""

import argparse
import html
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ARTIFACTS = Path(__file__).resolve().parent / "artifacts"
LAB_ROOT = Path(__file__).resolve().parent.parent

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
SEVERITY_TAG = {"high": "P1", "medium": "P2", "low": "P3", "info": "P4"}

EVIDENCE_RULES = [
    {
        "match": "known-compromised package",
        "group": "supply",
        "title": "Known-compromised package on an endpoint",
        "lane": "MSP + practice owner",
        "confidence": "Verified",
        "ask": "Remove or replace the flagged package, then re-scan the endpoint.",
        "proof": "Remediated lockfile + clean scan receipt",
        "due": "7 days",
    },
    {
        "match": "scribe transmission",
        "group": "scribe",
        "title": "AI scribe transmissions without verified BAA",
        "lane": "Practice owner + scribe vendor",
        "confidence": "Observed",
        "ask": "Obtain a signed BAA and subprocessor list before any expansion.",
        "proof": "Signed BAA + subprocessor list",
        "due": "7 days",
    },
    {
        "match": "on local desktop",
        "group": "endpoint",
        "title": "Patient-adjacent exports cached on endpoints",
        "lane": "MSP + front office",
        "confidence": "Verified",
        "ask": "Remove local copies and document a share-only workflow.",
        "proof": "Cleanup confirmation + workflow note",
        "due": "7 days",
    },
    {
        "match": "patient-adjacent data on file share",
        "group": "shares",
        "title": "Patient-adjacent data on file shares",
        "lane": "Practice owner + MSP",
        "confidence": "Verified",
        "ask": "Confirm business need per export; move to minimal-access share or remove.",
        "proof": "Share ACL export + owner signoff",
        "due": "14 days",
    },
    {
        "match": "public web intake submission",
        "group": "intake",
        "title": "Public web intake form in use",
        "lane": "MSP + web vendor",
        "confidence": "Observed",
        "ask": "Confirm TLS, retention, and access control for the intake form.",
        "proof": "Vendor security page + retention statement",
        "due": "30 days",
    },
    {
        "match": "auth failures",
        "group": "auth",
        "title": "Authentication failures in the review window",
        "lane": "MSP",
        "confidence": "Observed",
        "ask": "Review the failure source and any inbound authentication attempts.",
        "proof": "Auth log summary",
        "due": "14 days",
    },
    {
        "match": "SG-IT membership",
        "group": "admin",
        "title": "Admin-equivalent group membership",
        "lane": "MSP",
        "confidence": "Verified",
        "ask": "Confirm business need; enforce MFA on admin-equivalent access.",
        "proof": "Access review signoff + MFA evidence",
        "due": "30 days",
    },
    {
        "match": "never logged on",
        "group": "dormant",
        "title": "Dormant enabled accounts",
        "lane": "MSP",
        "confidence": "Verified",
        "ask": "Disable or document each unused account.",
        "proof": "Account disposition list",
        "due": "30 days",
    },
    {
        "match": "disabled account present",
        "group": "disabled",
        "title": "Disabled accounts still present",
        "lane": "Practice owner",
        "confidence": "Verified",
        "ask": "Confirm disabled accounts are still required; remove if not.",
        "proof": "Offboarding record",
        "due": "90 days",
    },
    {
        "match": "cached locally",
        "group": "cached",
        "title": "Share files cached on supporting endpoints",
        "lane": "Practice owner",
        "confidence": "Verified",
        "ask": "Confirm endpoint access scope; remove cached data if not needed.",
        "proof": "Access decision note",
        "due": "60 days",
    },
]

DEFAULT_RULE = {
    "group": "other",
    "title": None,
    "lane": "Practice owner",
    "confidence": "Observed",
    "ask": "Review the item and assign an owner.",
    "proof": "Review note",
    "due": "30 days",
}

GROUP_ORDER = ["supply", "scribe", "endpoint", "shares", "intake", "auth", "admin", "proto", "dormant", "disabled", "cached", "other"]

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


def redact(value):
    s = str(value)
    s = s.replace(str(LAB_ROOT) + "/", "")
    s = s.replace(str(Path.home()) + "/", "~/")
    return s


def esc(value):
    return html.escape(redact(value))


def latest_snapshot():
    candidates = sorted(ARTIFACTS.glob("*/*.json"))
    if not candidates:
        raise SystemExit("no snapshots found under artifacts/")
    return candidates[-1]


def rule_for(detail):
    for rule in EVIDENCE_RULES:
        if rule["match"].lower() in detail.lower():
            return rule
    return DEFAULT_RULE


def prose_ts(iso):
    try:
        dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError):
        return str(iso)
    return f"{dt.day} {dt.strftime('%b %Y')}, {dt.strftime('%H:%M')} UTC"


def due_date(collected_iso, due_text):
    m = re.search(r"(\d+)", due_text or "")
    if not m:
        return due_text or ""
    days = int(m.group(1))
    try:
        dt = datetime.strptime(collected_iso, "%Y-%m-%dT%H:%M:%SZ") + timedelta(days=days)
    except (ValueError, TypeError):
        return due_text
    return f"{dt.day} {dt.strftime('%b %Y')}"


def extract_item(group, detail):
    if group in ("dormant", "disabled"):
        return detail.split(":")[0].strip()
    if group == "endpoint":
        m = re.match(r"([^(]+)\(([^)]+)\):\s*(\d+)", detail)
        if m:
            n = int(m.group(3))
            return f"{m.group(1).strip()} \u2014 {n} file{'s' if n != 1 else ''}"
        return detail.split(":")[0].strip()
    if group == "shares":
        return detail.split(":", 1)[1].strip() if ":" in detail else detail
    return detail


def build_rows(snap, collected_iso):
    findings = sorted(
        snap.get("findings", []),
        key=lambda x: (SEVERITY_ORDER.get(x.get("severity", "info"), 9), x.get("section", "")),
    )
    consolidated = {}
    rows = []
    for f in findings:
        detail = f.get("detail", "")
        rule = rule_for(detail)
        group = rule.get("group") or "other"
        severity = f.get("severity", "info")
        if group in ("supply", "scribe", "endpoint", "shares", "intake", "auth", "admin", "dormant", "disabled", "cached"):
            if group in consolidated:
                row = consolidated[group]
                row["items"].append(extract_item(group, detail))
                if SEVERITY_ORDER.get(severity, 9) < SEVERITY_ORDER.get(row["severity"], 9):
                    row["severity"] = severity
                continue
            row = {
                "group": group,
                "match": rule.get("match", ""),
                "title": rule["title"] or detail,
                "severity": severity,
                "lane": rule["lane"],
                "confidence": rule["confidence"],
                "ask": rule["ask"],
                "proof": rule["proof"],
                "due": due_date(collected_iso, rule["due"]),
                "items": [extract_item(group, detail)],
            }
            consolidated[group] = row
            rows.append(row)
        else:
            rows.append(
                {
                    "group": group,
                    "match": rule.get("match", ""),
                    "title": detail,
                    "severity": severity,
                    "lane": rule["lane"],
                    "confidence": rule["confidence"],
                    "ask": rule["ask"],
                    "proof": rule["proof"],
                    "due": due_date(collected_iso, rule["due"]),
                    "items": [],
                }
            )
    rows.sort(key=lambda r: (SEVERITY_ORDER.get(r["severity"], 9), GROUP_ORDER.index(r["group"]) if r["group"] in GROUP_ORDER else 99))
    for i, row in enumerate(rows, 1):
        row["ref"] = f"E-{i:02d}"
    return rows


def build_decisions(rows):
    decisions = []
    for tmpl in DECISION_TEMPLATES:
        refs = [r["ref"] for r in rows if r["group"] in tmpl["match_groups"]]
        if refs:
            d = dict(tmpl)
            d["refs"] = refs
            decisions.append(d)
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


def build_lanes(rows):
    canonical = {
        "practice owner": "Practice owner",
        "msp": "MSP",
        "scribe vendor": "Scribe vendor",
        "web vendor": "Web vendor",
        "front office": "Front office",
    }
    lanes = {}
    for r in rows:
        for raw in [p.strip() for p in r["lane"].split("+")]:
            key = raw.lower()
            entry = lanes.setdefault(key, {"recipient": canonical.get(key, raw.title()), "pairs": []})
            num = int(r["ref"].split("-")[1])
            entry["pairs"].append((num, r["due"], r["ref"]))
    order = ["practice owner", "msp", "scribe vendor", "web vendor", "front office"]
    ordered = sorted(lanes.items(), key=lambda kv: order.index(kv[0]) if kv[0] in order else 99)
    result = []
    for _, lane in ordered[:5]:
        pairs = sorted(lane["pairs"])
        collapsed = []
        for num, due, ref in pairs:
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


def render(snap):
    counts = snap.get("finding_counts", {})
    identity = snap.get("identity", {})
    shares = snap.get("shares", {})
    auth = snap.get("auth", {})
    ehr = snap.get("ehr", {})
    endpoints = snap.get("endpoints", {})
    supply = snap.get("supply_chain", {})
    drift = snap.get("drift", {})

    collected = snap.get("collected_at", "")
    collected_prose = prose_ts(collected)
    doc_id = "VLR-PTP-" + collected.replace("-", "").replace("T", "-").replace(":", "").replace("Z", "")[:13]

    rows = build_rows(snap, collected)
    decisions = build_decisions(rows)
    lanes = build_lanes(rows)

    p1 = counts.get("high", 0)
    p2 = counts.get("medium", 0)
    p3 = counts.get("low", 0)
    p4 = counts.get("info", 0)

    # --- section 1: summary ---
    count_line = (
        f'<span class="count"><span class="ck hot">P1</span><span class="cv">{p1}</span></span>'
        f'<span class="count"><span class="ck">P2</span><span class="cv">{p2}</span></span>'
        f'<span class="count"><span class="ck">P3</span><span class="cv">{p3}</span></span>'
        f'<span class="count"><span class="ck">P4</span><span class="cv">{p4}</span></span>'
    )
    summary_sentence = (
        f"{p1} priority-1 finding{'s' if p1 != 1 else ''}; "
        f"{len(decisions)} require owner decision (&sect;2). Evidence schedule in &sect;3."
    )

    drift_sentence = ""
    if drift.get("status") == "baseline":
        drift_sentence = f"First collection for this packet; baseline established {collected_prose}."
    else:
        total_changes = sum(
            len(drift.get(k, []))
            for k in ("findings_new", "findings_resolved", "user_changes", "group_changes", "share_changes", "endpoint_changes")
        )
        if total_changes == 0:
            drift_sentence = f"No changes against the {prose_ts(drift.get('compared_to', collected))} snapshot."
        else:
            drift_rows = []
            labels = [
                ("findings_new", "New finding"),
                ("findings_resolved", "Resolved"),
                ("user_changes", "Identity"),
                ("group_changes", "Groups"),
                ("share_changes", "Shares"),
                ("endpoint_changes", "Endpoints"),
            ]
            for key, label in labels:
                for item in drift.get(key, []):
                    drift_rows.append((label, item))
            for metric, delta in drift.get("counter_deltas", {}).items():
                drift_rows.append(("Activity", f"{metric}: {'+' if delta >= 0 else ''}{delta}"))
            drift_list = "".join(
                f"<div class='drift'><dt>{esc(k)}</dt><dd>{esc(v)}</dd></div>" for k, v in drift_rows
            )
            drift_sentence = f"{total_changes} change{'s' if total_changes != 1 else ''} against the {prose_ts(drift.get('compared_to', collected))} snapshot." + f"<dl class='drift-list'>{drift_list}</dl>"

    # --- section 2: decision brief ---
    clause_items = ""
    for i, d in enumerate(decisions, 1):
        verdict_cls = "hot" if d["state"] == "block" else ""
        refs = " ".join(d.get("refs", []))
        xref = f' <span class="xref">&rarr; {esc(refs)}</span>' if refs else ""
        clause_items += f"""<div class="clause">
        <div class="clause-rail"><span class="cnum">2.{i}</span><span class="verdict {verdict_cls}">{esc(d['state'].upper())}</span></div>
        <div class="clause-body">
          <p><strong>{esc(d['title'])}</strong> {esc(d['body'])}</p>
          <p class="proof-line"><span class="plabel">Proof to save:</span> {esc(d['proof'])}{xref}</p>
        </div>
      </div>"""

    # --- section 3: evidence schedule ---
    table_groups = ""
    current = None
    for r in rows:
        sev = r["severity"]
        if sev != current:
            current = sev
            tag = SEVERITY_TAG.get(sev, "P4")
            tag_cls = "hot" if sev == "high" else ""
            label = {"high": "Priority 1", "medium": "Priority 2", "low": "Priority 3", "info": "Priority 4"}[sev]
            earliest = r["due"]
            table_groups += (
                f'<tr class="pgroup"><td colspan="4"><span class="ptag {tag_cls}">{tag}</span>'
                f"{label} &mdash; act by {esc(earliest)}</td></tr>"
            )
        items_html = ""
        if r["items"]:
            items_html = "<div class='enum'>" + "<br>".join(esc(x) for x in r["items"]) + "</div>"
        table_groups += f"""<tr>
        <td class="ref"><span class="mono refnum">{esc(r['ref'])}</span></td>
        <td class="finding">
          <strong>{esc(r['title'])}</strong>{items_html}
          <p class="ask">{esc(r['ask'])}</p>
          <p class="proof"><span class="plabel">Proof:</span> {esc(r['proof'])}</p>
          <p class="ev">Evidence: {esc(r['confidence'])}</p>
        </td>
        <td class="lane">{esc(r['lane'])}</td>
        <td class="due mono">{esc(r['due'])}</td>
      </tr>"""

    lane_items = "".join(
        f"<p class='lane-row'><strong>{esc(l['recipient'])}</strong> &mdash; {esc(l['refs'])}</p>" for l in lanes
    )

    # --- section 5: supporting evidence ---
    user_rows = "".join(
        f"<tr><td class='mono'>{esc(u.get('sam'))}</td><td>{'Enabled' if u.get('enabled') else 'Disabled'}</td>"
        f"<td class='mono'>{esc(u.get('last_logon') or '--')}</td>"
        f"<td>{esc(', '.join([x for x in (('never logged on' if u.get('never_logged_on') else ''), ('stale' if u.get('stale') else '')) if x]) or '--')}</td></tr>"
        for u in identity.get("users", [])
    )
    group_rows = "".join(
        f"<tr><td>{esc(g)}</td><td class='mono'>{esc(', '.join(m) if m else '(empty)')}</td></tr>"
        for g, m in identity.get("privileged_groups", {}).items()
    )
    policy_rows = "".join(
        f"<div><dt>{esc(k)}</dt><dd>{esc(v)}</dd></div>" for k, v in identity.get("password_policy", {}).items()
    )
    share_rows = "".join(
        f"<tr><td class='mono'>{esc(f.get('path'))}</td><td class='mono right'>{esc(f.get('sha256_16') or 'n/a')}</td></tr>"
        for f in shares.get("files", [])
    )
    share_hashes = {f.get("sha256_16") for f in shares.get("files", []) if f.get("sha256_16")}
    endpoint_rows = ""
    for h in endpoints.get("hosts", []):
        for c in h.get("local_copies", []):
            match = " <span class='eqmark'>= share copy</span>" if c.get("sha256_16") in share_hashes else ""
            endpoint_rows += (
                f"<tr><td><strong>{esc(h.get('name'))}</strong><span class='sub'>{esc(h.get('role'))}</span></td>"
                f"<td class='mono'>{esc(c.get('file'))}{match}</td>"
                f"<td class='mono right'>{esc(c.get('sha256_16') or 'hash unavailable')}</td></tr>"
            )
    endpoint_rows = endpoint_rows or "<tr><td colspan='3' class='muted'>No local copies detected.</td></tr>"
    supply_rows = "".join(
        f"<tr><td class='mono hot'>{esc((f.get('severity') or 'medium').upper())}</td>"
        f"<td class='mono'>{esc(f.get('package'))}@{esc(f.get('version'))}</td>"
        f"<td>{esc(f.get('ecosystem'))}</td><td>{esc(f.get('catalog'))}</td></tr>"
        for f in supply.get("findings", [])
    ) or "<tr><td colspan='4' class='muted'>No package exposures detected.</td></tr>"

    generated = datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC").lstrip("0")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Practice Trust Packet &middot; {esc(snap.get('lab'))}</title>
<style>
:root {{
  --ink: #17191d; --body: #3a3f45; --muted: #6d737a; --faint: #9aa0a7;
  --hair: rgba(23,25,29,0.16); --hair-soft: rgba(23,25,29,0.08);
  --paper: #fcfbf9; --hot: #8f2f26; --gold: #c9a84c;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", "Helvetica Neue", Arial, sans-serif;
  --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0; background: var(--paper); color: var(--ink);
  font: 15px/1.55 var(--sans); -webkit-font-smoothing: antialiased;
}}
.sheet {{ max-width: 1040px; margin: 0 auto; padding: 0 40px 72px; }}
h1, h2, h3 {{ margin: 0; letter-spacing: -0.015em; }}
p {{ margin: 0; }}
.mono {{ font-family: var(--mono); font-size: 12px; }}
.sub {{ display: block; margin-top: 2px; color: var(--muted); font-size: 12px; }}
.muted {{ color: var(--muted); }}
.right {{ text-align: right; }}
.hot {{ color: var(--hot); }}

/* masthead + title block */
.masthead {{ border-top: 2px solid var(--gold); margin-top: 34px; }}
.masthead-row {{
  display: flex; align-items: baseline; justify-content: space-between; gap: 24px;
  padding: 16px 0 12px; border-bottom: 1px solid var(--ink);
}}
.wordmark {{ font-size: 12px; font-weight: 700; letter-spacing: 0.24em; text-transform: uppercase; }}
.docid {{ font-family: var(--mono); font-size: 12px; color: var(--muted); }}
.title-block {{ padding-top: 30px; }}
h1 {{ font-size: 32px; font-weight: 700; line-height: 1.1; letter-spacing: -0.015em; }}
.standfirst {{ margin-top: 10px; font-size: 17px; line-height: 1.5; max-width: 640px; }}
.kvb {{
  display: grid; grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0 48px; margin: 26px 0 0; padding: 0; max-width: 760px;
}}
.kvb div {{ display: flex; justify-content: space-between; gap: 16px; padding: 7px 0; border-bottom: 1px solid var(--hair-soft); }}
.kvb dt {{ color: var(--muted); }}
.kvb dd {{ margin: 0; font-family: var(--mono); font-size: 12px; text-align: right; }}
.see-also {{ margin-top: 12px; font-size: 12px; color: var(--muted); }}

/* sections */
section {{ margin-top: 64px; }}
h2 {{ font-size: 19px; font-weight: 700; line-height: 1.25; padding-top: 14px; border-top: 1px solid var(--ink); }}
h2 .secnum {{ color: var(--faint); font-weight: 700; margin-right: 12px; font-variant-numeric: tabular-nums; }}
h3 {{ font-size: 15px; font-weight: 700; line-height: 1.4; padding-bottom: 8px; border-bottom: 1px solid var(--hair); }}
.sec-lede {{ margin-top: 12px; color: var(--body); max-width: 640px; }}
.sec-note {{ margin-top: 12px; font-size: 12px; color: var(--muted); }}

/* summary */
.counts {{ display: flex; gap: 40px; margin-top: 22px; padding: 12px 0; border-bottom: 1px solid var(--hair); }}
.count {{ display: inline-flex; align-items: baseline; gap: 8px; }}
.ck {{ font-size: 11px; font-weight: 600; letter-spacing: 0.06em; text-transform: uppercase; color: var(--muted); }}
.cv {{ min-width: 2ch; text-align: right; font-size: 19px; font-weight: 700; font-variant-numeric: tabular-nums; letter-spacing: -0.01em; }}
.summary-sentence {{ margin-top: 14px; color: var(--body); }}
.change-note {{ margin-top: 18px; font-size: 13.5px; color: var(--body); }}
.change-note .plabel {{ color: var(--muted); }}
.drift-list {{ margin: 10px 0 0; padding: 0; }}
.drift {{ display: grid; grid-template-columns: 120px minmax(0, 1fr); gap: 14px; padding: 5px 0; border-bottom: 1px solid var(--hair-soft); }}
.drift dt {{ font-size: 11px; font-weight: 600; letter-spacing: 0.06em; text-transform: uppercase; color: var(--muted); padding-top: 1px; }}
.drift dd {{ margin: 0; }}

/* decision brief */
.clause {{ display: grid; grid-template-columns: 64px minmax(0, 1fr); gap: 20px; padding: 20px 0; border-bottom: 1px solid var(--hair-soft); }}
.clause:first-of-type {{ border-top: 1px solid var(--hair-soft); margin-top: 22px; }}
.clause-rail {{ display: flex; flex-direction: column; gap: 4px; }}
.cnum {{ font-family: var(--mono); font-size: 12px; color: var(--ink); }}
.verdict {{ font-size: 11px; font-weight: 600; letter-spacing: 0.06em; text-transform: uppercase; color: var(--ink); }}
.clause-body p {{ color: var(--body); max-width: 640px; }}
.clause-body strong {{ color: var(--ink); font-weight: 700; }}
.proof-line {{ margin-top: 9px !important; font-size: 13px; color: var(--muted); }}
.plabel {{ color: var(--muted); }}
.xref {{ font-family: var(--mono); font-size: 11.5px; }}

/* evidence schedule */
table {{ width: 100%; border-collapse: collapse; }}
.sched {{ margin-top: 22px; }}
.sched th {{
  padding: 0 14px 8px 0; text-align: left; vertical-align: bottom;
  border-bottom: 1px solid var(--ink);
  font-size: 11px; font-weight: 600; letter-spacing: 0.06em; text-transform: uppercase; color: var(--muted); white-space: nowrap;
}}
.sched td {{ padding: 12px 14px 12px 0; border-bottom: 1px solid var(--hair-soft); vertical-align: top; font-size: 13px; line-height: 1.45; font-variant-numeric: tabular-nums; }}
.sched td:last-child, .sched th:last-child {{ padding-right: 0; }}
.sched tr:last-child td {{ border-bottom: 0; }}
.pgroup td {{ padding: 20px 0 8px; border-bottom: 1px solid var(--hair); font-size: 12.5px; font-weight: 600; color: var(--body); }}
.ptag {{ display: inline-block; margin-right: 10px; font-family: var(--mono); font-weight: 700; font-size: 12px; }}
.ref {{ width: 56px; }}
.refnum {{ color: var(--muted); }}
.finding {{ min-width: 320px; }}
.finding strong {{ font-weight: 700; }}
.enum {{ margin-top: 5px; font-family: var(--mono); font-size: 11.5px; line-height: 1.65; color: var(--body); overflow-wrap: anywhere; }}
.finding .ask {{ margin-top: 8px; color: var(--body); max-width: 560px; }}
.finding .proof {{ margin-top: 4px; color: var(--muted); max-width: 560px; }}
.finding .ev {{ margin-top: 6px; font-size: 12px; color: var(--muted); }}
.lane {{ width: 150px; color: var(--body); }}
.due {{ width: 96px; white-space: nowrap; color: var(--body); }}

/* reviewer lanes */
.lane-row {{ padding: 10px 0; border-bottom: 1px solid var(--hair-soft); max-width: 760px; }}
.lane-row strong {{ font-weight: 700; }}
.lane-row:first-of-type {{ margin-top: 18px; border-top: 1px solid var(--hair-soft); }}

/* supporting evidence */
.subsec {{ margin-top: 42px; }}
.subsec:first-of-type {{ margin-top: 30px; }}
.evidence-table {{ margin-top: 14px; }}
.evidence-table th {{ padding: 0 14px 7px 0; text-align: left; border-bottom: 1px solid var(--ink); font-size: 11px; font-weight: 600; letter-spacing: 0.06em; text-transform: uppercase; color: var(--muted); }}
.evidence-table td {{ padding: 9px 14px 9px 0; border-bottom: 1px solid var(--hair-soft); font-size: 13px; font-variant-numeric: tabular-nums; }}
.evidence-table tr:last-child td {{ border-bottom: 0; }}
.evidence-table td:last-child, .evidence-table th:last-child {{ padding-right: 0; }}
.split {{ display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 48px; }}
.policy {{ margin: 0; }}
.policy div {{ display: flex; justify-content: space-between; gap: 16px; padding: 6px 0; border-bottom: 1px solid var(--hair-soft); }}
.policy dt {{ color: var(--muted); }}
.policy dd {{ margin: 0; font-family: var(--mono); font-size: 12px; }}
.eqmark {{ font-family: var(--mono); font-size: 11px; color: var(--muted); }}

/* section 6 + attestation */
.limits {{ margin-top: 18px; max-width: 720px; }}
.limit {{ display: grid; grid-template-columns: 56px minmax(0, 1fr); gap: 16px; padding: 10px 0; border-bottom: 1px solid var(--hair-soft); }}
.limit dt {{ font-family: var(--mono); font-size: 12px; color: var(--muted); }}
.limit dd {{ margin: 0; color: var(--body); }}
.stamp {{ display: flex; flex-wrap: wrap; gap: 8px 32px; margin-top: 22px; font-size: 12px; color: var(--muted); }}
.stamp span {{ font-family: var(--mono); }}
.attestation {{ margin-top: 34px; border-top: 2px solid var(--gold); padding-top: 14px; display: flex; flex-wrap: wrap; justify-content: space-between; gap: 10px 28px; font-size: 12px; color: var(--body); }}
.attestation .sig {{ font-family: var(--mono); }}

@media (max-width: 760px) {{
  .sheet {{ padding: 0 22px 56px; }}
  h1 {{ font-size: 26px; }}
  .kvb {{ grid-template-columns: 1fr; gap: 0; }}
  .counts {{ flex-wrap: wrap; gap: 18px 32px; }}
  .clause {{ grid-template-columns: 1fr; gap: 8px; }}
  .clause-rail {{ flex-direction: row; gap: 12px; align-items: baseline; }}
  .split {{ grid-template-columns: 1fr; gap: 0; }}
  .sched th:nth-child(3), .sched td:nth-child(3) {{ display: none; }}
  .finding {{ min-width: 0; }}
  .drift {{ grid-template-columns: 1fr; gap: 0; }}
}}
@media print {{
  @page {{ margin: 18mm 16mm; }}
  body {{ background: #fff; }}
  .sheet {{ max-width: none; padding: 0; }}
  h1, h2, h3 {{ break-after: avoid; page-break-after: avoid; }}
  .sec-note, .sec-lede {{ break-after: avoid; page-break-after: avoid; }}
  section {{ break-inside: auto; margin-top: 44px; }}
  section.sec-short {{ break-inside: avoid; page-break-inside: avoid; }}
  .subsec {{ break-inside: avoid; page-break-inside: avoid; }}
  .kvb, .counts, .summary-sentence, .change-note, .sec-note, .lane-row {{ break-inside: avoid; }}
  .clause, .limit, .subsec table tr, .evidence-table tr {{ break-inside: avoid; }}
  .pgroup {{ break-inside: avoid; break-after: avoid; page-break-after: avoid; }}
  table, .sched {{ break-inside: auto; }}
  .sched, .evidence-table {{ break-before: avoid; page-break-before: avoid; }}
  section.sec-pagebreak {{ break-before: page; page-break-before: always; }}
  thead {{ display: table-header-group; }}
  tr {{ break-inside: avoid; page-break-inside: avoid; }}
}}
</style>
</head>
<body>
<div class="sheet">

  <header class="masthead">
    <div class="masthead-row">
      <span class="wordmark">Velari</span>
      <span class="docid">{esc(doc_id)}</span>
    </div>
  </header>

  <div class="title-block">
    <h1>Practice Trust Packet</h1>
    <p class="standfirst">One review pass across identity, data movement, endpoints, and supply chain for {esc(snap.get('lab'))}. What changed, what it means, and the proof to save.</p>
    <dl class="kvb">
      <div><dt>Subject</dt><dd>{esc(snap.get('lab'))}</dd></div>
      <div><dt>Collected</dt><dd>{esc(collected_prose)}</dd></div>
      <div><dt>Auth window</dt><dd>{esc(auth.get('window_hours', 24))} hours</dd></div>
      <div><dt>Collector</dt><dd>{esc(snap.get('collector'))}</dd></div>
      <div><dt>Prepared for</dt><dd>Practice owner &middot; MSP &middot; counsel</dd></div>
      <div><dt>Schema</dt><dd>{esc(snap.get('schema'))}</dd></div>
    </dl>
    <p class="see-also">Boundaries and limitations: see &sect;6. Synthetic lab data; no real patient information.</p>
  </div>

  <section class="sec-short">
    <h2><span class="secnum">1</span>Summary of findings</h2>
    <div class="counts">{count_line}</div>
    <p class="summary-sentence">{summary_sentence}</p>
    <p class="change-note"><span class="plabel">Change monitor &mdash;</span> {drift_sentence}</p>
  </section>

  <section class="sec-short">
    <h2><span class="secnum">2</span>Decision brief</h2>
    {clause_items}
  </section>

  <section class="sec-short sec-pagebreak">
    <h2><span class="secnum">3</span>Evidence schedule</h2>
    <p class="sec-note">Due windows are computed from collection ({esc(collected_prose)}). Refs E-nn are cited throughout.</p>
    <table class="sched">
      <thead><tr><th>Ref</th><th>Finding</th><th>Owner lane</th><th>Due</th></tr></thead>
      <tbody>{table_groups}</tbody>
    </table>
  </section>

  <section class="sec-short">
    <h2><span class="secnum">4</span>Reviewer lanes</h2>
    {lane_items}
  </section>

  <section>
    <h2><span class="secnum">5</span>Supporting evidence</h2>

    <div class="split">
      <div class="subsec">
        <h3>5.1 Password policy</h3>
        <dl class="policy">{policy_rows}</dl>
      </div>
      <div class="subsec">
        <h3>5.2 Privileged groups</h3>
        <table class="evidence-table"><thead><tr><th>Group</th><th>Members</th></tr></thead><tbody>{group_rows}</tbody></table>
      </div>
    </div>

    <div class="subsec">
      <h3>5.3 Account review</h3>
      <table class="evidence-table"><thead><tr><th>Account</th><th>State</th><th>Last logon</th><th>Flags</th></tr></thead>
      <tbody>{user_rows}</tbody></table>
    </div>

    <div class="subsec">
      <h3>5.4 File shares &mdash; patient-adjacent data outside the EHR</h3>
      <table class="evidence-table"><thead><tr><th>Path</th><th class="right">sha256 (prefix)</th></tr></thead><tbody>{share_rows}</tbody></table>
    </div>

    <div class="subsec">
      <h3>5.5 Endpoint exposure</h3>
      <table class="evidence-table"><thead><tr><th>Endpoint</th><th>Local copy</th><th class="right">sha256 (prefix)</th></tr></thead>
      <tbody>{endpoint_rows}</tbody></table>
    </div>

    <div class="subsec">
      <h3>5.6 Supply chain &mdash; Bumblebee scan ({esc(supply.get('status', 'skipped'))})</h3>
      <table class="evidence-table"><thead><tr><th>Severity</th><th>Package</th><th>Ecosystem</th><th>Catalog</th></tr></thead>
      <tbody>{supply_rows}</tbody></table>
    </div>

    <div class="subsec">
      <h3>5.7 EHR surface</h3>
      <table class="evidence-table">
        <thead><tr><th>Signal</th><th class="right">Value</th></tr></thead>
        <tbody>
          <tr><td>Portal health</td><td class="mono right">{esc(ehr.get('health', {}).get('status', 'unknown'))}</td></tr>
          <tr><td>Public intake submissions (all time)</td><td class="mono right">{esc(ehr.get('intake_submissions', 0))}</td></tr>
          <tr><td>Scribe transmission events (all time)</td><td class="mono right">{esc(ehr.get('scribe_transmissions', 0))}</td></tr>
        </tbody>
      </table>
    </div>
  </section>

  <section class="sec-short">
    <h2><span class="secnum">6</span>Limitations and attestation</h2>
    <dl class="limits">
      <div class="limit"><dt>6.1</dt><dd><strong>No PHI.</strong> Synthetic lab data only. No real patient information is collected, stored, or shared in this packet.</dd></div>
      <div class="limit"><dt>6.2</dt><dd><strong>Qualification.</strong> A review aid; does not replace counsel, insurer, MSP, a qualified assessor, or the official HHS/ONC SRA Tool. Not legal advice; not a breach determination.</dd></div>
      <div class="limit"><dt>6.3</dt><dd><strong>Method.</strong> Metadata-only collection from the synthetic lab: directory service queries, share inventories, hashes, auth audit logs, and a read-only package exposure scan.</dd></div>
    </dl>
    <div class="stamp">
      <span>Generated {esc(generated)}</span>
      <span>Snapshot {esc(collected)}</span>
      <span>{esc(snap.get('schema'))}</span>
    </div>
    <div class="attestation">
      <span>Prepared by Velari &middot; {esc(snap.get('collector'))}</span>
      <span class="sig">Reviewed by ______________________&nbsp;&nbsp;Date ____________</span>
    </div>
  </section>

</div>
</body>
</html>"""


def main():
    ap = argparse.ArgumentParser(description="Render a practice snapshot JSON as a review packet HTML")
    ap.add_argument("snapshot", nargs="?", help="path to snapshot JSON")
    ap.add_argument("--latest", action="store_true", help="use the newest snapshot")
    ap.add_argument("--out", help="output path (default: beside the JSON)")
    args = ap.parse_args()

    if args.latest or not args.snapshot:
        path = latest_snapshot()
    else:
        path = Path(args.snapshot)
    snap = json.loads(path.read_text(encoding="utf-8"))
    output = Path(args.out) if args.out else path.with_suffix(".html")
    output.write_text(render(snap), encoding="utf-8")
    latest_link = ARTIFACTS.parent / "latest.html"
    try:
        latest_link.write_text(render(snap), encoding="utf-8")
    except OSError:
        pass
    print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
