"""HTML fragments for each packet section.

Every value that can come from a snapshot passes through `esc()`; the only
unescaped strings are markup and CSS variables defined in this repo.
"""

from __future__ import annotations

from typing import Any

from .data import SEVERITY_TAG
from .rules import format_cites
from .text import esc, prose_ts

SEVERITY_LABEL = {"high": "Priority 1", "medium": "Priority 2", "low": "Priority 3", "info": "Priority 4"}


def cite_html(row: dict[str, Any]) -> str:
    return f" &middot; HIPAA: {esc(format_cites(row['hipaa']))}" if row.get("hipaa") else ""


def drift_block(drift: dict[str, Any], collected_prose: str) -> str:
    if drift.get("status") == "baseline":
        return f"First collection for this packet; baseline established {esc(collected_prose)}."

    labels = [
        ("findings_new", "New finding"),
        ("findings_resolved", "Resolved"),
        ("findings_changed", "Changed"),
        ("user_changes", "Identity"),
        ("group_changes", "Groups"),
        ("share_changes", "Shares"),
        ("endpoint_changes", "Endpoints"),
    ]
    drift_rows = [(label, item) for key, label in labels for item in drift.get(key, [])]
    for metric, delta in drift.get("counter_deltas", {}).items():
        drift_rows.append(("Activity", f"{metric}: {'+' if delta >= 0 else ''}{delta}"))
    if not drift_rows:
        return f"No changes against the {esc(prose_ts(drift.get('compared_to', collected_prose)))} snapshot."
    total = len(drift_rows)
    drift_list = "".join(f"<div class='drift'><dt>{esc(k)}</dt><dd>{esc(v)}</dd></div>" for k, v in drift_rows)
    return (
        f"{total} change{'s' if total != 1 else ''} against the "
        f"{esc(prose_ts(drift.get('compared_to')))} snapshot.<dl class='drift-list'>{drift_list}</dl>"
    )


def summary_section(counts: dict[str, Any], decisions: int, drift_sentence: str) -> str:
    p1, p2, p3, p4 = (counts.get(k, 0) for k in ("high", "medium", "low", "info"))
    count_line = (
        f'<span class="count"><span class="ck hot">P1</span><span class="cv">{esc(p1)}</span></span>'
        f'<span class="count"><span class="ck">P2</span><span class="cv">{esc(p2)}</span></span>'
        f'<span class="count"><span class="ck">P3</span><span class="cv">{esc(p3)}</span></span>'
        f'<span class="count"><span class="ck">P4</span><span class="cv">{esc(p4)}</span></span>'
    )
    summary = (
        f"{esc(p1)} priority-1 finding{'s' if p1 != 1 else ''}; "
        f"{esc(decisions)} require owner decision (&sect;2). Evidence schedule in &sect;3."
    )
    return f"""  <section class="sec-short">
    <h2 id="summary"><span class="secnum">1</span>Summary of findings</h2>
    <div class="counts">{count_line}</div>
    <p class="summary-sentence">{summary}</p>
    <p class="change-note"><span class="plabel">Change monitor &mdash;</span> {drift_sentence}</p>
  </section>"""


def decisions_section(decisions: list[dict[str, Any]]) -> str:
    clause_items = ""
    for i, decision in enumerate(decisions, 1):
        verdict_cls = "hot" if decision["state"] == "block" else ""
        refs = " ".join(decision.get("refs", []))
        xref = f' <span class="xref">&rarr; {esc(refs)}</span>' if refs else ""
        clause_items += f"""<div class="clause">
        <div class="clause-rail"><span class="cnum">2.{i}</span><span class="verdict {verdict_cls}">{esc(decision["state"].upper())}</span></div>
        <div class="clause-body">
          <p><strong>{esc(decision["title"])}</strong> {esc(decision["body"])}</p>
          <p class="proof-line"><span class="plabel">Proof to save:</span> {esc(decision["proof"])}{xref}</p>
        </div>
      </div>"""
    return f"""  <section class="sec-short">
    <h2 id="decisions"><span class="secnum">2</span>Decision brief</h2>
    {clause_items}
  </section>"""


def schedule_section(rows: list[dict[str, Any]], collected_prose: str) -> str:
    table_groups = ""
    current: str | None = None
    for row in rows:
        severity = row["severity"]
        if severity != current:
            current = severity
            tag = SEVERITY_TAG.get(severity, "P4")
            tag_cls = "hot" if severity == "high" else ""
            label = SEVERITY_LABEL[severity]
            table_groups += (
                f'<tr class="pgroup"><td colspan="4"><span class="ptag {tag_cls}">{tag}</span>'
                f"{label} &mdash; act by {esc(row['due'])}</td></tr>"
            )
        items_html = ""
        if row["items"]:
            items_html = "<div class='enum'>" + "<br>".join(esc(x) for x in row["items"]) + "</div>"
        table_groups += f"""<tr>
        <td class="ref"><span class="mono refnum">{esc(row["ref"])}</span></td>
        <td class="finding">
          <strong>{esc(row["title"])}</strong>{items_html}
          <p class="ask">{esc(row["ask"])}</p>
          <p class="proof"><span class="plabel">Proof:</span> {esc(row["proof"])}</p>
          <p class="ev">Evidence: {esc(row["confidence"])}{cite_html(row)}</p>
        </td>
        <td class="lane">{esc(row["lane"])}</td>
        <td class="due mono">{esc(row["due"])}</td>
      </tr>"""
    return f"""  <section class="sec-short sec-pagebreak">
    <h2 id="evidence"><span class="secnum">3</span>Evidence schedule</h2>
    <p class="sec-note">Due windows are computed from collection ({esc(collected_prose)}). Refs E-nn are cited throughout.</p>
    <table class="sched">
      <thead><tr><th scope="col">Ref</th><th scope="col">Finding</th><th scope="col">Owner lane</th><th scope="col">Due</th></tr></thead>
      <tbody>{table_groups}</tbody>
    </table>
  </section>"""


def lanes_section(lanes: list[dict[str, str]]) -> str:
    lane_items = "".join(
        f"<p class='lane-row'><strong>{esc(lane['recipient'])}</strong> &mdash; {esc(lane['refs'])}</p>"
        for lane in lanes
    )
    return f"""  <section class="sec-short">
    <h2 id="lanes"><span class="secnum">4</span>Reviewer lanes</h2>
    {lane_items}
  </section>"""


def crosswalk_rows(rows: list[dict[str, Any]]) -> str:
    return (
        "".join(
            f"<tr><td class='mono'>{esc(row['ref'])}</td><td>{esc(row['title'])}</td><td>"
            + "<br>".join(
                f"<span class='mono'>&sect;{esc(cite.section)}</span> {esc(cite.title)} "
                f"<span class='muted'>({esc(cite.kind)})</span>"
                for cite in row["hipaa"]
            )
            + "</td></tr>"
            for row in rows
            if row.get("hipaa")
        )
        or "<tr><td colspan='3' class='muted'>No mapped findings.</td></tr>"
    )


def supporting_section(snap: dict[str, Any], rows: list[dict[str, Any]]) -> str:
    identity = snap.get("identity", {})
    shares = snap.get("shares", {})
    endpoints = snap.get("endpoints", {})
    supply = snap.get("supply_chain", {})
    ehr = snap.get("ehr", {})

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
    for host in endpoints.get("hosts", []):
        for copy in host.get("local_copies", []):
            match = " <span class='eqmark'>= share copy</span>" if copy.get("sha256_16") in share_hashes else ""
            endpoint_rows += (
                f"<tr><td><strong>{esc(host.get('name'))}</strong><span class='sub'>{esc(host.get('role'))}</span></td>"
                f"<td class='mono'>{esc(copy.get('file'))}{match}</td>"
                f"<td class='mono right'>{esc(copy.get('sha256_16') or 'hash unavailable')}</td></tr>"
            )
    endpoint_rows = endpoint_rows or "<tr><td colspan='3' class='muted'>No local copies detected.</td></tr>"
    supply_rows = (
        "".join(
            f"<tr><td class='mono hot'>{esc((f.get('severity') or 'medium').upper())}</td>"
            f"<td class='mono'>{esc(f.get('package'))}@{esc(f.get('version'))}</td>"
            f"<td>{esc(f.get('ecosystem'))}</td><td>{esc(f.get('catalog'))}</td></tr>"
            for f in supply.get("findings", [])
        )
        or "<tr><td colspan='4' class='muted'>No package exposures detected.</td></tr>"
    )

    return f"""  <section>
    <h2 id="supporting"><span class="secnum">5</span>Supporting evidence</h2>

    <div class="split">
      <div class="subsec">
        <h3>5.1 Password policy</h3>
        <dl class="policy">{policy_rows}</dl>
      </div>
      <div class="subsec">
        <h3>5.2 Privileged groups</h3>
        <table class="evidence-table"><thead><tr><th scope="col">Group</th><th scope="col">Members</th></tr></thead><tbody>{group_rows}</tbody></table>
      </div>
    </div>

    <div class="subsec">
      <h3>5.3 Account review</h3>
      <table class="evidence-table"><thead><tr><th scope="col">Account</th><th scope="col">State</th><th scope="col">Last logon</th><th scope="col">Flags</th></tr></thead>
      <tbody>{user_rows}</tbody></table>
    </div>

    <div class="subsec">
      <h3>5.4 File shares &mdash; patient-adjacent data outside the EHR</h3>
      <table class="evidence-table"><thead><tr><th scope="col">Path</th><th scope="col" class="right">sha256 (prefix)</th></tr></thead><tbody>{share_rows}</tbody></table>
    </div>

    <div class="subsec">
      <h3>5.5 Endpoint exposure</h3>
      <table class="evidence-table"><thead><tr><th scope="col">Endpoint</th><th scope="col">Local copy</th><th scope="col" class="right">sha256 (prefix)</th></tr></thead>
      <tbody>{endpoint_rows}</tbody></table>
    </div>

    <div class="subsec">
      <h3>5.6 Supply chain &mdash; Bumblebee scan ({esc(supply.get("status", "skipped"))})</h3>
      <table class="evidence-table"><thead><tr><th scope="col">Severity</th><th scope="col">Package</th><th scope="col">Ecosystem</th><th scope="col">Catalog</th></tr></thead>
      <tbody>{supply_rows}</tbody></table>
    </div>

    <div class="subsec">
      <h3>5.7 EHR surface</h3>
      <table class="evidence-table">
        <thead><tr><th scope="col">Signal</th><th scope="col" class="right">Value</th></tr></thead>
        <tbody>
          <tr><td>Portal health</td><td class="mono right">{esc(ehr.get("health", {}).get("status", "unknown"))}</td></tr>
          <tr><td>Public intake submissions (all time)</td><td class="mono right">{esc(ehr.get("intake_submissions", 0))}</td></tr>
          <tr><td>Scribe transmission events (all time)</td><td class="mono right">{esc(ehr.get("scribe_transmissions", 0))}</td></tr>
        </tbody>
      </table>
    </div>

    <div class="subsec">
      <h3>5.8 HIPAA Security Rule crosswalk</h3>
      <p class="sec-note">Provisions each finding is relevant to, for routing only. Not a compliance determination or gap assessment.</p>
      <table class="evidence-table"><thead><tr><th scope="col">Ref</th><th scope="col">Finding</th><th scope="col">Relevant provisions (45 CFR 164)</th></tr></thead>
      <tbody>{crosswalk_rows(rows)}</tbody></table>
    </div>
  </section>"""


def ledger_line(head: dict[str, Any] | None) -> str:
    """Footer line naming the evidence ledger head, or "" when none was supplied.

    A failed verification is shown plainly rather than omitted: a packet whose
    evidence chain does not verify must not look the same as one that does.
    """
    if not head or not head.get("present"):
        return ""
    digest = esc(str(head.get("head_entry_hash") or "")[:16])
    count = int(head.get("entry_count") or 0)
    entries = f"{count} entr{'y' if count == 1 else 'ies'}"
    if head.get("ok"):
        return f"      <span>Ledger head {digest} &middot; {entries} &middot; chain verified</span>\n"
    problems = int(head.get("error_count") or 0)
    return (
        f'      <span class="ledger-fail">Ledger head {digest} &middot; {entries} &middot; '
        f"VERIFICATION FAILED ({problems} problem{'s' if problems != 1 else ''})</span>\n"
    )


def limitations_section(
    snap: dict[str, Any], collected: object, generated: str, ledger_head: dict[str, Any] | None = None
) -> str:
    return f"""  <section class="sec-short">
    <h2 id="limitations"><span class="secnum">6</span>Limitations and attestation</h2>
    <dl class="limits">
      <div class="limit"><dt>6.1</dt><dd><strong>No PHI.</strong> Synthetic lab data only. No real patient information is collected, stored, or shared in this packet.</dd></div>
      <div class="limit"><dt>6.2</dt><dd><strong>Qualification.</strong> A review aid; does not replace counsel, insurer, MSP, a qualified assessor, or the official HHS/ONC SRA Tool. Not legal advice; not a breach determination.</dd></div>
      <div class="limit"><dt>6.3</dt><dd><strong>Method.</strong> Metadata-only collection from the synthetic lab: directory service queries, share inventories, hashes, auth audit logs, and a read-only package exposure scan.</dd></div>
    </dl>
    <div class="stamp">
      <span>Generated {esc(generated)}</span>
      <span>Snapshot {esc(collected)}</span>
      <span>{esc(snap.get("schema"))}</span>
{ledger_line(ledger_head)}    </div>
    <div class="attestation">
      <span>Prepared by Velari &middot; {esc(snap.get("collector"))}</span>
      <span class="sig">Reviewed by ______________________&nbsp;&nbsp;Date ____________</span>
    </div>
  </section>"""
