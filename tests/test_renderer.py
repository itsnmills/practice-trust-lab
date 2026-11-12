import copy
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import hipaa_crosswalk as hc
import pytest
import render_practice_snapshot as r
from practice_render import RULES, rule_for_detail

SAMPLE = Path(__file__).resolve().parent.parent / "examples" / "sample-snapshot.json"
FIXED_NOW = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)
PAYLOAD = "<script>alert('x')</script>"


@pytest.fixture(scope="module")
def sample():
    return json.loads(SAMPLE.read_text(encoding="utf-8"))


def test_sample_snapshot_renders(sample):
    html_out = r.render(sample, now=FIXED_NOW)
    assert html_out.startswith("<!doctype html>")
    assert "millslab.internal" in html_out
    assert html_out.rstrip().endswith("</html>")


def test_sample_has_only_lab_containers(sample):
    names = {c["name"] for c in sample["containers"]}
    assert names == {"samba-dc", "clinic-ehr", "ws-clinical-01", "fd-frontdesk-01", "msp-jump-01"}


def test_output_is_self_contained(sample):
    out = r.render(sample, now=FIXED_NOW)
    assert "<style>" in out and "packet.css" not in out
    assert not re.search(r"""(?:src|href)\s*=\s*["']https?://""", out, re.I)
    assert "<script" not in out.lower()


def test_legacy_snapshot_without_rule_ids_still_renders(sample):
    assert all("rule_id" not in finding for finding in sample["findings"])
    out = r.render(sample, now=FIXED_NOW)
    assert "Dormant enabled accounts" in out
    assert "E-01" in out


def test_hostile_finding_text_is_escaped(sample):
    snap = copy.deepcopy(sample)
    snap["findings"].append({"section": "identity", "severity": "high", "detail": f"x: {PAYLOAD}"})
    out = r.render(snap, now=FIXED_NOW)
    assert PAYLOAD not in out
    assert "&lt;script&gt;" in out


def test_hostile_input_is_escaped_in_every_section(sample):
    snap = copy.deepcopy(sample)
    snap["lab"] = PAYLOAD
    snap["collector"] = PAYLOAD
    snap["schema"] = PAYLOAD
    snap["auth"]["window_hours"] = PAYLOAD
    snap["identity"]["password_policy"] = {PAYLOAD: PAYLOAD}
    snap["identity"]["users"].append(
        {"sam": PAYLOAD, "enabled": True, "last_logon": PAYLOAD, "stale": True, "never_logged_on": True}
    )
    snap["identity"]["privileged_groups"] = {PAYLOAD: [PAYLOAD]}
    snap["shares"]["files"].append({"path": f"/srv/{PAYLOAD}.csv", "sha256_16": PAYLOAD})
    snap["endpoints"]["hosts"].append(
        {
            "name": PAYLOAD,
            "role": PAYLOAD,
            "local_copies": [{"file": f"{PAYLOAD}.csv", "sha256_16": PAYLOAD, "readable": True}],
            "activity": {},
        }
    )
    snap["supply_chain"]["findings"].append(
        {
            "severity": "high",
            "detail": PAYLOAD,
            "package": PAYLOAD,
            "version": PAYLOAD,
            "ecosystem": PAYLOAD,
            "catalog": PAYLOAD,
            "project": PAYLOAD,
        }
    )
    snap["ehr"]["health"] = {"status": PAYLOAD}
    snap["drift"] = {
        "status": "compared",
        "compared_to": PAYLOAD,
        "findings_new": [PAYLOAD],
        "findings_resolved": [PAYLOAD],
        "findings_changed": [PAYLOAD],
        "user_changes": [PAYLOAD],
        "group_changes": [PAYLOAD],
        "share_changes": [PAYLOAD],
        "endpoint_changes": [PAYLOAD],
        "counter_deltas": {PAYLOAD: 1},
    }
    for rule in RULES.values():
        snap["findings"].append(
            {
                "section": "identity",
                "severity": rule.severity,
                "detail": f"{PAYLOAD} {rule.rule_id}",
                "rule_id": rule.rule_id,
                "subject": PAYLOAD,
            }
        )
    out = r.render(snap, now=FIXED_NOW)
    assert PAYLOAD not in out
    assert "&lt;script&gt;" in out
    assert "&lt;/script&gt;" in out


def test_redact_strips_home_and_lab_paths():
    assert r.redact(f"{r.LAB_ROOT}/frontdesk-01/home/x") == "frontdesk-01/home/x"
    assert r.redact(f"{r.Path.home()}/secret") == "~/secret"


@pytest.mark.parametrize(
    "detail, group",
    [
        ("Known-compromised package node-ipc@10.1.1", "supply"),
        ("3 scribe transmission events; verify signed BAA", "scribe"),
        ("ws-clinical-01 (Clinical workstation): 2 patient-adjacent files on local desktop", "endpoint"),
        ("patient-adjacent data on file share: /x/intake.csv", "shares"),
        ("SG-IT membership = local admin equivalent", "admin"),
        ("jdoe: enabled account has never logged on", "dormant"),
        ("something unmapped", "other"),
    ],
)
def test_legacy_rule_lookup_maps_findings_to_groups(detail, group):
    assert rule_for_detail(detail).group == group
    assert r.rule_for(detail).group == group


def test_rule_id_beats_detail_text(sample):
    snap = copy.deepcopy(sample)
    for finding in snap["findings"]:
        if "never logged on" in finding["detail"]:
            finding["rule_id"] = "IDN-STALE-ACCOUNT"
            finding["subject"] = finding["detail"].split(":")[0]
            finding["detail"] = "reworded with no legacy phrase"
    rows = r.build_rows(snap, snap["collected_at"])
    groups = {row["group"] for row in rows}
    assert "dormant" not in groups
    assert "other" in groups


def test_build_rows_consolidates_and_ranks(sample):
    rows = r.build_rows(sample, sample["collected_at"])
    refs = [row["ref"] for row in rows]
    assert refs == [f"E-{i:02d}" for i in range(1, len(rows) + 1)]
    sev = [r.SEVERITY_ORDER[row["severity"]] for row in rows]
    assert sev == sorted(sev)
    groups = [row["group"] for row in rows if row["group"] != "other"]
    assert len(groups) == len(set(groups)), "grouped findings must consolidate into one row"


def test_build_rows_uses_rule_default_severity():
    snap = {"findings": [{"detail": "reworded", "rule_id": "AUTH-FAILURES"}]}
    [row] = r.build_rows(snap, "2026-01-01T00:00:00Z")
    assert row["severity"] == "medium"
    assert row["title"] == "Authentication failures in the review window"


def test_decisions_default_to_allow_when_clean():
    [d] = r.build_decisions([])
    assert d["state"] == "allow"


def test_decisions_block_on_supply_chain(sample):
    rows = r.build_rows(sample, sample["collected_at"])
    assert r.build_decisions(rows)[0]["state"] == "block"


def test_due_date_and_prose_ts():
    assert r.due_date("2026-09-13T18:57:14Z", "7 days") == "20 Sep 2026"
    assert r.due_date("garbage", "7 days") == "7 days"
    assert r.prose_ts("2026-09-13T18:57:14Z") == "13 Sep 2026, 18:57 UTC"
    assert r.prose_ts(None) == "None"


def test_lane_refs_collapse_consecutive_items():
    rows = [
        {"ref": "E-01", "lane": "MSP", "due": "1 Jan"},
        {"ref": "E-02", "lane": "MSP", "due": "1 Jan"},
        {"ref": "E-03", "lane": "MSP", "due": "8 Jan"},
    ]
    [lane] = r.build_lanes(rows)
    assert lane["recipient"] == "MSP"
    assert lane["refs"] == "E-01–E-02 (1 Jan); E-03 (8 Jan)"


def test_rows_carry_hipaa_citations_for_mapped_groups(sample):
    rows = r.build_rows(sample, sample["collected_at"])
    for row in rows:
        assert bool(row["hipaa"]) == (row["group"] in hc.CROSSWALK)


def test_packet_shows_crosswalk_and_citations(sample):
    out = r.render(sample, now=FIXED_NOW)
    assert "5.8 HIPAA Security Rule crosswalk" in out
    assert "\u00a7164.308(b)(1)" in out  # scribe/BAA
    assert "HIPAA: " in out


# --- accessibility ----------------------------------------------------------


def test_document_language_is_declared(sample):
    out = r.render(sample, now=FIXED_NOW)
    assert re.search(r"<html\s+lang=\"en\">", out)


def test_every_table_header_has_scope(sample):
    out = r.render(sample, now=FIXED_NOW)
    headers = re.findall(r"<th\b[^>]*>", out)
    assert headers
    assert [th for th in headers if "scope=" not in th] == []


def test_skip_link_targets_main_landmark(sample):
    out = r.render(sample, now=FIXED_NOW)
    assert 'class="skip-link" href="#main"' in out
    assert 'id="main"' in out


def test_print_structure_is_present(sample):
    out = r.render(sample, now=FIXED_NOW)
    assert "@media print" in out
    assert "page-break-before: always" in out
    assert 'id="summary"' in out and 'id="evidence"' in out


def test_drift_changed_findings_are_shown(sample):
    snap = copy.deepcopy(sample)
    snap["drift"] = {
        "status": "compared",
        "compared_to": "2026-09-13T18:56:15Z",
        "findings_new": [],
        "findings_resolved": [],
        "findings_changed": ["[medium] 12 auth failures -> 15 auth failures"],
        "user_changes": [],
        "group_changes": [],
        "share_changes": [],
        "endpoint_changes": [],
        "counter_deltas": {"finding:AUTH-FAILURES": 3},
    }
    out = r.render(snap, now=FIXED_NOW)
    assert "<dt>Changed</dt>" in out
    assert "12 auth failures -&gt; 15 auth failures" in out
    assert "finding:AUTH-FAILURES: +3" in out


def _css_vars() -> dict[str, str]:
    css = r.read_css()
    block = re.search(r":root\s*\{(.*?)\}", css, re.S)
    assert block
    return dict(re.findall(r"--([a-z-]+):\s*(#[0-9a-fA-F]{6})", block.group(1)))


def _luminance(hex_color: str) -> float:
    channels = [int(hex_color.lstrip("#")[i : i + 2], 16) / 255 for i in (0, 2, 4)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast(a: str, b: str) -> float:
    high, low = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def test_css_text_colours_meet_wcag_aa_on_paper():
    variables = _css_vars()
    paper = variables["paper"]
    for name in ("ink", "body", "muted", "faint", "hot"):
        assert _contrast(variables[name], paper) >= 4.5, name


# --- ledger head in the footer -------------------------------------------------


def _head(**over):
    base = {"present": True, "ok": True, "entry_count": 3, "head_entry_hash": "ab12" * 16, "error_count": 0}
    return {**base, **over}


def test_footer_shows_verified_ledger_head(sample):
    out = r.render(sample, ledger_head=_head())
    assert "Ledger head ab12ab12ab12ab12 &middot; 3 entries &middot; chain verified" in out


def test_footer_shows_failed_verification_loudly(sample):
    out = r.render(sample, ledger_head=_head(ok=False, error_count=2))
    assert "VERIFICATION FAILED (2 problems)" in out
    assert "chain verified" not in out


def test_footer_omits_ledger_when_absent_or_not_supplied(sample):
    assert "Ledger head" not in r.render(sample)
    assert "Ledger head" not in r.render(sample, ledger_head=_head(present=False))


def test_footer_singular_entry_wording(sample):
    assert "1 entry &middot;" in r.render(sample, ledger_head=_head(entry_count=1))
