from datetime import datetime, timezone

import pytest
from practice_evidence.models import Finding
from practice_evidence.sections import auth, containers, ehr, endpoints, identity, shares, supply_chain

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


# --- containers -------------------------------------------------------------


def test_containers_keep_only_lab_containers():
    raw = "\n".join(
        [
            "samba-dc|Up 2 hours|127.0.0.1:389->389/tcp",
            "osticket-web-1|Up 4 weeks|127.0.0.1:8080->80/tcp",
            "fd-frontdesk-01|Up 1 hour|",
            "malformed line",
        ]
    )
    assert [x["name"] for x in containers.parse(raw)] == ["samba-dc", "fd-frontdesk-01"]


def test_containers_do_not_truncate_ports():
    ports = ", ".join(f"127.0.0.1:{p}->{p}/tcp" for p in range(1000, 1015))
    [row] = containers.parse(f"samba-dc|Up|{ports}")
    assert row["ports"] == ports


# --- auth -------------------------------------------------------------------


def test_auth_regex_success_and_failure():
    ok = "[2026] user [MILLSLAB]\\[malvarez] at [x] status [NT_STATUS_OK] workstation [W]"
    bad = "user [MILLSLAB]\\[svc-temp] at [x] status [NT_STATUS_WRONG_PASSWORD]"
    m1, m2 = auth.AUTH_RE.search(ok), auth.AUTH_RE.search(bad)
    assert (m1.group("user"), m1.group("status")) == ("malvarez", "NT_STATUS_OK")
    assert (m2.group("user"), m2.group("status")) == ("svc-temp", "NT_STATUS_WRONG_PASSWORD")
    assert auth.AUTH_RE.search("samba started") is None


def _line(user, status):
    return f"user [MILLSLAB]\\[{user}] at [x] status [{status}]"


def test_auth_summary_counts_and_threshold():
    log = "\n".join([_line("a", "NT_STATUS_OK")] + [_line("b", "NT_STATUS_WRONG_PASSWORD")] * 5 + ["noise"])
    s = auth.summarize(log, 24)
    assert (s["success"], s["failures"]) == (1, 5)
    assert s["by_user"]["b"] == {"success": 0, "fail": 5}
    assert [f["severity"] for f in s["findings"]] == ["medium"]


def test_auth_summary_flags_non_password_failures_below_threshold():
    s = auth.summarize(_line("a", "NT_STATUS_ACCOUNT_LOCKED_OUT"), 24)
    assert s["findings"] == [
        {
            "severity": "low",
            "detail": "non-password auth failure observed: NT_STATUS_ACCOUNT_LOCKED_OUT",
            "rule_id": "AUTH-NONPASSWORD-FAILURE",
            "subject": "NT_STATUS_ACCOUNT_LOCKED_OUT",
        }
    ]


# --- identity ---------------------------------------------------------------


def test_filetime_conversion():
    assert identity.filetime_to_datetime("0") is None
    assert identity.filetime_to_datetime("garbage") is None
    assert identity.filetime_to_datetime(None) is None
    dt = identity.filetime_to_datetime("133801920000000000")
    assert dt.year == 2025


def test_parse_key_value_handles_colons_in_values():
    assert identity.parse_key_value("a: b\nurl: http://x:80\nnocolon") == {"a": "b", "url": "http://x:80"}


def test_parse_user_list_drops_builtins_and_errors():
    raw = "Administrator\nGuest\nkrbtgt\nmalvarez\n__ERROR__ boom\n"
    assert identity.parse_user_list(raw) == ["malvarez"]


def test_classify_disabled_stale_and_never_logged_on():
    disabled = identity.classify_user("d", {"userAccountControl": "514"}, NOW)
    assert disabled["enabled"] is False and not disabled["never_logged_on"]
    never = identity.classify_user("n", {"userAccountControl": "512"}, NOW)
    assert never["never_logged_on"] is True and never["stale"] is False
    # 2025-01 logon is >45 days before NOW
    stale = identity.classify_user("s", {"userAccountControl": "512", "lastLogonTimestamp": "133801920000000000"}, NOW)
    assert stale["stale"] is True and stale["never_logged_on"] is False


def test_user_findings_severities():
    assert [
        f.severity
        for f in identity.user_findings({"sam": "x", "enabled": False, "stale": False, "never_logged_on": False})
    ] == ["info"]
    assert [
        f.severity
        for f in identity.user_findings({"sam": "x", "enabled": True, "stale": True, "never_logged_on": False})
    ] == ["medium"]
    assert [
        f.severity
        for f in identity.user_findings({"sam": "x", "enabled": True, "stale": False, "never_logged_on": True})
    ] == ["low"]


# --- shares -----------------------------------------------------------------

SMB = """
[global]
workgroup = MILLSLAB
[sysvol]
path = /var/lib/samba/sysvol
[ClinicalShare]
path = /srv/samba/shares/Clinical
read only = no
[netlogon]
path = /var/lib/samba/netlogon
[ITShare]
path = /srv/samba/shares/IT
"""


def test_smb_conf_ignores_system_shares_and_does_not_leak_their_options():
    parsed = shares.parse_smb_conf(SMB)
    assert [s["name"] for s in parsed] == ["ClinicalShare", "ITShare"]
    # regression: options under [netlogon] used to be attached to ClinicalShare
    assert parsed[0] == {"name": "ClinicalShare", "path": "/srv/samba/shares/Clinical", "read only": "no"}


def test_share_findings_flag_patient_adjacent_paths_only():
    files = [{"path": "/s/Clinical/schedule.csv"}, {"path": "/s/IT/runbook.md"}, {"path": "/s/FO/Intake_2026.csv"}]
    assert [f.detail for f in shares.share_findings(files)] == [
        "patient-adjacent data on file share: /s/Clinical/schedule.csv",
        "patient-adjacent data on file share: /s/FO/Intake_2026.csv",
    ]


# --- ehr --------------------------------------------------------------------


def test_ehr_count_events_skips_malformed_lines(tmp_path):
    log = tmp_path / "access.jsonl"
    log.write_text('{"event":"scribe_transmission"}\nnot json\n{"event":"scribe_transmission"}\n{"no_event":1}\n[1]\n')
    assert ehr.count_events(log) == {"scribe_transmission": 2}
    assert ehr.count_events(tmp_path / "missing") == {}


def test_ehr_findings_pluralise_and_rank():
    out = ehr.event_findings({"scribe_transmission": 3, "intake_submitted": 1})
    assert [(f.severity, f.ref_key) for f in out] == [("high", None), ("medium", "ehr-intake")]
    assert "1 public web intake submission;" in out[1].detail
    assert "2 public web intake submissions;" in ehr.event_findings({"intake_submitted": 2})[0].detail
    assert ehr.event_findings({}) == []


# --- endpoints --------------------------------------------------------------

SPEC = {"name": "ws-clinical-01", "role": "Clinical workstation"}


def test_endpoint_scan_hashes_copies_and_skips_dirs(tmp_path):
    (tmp_path / "schedule.csv").write_text("x")
    (tmp_path / "sub").mkdir()
    copies = endpoints.scan_copies(tmp_path)
    assert [c["file"] for c in copies] == ["schedule.csv"]
    assert len(copies[0]["sha256_16"]) == 16 and copies[0]["readable"]
    assert endpoints.scan_copies(tmp_path / "nope") == []


def test_endpoint_findings():
    adj = [{"file": "patient_schedule.csv", "readable": True}, {"file": "notes.txt", "readable": True}]
    [f] = endpoints.host_findings(SPEC, adj)
    assert (f.severity, f.ref_key) == ("high", "endpoint-ws-clinical-01")
    assert "1 patient-adjacent file on local desktop" in f.detail
    [g] = endpoints.host_findings(SPEC, [{"file": "readme.txt", "readable": True}])
    assert g.severity == "info" and "1 share file cached locally" in g.detail
    unreadable = endpoints.host_findings(SPEC, [{"file": "readme.txt", "readable": False}])
    assert unreadable[0].severity == "low"
    assert endpoints.host_findings(SPEC, []) == []


def test_endpoint_activity_counts_tolerate_garbage(tmp_path):
    p = tmp_path / "activity.jsonl"
    p.write_text('{"event":"copy"}\n{"event":"copy"}\nbad\n[]\n{"x":1}\n')
    assert endpoints.count_activity(p) == {"copy": 2, "unknown": 2}


# --- supply chain -----------------------------------------------------------


def test_supply_chain_parses_findings_and_relativises_paths():
    rec = {
        "record_type": "finding",
        "severity": "critical",
        "package_name": "node-ipc",
        "version": "10.1.1",
        "ecosystem": "npm",
        "catalog_name": "c",
        "project_path": "/lab/frontdesk-01/home/x",
        "source_file": "/lab/f",
    }
    import json

    raw = "\n".join([json.dumps(rec), json.dumps({"record_type": "summary"}), "garbage"])
    [f] = supply_chain.parse_findings(raw, lab_root="/lab")
    d = f.to_dict()
    assert d["severity"] == "high"
    assert d["project"] == "frontdesk-01/home/x"
    assert d["detail"] == "Known-compromised package node-ipc@10.1.1 (npm) in frontdesk-01/home/x"


@pytest.mark.parametrize(
    "raw, expected", [("critical", "high"), ("high", "high"), ("medium", "medium"), ("low", "low"), ("weird", "low")]
)
def test_supply_chain_severity_mapping(raw, expected):
    assert supply_chain.map_severity(raw) == expected


# --- models -----------------------------------------------------------------


def test_finding_serialises_flat_and_validates_severity():
    f = Finding("high", "d", ref_key="k", extra={"package": "p"})
    assert f.to_dict() == {"severity": "high", "detail": "d", "ref_key": "k", "package": "p"}
    assert Finding("low", "d").to_dict() == {"severity": "low", "detail": "d"}
    with pytest.raises(ValueError):
        Finding("urgent", "d")
