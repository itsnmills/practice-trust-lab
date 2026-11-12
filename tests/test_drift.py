from practice_evidence.drift import compute_drift, finding_key, legacy_endpoint_copies

# --- drift ------------------------------------------------------------------


def snap(users=None, groups=None, files=None, findings=None, ehr=None, auth=None):
    return {
        "collected_at": "2026-01-01T00:00:00Z",
        "identity": {
            "users": [{"sam": s, "enabled": e} for s, e in (users or {}).items()],
            "privileged_groups": groups or {},
        },
        "shares": {"files": [{"path": p, "sha256_16": h} for p, h in (files or {}).items()]},
        "endpoints": {"hosts": []},
        "findings": findings or [],
        "ehr": ehr or {},
        "auth": auth or {},
    }


def test_drift_baseline_when_no_previous_snapshot():
    d = compute_drift(None, snap())
    assert d["status"] == "baseline"
    assert d["compared_to"] is None


def test_drift_identity_changes():
    prev = snap(users={"a": True, "b": True, "gone": True})
    cur = snap(users={"a": True, "b": False, "new": True})
    d = compute_drift(prev, cur)
    assert d["status"] == "compared"
    assert d["user_changes"] == ["account added: new", "account removed: gone", "account disabled: b"]


def test_drift_privileged_group_membership():
    prev = snap(groups={"SG-IT": ["alice"]})
    cur = snap(groups={"SG-IT": ["bob"], "Domain Admins": ["carol"]})
    d = compute_drift(prev, cur)
    assert sorted(d["group_changes"]) == [
        "Domain Admins: carol added",
        "SG-IT: alice removed",
        "SG-IT: bob added",
    ]


def test_drift_share_file_hash_change():
    prev = snap(files={"/s/a.csv": "1", "/s/b.csv": "2"})
    cur = snap(files={"/s/a.csv": "9", "/s/c.csv": "3"})
    d = compute_drift(prev, cur)
    assert sorted(d["share_changes"]) == [
        "file added: /s/c.csv",
        "file content changed: /s/a.csv",
        "file removed: /s/b.csv",
    ]


def test_drift_new_and_resolved_findings():
    old = {"section": "ehr", "severity": "high", "detail": "old"}
    kept = {"section": "ehr", "severity": "low", "detail": "kept"}
    new = {"section": "auth", "severity": "medium", "detail": "new"}
    d = compute_drift(snap(findings=[old, kept]), snap(findings=[kept, new]))
    assert d["findings_new"] == ["[medium] new"]
    assert d["findings_resolved"] == ["[high] old"]
    assert d["findings_changed"] == []


def test_drift_counter_deltas():
    prev = snap(ehr={"scribe_transmissions": 2}, auth={"failures": 5, "success": 10})
    cur = snap(ehr={"scribe_transmissions": 5}, auth={"failures": 5, "success": 8})
    d = compute_drift(prev, cur)
    assert d["counter_deltas"] == {"scribe_transmissions": 3, "auth_success": -2}


def test_drift_identical_snapshots_report_nothing():
    s = snap(users={"a": True}, files={"/s/a": "1"})
    d = compute_drift(s, s)
    for key in (
        "user_changes",
        "group_changes",
        "share_changes",
        "endpoint_changes",
        "findings_new",
        "findings_resolved",
        "findings_changed",
    ):
        assert d[key] == []
    assert d["counter_deltas"] == {}


def test_legacy_snapshot_endpoint_copies_are_compared():
    legacy = {"workstation": {"local_copies": [{"file": "x.csv", "sha256_16": "aa"}]}}
    assert legacy_endpoint_copies(legacy) == {"ws-clinical-01:x.csv": "aa"}


# --- stable rule ids --------------------------------------------------------


def test_finding_key_prefers_rule_and_subject():
    stable = {"rule_id": "AUTH-FAILURES", "subject": "domain", "section": "auth", "detail": "12 failures"}
    assert finding_key(stable) == ("rule", "AUTH-FAILURES\x00domain")
    legacy = {"section": "auth", "detail": "12 failures"}
    assert finding_key(legacy) == ("legacy", "auth\x0012 failures")


def test_rule_id_count_change_is_changed_not_new_and_resolved():
    prev = snap(findings=[{"rule_id": "AUTH-FAILURES", "severity": "medium", "detail": "12 auth failures in last 24h"}])
    cur = snap(findings=[{"rule_id": "AUTH-FAILURES", "severity": "medium", "detail": "15 auth failures in last 24h"}])
    d = compute_drift(prev, cur)
    assert d["findings_new"] == []
    assert d["findings_resolved"] == []
    assert d["findings_changed"] == ["[medium] 12 auth failures in last 24h -> 15 auth failures in last 24h"]
    assert d["counter_deltas"]["finding:AUTH-FAILURES"] == 3


def test_rule_id_subject_change_is_new_and_resolved():
    prev = snap(findings=[{"rule_id": "IDN-DORMANT-ACCOUNT", "subject": "alice", "severity": "low", "detail": "a"}])
    cur = snap(findings=[{"rule_id": "IDN-DORMANT-ACCOUNT", "subject": "bob", "severity": "low", "detail": "a"}])
    d = compute_drift(prev, cur)
    assert d["findings_new"] == ["[low] a"]
    assert d["findings_resolved"] == ["[low] a"]
    assert d["findings_changed"] == []


def test_rule_id_reworded_detail_is_changed():
    prev = snap(
        findings=[
            {"rule_id": "SUPPLY-KNOWN-BAD-PACKAGE", "subject": "node-ipc", "severity": "high", "detail": "old wording"}
        ]
    )
    cur = snap(
        findings=[
            {"rule_id": "SUPPLY-KNOWN-BAD-PACKAGE", "subject": "node-ipc", "severity": "high", "detail": "new wording"}
        ]
    )
    d = compute_drift(prev, cur)
    assert d["findings_changed"] == ["[high] old wording -> new wording"]
    assert d["findings_new"] == [] and d["findings_resolved"] == []
    assert "finding:SUPPLY-KNOWN-BAD-PACKAGE:node-ipc" not in d["counter_deltas"]


def test_rule_id_severity_change_is_reported():
    prev = snap(findings=[{"rule_id": "AUTH-FAILURES", "severity": "medium", "detail": "x"}])
    cur = snap(findings=[{"rule_id": "AUTH-FAILURES", "severity": "high", "detail": "x"}])
    d = compute_drift(prev, cur)
    assert d["findings_changed"] == ["[medium->high] x -> x"]
    assert d["findings_new"] == [] and d["findings_resolved"] == []


def test_legacy_count_change_is_paired_as_changed():
    prev = snap(findings=[{"section": "auth", "severity": "medium", "detail": "20 auth failures in last 24h"}])
    cur = snap(findings=[{"section": "auth", "severity": "medium", "detail": "25 auth failures in last 24h"}])
    d = compute_drift(prev, cur)
    assert d["findings_new"] == []
    assert d["findings_resolved"] == []
    assert d["findings_changed"] == ["[medium] 20 auth failures in last 24h -> 25 auth failures in last 24h"]
    assert d["counter_deltas"]["finding:auth"] == 5


def test_legacy_count_change_in_endpoints_is_paired():
    prev = snap(
        findings=[
            {
                "section": "endpoints",
                "severity": "high",
                "detail": "ws-01 (Clinical): 2 patient-adjacent files on local desktop",
            }
        ]
    )
    cur = snap(
        findings=[
            {
                "section": "endpoints",
                "severity": "high",
                "detail": "ws-01 (Clinical): 3 patient-adjacent files on local desktop",
            }
        ]
    )
    d = compute_drift(prev, cur)
    assert d["findings_new"] == [] and d["findings_resolved"] == []
    assert d["findings_changed"] == [
        "[high] ws-01 (Clinical): 2 patient-adjacent files on local desktop -> "
        "ws-01 (Clinical): 3 patient-adjacent files on local desktop"
    ]


def test_legacy_reworded_finding_is_still_new_and_resolved():
    prev = snap(findings=[{"section": "identity", "severity": "low", "detail": "old wording"}])
    cur = snap(findings=[{"section": "identity", "severity": "low", "detail": "new wording"}])
    d = compute_drift(prev, cur)
    assert d["findings_new"] == ["[low] new wording"]
    assert d["findings_resolved"] == ["[low] old wording"]
    assert d["findings_changed"] == []


def test_legacy_share_path_numbers_are_not_paired():
    prev = snap(
        findings=[
            {
                "section": "shares",
                "severity": "high",
                "detail": "patient-adjacent data on file share: /s/intake-2026-09.csv",
            }
        ]
    )
    cur = snap(
        findings=[
            {
                "section": "shares",
                "severity": "high",
                "detail": "patient-adjacent data on file share: /s/intake-2026-10.csv",
            }
        ]
    )
    d = compute_drift(prev, cur)
    assert d["findings_new"] and d["findings_resolved"]
    assert d["findings_changed"] == []


def test_mixed_legacy_and_rule_snapshots_do_not_crash():
    prev = snap(findings=[{"section": "auth", "severity": "medium", "detail": "20 auth failures in last 24h"}])
    cur = snap(findings=[{"rule_id": "AUTH-FAILURES", "severity": "medium", "detail": "20 auth failures in last 24h"}])
    d = compute_drift(prev, cur)
    assert d["status"] == "compared"
    assert isinstance(d["findings_new"], list)
    assert isinstance(d["findings_resolved"], list)
