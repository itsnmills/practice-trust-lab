"""End-to-end tests: snapshot.build() and the CLI run with no Docker at all."""

from __future__ import annotations

import json

from practice_evidence import SCHEMA, cli, ledger, snapshot
from practice_evidence.drift import compute_drift
from practice_evidence.report import render_markdown
from practice_evidence.runner import FakeRunner, use_runner
from practice_evidence.sections import auth, identity, shares
from support import NOW, load_snapshot, run_cli, snapshot_files


def _build(lab, scenario="run1"):
    lab.set_ehr(scenario)
    with use_runner(lab.runner(scenario)):
        return snapshot.build(NOW, hours=24)


# --- snapshot content -------------------------------------------------------


def test_build_collects_every_section_from_fake_runner(lab):
    snap = _build(lab)
    assert snap["collector"] == "collect_practice_evidence.py"
    assert snap["schema"] == SCHEMA
    assert snap["collected_at"] == "2026-11-12T12:00:00Z"
    assert "section_errors" not in snap

    names = {c["name"] for c in snap["containers"]}
    assert names == {"samba-dc", "clinic-ehr", "ws-clinical-01", "fd-frontdesk-01", "msp-jump-01"}
    assert "osticket-web-1" not in names and "watchtower" not in names
    assert all(c["name"] in names for c in snap["containers"])


def test_build_identity_shares_auth_ehr_endpoints(lab):
    snap = _build(lab)
    users = {u["sam"]: u for u in snap["identity"]["users"]}
    assert set(users) == {"malvarez", "jchen", "dpark", "svc-backup", "rhayes", "nmills"}
    assert users["svc-backup"]["enabled"] is False
    assert users["malvarez"]["never_logged_on"] is True
    assert users["dpark"]["stale"] is True
    assert snap["identity"]["password_policy"]["Minimum password length"] == "10"
    assert snap["identity"]["privileged_groups"]["SG-IT"] == ["nmills"]

    assert [s["name"] for s in snap["shares"]["shares"]] == ["ClinicalShare", "FrontOfficeShare", "ITShare"]
    by_path = {f["path"]: f["sha256_16"] for f in snap["shares"]["files"]}
    assert by_path["/srv/samba/shares/clinical/patient-schedule-export-2026-09.csv"] == "cb7d87f29c7bf504"
    assert len(by_path) == 6

    assert snap["auth"]["success"] == 6
    assert snap["auth"]["failures"] == 5
    assert snap["auth"]["failure_reasons"] == {
        "NT_STATUS_WRONG_PASSWORD": 3,
        "NT_STATUS_ACCOUNT_LOCKED_OUT": 2,
    }
    assert snap["ehr"]["health"]["status"] == "ok"
    assert snap["ehr"]["scribe_transmissions"] == 2
    assert snap["ehr"]["intake_submissions"] == 1
    assert [c["file"] for c in snap["endpoints"]["hosts"][0]["local_copies"]] == [
        "insurance-verification-2026-09.csv",
        "patient-schedule-export-2026-09.csv",
    ]
    assert snap["supply_chain"]["status"] == "complete"
    assert snap["supply_chain"]["findings"][0]["package"] == "node-ipc"


def test_build_finding_counts_and_severity_order(lab):
    snap = _build(lab)
    assert snap["finding_counts"] == {"high": 8, "medium": 5, "low": 4, "info": 3}
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    severities = [order[f["severity"]] for f in snap["findings"]]
    assert severities == sorted(severities)
    assert all("section" in f for f in snap["findings"])


# --- CLI contract -----------------------------------------------------------


def test_cli_first_run_writes_snapshot_markdown_and_ledger(lab, capsys):
    code = run_cli(lab, "run1")
    out = capsys.readouterr()
    assert code == 0
    assert "snapshot: " in out.out and "markdown: " in out.out
    assert "findings: high=8, info=3, low=4, medium=5" in out.out
    assert out.err == ""

    [json_path] = snapshot_files(lab)
    md_path = json_path.with_suffix(".md")
    assert md_path.is_file()
    snap = load_snapshot(json_path)
    assert snap["drift"]["status"] == "baseline"

    md = md_path.read_text(encoding="utf-8")
    assert md.startswith("# Practice Snapshot - 2026-11-12")
    assert "## Findings" in md
    assert "patient-adjacent data on file share" in md
    assert "_Synthetic lab data. No real patient information. Metadata-only evidence._" in md

    ok, msgs = ledger.verify_ledger(lab.ledger, base_dir=lab.base_dir)
    assert ok, msgs
    assert "1 chained entry checked" in msgs[-1]


def test_cli_second_run_reports_drift(lab):
    assert run_cli(lab, "run1") == 0
    assert run_cli(lab, "run2") == 0
    paths = snapshot_files(lab)
    assert len(paths) == 2
    drift = load_snapshot(paths[-1])["drift"]

    assert drift["status"] == "compared"
    assert drift["user_changes"] == ["account added: nbruce", "account disabled: jchen"]
    assert drift["group_changes"] == ["SG-IT: nbruce added", "SG-IT: nmills removed"]
    assert drift["share_changes"] == [
        "file added: /srv/samba/shares/clinical/new-patient-notes.txt",
        "file content changed: /srv/samba/shares/clinical/patient-schedule-export-2026-09.csv",
    ]
    assert drift["counter_deltas"]["scribe_transmissions"] == 2
    assert drift["counter_deltas"]["auth_success"] == 2
    assert any(
        "2 scribe transmission events" in item and "4 scribe transmission events" in item
        for item in drift["findings_changed"]
    )
    assert any("jchen: disabled account present" in item for item in drift["findings_new"])
    assert any("new-patient-notes.txt" in item for item in drift["findings_new"])

    ok, msgs = ledger.verify_ledger(lab.ledger, base_dir=lab.base_dir)
    assert ok, msgs
    assert "2 chained entries checked" in msgs[-1]


def test_cli_skip_supply_chain(lab):
    code = run_cli(lab, "run1", "--skip-supply-chain")
    assert code == 0
    snap = load_snapshot(snapshot_files(lab)[0])
    assert snap["supply_chain"]["status"] == "skipped"
    assert not any(f.get("package") == "node-ipc" for f in snap["findings"])
    assert snap["finding_counts"]["high"] == 7


def test_cli_quiet_suppresses_progress(lab, capsys):
    assert run_cli(lab, "run1", "--quiet") == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_cli_paths_come_from_environment(lab, monkeypatch, capsys):
    monkeypatch.setenv("EVIDENCE_ARTIFACTS_DIR", str(lab.artifacts))
    monkeypatch.setenv("EVIDENCE_LEDGER", str(lab.ledger))
    lab.set_ehr("run1")
    with use_runner(lab.runner("run1")):
        code = cli.main([])
    assert code == 0
    assert len(snapshot_files(lab)) == 1
    assert lab.ledger.is_file()
    assert "snapshot: " in capsys.readouterr().out


def test_verify_ledger_detects_tampering(lab):
    assert run_cli(lab, "run1") == 0
    [json_path] = snapshot_files(lab)
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    payload["lab"] = "tampered"
    json_path.write_text(json.dumps(payload), encoding="utf-8")
    code = cli.main(["--verify-ledger", "--artifacts-dir", str(lab.artifacts), "--ledger", str(lab.ledger)])
    assert code == 1


# --- failure modes ----------------------------------------------------------


def test_preflight_failure_exits_2_and_writes_nothing(lab, capsys):
    with use_runner(FakeRunner({})):
        code = cli.main(["--artifacts-dir", str(lab.artifacts), "--ledger", str(lab.ledger)])
    assert code == 2
    assert snapshot_files(lab) == []
    assert not lab.ledger.exists()
    assert "error: docker daemon not reachable" in capsys.readouterr().err


def test_preflight_container_not_running_exits_2(lab, capsys):
    runner = FakeRunner(
        {
            ("docker", "info"): "Server Version: 27.0.4\n",
            ("docker", "inspect", "-f", "{{.State.Running}}", "samba-dc"): "false",
        }
    )
    with use_runner(runner):
        code = cli.main(["--artifacts-dir", str(lab.artifacts), "--ledger", str(lab.ledger)])
    assert code == 2
    assert "is not running" in capsys.readouterr().err
    assert snapshot_files(lab) == []


def test_section_failure_degrades_gracefully(lab, monkeypatch):
    def boom():
        raise RuntimeError("share collector exploded")

    monkeypatch.setattr(shares, "collect", boom)
    snap = _build(lab)

    assert snap["section_errors"] == {"shares": "RuntimeError: share collector exploded"}
    assert snap["shares"] == {"shares": [], "files": [], "findings": []}
    error_findings = [f for f in snap["findings"] if f["section"] == "shares"]
    assert len(error_findings) == 1
    assert error_findings[0]["severity"] == "medium"
    assert error_findings[0]["detail"] == "shares section failed: RuntimeError: share collector exploded"

    # The rest of the pass survives.
    assert snap["identity"]["users"]
    assert snap["auth"]["success"] == 6
    assert snap["ehr"]["scribe_transmissions"] == 2
    assert snap["supply_chain"]["status"] == "complete"

    snap["drift"] = compute_drift(None, snap)
    md = render_markdown(snap, "2026-11-12")
    assert "shares section failed" in md
    assert "## File shares" in md


def test_cli_strict_exits_3_but_still_records_evidence(lab, monkeypatch, capsys):
    def boom():
        raise RuntimeError("identity collector exploded")

    monkeypatch.setattr(identity, "collect", boom)
    code = run_cli(lab, "run1", "--strict")
    assert code == 3
    assert "--strict" in capsys.readouterr().err
    files = snapshot_files(lab)
    assert len(files) == 1
    ok, msgs = ledger.verify_ledger(lab.ledger, base_dir=lab.base_dir)
    assert ok, msgs


def test_cli_strict_exits_0_on_clean_run(lab):
    assert run_cli(lab, "run1", "--strict") == 0


def test_cli_degrades_gracefully_and_still_exits_0(lab, monkeypatch, capsys):
    def boom():
        raise RuntimeError("identity collector exploded")

    monkeypatch.setattr(identity, "collect", boom)
    code = run_cli(lab, "run1")
    out = capsys.readouterr()
    assert code == 0
    assert "warning: identity section failed: RuntimeError: identity collector exploded" in out.out
    snap = load_snapshot(snapshot_files(lab)[0])
    assert snap["section_errors"]["identity"] == "RuntimeError: identity collector exploded"
    assert snap["identity"] == {"password_policy": {}, "users": [], "privileged_groups": {}, "findings": []}
    assert snap["finding_counts"]["medium"] == 4
    ok, msgs = ledger.verify_ledger(lab.ledger, base_dir=lab.base_dir)
    assert ok, msgs


def test_section_error_findings_do_not_crash_drift_or_render(lab, monkeypatch):
    monkeypatch.setattr(auth, "collect", lambda hours: (_ for _ in ()).throw(ValueError("bad log")))
    snap = _build(lab)
    assert snap["auth"]["window_hours"] == 0
    snap["drift"] = compute_drift(None, snap)
    assert "auth section failed: ValueError: bad log" in render_markdown(snap, "2026-11-12")


def test_fake_runner_records_calls_and_serves_keyed_output(lab):
    runner = lab.runner("run1")
    assert runner.run(["docker", "info"]).startswith("Server Version")
    assert runner.run(["docker", "inspect", "-f", "{{.State.Running}}", "samba-dc"]) == "true"
    assert runner.run(["rm", "-rf", "/"]).startswith("__ERROR__")
    assert ["rm", "-rf", "/"] in runner.calls
