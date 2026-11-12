import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

from practice_evidence import ledger as ledger_mod
from practice_evidence.ledger import (
    CHAIN_VERSION,
    GENESIS,
    append_entry,
    build_ledger_entry,
    entry_digest,
    file_sha256,
    head_summary,
    last_entry_hash,
    verify_ledger,
    verify_ledger_report,
)

ROOT = Path(__file__).resolve().parent.parent

# --- ledger hash chain ------------------------------------------------------


def _write_snapshot(dirpath, name, payload):
    p = dirpath / name
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def _append(ledger, base, n):
    j = _write_snapshot(base, f"s{n}.json", {"n": n})
    m = base / f"s{n}.md"
    m.write_text("md", encoding="utf-8")
    entry = build_ledger_entry(
        {"collected_at": f"2026-01-0{n}T00:00:00Z", "finding_counts": {"high": n}},
        j,
        m,
        last_entry_hash(ledger),
        base_dir=base,
    )
    append_entry(ledger, entry)


def build_ledger(tmp_path, entries=3):
    ledger = tmp_path / "ledger.jsonl"
    for n in range(1, entries + 1):
        _append(ledger, tmp_path, n)
    return ledger


def test_ledger_verifies_when_untouched(tmp_path):
    ledger = build_ledger(tmp_path)
    ok, msgs = verify_ledger(ledger)
    assert ok, msgs
    assert "3 chained entries checked" in msgs[-1]


def test_ledger_detects_modified_snapshot(tmp_path):
    ledger = build_ledger(tmp_path)
    (tmp_path / "s2.json").write_text('{"n": 999}', encoding="utf-8")
    ok, msgs = verify_ledger(ledger)
    assert not ok
    assert any("snapshot modified" in m and "s2.json" in m for m in msgs)


def test_ledger_detects_deleted_entry(tmp_path):
    ledger = build_ledger(tmp_path)
    lines = ledger.read_text().splitlines()
    ledger.write_text("\n".join([lines[0], lines[2]]) + "\n")
    ok, msgs = verify_ledger(ledger)
    assert not ok
    assert any("chain broken" in m for m in msgs)


def test_ledger_detects_edited_entry(tmp_path):
    ledger = build_ledger(tmp_path)
    lines = ledger.read_text().splitlines()
    entry = json.loads(lines[1])
    entry["findings"] = {"high": 0}
    lines[1] = json.dumps(entry)
    ledger.write_text("\n".join(lines) + "\n")
    ok, msgs = verify_ledger(ledger)
    assert not ok
    assert any("entry_hash" in m for m in msgs)


def test_ledger_skips_legacy_lines_and_chains_after_them(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text(json.dumps({"ts": "old", "sha256": "abc"}) + "\n")
    _append(ledger, tmp_path, 1)
    ok, msgs = verify_ledger(ledger)
    assert ok, msgs
    assert any("legacy" in m for m in msgs)


def test_first_entry_chains_from_genesis(tmp_path):
    assert last_entry_hash(tmp_path / "missing.jsonl") == GENESIS


# --- structured results and chain versioning -------------------------------


def test_report_exposes_typed_problems_with_lines_and_severities(tmp_path):
    ledger = build_ledger(tmp_path)
    lines = ledger.read_text().splitlines()
    entry = json.loads(lines[1])
    entry["findings"] = {"high": 0}
    lines[1] = json.dumps(entry)
    ledger.write_text("\n".join(lines) + "\n")

    report = verify_ledger_report(ledger)
    assert not report.ok
    digest_problem = next(p for p in report.problems if p.code == "entry_digest_mismatch")
    assert digest_problem.severity == ledger_mod.ERROR
    assert digest_problem.line == 2
    assert "entry_hash" in digest_problem.message
    assert report.head_hash == json.loads(lines[2])["entry_hash"]
    assert report.as_dict()["chained"] == 3


def test_new_entries_carry_chain_version(tmp_path):
    ledger = build_ledger(tmp_path, entries=1)
    entry = json.loads(ledger.read_text().splitlines()[0])
    assert entry["v"] == CHAIN_VERSION


def test_pre_versioning_entries_still_verify(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    snap = _write_snapshot(tmp_path, "old.json", {"n": 1})
    md = tmp_path / "old.md"
    md.write_text("md", encoding="utf-8")
    entry = build_ledger_entry(
        {"collected_at": "2025-01-01T00:00:00Z", "finding_counts": {"high": 1}},
        snap,
        md,
        GENESIS,
        base_dir=tmp_path,
    )
    entry.pop("v")
    entry["entry_hash"] = entry_digest(entry)
    ledger.write_text(json.dumps(entry) + "\n", encoding="utf-8")

    report = verify_ledger_report(ledger)
    assert report.ok, report.messages
    assert report.unversioned == 1
    assert report.chained == 1


def test_unknown_future_chain_version_is_an_error(tmp_path):
    ledger = build_ledger(tmp_path, entries=1)
    entry = json.loads(ledger.read_text().splitlines()[0])
    entry["v"] = CHAIN_VERSION + 1
    entry["entry_hash"] = entry_digest(entry)
    ledger.write_text(json.dumps(entry) + "\n", encoding="utf-8")

    report = verify_ledger_report(ledger)
    assert not report.ok
    assert any(p.code == "unsupported_chain_version" and p.line == 1 for p in report.problems)


def test_missing_snapshot_is_warning_not_failure(tmp_path):
    ledger = build_ledger(tmp_path)
    (tmp_path / "s2.json").unlink()
    report = verify_ledger_report(ledger)
    assert report.ok
    assert any(p.severity == ledger_mod.WARNING and p.code == "snapshot_missing" for p in report.problems)


# --- crash safety: partial trailing line -----------------------------------


def test_partial_trailing_line_is_tolerated(tmp_path):
    ledger = build_ledger(tmp_path, entries=2)
    head = last_entry_hash(ledger)
    with ledger.open("ab") as fh:
        fh.write(b'{"ts": "2026-01-03T00:00')

    report = verify_ledger_report(ledger)
    assert report.ok, report.messages
    assert report.trailing_partial is True
    assert report.chained == 2
    assert report.head_hash == head
    assert any(p.code == "truncated_tail" and p.line == 3 for p in report.problems)
    ok, msgs = verify_ledger(ledger)
    assert ok
    assert msgs[-1] == "2 chained entries checked"


def test_append_after_partial_tail_quarantines_it_and_keeps_chain(tmp_path):
    ledger = build_ledger(tmp_path, entries=2)
    torn = b'{"ts": "2026-01-03T00:00'
    with ledger.open("ab") as fh:
        fh.write(torn)

    _append(ledger, tmp_path, 3)

    report = verify_ledger_report(ledger)
    assert report.ok, report.messages
    assert report.chained == 3
    assert not report.trailing_partial
    recovered = Path(str(ledger) + ".recovered")
    assert recovered.is_file()
    assert torn in recovered.read_bytes()
    assert torn not in ledger.read_bytes()


def test_missing_final_newline_is_repaired_on_append(tmp_path):
    ledger = build_ledger(tmp_path, entries=2)
    data = ledger.read_bytes()
    assert data.endswith(b"\n")
    ledger.write_bytes(data[:-1])

    _append(ledger, tmp_path, 3)

    report = verify_ledger_report(ledger)
    assert report.ok, report.messages
    assert report.chained == 3
    assert ledger.read_bytes().endswith(b"\n")


# --- locking ---------------------------------------------------------------

_CONCURRENT_APPENDER = textwrap.dedent(
    """
    import json, sys
    from pathlib import Path
    from practice_evidence import ledger

    base = Path(sys.argv[1])
    tag = sys.argv[2]
    for i in range(8):
        j = base / f"{tag}-{i}.json"
        j.write_text(json.dumps({"n": i}), encoding="utf-8")
        m = base / f"{tag}-{i}.md"
        m.write_text("md", encoding="utf-8")
        ledger.append_chained(
            base / "ledger.jsonl",
            {"collected_at": "2026-01-01T00:00:00Z", "finding_counts": {"high": i}},
            j,
            m,
            base_dir=base,
        )
    print("done")
    """
)


def test_concurrent_appenders_do_not_fork_the_chain(tmp_path):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "evidence")
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", _CONCURRENT_APPENDER, str(tmp_path), tag],
            env=env,
            cwd=str(tmp_path),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for tag in ("a", "b")
    ]
    for proc in procs:
        out, err = proc.communicate(timeout=120)
        assert proc.returncode == 0, err.decode()

    report = verify_ledger_report(tmp_path / "ledger.jsonl")
    assert report.ok, report.messages
    assert report.chained == 16
    assert (tmp_path / "ledger.jsonl.lock").is_file()


# --- head summary for the renderer -----------------------------------------


def test_head_summary_reports_verified_head(tmp_path):
    ledger = build_ledger(tmp_path, entries=3)
    summary = head_summary(ledger)
    assert summary["present"] is True
    assert summary["ok"] is True
    assert summary["entry_count"] == 3
    assert summary["head_entry_hash"] == last_entry_hash(ledger)
    assert summary["head_ts"] == "2026-01-03T00:00:00Z"
    assert summary["ledger_sha256"] == file_sha256(ledger)
    assert summary["error_count"] == 0


def test_head_summary_handles_missing_ledger(tmp_path):
    summary = head_summary(tmp_path / "absent.jsonl")
    assert summary["present"] is False
    assert summary["entry_count"] == 0
    assert summary["head_entry_hash"] == GENESIS
    assert summary["ledger_sha256"] is None
    assert summary["ok"] is False


def test_verify_missing_ledger_keeps_legacy_message(tmp_path):
    ok, msgs = verify_ledger(tmp_path / "absent.jsonl")
    assert not ok
    assert msgs == [f"ledger not found: {tmp_path / 'absent.jsonl'}"]


def test_snapshot_path_must_stay_inside_the_evidence_root(tmp_path):
    ledger = build_ledger(tmp_path, entries=1)
    entry = json.loads(ledger.read_text().splitlines()[0])
    entry["json"] = "../outside.json"
    entry["entry_hash"] = entry_digest(entry)
    ledger.write_text(json.dumps(entry) + "\n", encoding="utf-8")

    report = verify_ledger_report(ledger)
    assert not report.ok
    assert any(p.code == "snapshot_path_invalid" for p in report.problems)


def test_unreadable_snapshot_is_a_typed_error(tmp_path):
    import os

    import pytest

    if os.name != "posix" or os.geteuid() == 0:
        pytest.skip("permission bits are not enforceable here")
    ledger = build_ledger(tmp_path, entries=1)
    snap = tmp_path / "s1.json"
    os.chmod(snap, 0o000)
    try:
        report = verify_ledger_report(ledger)
    finally:
        os.chmod(snap, 0o600)
    assert not report.ok
    assert any(p.code == "snapshot_unreadable" and p.line == 1 for p in report.problems)
