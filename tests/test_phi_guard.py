"""No-PHI / no-credential guard: scanner tests against real and synthetic artifacts."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest
import render_practice_snapshot as renderer
from practice_evidence import redaction
from practice_evidence.report import render_markdown

ROOT = Path(__file__).resolve().parent.parent
SAMPLE_SNAPSHOT = ROOT / "examples" / "sample-snapshot.json"
SAMPLE_PACKET = ROOT / "examples" / "sample-packet.html"


@pytest.fixture(scope="module")
def sample() -> dict:
    return json.loads(SAMPLE_SNAPSHOT.read_text(encoding="utf-8"))


def rules(text: str) -> set[str]:
    return {finding.rule for finding in redaction.scan_text(text)}


# --------------------------------------------------------------------------
# Committed artifacts and full renders must be clean
# --------------------------------------------------------------------------


def test_committed_sample_snapshot_is_clean():
    assert redaction.scan_file(SAMPLE_SNAPSHOT) == []


def test_committed_sample_packet_is_clean():
    assert redaction.scan_file(SAMPLE_PACKET) == []


def test_full_renderer_output_is_clean(sample):
    assert redaction.scan_text(renderer.render(sample), source="rendered.html") == []


def test_markdown_output_is_clean(sample):
    text = render_markdown(sample, "2026-09-13")
    assert redaction.scan_text(text, source="snapshot.md") == []


# --------------------------------------------------------------------------
# Positive cases: every documented pattern must flag
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text, rule",
    [
        ("SSN 123-45-6789", "ssn"),
        ('"date_of_birth": "1980-04-12"', "dob"),
        ("DOB: 04/12/1980", "dob"),
        ("Patient Name: Jane Q Public", "name"),
        ('"patient_name": "Jane Doe"', "name"),
        ("call 212-555-1234", "phone"),
        ("email jdoe@example.com", "email"),
        ('"mrn": "1234567"', "mrn"),
        ("MRN-998877", "mrn"),
        ("password=hunter2", "secret"),
        ("api_key: sk-abc123", "secret"),
        ("Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345", "secret"),
        ("-----BEGIN RSA PRIVATE KEY-----", "private_key"),
        ("token " + "deadbeef" * 8, "long_token"),
        ("/home/alice/.ssh/id_rsa", "home_path"),
        ("/Users/alice/notes.txt", "home_path"),
        (r"C:\Users\alice\secret.txt", "home_path"),
    ],
)
def test_positive_patterns_flag(text, rule):
    found = redaction.scan_text(text)
    assert rule in {f.rule for f in found}, f"{rule} not flagged in {text!r}: {found}"


# --------------------------------------------------------------------------
# Documented synthetic allowlist must stay clean
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "555-0100",
        "555-0199",
        "(555) 555-0100",
        "jdoe@millslab.internal",
        "Administrator@MILLSLAB.INTERNAL",
        '"mrn": "SYN-000123"',
        "MRN: syn-abc",
        '"sha256_16": "425f71091bc9d3b4"',
        '"sha256": "' + "ab" * 32 + '"',
        "/srv/samba/shares/clinical/patient-schedule-export-2026-09.csv",
        "frontdesk-01/home/Desktop/Downloads/billing-helper",
        "workstation-01/home/Desktop/incoming/x.csv",
        "millslab.internal (synthetic)",
    ],
)
def test_synthetic_allowlist_is_clean(text):
    assert redaction.scan_text(text) == []


def test_hash_allowlist_only_applies_to_hash_fields():
    assert redaction.scan_text('"sha256": "' + "ab" * 32 + '"') == []
    assert rules('"notes": "' + "ab" * 32 + '"') == {"long_token"}


def test_synthetic_phone_range_is_exact():
    assert redaction.scan_text("555-555-0100") == []
    assert rules("555-555-0200") == {"phone"}


# --------------------------------------------------------------------------
# Masking and CLI behaviour
# --------------------------------------------------------------------------


def test_findings_do_not_reprint_the_suspect_value():
    [finding] = redaction.scan_text("password=hunter2")
    assert finding.rule == "secret"
    assert "hunter2" not in finding.excerpt
    assert "hunter2" not in str(finding)


def test_scan_paths_reports_per_file(tmp_path):
    clean = tmp_path / "clean.txt"
    clean.write_text("millslab.internal\n", encoding="utf-8")
    dirty = tmp_path / "dirty.txt"
    dirty.write_text("SSN 123-45-6789\n", encoding="utf-8")
    result = redaction.scan_paths([clean, dirty])
    assert result[str(clean)] == []
    assert [f.rule for f in result[str(dirty)]] == ["ssn"]


def test_cli_exit_codes(tmp_path, capsys):
    clean = tmp_path / "clean.txt"
    clean.write_text("millslab.internal\n", encoding="utf-8")
    dirty = tmp_path / "dirty.txt"
    dirty.write_text("password=hunter2\n", encoding="utf-8")

    assert redaction.main([str(clean)]) == 0
    assert "clean: 1 file" in capsys.readouterr().out

    assert redaction.main([str(dirty)]) == 1
    captured = capsys.readouterr()
    assert "secret" in captured.out
    assert "hunter2" not in captured.out
    assert "hunter2" not in captured.err

    assert redaction.main([str(tmp_path / "missing.txt")]) == 2


# --------------------------------------------------------------------------
# Regression: a poisoned snapshot must not slip through the packet renderer
# --------------------------------------------------------------------------


def test_rendered_packet_from_poisoned_snapshot_is_flagged(sample):
    poisoned = copy.deepcopy(sample)
    poisoned["findings"].append(
        {"section": "identity", "severity": "high", "detail": "patient MRN 4451200 for Jane Doe"}
    )
    packet = renderer.render(poisoned)
    found = redaction.scan_text(packet, source="poisoned.html")
    assert "mrn" in {f.rule for f in found}


def test_poisoned_markdown_is_flagged(sample):
    poisoned = copy.deepcopy(sample)
    poisoned["findings"].append({"section": "identity", "severity": "high", "detail": "contact jdoe@example.com"})
    text = render_markdown(poisoned, "2026-09-13")
    assert "email" in rules(text)


# --------------------------------------------------------------------------
# A freshly collected snapshot and its packet must also be clean
# --------------------------------------------------------------------------


def test_freshly_built_snapshot_and_packet_are_clean(tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / "tests" / "e2e"))
    from practice_evidence import snapshot
    from practice_evidence.drift import compute_drift
    from practice_evidence.runner import use_runner
    from support import NOW, FakeLab

    lab = FakeLab(tmp_path, monkeypatch)
    lab.set_ehr("run1")
    with use_runner(lab.runner("run1")):
        doc = snapshot.build(NOW, hours=24)
    doc["drift"] = compute_drift(None, doc)

    assert redaction.scan_text(json.dumps(doc, indent=2), source="built.json") == []
    assert redaction.scan_text(renderer.render(doc), source="built.html") == []
    assert redaction.scan_text(render_markdown(doc, "2026-11-12"), source="built.md") == []


def test_supply_chain_relative_paths_carry_no_absolute_lab_root():
    from practice_evidence.sections import supply_chain

    rec = {
        "record_type": "finding",
        "severity": "critical",
        "package_name": "node-ipc",
        "version": "10.1.1",
        "ecosystem": "npm",
        "catalog_name": "c",
        "project_path": "/lab/frontdesk-01/home/x",
        "source_file": "/lab/frontdesk-01/home/x/package-lock.json",
    }
    [finding] = supply_chain.parse_findings(json.dumps(rec), lab_root="/lab")
    serialized = json.dumps(finding.to_dict())
    assert "/lab" not in serialized
    assert "frontdesk-01/home/x/package-lock.json" in serialized


def test_cli_second_run_writes_relative_drift_path_and_clean_snapshot(tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / "tests" / "e2e"))
    from support import FakeLab, run_cli, snapshot_files

    lab = FakeLab(tmp_path, monkeypatch)
    assert run_cli(lab, "run1") == 0
    assert run_cli(lab, "run2") == 0
    path = snapshot_files(lab)[-1]
    doc = json.loads(path.read_text(encoding="utf-8"))

    compared = doc["drift"]["compared_to_path"]
    assert compared and not Path(compared).is_absolute()
    assert redaction.scan_file(path) == []
