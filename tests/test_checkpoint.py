import json
import os
import random
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest
from practice_evidence import checkpoint
from practice_evidence import ledger as ledger_mod
from practice_evidence.ledger import GENESIS, file_sha256, last_entry_hash, verify_ledger_report

POSIX = os.name == "posix"


def build_ledger(tmp_path, entries=3, prefix="s", start=1):
    ledger_path = tmp_path / "ledger.jsonl"
    for n in range(start, start + entries):
        j = tmp_path / f"{prefix}{n}.json"
        j.write_text(json.dumps({"n": n}), encoding="utf-8")
        m = tmp_path / f"{prefix}{n}.md"
        m.write_text("md", encoding="utf-8")
        ledger_mod.append_chained(
            ledger_path,
            {"collected_at": f"2026-01-{n:02d}T00:00:00Z", "finding_counts": {"high": n}},
            j,
            m,
            base_dir=tmp_path,
        )
    return ledger_path


def write_key(path, value=b"correct horse battery staple", mode=0o600):
    path.write_bytes(value)
    if POSIX:
        os.chmod(path, mode)
    return path


# --- checkpoint contents ---------------------------------------------------


def test_checkpoint_records_head_count_bytes_and_digest(tmp_path):
    ledger_path = build_ledger(tmp_path)
    cp = checkpoint.create_checkpoint(ledger_path)

    assert cp["kind"] == checkpoint.CHECKPOINT_KIND
    assert cp["entry_count"] == 3
    assert cp["head_entry_hash"] == last_entry_hash(ledger_path)
    assert cp["ledger_sha256"] == file_sha256(ledger_path)
    assert cp["ledger_bytes"] == ledger_path.stat().st_size
    assert cp["head_ts"] == "2026-01-03T00:00:00Z"
    assert cp["created_at"].endswith("Z")
    assert "signature" not in cp


def test_write_and_load_roundtrip(tmp_path):
    ledger_path = build_ledger(tmp_path)
    out = tmp_path / "anchors" / "anchor.json"
    written = checkpoint.write_checkpoint(ledger_path, out)
    assert out.is_file()
    assert not out.with_name(out.name + ".tmp").exists()
    loaded = checkpoint.load_checkpoint(out)
    assert loaded == written


def test_default_checkpoint_path_is_timestamped(tmp_path):
    when = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    path = checkpoint.default_checkpoint_path(now=when, base_dir=tmp_path)
    assert path == tmp_path / "checkpoints" / "checkpoint-20260102T030405Z.json"


def test_refuses_to_checkpoint_broken_or_empty_ledger(tmp_path):
    ledger_path = build_ledger(tmp_path)
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(checkpoint.CheckpointError, match="no chained entries"):
        checkpoint.create_checkpoint(empty)

    lines = ledger_path.read_text().splitlines()
    entry = json.loads(lines[1])
    entry["findings"] = {"high": 0}
    lines[1] = json.dumps(entry)
    ledger_path.write_text("\n".join(lines) + "\n")
    with pytest.raises(checkpoint.CheckpointError, match="refusing to checkpoint"):
        checkpoint.create_checkpoint(ledger_path)


# --- checkpoint verification ----------------------------------------------


def test_clean_checkpoint_verifies_exactly(tmp_path):
    ledger_path = build_ledger(tmp_path)
    cp = checkpoint.create_checkpoint(ledger_path)
    report = checkpoint.verify_checkpoint(ledger_path, cp)
    assert report.ok, report.messages
    assert report.exact_match is True
    assert any(p.code == "checkpoint_unsigned" for p in report.problems)
    assert "3 entries" in report.summary


def test_legitimate_append_keeps_anchor_valid_but_changes_bytes(tmp_path):
    ledger_path = build_ledger(tmp_path)
    cp = checkpoint.create_checkpoint(ledger_path)
    build_ledger(tmp_path, entries=1, prefix="later", start=4)

    report = checkpoint.verify_checkpoint(ledger_path, cp)
    assert report.ok, report.messages
    assert report.exact_match is False
    assert any(p.code == "checkpoint_ledger_changed" and p.severity == ledger_mod.WARNING for p in report.problems)


def test_truncation_is_detected(tmp_path):
    ledger_path = build_ledger(tmp_path)
    cp = checkpoint.create_checkpoint(ledger_path)
    lines = ledger_path.read_text().splitlines()
    ledger_path.write_text("\n".join(lines[:-1]) + "\n")

    report = checkpoint.verify_checkpoint(ledger_path, cp)
    assert not report.ok
    assert any(p.code == "checkpoint_truncated" for p in report.problems)
    assert report.exact_match is False
    assert report.input_error is False


def test_rewritten_snapshot_is_detected(tmp_path):
    ledger_path = build_ledger(tmp_path)
    cp = checkpoint.create_checkpoint(ledger_path)
    (tmp_path / "s2.json").write_text('{"n": 999}', encoding="utf-8")

    report = checkpoint.verify_checkpoint(ledger_path, cp)
    assert not report.ok
    assert any(p.code == "snapshot_modified" for p in report.all_problems)


def test_fully_rebuilt_chain_with_same_length_is_detected(tmp_path):
    ledger_path = build_ledger(tmp_path)
    cp = checkpoint.create_checkpoint(ledger_path)
    ledger_path.unlink()
    build_ledger(tmp_path, entries=3, prefix="r")

    report = checkpoint.verify_checkpoint(ledger_path, cp)
    assert not report.ok
    assert any(p.code == "checkpoint_head_moved" for p in report.problems)


def test_rebuilt_chain_with_extra_entries_is_detected(tmp_path):
    ledger_path = build_ledger(tmp_path)
    cp = checkpoint.create_checkpoint(ledger_path)
    ledger_path.unlink()
    build_ledger(tmp_path, entries=5, prefix="r")

    report = checkpoint.verify_checkpoint(ledger_path, cp)
    assert not report.ok
    assert any(p.code == "checkpoint_head_moved" for p in report.problems)


def test_entry_that_does_not_chain_from_head_is_detected(tmp_path):
    ledger_path = build_ledger(tmp_path)
    cp = checkpoint.create_checkpoint(ledger_path)
    j = tmp_path / "detached.json"
    j.write_text("{}", encoding="utf-8")
    m = tmp_path / "detached.md"
    m.write_text("md", encoding="utf-8")
    entry = ledger_mod.build_ledger_entry(
        {"collected_at": "2026-02-01T00:00:00Z", "finding_counts": {"high": 1}},
        j,
        m,
        GENESIS,
        base_dir=tmp_path,
    )
    ledger_mod.append_entry(ledger_path, entry)

    report = checkpoint.verify_checkpoint(ledger_path, cp)
    assert not report.ok
    assert any(p.code == "chain_broken" for p in report.all_problems)


def test_checkpoint_structure_is_validated(tmp_path):
    ledger_path = build_ledger(tmp_path)
    report = checkpoint.verify_checkpoint(ledger_path, {"kind": "wrong"})
    assert not report.ok
    assert any(p.code == "checkpoint_invalid" for p in report.problems)
    assert report.input_error is True


# --- HMAC signing ----------------------------------------------------------


def test_hmac_roundtrip_with_key_file(tmp_path):
    ledger_path = build_ledger(tmp_path)
    key_file = write_key(tmp_path / "checkpoint.key")
    cp = checkpoint.create_checkpoint(ledger_path, key_file=key_file)
    assert cp["signature"]["alg"] == "hmac-sha256"
    assert cp["signature"]["key_id"] == checkpoint.key_id(key_file.read_bytes())

    report = checkpoint.verify_checkpoint(ledger_path, cp, key_file=key_file)
    assert report.ok, report.messages
    assert not any(p.code == "checkpoint_unsigned" for p in report.problems)


def test_hmac_wrong_key_fails(tmp_path):
    ledger_path = build_ledger(tmp_path)
    cp = checkpoint.create_checkpoint(ledger_path, key_file=write_key(tmp_path / "right.key"))
    report = checkpoint.verify_checkpoint(ledger_path, cp, key_file=write_key(tmp_path / "wrong.key", b"wrong"))
    assert not report.ok
    assert any(p.code == "signature_invalid" for p in report.problems)


def test_hmac_detects_tampered_checkpoint_body(tmp_path):
    ledger_path = build_ledger(tmp_path)
    key_file = write_key(tmp_path / "checkpoint.key")
    cp = checkpoint.create_checkpoint(ledger_path, key_file=key_file)
    cp["created_at"] = "2020-01-01T00:00:00Z"

    report = checkpoint.verify_checkpoint(ledger_path, cp, key_file=key_file)
    assert not report.ok
    assert any(p.code == "signature_invalid" for p in report.problems)


def test_hmac_key_from_environment(tmp_path, monkeypatch):
    ledger_path = build_ledger(tmp_path)
    monkeypatch.setenv(checkpoint.DEFAULT_KEY_ENV, "env-secret-value")
    cp = checkpoint.create_checkpoint(ledger_path)
    assert cp["signature"]["alg"] == "hmac-sha256"

    report = checkpoint.verify_checkpoint(ledger_path, cp)
    assert report.ok, report.messages


def test_key_material_is_never_written_or_logged(tmp_path):
    ledger_path = build_ledger(tmp_path)
    secret = b"never-print-this-value"
    key_file = write_key(tmp_path / "checkpoint.key", secret)
    out = tmp_path / "anchor.json"
    checkpoint.write_checkpoint(ledger_path, out, key_file=key_file)
    text = out.read_text(encoding="utf-8")
    assert secret.decode() not in text
    assert checkpoint.key_id(secret) in text  # public identifier is fine

    report = checkpoint.verify_checkpoint(ledger_path, checkpoint.load_checkpoint(out), key_file=key_file)
    assert report.ok
    assert all(secret.decode() not in p.message for p in report.problems)


@pytest.mark.skipif(not POSIX, reason="POSIX permission bits")
def test_key_file_permissions_are_enforced(tmp_path):
    ledger_path = build_ledger(tmp_path)
    loose = write_key(tmp_path / "loose.key", mode=0o644)
    with pytest.raises(checkpoint.CheckpointError, match="chmod 600"):
        checkpoint.create_checkpoint(ledger_path, key_file=loose)

    cp = checkpoint.create_checkpoint(ledger_path, key_file=write_key(tmp_path / "good.key"))
    report = checkpoint.verify_checkpoint(ledger_path, cp, key_file=loose)
    assert not report.ok
    assert any(p.code == "signature_key_error" for p in report.problems)
    assert report.input_error is True


def test_hmac_signing_requires_a_key(tmp_path):
    ledger_path = build_ledger(tmp_path)
    with pytest.raises(checkpoint.CheckpointError, match="needs a key"):
        checkpoint.create_checkpoint(ledger_path, sign="hmac", key_env=None)


# --- SSH and OpenSSL shell-out (mocked) -----------------------------------

FAKE_SSH = "/usr/bin/ssh-keygen"
FAKE_OPENSSL = "/usr/bin/openssl"


def _fake_tools(monkeypatch, ssh=FAKE_SSH, openssl=FAKE_OPENSSL):
    def which(name):
        return {"ssh-keygen": ssh, "openssl": openssl}.get(name)

    monkeypatch.setattr(checkpoint.shutil, "which", which)


def test_ssh_sign_and_verify_shell_out_uses_argv_not_shell(tmp_path, monkeypatch):
    ledger_path = build_ledger(tmp_path)
    key = tmp_path / "id_ed25519"
    key.write_text("PRIVATE", encoding="utf-8")
    allowed = tmp_path / "allowed_signers"
    allowed.write_text("auditor ssh-ed25519 AAAA\n", encoding="utf-8")
    calls = []

    def fake_run(argv, *, input_bytes=None, timeout=30):
        calls.append(list(argv))
        assert isinstance(argv, list)
        if "sign" in argv:
            Path(argv[-1] + ".sig").write_text("FAKE-SSH-SIGNATURE", encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    _fake_tools(monkeypatch)
    monkeypatch.setattr(checkpoint, "_run", fake_run)

    cp = checkpoint.create_checkpoint(ledger_path, sign="ssh", ssh_key=key, ssh_identity="auditor")
    assert cp["signature"]["alg"] == "ssh"
    assert cp["signature"]["identity"] == "auditor"
    report = checkpoint.verify_checkpoint(ledger_path, cp, allowed_signers=allowed, ssh_identity="auditor")
    assert report.ok, report.messages
    assert calls and all(isinstance(c, list) for c in calls)
    assert any("-Y" in c and "sign" in c for c in calls)
    assert any("-Y" in c and "verify" in c for c in calls)
    assert str(key) in calls[0]


def test_ssh_requested_without_tool_fails_clearly_at_creation(tmp_path, monkeypatch):
    ledger_path = build_ledger(tmp_path)
    _fake_tools(monkeypatch, ssh=None)
    with pytest.raises(checkpoint.CheckpointError, match="ssh-keygen not found"):
        checkpoint.create_checkpoint(ledger_path, sign="ssh", ssh_key=tmp_path / "missing")


def test_ssh_verify_skips_cleanly_when_tool_absent(tmp_path, monkeypatch):
    ledger_path = build_ledger(tmp_path)
    cp = checkpoint.create_checkpoint(ledger_path)
    cp["signature"] = {"alg": "ssh", "namespace": "n", "identity": "i", "value": "sig"}
    _fake_tools(monkeypatch, ssh=None)
    report = checkpoint.verify_checkpoint(ledger_path, cp, allowed_signers=tmp_path / "any")
    assert report.ok
    assert any(p.code == "signing_tool_missing" and p.severity == ledger_mod.WARNING for p in report.problems)


def test_ssh_verify_requires_allowed_signers(tmp_path, monkeypatch):
    ledger_path = build_ledger(tmp_path)
    cp = checkpoint.create_checkpoint(ledger_path)
    cp["signature"] = {"alg": "ssh", "namespace": "n", "identity": "i", "value": "sig"}
    _fake_tools(monkeypatch)
    report = checkpoint.verify_checkpoint(ledger_path, cp)
    assert not report.ok
    assert any(p.code == "signature_verify_input_missing" for p in report.problems)


def test_openssl_sign_and_verify_shell_out(tmp_path, monkeypatch):
    ledger_path = build_ledger(tmp_path)
    key = tmp_path / "private.pem"
    key.write_text("PRIVATE", encoding="utf-8")
    pub = tmp_path / "public.pem"
    pub.write_text("PUBLIC", encoding="utf-8")
    calls = []

    def fake_run(argv, *, input_bytes=None, timeout=30):
        calls.append(list(argv))
        if "-out" in argv:
            Path(argv[argv.index("-out") + 1]).write_bytes(b"FAKE-OSSL-SIGNATURE")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    _fake_tools(monkeypatch)
    monkeypatch.setattr(checkpoint, "_run", fake_run)

    cp = checkpoint.create_checkpoint(ledger_path, sign="openssl", openssl_key=key)
    assert cp["signature"]["alg"] == "openssl-sha256"
    report = checkpoint.verify_checkpoint(ledger_path, cp, openssl_pubkey=pub)
    assert report.ok, report.messages
    assert any("-sign" in c for c in calls)
    assert any("-verify" in c for c in calls)


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="ssh-keygen not installed")
def test_ssh_real_sign_verify_roundtrip(tmp_path):
    ledger_path = build_ledger(tmp_path)
    key = tmp_path / "id_ed25519"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "auditor", "-f", str(key)],
        check=True,
        capture_output=True,
    )
    allowed = tmp_path / "allowed_signers"
    allowed.write_text(f"auditor {key.with_suffix('.pub').read_text().strip()}\n", encoding="utf-8")

    cp = checkpoint.create_checkpoint(ledger_path, sign="ssh", ssh_key=key, ssh_identity="auditor")
    report = checkpoint.verify_checkpoint(ledger_path, cp, allowed_signers=allowed, ssh_identity="auditor")
    assert report.ok, report.messages

    cp["created_at"] = "2020-01-01T00:00:00Z"
    tampered = checkpoint.verify_checkpoint(ledger_path, cp, allowed_signers=allowed, ssh_identity="auditor")
    assert not tampered.ok
    assert any(p.code == "signature_invalid" for p in tampered.problems)


# --- collector CLI wiring --------------------------------------------------


def test_collector_cli_writes_and_verifies_checkpoint(tmp_path):
    from practice_evidence import cli

    ledger_path = build_ledger(tmp_path)
    out = tmp_path / "anchor.json"
    assert cli.main(["--ledger", str(ledger_path), "--checkpoint", str(out), "--quiet"]) == 0
    assert out.is_file()

    assert cli.main(["--ledger", str(ledger_path), "--verify-checkpoint", str(out)]) == 0

    lines = ledger_path.read_text().splitlines()
    ledger_path.write_text("\n".join(lines[:-1]) + "\n")
    assert cli.main(["--ledger", str(ledger_path), "--verify-checkpoint", str(out)]) == 1


def test_collector_cli_returns_input_error_for_bad_key(tmp_path, capsys):
    from practice_evidence import cli

    ledger_path = build_ledger(tmp_path)
    loose = write_key(tmp_path / "loose.key", mode=0o644)
    code = cli.main(
        [
            "--ledger",
            str(ledger_path),
            "--checkpoint",
            str(tmp_path / "anchor.json"),
            "--sign",
            "hmac",
            "--key-file",
            str(loose),
            "--quiet",
        ]
    )
    assert code == 2
    err = capsys.readouterr().err
    assert "chmod 600" in err
    assert "correct horse battery staple" not in err


def test_collector_cli_missing_checkpoint_is_input_error(tmp_path):
    from practice_evidence import cli

    ledger_path = build_ledger(tmp_path)
    assert cli.main(["--ledger", str(ledger_path), "--verify-checkpoint", str(tmp_path / "nope.json")]) == 2


# --- property-style mutation test -----------------------------------------


def _mutate_edit_value(lines):
    idx = random.randrange(len(lines))
    entry = json.loads(lines[idx])
    entry["findings"] = {"high": 99}
    lines[idx] = json.dumps(entry)


def _mutate_delete(lines):
    del lines[random.randrange(len(lines))]


def _mutate_reorder(lines):
    idx = random.randrange(len(lines) - 1)
    lines[idx], lines[idx + 1] = lines[idx + 1], lines[idx]


def _mutate_insert(lines):
    idx = random.randrange(len(lines))
    lines.insert(random.randrange(len(lines) + 1), lines[idx])


def _mutate_whitespace(lines):
    idx = random.randrange(len(lines))
    lines[idx] = lines[idx].replace(":", ": ", 1)


def _mutate_blank_line(lines):
    lines.insert(random.randrange(len(lines) + 1), "")


LEDGER_MUTATORS = [
    ("edit_value", _mutate_edit_value),
    ("delete", _mutate_delete),
    ("reorder", _mutate_reorder),
    ("insert", _mutate_insert),
    ("whitespace", _mutate_whitespace),
    ("blank_line", _mutate_blank_line),
]


def test_every_random_ledger_mutation_is_detected(tmp_path):
    random.seed(20261112)
    ledger_path = build_ledger(tmp_path, entries=5)
    cp = checkpoint.create_checkpoint(ledger_path)
    base_lines = ledger_path.read_text().splitlines()
    base_snapshots = {p.name: p.read_bytes() for p in tmp_path.glob("s*.json")}

    for trial in range(36):
        name, mutate = LEDGER_MUTATORS[trial % len(LEDGER_MUTATORS)]
        for snap_name, content in base_snapshots.items():
            (tmp_path / snap_name).write_bytes(content)
        lines = list(base_lines)
        mutate(lines)
        ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        chain = verify_ledger_report(ledger_path)
        anchored = checkpoint.verify_checkpoint(ledger_path, cp)
        detected = (not chain.ok) or (not anchored.ok) or (not anchored.exact_match)
        assert detected, f"{name} mutation went undetected on trial {trial}"
        if name in {"edit_value", "delete", "reorder", "insert"}:
            assert not chain.ok or not anchored.ok, f"{name} should break the chain or the anchor"

    for snap_name, content in base_snapshots.items():
        (tmp_path / snap_name).write_bytes(content)


def test_every_random_snapshot_mutation_is_detected(tmp_path):
    random.seed(20261113)
    ledger_path = build_ledger(tmp_path, entries=4)
    cp = checkpoint.create_checkpoint(ledger_path)
    base_snapshots = {p.name: p.read_bytes() for p in tmp_path.glob("s*.json")}

    for trial in range(16):
        for snap_name, content in base_snapshots.items():
            (tmp_path / snap_name).write_bytes(content)
        victim = random.choice(sorted(base_snapshots))
        data = bytearray(base_snapshots[victim])
        pos = random.randrange(len(data))
        data[pos] = (data[pos] + 1) % 256
        (tmp_path / victim).write_bytes(bytes(data))

        chain = verify_ledger_report(ledger_path)
        anchored = checkpoint.verify_checkpoint(ledger_path, cp)
        assert not chain.ok, f"snapshot mutation went undetected on trial {trial}"
        assert not anchored.ok


def test_checkpoint_detects_truncated_final_entry(tmp_path):
    ledger_path = build_ledger(tmp_path)
    cp = checkpoint.create_checkpoint(ledger_path)
    text = ledger_path.read_text(encoding="utf-8")
    ledger_path.write_text(text[:-15], encoding="utf-8")

    chain = verify_ledger_report(ledger_path)
    assert chain.ok  # an incomplete tail is a warning, not a chain failure
    assert chain.trailing_partial is True

    anchored = checkpoint.verify_checkpoint(ledger_path, cp)
    assert not anchored.ok
    assert any(p.code == "checkpoint_truncated" for p in anchored.problems)


def test_signature_shell_outs_treat_hostile_filenames_as_arguments(tmp_path, monkeypatch):
    ledger_path = build_ledger(tmp_path)
    key = tmp_path / "id; touch pwned $(whoami)"
    key.write_text("PRIVATE", encoding="utf-8")
    calls = []

    def fake_run(argv, *, input_bytes=None, timeout=30):
        calls.append(list(argv))
        if "sign" in argv:
            Path(argv[-1] + ".sig").write_text("FAKE-SIG", encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    _fake_tools(monkeypatch)
    monkeypatch.setattr(checkpoint, "_run", fake_run)
    checkpoint.create_checkpoint(ledger_path, sign="ssh", ssh_key=key)

    assert str(key) in calls[0]
    assert all(isinstance(part, str) for part in calls[0])
    assert not (tmp_path / "pwned").exists()


def test_sign_none_does_not_read_or_require_a_key(tmp_path):
    ledger_path = build_ledger(tmp_path)
    loose = write_key(tmp_path / "unused.key", mode=0o644)
    cp = checkpoint.create_checkpoint(ledger_path, sign="none", key_file=loose)
    assert "signature" not in cp


def test_require_exact_rejects_an_append(tmp_path):
    ledger_path = build_ledger(tmp_path)
    cp = checkpoint.create_checkpoint(ledger_path)
    build_ledger(tmp_path, entries=1, prefix="later", start=4)

    relaxed = checkpoint.verify_checkpoint(ledger_path, cp)
    assert relaxed.ok and relaxed.exact_match is False

    strict = checkpoint.verify_checkpoint(ledger_path, cp, require_exact=True)
    assert not strict.ok
    assert any(p.code == "checkpoint_bytes_changed" for p in strict.problems)
