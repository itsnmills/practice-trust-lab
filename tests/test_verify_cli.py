import ast
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from practice_evidence import checkpoint
from practice_evidence import ledger as ledger_mod

ROOT = Path(__file__).resolve().parent.parent
VERIFIER = ROOT / "evidence" / "verify_evidence.py"


def build_ledger(tmp_path, entries=3, base_dir=None):
    base = base_dir or tmp_path
    ledger_path = base / "ledger.jsonl"
    for n in range(1, entries + 1):
        j = base / f"s{n}.json"
        j.write_text(json.dumps({"n": n}), encoding="utf-8")
        m = base / f"s{n}.md"
        m.write_text("md", encoding="utf-8")
        ledger_mod.append_chained(
            ledger_path,
            {"collected_at": f"2026-01-{n:02d}T00:00:00Z", "finding_counts": {"high": n}},
            j,
            m,
            base_dir=base,
        )
    return ledger_path


def run_verifier(*args, env=None):
    full_env = os.environ.copy()
    full_env.pop("VELARI_CHECKPOINT_KEY", None)
    if env:
        full_env.update(env)
    return subprocess.run(
        [sys.executable, "-I", str(VERIFIER), *[str(a) for a in args]],
        capture_output=True,
        text=True,
        env=full_env,
        timeout=60,
    )


def sign_key(tmp_path, value=b"auditor-hmac-key", name="checkpoint.key"):
    path = tmp_path / name
    path.write_bytes(value)
    if os.name == "posix":
        os.chmod(path, 0o600)
    return path


# --- help and usage --------------------------------------------------------


def test_help_runs_and_documents_exit_codes():
    result = run_verifier("--help")
    assert result.returncode == 0
    assert "usage:" in result.stdout
    assert "exit codes" in result.stdout.lower()


def test_no_arguments_is_usage_error():
    result = run_verifier()
    assert result.returncode == 2
    assert "usage:" in result.stderr


def test_extra_argument_is_usage_error(tmp_path):
    ledger_path = build_ledger(tmp_path)
    result = run_verifier(ledger_path, "surprise")
    assert result.returncode == 2


def test_missing_ledger_is_input_error(tmp_path):
    result = run_verifier(tmp_path / "absent.jsonl")
    assert result.returncode == 2
    assert "not found" in result.stdout + result.stderr


# --- ledger and snapshots --------------------------------------------------


def test_clean_ledger_verifies(tmp_path):
    ledger_path = build_ledger(tmp_path)
    result = run_verifier(ledger_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ok: 3 chained entries checked" in result.stdout


def test_modified_snapshot_fails(tmp_path):
    ledger_path = build_ledger(tmp_path)
    (tmp_path / "s2.json").write_text('{"n": 999}', encoding="utf-8")
    result = run_verifier(ledger_path)
    assert result.returncode == 1
    assert "FAIL" in result.stdout
    assert "snapshot modified" in result.stdout


def test_deleted_entry_fails(tmp_path):
    ledger_path = build_ledger(tmp_path)
    lines = ledger_path.read_text().splitlines()
    ledger_path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    result = run_verifier(ledger_path)
    assert result.returncode == 1
    assert "chain broken" in result.stdout


def test_missing_snapshot_is_a_warning(tmp_path):
    ledger_path = build_ledger(tmp_path)
    (tmp_path / "s2.json").unlink()
    result = run_verifier(ledger_path)
    assert result.returncode == 0
    assert "warn:" in result.stdout and "snapshot file missing" in result.stdout


def test_base_dir_overrides_snapshot_resolution(tmp_path):
    state = tmp_path / "state"
    nested = tmp_path / "nested"
    state.mkdir()
    nested.mkdir()
    ledger_path = build_ledger(state)
    ledger_path.rename(nested / "ledger.jsonl")
    (state / "s2.json").write_text('{"n": 999}', encoding="utf-8")

    without = run_verifier(nested / "ledger.jsonl")
    assert without.returncode == 0  # snapshots appear missing, which is a warning

    with_base = run_verifier(nested / "ledger.jsonl", "--base-dir", state)
    assert with_base.returncode == 1
    assert "snapshot modified" in with_base.stdout


# --- checkpoints -----------------------------------------------------------


def test_checkpoint_verifies(tmp_path):
    ledger_path = build_ledger(tmp_path)
    cp = checkpoint.create_checkpoint(ledger_path)
    cp_path = tmp_path / "anchor.json"
    cp_path.write_text(json.dumps(cp), encoding="utf-8")

    result = run_verifier(ledger_path, "--checkpoint", cp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "checkpoint: 3 entries" in result.stdout


def test_checkpoint_detects_truncation(tmp_path):
    ledger_path = build_ledger(tmp_path)
    cp_path = tmp_path / "anchor.json"
    cp_path.write_text(json.dumps(checkpoint.create_checkpoint(ledger_path)), encoding="utf-8")
    lines = ledger_path.read_text().splitlines()
    ledger_path.write_text("\n".join(lines[:-1]) + "\n")

    result = run_verifier(ledger_path, "--checkpoint", cp_path)
    assert result.returncode == 1
    assert "ledger truncated" in result.stdout


def test_checkpoint_detects_rebuilt_chain(tmp_path):
    ledger_path = build_ledger(tmp_path)
    cp_path = tmp_path / "anchor.json"
    cp_path.write_text(json.dumps(checkpoint.create_checkpoint(ledger_path)), encoding="utf-8")
    ledger_path.unlink()
    for m in range(1, 4):
        (tmp_path / f"r{m}.json").write_text(json.dumps({"n": m + 100}), encoding="utf-8")
        (tmp_path / f"r{m}.md").write_text("md", encoding="utf-8")
        ledger_mod.append_chained(
            ledger_path,
            {"collected_at": f"2026-03-{m:02d}T00:00:00Z", "finding_counts": {"high": m}},
            tmp_path / f"r{m}.json",
            tmp_path / f"r{m}.md",
            base_dir=tmp_path,
        )

    result = run_verifier(ledger_path, "--checkpoint", cp_path)
    assert result.returncode == 1
    assert "history rewritten" in result.stdout


def test_missing_checkpoint_is_input_error(tmp_path):
    ledger_path = build_ledger(tmp_path)
    result = run_verifier(ledger_path, "--checkpoint", tmp_path / "absent.json")
    assert result.returncode == 2
    assert "checkpoint not found" in result.stdout


def test_malformed_checkpoint_is_input_error(tmp_path):
    ledger_path = build_ledger(tmp_path)
    cp_path = tmp_path / "bad.json"
    cp_path.write_text("{not json", encoding="utf-8")
    result = run_verifier(ledger_path, "--checkpoint", cp_path)
    assert result.returncode == 2


def test_structurally_invalid_checkpoint_is_input_error(tmp_path):
    ledger_path = build_ledger(tmp_path)
    cp_path = tmp_path / "bad.json"
    cp_path.write_text(json.dumps({"kind": "wrong"}), encoding="utf-8")
    result = run_verifier(ledger_path, "--checkpoint", cp_path)
    assert result.returncode == 2
    assert "checkpoint" in result.stdout.lower()


# --- checkpoint signatures -------------------------------------------------


def test_hmac_signed_checkpoint_with_key_file(tmp_path):
    ledger_path = build_ledger(tmp_path)
    key = sign_key(tmp_path)
    cp = checkpoint.create_checkpoint(ledger_path, key_file=key)
    cp_path = tmp_path / "anchor.json"
    cp_path.write_text(json.dumps(cp), encoding="utf-8")

    ok = run_verifier(ledger_path, "--checkpoint", cp_path, "--key-file", key)
    assert ok.returncode == 0, ok.stdout + ok.stderr

    wrong_path = sign_key(tmp_path, b"different-key", name="wrong.key")
    bad = run_verifier(ledger_path, "--checkpoint", cp_path, "--key-file", wrong_path)
    assert bad.returncode == 1
    assert "signature does not match" in bad.stdout


def test_signed_checkpoint_without_key_is_input_error(tmp_path):
    ledger_path = build_ledger(tmp_path)
    key = sign_key(tmp_path)
    cp_path = tmp_path / "anchor.json"
    cp_path.write_text(json.dumps(checkpoint.create_checkpoint(ledger_path, key_file=key)), encoding="utf-8")
    result = run_verifier(ledger_path, "--checkpoint", cp_path)
    assert result.returncode == 2
    assert "HMAC-signed" in result.stdout


def test_hmac_key_from_environment(tmp_path):
    ledger_path = build_ledger(tmp_path)
    cp_path = tmp_path / "anchor.json"
    cp_path.write_text(json.dumps(checkpoint.create_checkpoint(ledger_path, key=b"env-hmac-key")), encoding="utf-8")
    result = run_verifier(ledger_path, "--checkpoint", cp_path, env={"VELARI_CHECKPOINT_KEY": "env-hmac-key"})
    assert result.returncode == 0, result.stdout + result.stderr


def test_tampered_checkpoint_body_fails(tmp_path):
    ledger_path = build_ledger(tmp_path)
    key = sign_key(tmp_path)
    cp = checkpoint.create_checkpoint(ledger_path, key_file=key)
    cp["created_at"] = "2020-01-01T00:00:00Z"
    cp_path = tmp_path / "anchor.json"
    cp_path.write_text(json.dumps(cp), encoding="utf-8")
    result = run_verifier(ledger_path, "--checkpoint", cp_path, "--key-file", key)
    assert result.returncode == 1
    assert "signature" in result.stdout.lower()


# --- JSON output -----------------------------------------------------------


def test_json_output_is_machine_readable(tmp_path):
    ledger_path = build_ledger(tmp_path)
    result = run_verifier(ledger_path, "--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["chained"] == 3
    assert payload["exit_code"] == 0
    assert isinstance(payload["problems"], list)
    assert payload["head_entry_hash"]


def test_json_output_reports_failure(tmp_path):
    ledger_path = build_ledger(tmp_path)
    lines = ledger_path.read_text().splitlines()
    ledger_path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    result = run_verifier(ledger_path, "--json")
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert any(p["code"] == "chain_broken" for p in payload["problems"])


# --- independence ----------------------------------------------------------


def test_verifier_does_not_import_the_collector_package():
    source = VERIFIER.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
    assert not any(name == "practice_evidence" or name.startswith("practice_evidence.") for name in imported)


@pytest.mark.parametrize("module", ["argparse", "hashlib", "hmac", "json", "subprocess"])
def test_verifier_uses_stdlib_modules(module):
    tree = ast.parse(VERIFIER.read_text(encoding="utf-8"))
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
    assert module in names


def test_path_traversal_in_ledger_fails(tmp_path):
    ledger_path = build_ledger(tmp_path)
    entry = json.loads(ledger_path.read_text().splitlines()[0])
    entry["json"] = "../../etc/hostname"
    entry["entry_hash"] = ledger_mod.entry_digest(entry)
    lines = ledger_path.read_text().splitlines()
    lines[0] = json.dumps(entry)
    ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = run_verifier(ledger_path)
    assert result.returncode == 1
    assert "escapes the evidence root" in result.stdout


def test_require_exact_rejects_appended_ledger(tmp_path):
    ledger_path = build_ledger(tmp_path)
    cp_path = tmp_path / "anchor.json"
    cp_path.write_text(json.dumps(checkpoint.create_checkpoint(ledger_path)), encoding="utf-8")

    extra = tmp_path / "extra.json"
    extra.write_text("{}", encoding="utf-8")
    extra_md = tmp_path / "extra.md"
    extra_md.write_text("md", encoding="utf-8")
    ledger_mod.append_chained(
        ledger_path,
        {"collected_at": "2026-02-01T00:00:00Z", "finding_counts": {"high": 1}},
        extra,
        extra_md,
        base_dir=tmp_path,
    )

    relaxed = run_verifier(ledger_path, "--checkpoint", cp_path)
    assert relaxed.returncode == 0
    assert "file bytes changed" in relaxed.stdout

    strict = run_verifier(ledger_path, "--checkpoint", cp_path, "--require-exact")
    assert strict.returncode == 1
    assert "--require-exact" in strict.stdout


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_loose_key_permissions_fail_verification(tmp_path):
    ledger_path = build_ledger(tmp_path)
    cp_path = tmp_path / "anchor.json"
    cp_path.write_text(json.dumps(checkpoint.create_checkpoint(ledger_path, key=b"loose-secret")), encoding="utf-8")
    loose = tmp_path / "loose.key"
    loose.write_bytes(b"loose-secret")
    os.chmod(loose, 0o644)
    result = run_verifier(ledger_path, "--checkpoint", cp_path, "--key-file", loose)
    assert result.returncode == 2
    assert "chmod 600" in result.stdout
    assert "loose-secret" not in result.stdout + result.stderr
