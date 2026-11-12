#!/usr/bin/env python3
"""verify_evidence.py - standalone, stdlib-only verifier for a Velari evidence set.

An auditor can copy this one file, a ledger, its snapshots, and an optional
checkpoint to any machine with Python 3.10+ and check them without installing
the collector package or any third-party dependency.

What it checks
  * every ledger line is valid JSON and every ``entry_hash`` recomputes;
  * every ``prev`` link matches the preceding entry (no edit/delete/reorder/insert);
  * every chained snapshot file still has the SHA-256 recorded at collection time;
  * with ``--checkpoint``: the ledger still has the recorded number of entries,
    the checkpointed entry hash is still at that position, any later entries
    chain from it, and the checkpoint signature verifies when a key is supplied.

Exit codes
  0  everything verified
  1  an integrity failure (chain, snapshot, checkpoint anchor, or signature)
  2  usage or input problem (missing/unreadable ledger, checkpoint, or key)

Checkpoints are opt-in. An unsigned checkpoint still proves that *some* file
with this content existed when it was created, but not who created it. HMAC
signatures are symmetric: only key holders can verify them. Use SSH or OpenSSL
signatures when a third party must verify authorship.

Usage
  python3 verify_evidence.py evidence/ledger.jsonl
  python3 verify_evidence.py evidence/ledger.jsonl --checkpoint anchor.json
  python3 verify_evidence.py evidence/ledger.jsonl --checkpoint anchor.json \\
      --key-file /secure/checkpoint.key
  python3 verify_evidence.py evidence/ledger.jsonl --checkpoint anchor.json \\
      --ssh-allowed-signers auditor_allowed_signers
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

GENESIS = "0" * 64
CHECKPOINT_KIND = "velari.evidence-checkpoint/1"
DEFAULT_KEY_ENV = "VELARI_CHECKPOINT_KEY"
DEFAULT_SSH_IDENTITY = "velari-evidence"
DEFAULT_SSH_NAMESPACE = "velari-evidence-checkpoint"
ERROR = "error"
WARNING = "warning"

INPUT_ERROR_CODES = frozenset(
    {
        "checkpoint_invalid",
        "checkpoint_unreadable",
        "signature_key_missing",
        "signature_key_error",
        "signature_verify_input_missing",
        "signature_unsupported",
    }
)


class VerifyError(Exception):
    """A verification step could not run; ``input_error`` picks exit code 2."""

    def __init__(self, message: str, *, input_error: bool = False) -> None:
        super().__init__(message)
        self.input_error = input_error


def problem(severity: str, code: str, message: str, line: int | None = None) -> dict[str, Any]:
    return {"severity": severity, "code": code, "line": line, "message": message}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def entry_digest(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    return sha256_bytes(json.dumps(body, sort_keys=True, separators=(",", ":")).encode())


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def checkpoint_body(checkpoint: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in checkpoint.items() if k != "signature"}


def parse_ledger(path: Path) -> tuple[list[tuple[int, dict[str, Any]]], int, list[dict[str, Any]]]:
    """Return (chained records, legacy count, problems)."""
    problems: list[dict[str, Any]] = []
    records: list[tuple[int, dict[str, Any]]] = []
    legacy = 0
    raw = path.read_bytes()
    text = raw.decode("utf-8", "replace")
    lines = text.splitlines()
    ends_with_newline = raw == b"" or raw.endswith(b"\n")
    last_nonempty = 0
    for idx, line in enumerate(lines, 1):
        if line.strip():
            last_nonempty = idx
    for n, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            if n == last_nonempty and not ends_with_newline:
                problems.append(
                    problem(
                        WARNING,
                        "truncated_tail",
                        f"line {n}: incomplete trailing entry ignored (partial write; not counted in the chain)",
                        n,
                    )
                )
            else:
                problems.append(problem(ERROR, "invalid_json", f"line {n}: not valid JSON", n))
            continue
        if not isinstance(entry, dict) or "entry_hash" not in entry:
            legacy += 1
            continue
        records.append((n, entry))
    return records, legacy, problems


def verify_ledger(path: Path, base_dir: Path) -> dict[str, Any]:
    records, legacy, problems = parse_ledger(path)
    prev = GENESIS
    head_hash = GENESIS
    head_ts: str | None = None
    head_line: int | None = None
    for n, entry in records:
        entry_hash = entry.get("entry_hash")
        if not isinstance(entry_hash, str):
            problems.append(problem(ERROR, "bad_entry_hash", f"line {n}: entry_hash is not a string", n))
            continue
        version = entry.get("v")
        if version is not None and (not isinstance(version, int) or isinstance(version, bool) or version < 1):
            problems.append(problem(ERROR, "bad_chain_version", f"line {n}: invalid chain version {version!r}", n))
        elif isinstance(version, int) and version > 1:
            problems.append(
                problem(
                    ERROR,
                    "unsupported_chain_version",
                    f"line {n}: unsupported chain version {version} (this verifier understands up to 1)",
                    n,
                )
            )
        if entry.get("prev") != prev:
            problems.append(
                problem(ERROR, "chain_broken", f"line {n}: chain broken (prev does not match preceding entry)", n)
            )
        if entry_digest(entry) != entry_hash:
            problems.append(
                problem(ERROR, "entry_digest_mismatch", f"line {n}: entry contents do not match entry_hash", n)
            )
        json_rel = entry.get("json")
        snap: Path | None = None
        if not isinstance(json_rel, str) or not json_rel:
            problems.append(problem(ERROR, "snapshot_path_invalid", f"line {n}: entry has no valid snapshot path", n))
        else:
            rel = Path(json_rel)
            if rel.is_absolute() or ".." in rel.parts:
                problems.append(
                    problem(
                        ERROR,
                        "snapshot_path_invalid",
                        f"line {n}: snapshot path escapes the evidence root: {json_rel}",
                        n,
                    )
                )
            else:
                candidate = base_dir / rel
                try:
                    inside = candidate.resolve().is_relative_to(base_dir.resolve())
                except OSError:
                    inside = False
                if not inside:
                    problems.append(
                        problem(
                            ERROR,
                            "snapshot_path_invalid",
                            f"line {n}: snapshot path resolves outside the evidence root: {json_rel}",
                            n,
                        )
                    )
                else:
                    snap = candidate
        if snap is not None:
            if not snap.is_file():
                problems.append(
                    problem(
                        WARNING,
                        "snapshot_missing",
                        f"line {n}: snapshot file missing (chain still checked): {json_rel}",
                        n,
                    )
                )
            else:
                try:
                    actual = sha256_bytes(snap.read_bytes())
                except OSError as exc:
                    problems.append(
                        problem(
                            ERROR,
                            "snapshot_unreadable",
                            f"line {n}: snapshot cannot be read: {json_rel} ({exc.strerror or exc})",
                            n,
                        )
                    )
                else:
                    if actual != entry.get("snapshot_sha256"):
                        problems.append(
                            problem(
                                ERROR,
                                "snapshot_modified",
                                f"line {n}: snapshot modified since collection: {json_rel}",
                                n,
                            )
                        )
        prev = entry_hash
        head_hash = entry_hash
        head_line = n
        if isinstance(entry.get("ts"), str):
            head_ts = entry["ts"]

    if legacy:
        problems.append(problem(WARNING, "legacy_lines", f"{legacy} legacy un-chained line(s) skipped", None))
    return {
        "records": records,
        "legacy": legacy,
        "problems": problems,
        "chained": len(records),
        "head_entry_hash": head_hash,
        "head_ts": head_ts,
        "head_line": head_line,
    }


def _load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise VerifyError(f"{label} not found: {path}", input_error=True)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerifyError(f"{label} is not readable JSON: {path}: {exc}", input_error=True) from exc
    if not isinstance(value, dict):
        raise VerifyError(f"{label} root is not a JSON object: {path}", input_error=True)
    return value


def _load_key(key_file: Path | None, key_env: str | None) -> bytes | None:
    if key_file is not None:
        if not key_file.is_file():
            raise VerifyError(f"key file not found: {key_file}", input_error=True)
        if os.name == "posix" and stat.S_IMODE(key_file.stat().st_mode) & 0o077:
            raise VerifyError(
                f"key file {key_file} is accessible by group/other; chmod 600 it before use", input_error=True
            )
        raw = key_file.read_bytes().rstrip(b"\r\n")
        if not raw:
            raise VerifyError(f"key file is empty: {key_file}", input_error=True)
        return raw
    if key_env:
        value = os.environ.get(key_env)
        if value:
            return value.encode("utf-8")
    return None


def _run(argv: list[str], *, input_bytes: bytes | None = None, timeout: int = 30) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(argv, input=input_bytes, capture_output=True, check=False, timeout=timeout)
    except FileNotFoundError as exc:
        raise VerifyError(f"signature tool not found: {argv[0]}") from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise VerifyError(f"could not run {Path(argv[0]).name}: {exc}") from exc


def _tool(name: str) -> str | None:
    return shutil.which(name)


def verify_ssh(data: bytes, signature: dict[str, Any], allowed_signers: Path, identity: str | None) -> bool:
    tool = _tool("ssh-keygen")
    if tool is None:
        raise VerifyError("ssh-keygen not found on PATH")
    if not allowed_signers.is_file():
        raise VerifyError(f"allowed_signers file not found: {allowed_signers}", input_error=True)
    value = signature.get("value")
    if not isinstance(value, str) or not value.strip():
        raise VerifyError("checkpoint signature has no value", input_error=True)
    signer = identity or signature.get("identity") or DEFAULT_SSH_IDENTITY
    namespace = signature.get("namespace") or DEFAULT_SSH_NAMESPACE
    with tempfile.TemporaryDirectory(prefix="velari-verify-") as tmp:
        sig_path = Path(tmp) / "payload.sig"
        sig_path.write_text(value if value.endswith("\n") else value + "\n", encoding="utf-8")
        result = _run(
            [
                tool,
                "-Y",
                "verify",
                "-f",
                str(allowed_signers),
                "-I",
                str(signer),
                "-n",
                str(namespace),
                "-s",
                str(sig_path),
            ],
            input_bytes=data,
        )
    return result.returncode == 0


def verify_openssl(data: bytes, signature: dict[str, Any], public_key: Path) -> bool:
    tool = _tool("openssl")
    if tool is None:
        raise VerifyError("openssl not found on PATH")
    if not public_key.is_file():
        raise VerifyError(f"OpenSSL public key not found: {public_key}", input_error=True)
    value = signature.get("value")
    if not isinstance(value, str):
        raise VerifyError("checkpoint signature has no value", input_error=True)
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise VerifyError("checkpoint signature is not valid base64", input_error=True) from exc
    with tempfile.TemporaryDirectory(prefix="velari-verify-") as tmp:
        payload = Path(tmp) / "payload"
        payload.write_bytes(data)
        sig_path = Path(tmp) / "payload.sig"
        sig_path.write_bytes(raw)
        result = _run([tool, "dgst", "-sha256", "-verify", str(public_key), "-signature", str(sig_path), str(payload)])
    return result.returncode == 0


def _validate_checkpoint(checkpoint: dict[str, Any]) -> list[dict[str, Any]]:
    problems: list[dict[str, Any]] = []
    if checkpoint.get("kind") != CHECKPOINT_KIND:
        problems.append(
            problem(
                ERROR,
                "checkpoint_invalid",
                f"unexpected checkpoint kind {checkpoint.get('kind')!r} (expected {CHECKPOINT_KIND})",
            )
        )
    count = checkpoint.get("entry_count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        problems.append(problem(ERROR, "checkpoint_invalid", "checkpoint entry_count is not a non-negative integer"))
    head = checkpoint.get("head_entry_hash")
    if not isinstance(head, str) or len(head) != 64 or any(c not in "0123456789abcdef" for c in head):
        problems.append(problem(ERROR, "checkpoint_invalid", "checkpoint head_entry_hash is not a sha256 hex digest"))
    file_hash = checkpoint.get("ledger_sha256")
    if not isinstance(file_hash, str) or len(file_hash) != 64:
        problems.append(problem(ERROR, "checkpoint_invalid", "checkpoint ledger_sha256 is not a sha256 hex digest"))
    if not isinstance(checkpoint.get("created_at"), str):
        problems.append(problem(ERROR, "checkpoint_invalid", "checkpoint created_at is missing"))
    return problems


def _verify_signature(
    checkpoint: dict[str, Any],
    *,
    key_file: Path | None,
    key_env: str | None,
    allowed_signers: Path | None,
    ssh_identity: str | None,
    openssl_pubkey: Path | None,
) -> list[dict[str, Any]]:
    problems: list[dict[str, Any]] = []
    signature = checkpoint.get("signature")
    if signature is None:
        return [
            problem(
                WARNING,
                "checkpoint_unsigned",
                "checkpoint is not signed; contents are anchored but authenticity is not established",
            )
        ]
    if not isinstance(signature, dict):
        return [problem(ERROR, "signature_invalid", "checkpoint signature is not an object")]
    alg = signature.get("alg")
    body = canonical_bytes(checkpoint_body(checkpoint))

    if alg == "hmac-sha256":
        try:
            key = _load_key(key_file, key_env)
        except VerifyError as exc:
            problems.append(problem(ERROR, "signature_key_error", str(exc)))
            return problems
        if key is None:
            problems.append(
                problem(
                    ERROR,
                    "signature_key_missing",
                    "checkpoint is HMAC-signed but no key was provided; use --key-file or VELARI_CHECKPOINT_KEY",
                )
            )
            return problems
        expected = hmac.new(key, body, hashlib.sha256).hexdigest()
        value = signature.get("value")
        if not isinstance(value, str) or not hmac.compare_digest(expected, value):
            problems.append(problem(ERROR, "signature_invalid", "HMAC signature does not match the checkpoint"))
        return problems

    if alg == "ssh":
        if _tool("ssh-keygen") is None:
            return [
                problem(
                    WARNING,
                    "signing_tool_missing",
                    "ssh-keygen not found; SSH signature not checked (install openssh-client to verify it)",
                )
            ]
        if allowed_signers is None:
            problems.append(
                problem(
                    ERROR,
                    "signature_verify_input_missing",
                    "checkpoint is SSH-signed; provide an allowed_signers file with --ssh-allowed-signers",
                )
            )
            return problems
        try:
            valid = verify_ssh(body, signature, allowed_signers, ssh_identity)
        except VerifyError as exc:
            problems.append(problem(ERROR, "signature_verify_failed", str(exc)))
            return problems
        if not valid:
            problems.append(problem(ERROR, "signature_invalid", "SSH signature does not verify for this checkpoint"))
        return problems

    if alg == "openssl-sha256":
        if _tool("openssl") is None:
            return [
                problem(
                    WARNING,
                    "signing_tool_missing",
                    "openssl not found; OpenSSL signature not checked (install openssl to verify it)",
                )
            ]
        if openssl_pubkey is None:
            problems.append(
                problem(
                    ERROR,
                    "signature_verify_input_missing",
                    "checkpoint is OpenSSL-signed; provide a public key with --openssl-pubkey",
                )
            )
            return problems
        try:
            valid = verify_openssl(body, signature, openssl_pubkey)
        except VerifyError as exc:
            problems.append(problem(ERROR, "signature_verify_failed", str(exc)))
            return problems
        if not valid:
            problems.append(
                problem(ERROR, "signature_invalid", "OpenSSL signature does not verify for this checkpoint")
            )
        return problems

    return [problem(ERROR, "signature_unsupported", f"unsupported checkpoint signature algorithm {alg!r}")]


def verify_checkpoint(
    path: Path,
    checkpoint: dict[str, Any],
    *,
    key_file: Path | None,
    key_env: str | None,
    allowed_signers: Path | None,
    ssh_identity: str | None,
    openssl_pubkey: Path | None,
    ledger_result: dict[str, Any],
    require_exact: bool = False,
) -> dict[str, Any]:
    problems = _validate_checkpoint(checkpoint)
    records: list[tuple[int, dict[str, Any]]] = ledger_result["records"]
    count = checkpoint.get("entry_count")
    head = checkpoint.get("head_entry_hash")
    anchor_errors = False

    if not problems and isinstance(count, int) and isinstance(head, str):
        if count == 0:
            if head != GENESIS:
                problems.append(
                    problem(
                        ERROR,
                        "checkpoint_invalid",
                        "checkpoint entry_count is 0 but head_entry_hash is not the genesis hash",
                    )
                )
                anchor_errors = True
            elif records:
                problems.append(
                    problem(
                        WARNING,
                        "checkpoint_genesis_only",
                        f"checkpoint anchors an empty ledger; {len(records)} entry/entries are not covered by it",
                    )
                )
        elif len(records) < count:
            problems.append(
                problem(
                    ERROR,
                    "checkpoint_truncated",
                    f"ledger truncated: checkpoint recorded {count} chained entries, ledger has {len(records)}",
                )
            )
            anchor_errors = True
        else:
            anchored = records[count - 1][1].get("entry_hash")
            if anchored != head:
                problems.append(
                    problem(
                        ERROR,
                        "checkpoint_head_moved",
                        f"ledger history rewritten: entry {count} has hash {str(anchored)[:12]}..., "
                        f"checkpoint anchored {head[:12]}...",
                    )
                )
                anchor_errors = True
            elif len(records) > count and records[count][1].get("prev") != head:
                problems.append(
                    problem(
                        ERROR,
                        "checkpoint_chain_broken",
                        f"entry {count + 1} does not chain from the checkpointed head",
                    )
                )
                anchor_errors = True

    exact_match = False
    actual_digest: str | None = None
    if path.is_file():
        data = path.read_bytes()
        actual_digest = sha256_bytes(data)
        expected_bytes = checkpoint.get("ledger_bytes")
        exact_match = actual_digest == checkpoint.get("ledger_sha256") and (
            not isinstance(expected_bytes, int) or expected_bytes == len(data)
        )
        ledger_ok = not any(p["severity"] == ERROR for p in ledger_result["problems"])
        if not exact_match and not anchor_errors and not problems and ledger_ok:
            if require_exact:
                problems.append(
                    problem(
                        ERROR,
                        "checkpoint_bytes_changed",
                        "ledger bytes differ from the checkpoint and --require-exact is set",
                    )
                )
            else:
                problems.append(
                    problem(
                        WARNING,
                        "checkpoint_ledger_changed",
                        "ledger bytes differ from the checkpoint (appended or re-serialized); "
                        "the checkpointed head still matches",
                    )
                )

    problems.extend(
        _verify_signature(
            checkpoint,
            key_file=key_file,
            key_env=key_env,
            allowed_signers=allowed_signers,
            ssh_identity=ssh_identity,
            openssl_pubkey=openssl_pubkey,
        )
    )

    state = "exact file match" if exact_match else "file bytes changed"
    summary = f"checkpoint: {count if isinstance(count, int) else '?'} entries, head {str(head)[:12]}..., {state}"
    if actual_digest is None:
        summary = f"checkpoint: ledger missing, expected head {str(head)[:12]}..."
    return {"problems": problems, "exact_match": exact_match, "summary": summary}


def build_result(args: argparse.Namespace) -> dict[str, Any]:
    ledger_path = Path(args.ledger)
    base_dir = Path(args.base_dir) if args.base_dir else ledger_path.parent
    if not ledger_path.is_file():
        raise VerifyError(f"ledger not found: {ledger_path}", input_error=True)
    try:
        ledger_result = verify_ledger(ledger_path, base_dir)
    except OSError as exc:
        raise VerifyError(f"could not read ledger {ledger_path}: {exc}", input_error=True) from exc

    result: dict[str, Any] = {
        "ok": True,
        "exit_code": 0,
        "ledger": str(ledger_path),
        "chained": ledger_result["chained"],
        "legacy": ledger_result["legacy"],
        "head_entry_hash": ledger_result["head_entry_hash"],
        "head_ts": ledger_result["head_ts"],
        "problems": list(ledger_result["problems"]),
        "checkpoint": None,
    }

    if args.checkpoint:
        cp_path = Path(args.checkpoint)
        try:
            checkpoint = _load_json(cp_path, "checkpoint")
            cp_result = verify_checkpoint(
                ledger_path,
                checkpoint,
                key_file=Path(args.key_file) if args.key_file else None,
                key_env=args.key_env,
                allowed_signers=Path(args.ssh_allowed_signers) if args.ssh_allowed_signers else None,
                ssh_identity=args.ssh_identity,
                openssl_pubkey=Path(args.openssl_pubkey) if args.openssl_pubkey else None,
                ledger_result=ledger_result,
                require_exact=args.require_exact,
            )
        except VerifyError as exc:
            code = "checkpoint_unreadable" if exc.input_error else "checkpoint_error"
            result["problems"].append(problem(ERROR, code, str(exc)))
            result["ok"] = False
            result["exit_code"] = 2 if exc.input_error else 1
            return result
        result["problems"].extend(cp_result["problems"])
        result["checkpoint"] = {
            "entry_count": checkpoint.get("entry_count"),
            "head_entry_hash": checkpoint.get("head_entry_hash"),
            "exact_match": cp_result["exact_match"],
            "signed": bool(checkpoint.get("signature")),
        }
        result["checkpoint_summary"] = cp_result["summary"]

    if any(p["severity"] == ERROR for p in result["problems"]):
        result["ok"] = False
        codes = {p["code"] for p in result["problems"] if p["severity"] == ERROR}
        result["exit_code"] = 2 if codes and codes <= INPUT_ERROR_CODES else 1
    return result


def render_text(result: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    for p in result["problems"]:
        if p["code"] == "legacy_lines":
            continue  # summarized below
        label = "FAIL" if p["severity"] == ERROR else "warn"
        lines.append(f"{label}: {p['message']}")
    if result["legacy"]:
        lines.append(f"warn: {result['legacy']} legacy un-chained line(s) skipped")
    if result["checkpoint"]:
        lines.append(result.get("checkpoint_summary", "checkpoint: checked"))
    prefix = "ok" if result["ok"] else "FAIL"
    lines.append(f"{prefix}: {result['chained']} chained entr{'y' if result['chained'] == 1 else 'ies'} checked")
    return lines


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Verify a Velari evidence ledger, its snapshots, and an optional off-host checkpoint. Stdlib only.",
        epilog="exit codes: 0 verified; 1 integrity failure; 2 usage or input error",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("ledger", help="path to ledger.jsonl")
    ap.add_argument("--base-dir", help="directory snapshot paths are relative to (default: the ledger's directory)")
    ap.add_argument("--checkpoint", help="checkpoint JSON to verify the ledger against")
    key_group = ap.add_mutually_exclusive_group()
    key_group.add_argument("--key-file", help="HMAC key file (must be mode 0600)")
    key_group.add_argument(
        "--key-env",
        default=None,
        metavar="NAME",
        help=f"environment variable holding the HMAC key (default: {DEFAULT_KEY_ENV})",
    )
    ap.add_argument("--ssh-allowed-signers", help="allowed_signers file for an SSH-signed checkpoint")
    ap.add_argument("--ssh-identity", help="signer identity for an SSH-signed checkpoint")
    ap.add_argument("--openssl-pubkey", help="public key file for an OpenSSL-signed checkpoint")
    ap.add_argument(
        "--require-exact",
        action="store_true",
        help="fail if the ledger bytes differ from the checkpoint at all (normal appends are otherwise accepted)",
    )
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON instead of text")
    args = ap.parse_args(argv)
    if args.key_env is None:
        args.key_env = DEFAULT_KEY_ENV

    try:
        result = build_result(args)
    except VerifyError as exc:
        result = {
            "ok": False,
            "exit_code": 2 if exc.input_error else 1,
            "ledger": str(args.ledger),
            "chained": 0,
            "legacy": 0,
            "head_entry_hash": GENESIS,
            "problems": [problem(ERROR, "ledger_unreadable", str(exc))],
            "checkpoint": None,
        }
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        for line in render_text(result):
            print(line)
    return int(result["exit_code"])


if __name__ == "__main__":
    sys.exit(main())
