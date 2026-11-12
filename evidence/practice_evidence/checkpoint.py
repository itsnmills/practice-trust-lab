"""Portable checkpoints that anchor the ledger head off-host.

A checkpoint is a small JSON file recording how long the hash chain is, the
``entry_hash`` at that position, and the SHA-256 of the whole ledger file. Store
it somewhere the collector host cannot rewrite (an email, a ticket, a git tag, a
printout). Verifying the ledger against it catches truncation, rewritten
history, and a fully rebuilt chain, which the chain alone cannot.

Signing is optional:

- HMAC-SHA256 with a key from a file (mode 0600 enforced) or an environment
  variable. This is the baseline, but it is symmetric: only key holders can
  verify, and it proves *custody of the key*, not third-party authorship.
- SSH (``ssh-keygen -Y sign``/``verify``) or OpenSSL signatures, used only when
  those binaries are present on PATH. No shell is used; every argument is a
  separate list element.

This module never logs, prints, or stores key material. Checkpoints carry only a
public ``key_id`` (a SHA-256 prefix for HMAC, the key filename for asymmetric
signatures) so a verifier can select the right key.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import ledger
from .config import EVIDENCE_DIR

CHECKPOINT_KIND = "velari.evidence-checkpoint/1"
DEFAULT_KEY_ENV = "VELARI_CHECKPOINT_KEY"
DEFAULT_SSH_IDENTITY = "velari-evidence"
DEFAULT_SSH_NAMESPACE = "velari-evidence-checkpoint"
SIGN_MODES = ("auto", "none", "hmac", "ssh", "openssl")

INPUT_ERROR_CODES = frozenset(
    {
        "checkpoint_invalid",
        "checkpoint_unreadable",
        "signature_key_missing",
        "signature_key_error",
        "signature_verify_input_missing",
        "signature_unsupported",
        "signing_tool_missing",
    }
)


class CheckpointError(Exception):
    """Raised when a checkpoint cannot be created or read."""


def canonical_bytes(value: Any) -> bytes:
    """Deterministic bytes signed/verified by every backend."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def checkpoint_body(checkpoint: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in checkpoint.items() if k != "signature"}


def key_id(key: bytes) -> str:
    """Public identifier for a key. Never reveals the key itself."""
    return hashlib.sha256(key).hexdigest()[:16]


def load_key_file(path: str | Path) -> bytes:
    """Read an HMAC key file, refusing group/other-readable modes on POSIX."""
    key_path = Path(path)
    if not key_path.is_file():
        raise CheckpointError(f"key file not found or not a regular file: {key_path}")
    if os.name == "posix":
        mode = stat.S_IMODE(key_path.stat().st_mode)
        if mode & 0o077:
            raise CheckpointError(
                f"key file {key_path} is accessible by group/other (mode {mode:04o}); chmod 600 it before use"
            )
    key = key_path.read_bytes().rstrip(b"\r\n")
    if not key:
        raise CheckpointError(f"key file is empty: {key_path}")
    return key


def resolve_key(
    key: bytes | str | None = None,
    key_file: str | Path | None = None,
    key_env: str | None = DEFAULT_KEY_ENV,
) -> bytes | None:
    """Resolve HMAC key material from an explicit value, file, or environment.

    Precedence: ``key``, then ``key_file``, then ``key_env``. The key is never
    included in an exception message.
    """
    if key is not None:
        raw = key.encode("utf-8") if isinstance(key, str) else key
        return raw or None
    if key_file is not None:
        return load_key_file(key_file)
    if key_env:
        value = os.environ.get(key_env)
        if value:
            return value.encode("utf-8")
    return None


def signing_tools() -> dict[str, str | None]:
    """Absolute paths of optional signature tools, or None when absent."""
    return {"ssh-keygen": shutil.which("ssh-keygen"), "openssl": shutil.which("openssl")}


def _run(argv: list[str], *, input_bytes: bytes | None = None, timeout: int = 30) -> subprocess.CompletedProcess[bytes]:
    if not argv or not isinstance(argv[0], str):
        raise CheckpointError("internal error: signature command must be a non-empty argv list")
    try:
        return subprocess.run(argv, input=input_bytes, capture_output=True, check=False, timeout=timeout)
    except FileNotFoundError as exc:
        raise CheckpointError(f"signature tool not found: {argv[0]}") from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise CheckpointError(f"could not run {Path(argv[0]).name}: {exc}") from exc


def _stderr_text(result: subprocess.CompletedProcess[bytes]) -> str:
    return result.stderr.decode("utf-8", "replace").strip()[:300]


def _tool_or_error(name: str, purpose: str) -> str:
    tool = shutil.which(name)
    if not tool:
        raise CheckpointError(
            f"{name} not found on PATH; cannot {purpose}. Install it, or use --sign none / --sign hmac."
        )
    return tool


def sign_ssh(
    data: bytes,
    key_path: str | Path,
    *,
    namespace: str = DEFAULT_SSH_NAMESPACE,
    identity: str = DEFAULT_SSH_IDENTITY,
) -> dict[str, Any]:
    """Sign bytes with ``ssh-keygen -Y sign``. argv only, no shell."""
    tool = _tool_or_error("ssh-keygen", "create an SSH-signed checkpoint")
    key = Path(key_path)
    if not key.is_file():
        raise CheckpointError(f"SSH private key not found: {key}")
    with tempfile.TemporaryDirectory(prefix="velari-cp-") as tmp:
        payload = Path(tmp) / "payload"
        payload.write_bytes(data)
        result = _run([tool, "-Y", "sign", "-f", str(key), "-n", namespace, str(payload)])
        signature_path = Path(str(payload) + ".sig")
        if result.returncode != 0 or not signature_path.is_file():
            raise CheckpointError(f"ssh-keygen -Y sign failed: {_stderr_text(result) or 'no signature produced'}")
        signature = signature_path.read_text(encoding="utf-8").strip()
    return {"alg": "ssh", "namespace": namespace, "identity": identity, "key_id": key.name, "value": signature}


def verify_ssh(
    data: bytes,
    signature: dict[str, Any],
    allowed_signers: str | Path,
    *,
    identity: str | None = None,
    namespace: str | None = None,
) -> bool:
    """Verify an SSH signature with an ``allowed_signers`` file."""
    tool = _tool_or_error("ssh-keygen", "verify an SSH-signed checkpoint")
    allowed = Path(allowed_signers)
    if not allowed.is_file():
        raise CheckpointError(f"allowed_signers file not found: {allowed}")
    value = signature.get("value")
    if not isinstance(value, str) or not value.strip():
        raise CheckpointError("checkpoint signature has no value")
    identity = identity or signature.get("identity") or DEFAULT_SSH_IDENTITY
    namespace = namespace or signature.get("namespace") or DEFAULT_SSH_NAMESPACE
    with tempfile.TemporaryDirectory(prefix="velari-cp-") as tmp:
        payload = Path(tmp) / "payload"
        payload.write_bytes(data)
        sig_path = Path(tmp) / "payload.sig"
        sig_path.write_text(value if value.endswith("\n") else value + "\n", encoding="utf-8")
        result = _run(
            [
                tool,
                "-Y",
                "verify",
                "-f",
                str(allowed),
                "-I",
                str(identity),
                "-n",
                str(namespace),
                "-s",
                str(sig_path),
            ],
            input_bytes=data,
        )
    return result.returncode == 0


def sign_openssl(data: bytes, key_path: str | Path) -> dict[str, Any]:
    """Detached RSA/EC signature with ``openssl dgst -sha256 -sign``."""
    tool = _tool_or_error("openssl", "create an OpenSSL-signed checkpoint")
    key = Path(key_path)
    if not key.is_file():
        raise CheckpointError(f"OpenSSL private key not found: {key}")
    with tempfile.TemporaryDirectory(prefix="velari-cp-") as tmp:
        payload = Path(tmp) / "payload"
        payload.write_bytes(data)
        sig_path = Path(tmp) / "payload.sig"
        result = _run([tool, "dgst", "-sha256", "-sign", str(key), "-out", str(sig_path), str(payload)])
        if result.returncode != 0 or not sig_path.is_file():
            raise CheckpointError(f"openssl signing failed: {_stderr_text(result) or 'no signature produced'}")
        signature = base64.b64encode(sig_path.read_bytes()).decode("ascii")
    return {"alg": "openssl-sha256", "key_id": key.name, "value": signature}


def verify_openssl(data: bytes, signature: dict[str, Any], public_key: str | Path) -> bool:
    """Verify an OpenSSL detached signature against a public key file."""
    tool = _tool_or_error("openssl", "verify an OpenSSL-signed checkpoint")
    pubkey = Path(public_key)
    if not pubkey.is_file():
        raise CheckpointError(f"OpenSSL public key not found: {pubkey}")
    value = signature.get("value")
    if not isinstance(value, str):
        raise CheckpointError("checkpoint signature has no value")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise CheckpointError("checkpoint signature is not valid base64") from exc
    with tempfile.TemporaryDirectory(prefix="velari-cp-") as tmp:
        payload = Path(tmp) / "payload"
        payload.write_bytes(data)
        sig_path = Path(tmp) / "payload.sig"
        sig_path.write_bytes(raw)
        result = _run([tool, "dgst", "-sha256", "-verify", str(pubkey), "-signature", str(sig_path), str(payload)])
    return result.returncode == 0


@dataclass
class CheckpointReport:
    """Result of verifying a ledger against a checkpoint."""

    path: Path
    checkpoint: dict[str, Any]
    ledger_report: ledger.LedgerReport
    problems: list[ledger.LedgerProblem] = field(default_factory=list)
    exact_match: bool = False
    summary: str = ""

    @property
    def ok(self) -> bool:
        return self.ledger_report.ok and not any(p.severity == ledger.ERROR for p in self.problems)

    @property
    def all_problems(self) -> list[ledger.LedgerProblem]:
        """Chain, snapshot and checkpoint findings in one typed list."""
        return list(self.ledger_report.problems) + list(self.problems)

    @property
    def messages(self) -> list[str]:
        msgs = self.ledger_report.messages
        msgs.extend(p.message for p in self.problems)
        if self.summary:
            msgs.append(self.summary)
        return msgs

    @property
    def input_error(self) -> bool:
        return any(p.code in INPUT_ERROR_CODES for p in self.problems)


def _now(now: datetime | None = None) -> str:
    stamp = now or datetime.now(timezone.utc)
    return stamp.strftime("%Y-%m-%dT%H:%M:%SZ")


def default_checkpoint_path(now: datetime | None = None, base_dir: Path = EVIDENCE_DIR) -> Path:
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    return Path(base_dir) / "checkpoints" / f"checkpoint-{stamp}.json"


def create_checkpoint(
    ledger_path: str | Path,
    *,
    key: bytes | str | None = None,
    key_file: str | Path | None = None,
    key_env: str | None = DEFAULT_KEY_ENV,
    sign: str = "auto",
    ssh_key: str | Path | None = None,
    ssh_identity: str = DEFAULT_SSH_IDENTITY,
    ssh_namespace: str = DEFAULT_SSH_NAMESPACE,
    openssl_key: str | Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Create a checkpoint dict for the current ledger head.

    Refuses to checkpoint a ledger that fails chain verification: anchoring a
    broken chain would launder the break. Snapshot warnings do not block it.
    """
    path = Path(ledger_path)
    if not path.is_file():
        raise CheckpointError(f"ledger not found: {path}")
    # Hold the append lock while reading, so entry_count and ledger_sha256
    # describe one consistent state even if a collector is running.
    with ledger.ledger_lock(path, required=False):
        report = ledger.verify_ledger_report(path)
        if not report.ok:
            detail = "; ".join(p.message for p in report.errors[:3])
            raise CheckpointError(f"refusing to checkpoint a ledger that fails verification: {detail}")
        if report.chained == 0:
            raise CheckpointError("refusing to checkpoint a ledger with no chained entries")
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise CheckpointError(f"could not read ledger {path}: {exc}") from exc

    body: dict[str, Any] = {
        "kind": CHECKPOINT_KIND,
        "created_at": _now(now),
        "ledger_name": path.name,
        "entry_count": report.chained,
        "head_entry_hash": report.head_hash,
        "head_ts": report.head_ts,
        "head_line": report.head_line,
        "ledger_bytes": len(data),
        "ledger_sha256": hashlib.sha256(data).hexdigest(),
        "note": "Off-host anchor. Verify with evidence/verify_evidence.py; see docs/EVIDENCE-INTEGRITY.md.",
    }

    mode = sign
    if mode not in SIGN_MODES:
        raise CheckpointError(f"unknown signing mode {mode!r}; choose one of {', '.join(SIGN_MODES)}")
    resolved_key: bytes | None = None
    if mode in ("auto", "hmac"):
        resolved_key = resolve_key(key=key, key_file=key_file, key_env=key_env)
    if mode == "auto":
        if resolved_key is not None:
            mode = "hmac"
        elif ssh_key is not None:
            mode = "ssh"
        elif openssl_key is not None:
            mode = "openssl"
        else:
            mode = "none"

    if mode == "hmac":
        if resolved_key is None:
            raise CheckpointError(
                "HMAC signing needs a key: pass --key-file PATH (mode 0600) or set VELARI_CHECKPOINT_KEY"
            )
        digest = hmac.new(resolved_key, canonical_bytes(body), hashlib.sha256).hexdigest()
        body["signature"] = {"alg": "hmac-sha256", "key_id": key_id(resolved_key), "value": digest}
    elif mode == "ssh":
        if ssh_key is None:
            raise CheckpointError("SSH signing needs --ssh-key PATH")
        body["signature"] = sign_ssh(canonical_bytes(body), ssh_key, namespace=ssh_namespace, identity=ssh_identity)
    elif mode == "openssl":
        if openssl_key is None:
            raise CheckpointError("OpenSSL signing needs --openssl-key PATH")
        body["signature"] = sign_openssl(canonical_bytes(body), openssl_key)
    return body


def write_checkpoint(ledger_path: str | Path, out_path: str | Path, **kwargs: Any) -> dict[str, Any]:
    """Create a checkpoint and atomically write it to ``out_path``."""
    checkpoint = create_checkpoint(ledger_path, **kwargs)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps(checkpoint, indent=2) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, out)
    try:
        fd = os.open(out.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:  # pragma: no cover - best effort
        return checkpoint
    try:
        os.fsync(fd)
    except OSError:  # pragma: no cover - best effort
        pass
    finally:
        os.close(fd)
    return checkpoint


def load_checkpoint(path: str | Path) -> dict[str, Any]:
    """Read a checkpoint file, raising CheckpointError with a clear message."""
    cp_path = Path(path)
    if not cp_path.is_file():
        raise CheckpointError(f"checkpoint not found: {cp_path}")
    try:
        checkpoint = json.loads(cp_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CheckpointError(f"checkpoint is not readable JSON: {cp_path}: {exc}") from exc
    if not isinstance(checkpoint, dict):
        raise CheckpointError(f"checkpoint root is not a JSON object: {cp_path}")
    return checkpoint


def _validate_checkpoint(checkpoint: dict[str, Any]) -> list[ledger.LedgerProblem]:
    problems: list[ledger.LedgerProblem] = []
    if checkpoint.get("kind") != CHECKPOINT_KIND:
        problems.append(
            ledger.LedgerProblem(
                ledger.ERROR,
                "checkpoint_invalid",
                f"unexpected checkpoint kind {checkpoint.get('kind')!r} (expected {CHECKPOINT_KIND})",
            )
        )
    count = checkpoint.get("entry_count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        problems.append(
            ledger.LedgerProblem(
                ledger.ERROR, "checkpoint_invalid", "checkpoint entry_count is not a non-negative integer"
            )
        )
    head = checkpoint.get("head_entry_hash")
    if not isinstance(head, str) or len(head) != 64 or any(c not in "0123456789abcdef" for c in head):
        problems.append(
            ledger.LedgerProblem(
                ledger.ERROR, "checkpoint_invalid", "checkpoint head_entry_hash is not a sha256 hex digest"
            )
        )
    file_hash = checkpoint.get("ledger_sha256")
    if not isinstance(file_hash, str) or len(file_hash) != 64:
        problems.append(
            ledger.LedgerProblem(
                ledger.ERROR, "checkpoint_invalid", "checkpoint ledger_sha256 is not a sha256 hex digest"
            )
        )
    if not isinstance(checkpoint.get("created_at"), str):
        problems.append(ledger.LedgerProblem(ledger.ERROR, "checkpoint_invalid", "checkpoint created_at is missing"))
    return problems


def _verify_signature(
    checkpoint: dict[str, Any],
    problems: list[ledger.LedgerProblem],
    *,
    key: bytes | str | None,
    key_file: str | Path | None,
    key_env: str | None,
    allowed_signers: str | Path | None,
    ssh_identity: str | None,
    openssl_pubkey: str | Path | None,
) -> None:
    signature = checkpoint.get("signature")
    if signature is None:
        problems.append(
            ledger.LedgerProblem(
                ledger.WARNING,
                "checkpoint_unsigned",
                "checkpoint is not signed; contents are anchored but authenticity is not established",
            )
        )
        return
    if not isinstance(signature, dict):
        problems.append(
            ledger.LedgerProblem(ledger.ERROR, "signature_invalid", "checkpoint signature is not an object")
        )
        return

    alg = signature.get("alg")
    body = canonical_bytes(checkpoint_body(checkpoint))

    if alg == "hmac-sha256":
        try:
            resolved = resolve_key(key=key, key_file=key_file, key_env=key_env)
        except CheckpointError as exc:
            problems.append(ledger.LedgerProblem(ledger.ERROR, "signature_key_error", str(exc)))
            return
        if resolved is None:
            problems.append(
                ledger.LedgerProblem(
                    ledger.ERROR,
                    "signature_key_missing",
                    "checkpoint is HMAC-signed but no key was provided; use --key-file or VELARI_CHECKPOINT_KEY",
                )
            )
            return
        expected = hmac.new(resolved, body, hashlib.sha256).hexdigest()
        value = signature.get("value")
        if not isinstance(value, str) or not hmac.compare_digest(expected, value):
            problems.append(
                ledger.LedgerProblem(ledger.ERROR, "signature_invalid", "HMAC signature does not match the checkpoint")
            )
            return
        expected_id = key_id(resolved)
        if signature.get("key_id") not in (None, expected_id):
            problems.append(
                ledger.LedgerProblem(
                    ledger.WARNING,
                    "signature_key_id_mismatch",
                    f"checkpoint key_id {signature.get('key_id')!r} does not match the supplied key ({expected_id})",
                )
            )
    elif alg == "ssh":
        if signing_tools()["ssh-keygen"] is None:
            problems.append(
                ledger.LedgerProblem(
                    ledger.WARNING,
                    "signing_tool_missing",
                    "ssh-keygen not found; SSH signature not checked (install openssh-client to verify it)",
                )
            )
            return
        if allowed_signers is None:
            problems.append(
                ledger.LedgerProblem(
                    ledger.ERROR,
                    "signature_verify_input_missing",
                    "checkpoint is SSH-signed; provide an allowed_signers file to verify it",
                )
            )
            return
        try:
            valid = verify_ssh(body, signature, allowed_signers, identity=ssh_identity)
        except CheckpointError as exc:
            problems.append(ledger.LedgerProblem(ledger.ERROR, "signature_verify_failed", str(exc)))
            return
        if not valid:
            problems.append(
                ledger.LedgerProblem(
                    ledger.ERROR, "signature_invalid", "SSH signature does not verify for this checkpoint"
                )
            )
    elif alg == "openssl-sha256":
        if signing_tools()["openssl"] is None:
            problems.append(
                ledger.LedgerProblem(
                    ledger.WARNING,
                    "signing_tool_missing",
                    "openssl not found; OpenSSL signature not checked (install openssl to verify it)",
                )
            )
            return
        if openssl_pubkey is None:
            problems.append(
                ledger.LedgerProblem(
                    ledger.ERROR,
                    "signature_verify_input_missing",
                    "checkpoint is OpenSSL-signed; provide a public key to verify it",
                )
            )
            return
        try:
            valid = verify_openssl(body, signature, openssl_pubkey)
        except CheckpointError as exc:
            problems.append(ledger.LedgerProblem(ledger.ERROR, "signature_verify_failed", str(exc)))
            return
        if not valid:
            problems.append(
                ledger.LedgerProblem(
                    ledger.ERROR, "signature_invalid", "OpenSSL signature does not verify for this checkpoint"
                )
            )
    else:
        problems.append(
            ledger.LedgerProblem(
                ledger.ERROR, "signature_unsupported", f"unsupported checkpoint signature algorithm {alg!r}"
            )
        )


def verify_checkpoint(
    ledger_path: str | Path,
    checkpoint: dict[str, Any],
    *,
    base_dir: Path | None = None,
    key: bytes | str | None = None,
    key_file: str | Path | None = None,
    key_env: str | None = DEFAULT_KEY_ENV,
    allowed_signers: str | Path | None = None,
    ssh_identity: str | None = None,
    openssl_pubkey: str | Path | None = None,
    ledger_report: ledger.LedgerReport | None = None,
    require_exact: bool = False,
) -> CheckpointReport:
    """Verify the ledger against a checkpoint, including its signature if given.

    Detection, in plain terms:

    - ``checkpoint_truncated``: the ledger has fewer chained entries than the
      checkpoint recorded.
    - ``checkpoint_head_moved``: the entry at the checkpointed position no
      longer has the checkpointed hash, i.e. history before that point was
      rewritten or the chain rebuilt.
    - ``checkpoint_chain_broken``: entries were appended that do not chain from
      the checkpointed head.
    - ``signature_invalid``: the signed body changed.
    - ``checkpoint_ledger_changed`` (warning): exact file bytes differ. Normal
      after appends, or after any benign re-serialization of the file.
    """
    path = Path(ledger_path)
    report = ledger_report if ledger_report is not None else ledger.verify_ledger_report(path, base_dir)
    problems = _validate_checkpoint(checkpoint)
    parsed = ledger.parse_ledger(path)
    count = checkpoint.get("entry_count")
    head = checkpoint.get("head_entry_hash")

    anchor_errors = False
    if not problems and isinstance(count, int) and isinstance(head, str):
        if count == 0:
            if head != ledger.GENESIS:
                problems.append(
                    ledger.LedgerProblem(
                        ledger.ERROR,
                        "checkpoint_invalid",
                        "checkpoint entry_count is 0 but head_entry_hash is not the genesis hash",
                    )
                )
                anchor_errors = True
            elif parsed.records:
                problems.append(
                    ledger.LedgerProblem(
                        ledger.WARNING,
                        "checkpoint_genesis_only",
                        f"checkpoint anchors an empty ledger; {len(parsed.records)} entry/entries are not covered by it",
                    )
                )
        elif len(parsed.records) < count:
            problems.append(
                ledger.LedgerProblem(
                    ledger.ERROR,
                    "checkpoint_truncated",
                    f"ledger truncated: checkpoint recorded {count} chained entries, ledger has {len(parsed.records)}",
                )
            )
            anchor_errors = True
        else:
            anchored = parsed.records[count - 1].entry.get("entry_hash")
            if anchored != head:
                problems.append(
                    ledger.LedgerProblem(
                        ledger.ERROR,
                        "checkpoint_head_moved",
                        f"ledger history rewritten: entry {count} has hash {str(anchored)[:12]}..., "
                        f"checkpoint anchored {head[:12]}...",
                    )
                )
                anchor_errors = True
            elif len(parsed.records) > count:
                next_prev = parsed.records[count].entry.get("prev")
                if next_prev != head:
                    problems.append(
                        ledger.LedgerProblem(
                            ledger.ERROR,
                            "checkpoint_chain_broken",
                            f"entry {count + 1} does not chain from the checkpointed head",
                        )
                    )
                    anchor_errors = True

    exact_match = False
    actual_digest: str | None = None
    data: bytes | None = None
    if path.is_file():
        try:
            data = path.read_bytes()
        except OSError as exc:
            problems.append(
                ledger.LedgerProblem(
                    ledger.ERROR, "ledger_unreadable", f"ledger cannot be read: {path} ({exc.strerror or exc})"
                )
            )
    if data is not None:
        actual_digest = hashlib.sha256(data).hexdigest()
        expected_digest = checkpoint.get("ledger_sha256")
        expected_bytes = checkpoint.get("ledger_bytes")
        exact_match = actual_digest == expected_digest and (
            not isinstance(expected_bytes, int) or expected_bytes == len(data)
        )
        if not exact_match and not anchor_errors and not problems and report.ok:
            if require_exact:
                problems.append(
                    ledger.LedgerProblem(
                        ledger.ERROR,
                        "checkpoint_bytes_changed",
                        "ledger bytes differ from the checkpoint and --require-exact is set",
                    )
                )
            else:
                problems.append(
                    ledger.LedgerProblem(
                        ledger.WARNING,
                        "checkpoint_ledger_changed",
                        "ledger bytes differ from the checkpoint (appended or re-serialized); "
                        "the checkpointed head still matches",
                    )
                )

    _verify_signature(
        checkpoint,
        problems,
        key=key,
        key_file=key_file,
        key_env=key_env,
        allowed_signers=allowed_signers,
        ssh_identity=ssh_identity,
        openssl_pubkey=openssl_pubkey,
    )

    state = "exact file match" if exact_match else "file bytes changed"
    summary = f"checkpoint: {count if isinstance(count, int) else '?'} entries, head {str(head)[:12]}..., {state}"
    if actual_digest is None:
        summary = f"checkpoint: ledger missing, expected head {str(head)[:12]}..."
    return CheckpointReport(
        path=path,
        checkpoint=checkpoint,
        ledger_report=report,
        problems=problems,
        exact_match=exact_match,
        summary=summary,
    )
