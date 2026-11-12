"""Hash-chained evidence ledger.

The ledger is append-only JSON-lines. Each chained entry pins the exact bytes of
one snapshot and the hash of the preceding entry, so an edited, deleted,
inserted or reordered entry breaks the chain.

A hash chain is *tamper-evident, not tamper-proof*: someone who can rewrite the
whole file can rebuild a consistent chain. Anchoring the head with a checkpoint
stored off-host closes that gap; see ``checkpoint.py`` and
``docs/EVIDENCE-INTEGRITY.md``.

Writes are serialized with ``fcntl.flock`` on a sidecar ``.lock`` file (POSIX)
and fsynced, so two collectors cannot fork the chain and a crash mid-write
leaves at worst an incomplete trailing line that verification tolerates and the
next append quarantines.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import EVIDENCE_DIR

try:  # pragma: no cover - exercised on POSIX
    import fcntl
except ImportError:  # pragma: no cover - Windows and other non-POSIX hosts
    fcntl = None  # type: ignore[assignment]

GENESIS = "0" * 64

#: Current on-disk chain format. Entries written by this module carry ``"v": 1``.
#: Entries without ``v`` are the pre-versioning format and still verify.
CHAIN_VERSION = 1

ERROR = "error"
WARNING = "warning"


def file_sha256(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def entry_digest(entry: dict[str, Any]) -> str:
    """Digest of a ledger entry over everything except its own `entry_hash`."""
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class LedgerProblem:
    """One typed verification finding, with a stable machine-readable code."""

    severity: str
    code: str
    message: str
    line: int | None = None

    def __str__(self) -> str:  # keeps `-` joining and f-strings pleasant
        return self.message

    def as_dict(self) -> dict[str, Any]:
        return {"severity": self.severity, "code": self.code, "line": self.line, "message": self.message}


@dataclass(frozen=True)
class LedgerRecord:
    """A parsed chained entry and the 1-based line it came from."""

    line: int
    entry: dict[str, Any]


@dataclass
class ParsedLedger:
    path: Path
    records: list[LedgerRecord] = field(default_factory=list)
    legacy: int = 0
    problems: list[LedgerProblem] = field(default_factory=list)
    trailing_partial_line: int | None = None


@dataclass
class LedgerReport:
    """Structured result of a full chain verification."""

    path: Path
    problems: list[LedgerProblem] = field(default_factory=list)
    chained: int = 0
    legacy: int = 0
    unversioned: int = 0
    head_hash: str = GENESIS
    head_ts: str | None = None
    head_line: int | None = None
    trailing_partial: bool = False

    @property
    def ok(self) -> bool:
        return not any(p.severity == ERROR for p in self.problems)

    @property
    def errors(self) -> list[LedgerProblem]:
        return [p for p in self.problems if p.severity == ERROR]

    @property
    def warnings(self) -> list[LedgerProblem]:
        return [p for p in self.problems if p.severity == WARNING]

    @property
    def messages(self) -> list[str]:
        """Legacy string messages, kept stable for `--verify-ledger` users."""
        msgs = [p.message for p in self.problems]
        if self.legacy:
            msgs.append(f"{self.legacy} legacy un-chained line(s) skipped")
        msgs.append(f"{self.chained} chained entr{'y' if self.chained == 1 else 'ies'} checked")
        return msgs

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "ok": self.ok,
            "chained": self.chained,
            "legacy": self.legacy,
            "unversioned": self.unversioned,
            "trailing_partial": self.trailing_partial,
            "head_entry_hash": self.head_hash,
            "head_ts": self.head_ts,
            "head_line": self.head_line,
            "problems": [p.as_dict() for p in self.problems],
        }


def _read_text(path: Path) -> str:
    # Replacement characters turn a torn multibyte write into an invalid JSON
    # line, which the tail handling below classifies correctly.
    return path.read_bytes().decode("utf-8", "replace")


def parse_ledger(ledger: Path) -> ParsedLedger:
    """Parse lines into chained records without checking links or digest.

    An incomplete *trailing* line (no final newline and not valid JSON) is the
    signature of a crash mid-write. It is reported as a warning, not an error,
    and is not counted in the chain: the last complete entry stays the head.
    """
    path = Path(ledger)
    parsed = ParsedLedger(path=path)
    if not path.is_file():
        return parsed

    try:
        raw = path.read_bytes()
    except OSError as exc:
        parsed.problems.append(
            LedgerProblem(
                ERROR,
                "ledger_unreadable",
                f"ledger cannot be read: {path} ({exc.strerror or exc})",
            )
        )
        return parsed
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
                parsed.trailing_partial_line = n
                parsed.problems.append(
                    LedgerProblem(
                        WARNING,
                        "truncated_tail",
                        f"line {n}: incomplete trailing entry ignored (partial write; not counted in the chain)",
                        n,
                    )
                )
            else:
                parsed.problems.append(LedgerProblem(ERROR, "invalid_json", f"line {n}: not valid JSON", n))
            continue
        if not isinstance(entry, dict) or "entry_hash" not in entry:
            parsed.legacy += 1
            continue
        parsed.records.append(LedgerRecord(n, entry))
    return parsed


def last_entry_hash(ledger: Path) -> str:
    """Hash of the newest chained entry, or GENESIS for an empty/legacy-only ledger."""
    if not Path(ledger).is_file():
        return GENESIS
    for line in reversed(_read_text(Path(ledger)).splitlines()):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(entry, dict) and isinstance(entry.get("entry_hash"), str):
            return str(entry["entry_hash"])
    return GENESIS


def build_ledger_entry(
    snapshot: dict[str, Any], json_path: Path, md_path: Path, prev_hash: str, base_dir: Path = EVIDENCE_DIR
) -> dict[str, Any]:
    """Chained ledger entry: links to the previous entry and pins the snapshot bytes."""
    entry: dict[str, Any] = {
        "v": CHAIN_VERSION,
        "ts": snapshot["collected_at"],
        "json": os.path.relpath(json_path, base_dir),
        "md": os.path.relpath(md_path, base_dir),
        "findings": snapshot["finding_counts"],
        "snapshot_sha256": file_sha256(json_path),
        "prev": prev_hash,
    }
    entry["entry_hash"] = entry_digest(entry)
    return entry


def _entry_version_problem(record: LedgerRecord) -> LedgerProblem | None:
    version = record.entry.get("v")
    if version is None:
        return None  # pre-versioning entry; accepted for backward compatibility
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        return LedgerProblem(
            ERROR, "bad_chain_version", f"line {record.line}: invalid chain version {version!r}", record.line
        )
    if version > CHAIN_VERSION:
        return LedgerProblem(
            ERROR,
            "unsupported_chain_version",
            f"line {record.line}: unsupported chain version {version} "
            f"(this verifier understands up to {CHAIN_VERSION})",
            record.line,
        )
    return None


def verify_ledger_report(ledger: Path, base_dir: Path | None = None) -> LedgerReport:
    """Walk the hash chain and snapshot hashes, returning typed problems.

    Problems carry ``severity`` (``error`` fails verification, ``warning`` does
    not), a stable ``code``, a 1-based ``line`` when applicable, and a message.
    """
    path = Path(ledger)
    base = Path(base_dir) if base_dir else path.parent
    report = LedgerReport(path=path)
    if not path.is_file():
        report.problems.append(LedgerProblem(ERROR, "ledger_missing", f"ledger not found: {path}"))
        return report

    parsed = parse_ledger(path)
    report.problems.extend(parsed.problems)
    report.legacy = parsed.legacy
    report.trailing_partial = parsed.trailing_partial_line is not None

    prev = GENESIS
    for record in parsed.records:
        entry = record.entry
        n = record.line
        version_problem = _entry_version_problem(record)
        if version_problem:
            report.problems.append(version_problem)
        elif entry.get("v") is None:
            report.unversioned += 1

        entry_hash = entry.get("entry_hash")
        if not isinstance(entry_hash, str):
            report.problems.append(LedgerProblem(ERROR, "bad_entry_hash", f"line {n}: entry_hash is not a string", n))
            continue

        if entry.get("prev") != prev:
            report.problems.append(
                LedgerProblem(
                    ERROR,
                    "chain_broken",
                    f"line {n}: chain broken (prev does not match preceding entry)",
                    n,
                )
            )
        if entry_digest(entry) != entry_hash:
            report.problems.append(
                LedgerProblem(
                    ERROR,
                    "entry_digest_mismatch",
                    f"line {n}: entry contents do not match entry_hash",
                    n,
                )
            )

        json_rel = entry.get("json")
        snap: Path | None = None
        if not isinstance(json_rel, str) or not json_rel:
            report.problems.append(
                LedgerProblem(ERROR, "snapshot_path_invalid", f"line {n}: entry has no valid snapshot path", n)
            )
        else:
            rel = Path(json_rel)
            if rel.is_absolute() or ".." in rel.parts:
                report.problems.append(
                    LedgerProblem(
                        ERROR,
                        "snapshot_path_invalid",
                        f"line {n}: snapshot path escapes the evidence root: {json_rel}",
                        n,
                    )
                )
            else:
                candidate = base / rel
                try:
                    inside = candidate.resolve().is_relative_to(base.resolve())
                except OSError:
                    inside = False
                if not inside:
                    report.problems.append(
                        LedgerProblem(
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
                report.problems.append(
                    LedgerProblem(
                        WARNING,
                        "snapshot_missing",
                        f"line {n}: snapshot file missing (chain still checked): {json_rel}",
                        n,
                    )
                )
            else:
                try:
                    actual = file_sha256(snap)
                except OSError as exc:
                    report.problems.append(
                        LedgerProblem(
                            ERROR,
                            "snapshot_unreadable",
                            f"line {n}: snapshot cannot be read: {json_rel} ({exc.strerror or exc})",
                            n,
                        )
                    )
                else:
                    if actual != entry.get("snapshot_sha256"):
                        report.problems.append(
                            LedgerProblem(
                                ERROR,
                                "snapshot_modified",
                                f"line {n}: snapshot modified since collection: {json_rel}",
                                n,
                            )
                        )

        prev = entry_hash
        report.chained += 1
        report.head_hash = entry_hash
        report.head_line = n
        if isinstance(entry.get("ts"), str):
            report.head_ts = entry["ts"]
    return report


def verify_ledger(ledger: Path, base_dir: Path | None = None) -> tuple[bool, list[str]]:
    """Walk the hash chain. Returns (ok, messages).

    Detects edited, deleted, reordered or inserted entries (broken chain) and
    modified snapshot files (byte-hash mismatch). Pre-chain legacy lines are
    skipped and reported, not treated as failures. A truncated final line from
    a crash mid-write is a warning, not a failure.
    """
    report = verify_ledger_report(ledger, base_dir)
    if any(p.code == "ledger_missing" for p in report.problems):
        return False, [report.problems[0].message]
    return report.ok, report.messages


@contextmanager
def ledger_lock(ledger: Path, *, required: bool = True) -> Iterator[None]:
    """Exclusive advisory lock around a ledger mutation.

    Uses ``fcntl.flock`` on ``<ledger>.lock`` where available. On platforms
    without ``fcntl`` the lock degrades to a no-op rather than failing the
    collector; that mode is not safe for concurrent writers.

    ``required=False`` lets a read-only operation (checkpoint creation) proceed
    when the sidecar lock file cannot be created, for example on a read-only
    evidence tree mounted for review.
    """
    if fcntl is None:  # pragma: no cover - non-POSIX only
        yield
        return
    lock_path = Path(str(ledger) + ".lock")
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    except OSError:
        if required:
            raise
        yield
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _fsync_dir(path: Path) -> None:
    if not hasattr(os, "O_DIRECTORY"):  # pragma: no cover - non-POSIX
        return
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:  # pragma: no cover - best effort
        return
    try:
        os.fsync(fd)
    except OSError:  # pragma: no cover - best effort
        pass
    finally:
        os.close(fd)


def _repair_tail(ledger: Path) -> bytes | None:
    """Make the file safe to append after a crash mid-write.

    - Complete last line without a trailing newline: add the newline.
    - Incomplete last line: copy its bytes to ``<ledger>.recovered`` (so nothing
      is silently discarded) and truncate it, leaving the chain intact.

    Returns the quarantined bytes, if any.
    """
    if not ledger.exists():
        return None
    data = ledger.read_bytes()
    if not data or data.endswith(b"\n"):
        return None

    start = data.rfind(b"\n") + 1
    tail = data[start:]
    try:
        parsed = json.loads(tail.decode("utf-8"))
        complete = isinstance(parsed, dict)
    except (UnicodeDecodeError, json.JSONDecodeError):
        complete = False

    if complete:
        with ledger.open("ab") as fh:
            fh.write(b"\n")
            fh.flush()
            os.fsync(fh.fileno())
        return None

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    recovered = Path(str(ledger) + ".recovered")
    with recovered.open("ab") as fh:
        fh.write(f"# recovered partial ledger tail {stamp}\n".encode())
        fh.write(tail + b"\n")
        fh.flush()
        os.fsync(fh.fileno())
    with ledger.open("r+b") as fh:
        fh.truncate(start)
        fh.flush()
        os.fsync(fh.fileno())
    return tail


def _append_locked(ledger: Path, entry: dict[str, Any]) -> None:
    _repair_tail(ledger)
    line = json.dumps(entry) + "\n"
    with ledger.open("a", encoding="utf-8") as fh:
        fh.write(line)
        fh.flush()
        os.fsync(fh.fileno())
    _fsync_dir(ledger.parent)


def append_entry(ledger: Path, entry: dict[str, Any]) -> None:
    """Append one entry under the ledger lock, repairing a torn tail first."""
    with ledger_lock(ledger):
        _append_locked(ledger, entry)


def append_chained(
    ledger: Path,
    snapshot: dict[str, Any],
    json_path: Path,
    md_path: Path,
    base_dir: Path = EVIDENCE_DIR,
) -> dict[str, Any]:
    """Build and append an entry whose ``prev`` is read under the lock.

    This is the concurrency-safe path: the previous hash and the append happen
    in one critical section, so two collectors cannot both chain from the same
    head.
    """
    with ledger_lock(ledger):
        prev = last_entry_hash(ledger)
        entry = build_ledger_entry(snapshot, json_path, md_path, prev, base_dir)
        _append_locked(ledger, entry)
        return entry


def head_summary(ledger: Path | None = None) -> dict[str, Any]:
    """Small, renderer-friendly summary of the ledger head.

    Safe to call when the ledger does not exist. ``ok`` reflects full
    verification (chain, snapshot bytes); a missing ledger is not an error for
    display purposes but ``present`` is false.
    """
    path = Path(ledger) if ledger is not None else EVIDENCE_DIR / "ledger.jsonl"
    present = path.is_file()
    report = verify_ledger_report(path)
    try:
        digest = file_sha256(path) if present else None
    except OSError:
        digest = None
    return {
        "path": str(path),
        "present": present,
        "ok": report.ok if present else False,
        "entry_count": report.chained,
        "legacy_count": report.legacy,
        "head_entry_hash": report.head_hash,
        "head_ts": report.head_ts,
        "head_line": report.head_line,
        "ledger_sha256": digest,
        "error_count": len(report.errors),
        "warning_count": len(report.warnings),
        "problems": [p.as_dict() for p in report.problems],
    }
