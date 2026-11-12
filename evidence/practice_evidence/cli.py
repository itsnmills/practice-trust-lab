"""Command-line entry point.

Usage: ``collect_practice_evidence.py [options]``.

Output contract (stable for scripts and CI):

* stdout carries only normal progress. ``--quiet`` suppresses everything except
  the errors below.
* stderr carries preflight errors only; those write no snapshot.
* Exit codes:

  - ``0`` snapshot written, ``--verify-ledger`` found a valid chain,
    ``--validate`` found a valid document, or a checkpoint was written/verified;
  - ``1`` ``--verify-ledger`` found a broken chain, missing snapshot,
    ``--validate`` found schema errors, or checkpoint verification failed;
  - ``2`` preflight failed (Docker CLI/daemon unavailable or the DC container is
    not running), a ``--validate`` file could not be read, or a checkpoint
    operation could not run (missing ledger, bad key, missing signing input);
    nothing was collected.

A section that raises unexpectedly is a degraded run, not a fatal error: its
section is emptied, a medium finding records the gap, the remaining sections are
still collected, and the exit code stays ``0``.

Artifact and ledger locations can be overridden with ``--artifacts-dir`` /
``--ledger`` or the ``EVIDENCE_ARTIFACTS_DIR`` / ``EVIDENCE_LEDGER`` environment
variables. The ledger's snapshot paths are stored relative to the artifacts
directory's parent, so a self-contained tree (for example ``out/artifacts`` plus
``out/ledger.jsonl``) verifies on its own.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import checkpoint, ledger
from .config import ARTIFACTS, LEDGER
from .drift import compute_drift, previous_snapshot
from .report import render_markdown
from .runner import preflight
from .schema import validate_snapshot
from .snapshot import build

EXIT_OK = 0
EXIT_LEDGER_INVALID = 1
EXIT_PREFLIGHT_FAILED = 2


def _env_path(name: str, default: Path) -> Path:
    value = os.environ.get(name)
    return Path(value).expanduser() if value else default


def _unique_stem(outdir: Path, ts: datetime) -> str:
    """Seconds + microseconds keeps two quick runs from overwriting each other."""
    stem = f"snapshot-{ts.strftime('%Y%m%dT%H%M%S%fZ')}"
    candidate, n = stem, 1
    while (outdir / f"{candidate}.json").exists() or (outdir / f"{candidate}.md").exists():
        n += 1
        candidate = f"{stem}-{n:02d}"
    return candidate


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Collect a dated practice-lab evidence snapshot",
        epilog=(
            "exit codes: 0 snapshot written, ledger verified, checkpoint written/verified, or document valid; "
            "1 ledger/checkpoint verification failed or document invalid; "
            "2 preflight failed (nothing collected), checkpoint input error, or file unreadable"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--hours", type=int, default=24, help="auth log window in hours (default: 24)")
    ap.add_argument("--skip-supply-chain", action="store_true", help="skip the Bumblebee scan section")
    ap.add_argument("--quiet", action="store_true", help="suppress progress output on stdout")
    ap.add_argument("--verify-ledger", action="store_true", help="verify the evidence ledger hash chain and exit")
    ap.add_argument(
        "--validate",
        metavar="FILE",
        help="validate a snapshot JSON against the schema, print problems, and exit",
    )
    ap.add_argument(
        "--checkpoint",
        nargs="?",
        const="",
        default=None,
        metavar="PATH",
        help="write a portable ledger checkpoint and exit (default: <ledger dir>/checkpoints/checkpoint-<ts>.json)",
    )
    ap.add_argument("--verify-checkpoint", metavar="PATH", help="verify the ledger against a checkpoint and exit")
    ap.add_argument("--key-file", metavar="PATH", help="HMAC checkpoint key file (mode 0600)")
    ap.add_argument(
        "--sign",
        choices=checkpoint.SIGN_MODES,
        default="auto",
        help="checkpoint signature: auto (default), none, hmac, ssh, or openssl",
    )
    ap.add_argument("--ssh-key", metavar="PATH", help="SSH private key for --sign ssh")
    ap.add_argument("--openssl-key", metavar="PATH", help="PEM private key for --sign openssl")
    ap.add_argument(
        "--artifacts-dir",
        type=Path,
        default=_env_path("EVIDENCE_ARTIFACTS_DIR", ARTIFACTS),
        metavar="PATH",
        help="snapshot output root (default: evidence/artifacts; env: EVIDENCE_ARTIFACTS_DIR)",
    )
    ap.add_argument(
        "--ledger",
        type=Path,
        default=_env_path("EVIDENCE_LEDGER", LEDGER),
        metavar="PATH",
        help="hash-chained ledger file (default: evidence/ledger.jsonl; env: EVIDENCE_LEDGER)",
    )
    args = ap.parse_args(argv)
    base_dir = args.artifacts_dir.parent

    if args.validate:
        try:
            document = json.loads(Path(args.validate).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: {args.validate}: {exc}", file=sys.stderr)
            return EXIT_PREFLIGHT_FAILED
        problems = validate_snapshot(document)
        for problem in problems:
            print(problem, file=sys.stderr if problem.severity == "error" else sys.stdout)
        if any(p.severity == "error" for p in problems):
            print(f"FAIL: {args.validate}: schema validation failed", file=sys.stderr)
            return EXIT_LEDGER_INVALID
        if not args.quiet:
            print(f"ok: {args.validate}: validates as {document.get('schema')}")
        return EXIT_OK

    if args.verify_ledger:
        ok, msgs = ledger.verify_ledger(args.ledger, base_dir=base_dir)
        for m in msgs:
            print(("ok: " if ok else "FAIL: ") + m)
        return EXIT_OK if ok else EXIT_LEDGER_INVALID

    if args.verify_checkpoint:
        try:
            cp = checkpoint.load_checkpoint(args.verify_checkpoint)
            report = checkpoint.verify_checkpoint(
                args.ledger, cp, base_dir=base_dir, key_file=args.key_file, ledger_report=None
            )
        except checkpoint.CheckpointError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_PREFLIGHT_FAILED
        for item in report.ledger_report.problems:
            print(f"{'FAIL' if item.severity == ledger.ERROR else 'warn'}: {item.message}")
        for item in report.problems:
            print(f"{'FAIL' if item.severity == ledger.ERROR else 'warn'}: {item.message}")
        print(f"{'ok' if report.ok else 'FAIL'}: {report.summary}")
        return EXIT_OK if report.ok else (EXIT_PREFLIGHT_FAILED if report.input_error else EXIT_LEDGER_INVALID)

    if args.checkpoint is not None:
        out = (
            Path(args.checkpoint)
            if args.checkpoint
            else checkpoint.default_checkpoint_path(base_dir=args.ledger.parent)
        )
        try:
            cp = checkpoint.write_checkpoint(
                args.ledger,
                out,
                key_file=args.key_file,
                sign=args.sign,
                ssh_key=args.ssh_key,
                openssl_key=args.openssl_key,
            )
        except checkpoint.CheckpointError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_PREFLIGHT_FAILED
        if not args.quiet:
            print(f"checkpoint: {out}")
            print(f"signature: {cp.get('signature', {}).get('alg', 'none')}")
            print("store this file off-host (email, ticket, git tag) - see docs/EVIDENCE-INTEGRITY.md")
        return EXIT_OK

    if not preflight():
        return EXIT_PREFLIGHT_FAILED

    ts = datetime.now(timezone.utc)
    snapshot = build(ts, args.hours, args.skip_supply_chain)

    day = ts.strftime("%Y-%m-%d")
    outdir = args.artifacts_dir / day
    outdir.mkdir(parents=True, exist_ok=True)
    stem = _unique_stem(outdir, ts)
    json_path, md_path = outdir / f"{stem}.json", outdir / f"{stem}.md"

    prev_path, prev = previous_snapshot(json_path, artifacts=args.artifacts_dir)
    drift = compute_drift(prev, snapshot)
    drift["compared_to_path"] = str(prev_path.relative_to(base_dir)) if prev_path else None
    snapshot["drift"] = drift

    problems = validate_snapshot(snapshot)
    for problem in problems:
        if problem.severity == "error":
            print(problem, file=sys.stderr)
    if any(p.severity == "error" for p in problems):
        print("error: snapshot failed schema validation; nothing written", file=sys.stderr)
        return EXIT_LEDGER_INVALID

    json_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    md_path.write_text(render_markdown(snapshot, day), encoding="utf-8")

    args.ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.append_chained(args.ledger, snapshot, json_path, md_path, base_dir=base_dir)

    if not args.quiet:
        counts = snapshot["finding_counts"]
        print(f"snapshot: {json_path}")
        print(f"markdown: {md_path}")
        print("findings: " + (", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none"))
        for section, error in snapshot.get("section_errors", {}).items():
            print(f"warning: {section} section failed: {error}")
    return EXIT_OK
