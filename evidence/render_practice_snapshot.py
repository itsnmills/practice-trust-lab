#!/usr/bin/env python3
"""render_practice_snapshot.py - render a practice-lab evidence JSON as a
self-contained, no-PHI review packet (HTML).

This module is the command-line entry point. The renderer itself lives in the
`practice_render` package: rules in `practice_render.rules`, snapshot shaping in
`practice_render.data`, HTML sections in `practice_render.sections`, and the
document assembly plus CSS in `practice_render.render`.

Usage:
  python3 render_practice_snapshot.py [snapshot.json]
  python3 render_practice_snapshot.py --latest
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from practice_evidence.config import LEDGER
from practice_evidence.ledger import head_summary
from practice_evidence.schema import validate_snapshot
from practice_render import (  # noqa: F401 - re-exported for existing callers
    DEFAULT_RULE,
    GROUP_ORDER,
    RULES,
    SEVERITY_ORDER,
    SEVERITY_TAG,
    build_decisions,
    build_lanes,
    build_rows,
    cites_for,
    document_id,
    due_date,
    esc,
    extract_item,
    format_cites,
    prose_ts,
    read_css,
    redact,
    render,
    rule_for_detail,
    rule_for_finding,
)

ARTIFACTS = Path(__file__).resolve().parent / "artifacts"
LAB_ROOT = Path(__file__).resolve().parent.parent


def rule_for(detail):
    """Backward-compatible alias for the legacy substring rule lookup."""
    return rule_for_detail(detail)


def latest_snapshot():
    candidates = sorted(ARTIFACTS.glob("*/*.json"))
    if not candidates:
        raise SystemExit("no snapshots found under artifacts/")
    return candidates[-1]


def main():
    ap = argparse.ArgumentParser(description="Render a practice snapshot JSON as a review packet HTML")
    ap.add_argument("snapshot", nargs="?", help="path to snapshot JSON")
    ap.add_argument("--latest", action="store_true", help="use the newest snapshot")
    ap.add_argument("--out", help="output path (default: beside the JSON)")
    args = ap.parse_args()

    if args.latest or not args.snapshot:
        path = latest_snapshot()
    else:
        path = Path(args.snapshot)
    snap = json.loads(path.read_text(encoding="utf-8"))
    problems = validate_snapshot(snap)
    for problem in problems:
        print(f"{path}: {problem}", file=sys.stderr)
    if any(p.severity == "error" for p in problems):
        print(f"error: {path} is not a valid snapshot; not rendering", file=sys.stderr)
        return 2
    output = Path(args.out) if args.out else path.with_suffix(".html")
    # Only snapshots produced into this checkout's artifacts dir belong to this ledger.
    # A sample or foreign snapshot must not display a head that is not its own.
    own = path.resolve().is_relative_to(ARTIFACTS.resolve())
    packet = render(snap, ledger_head=head_summary(LEDGER) if own else None)
    output.write_text(packet, encoding="utf-8")
    if not args.out:
        # Only refresh the convenience copy for default runs, not ad-hoc --out renders.
        try:
            (ARTIFACTS.parent / "latest.html").write_text(packet, encoding="utf-8")
        except OSError:
            pass
    print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
