"""Assemble the self-contained HTML review packet."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .data import build_decisions, build_lanes, build_rows
from .sections import (
    decisions_section,
    drift_block,
    lanes_section,
    limitations_section,
    schedule_section,
    summary_section,
    supporting_section,
)
from .text import document_id, esc, prose_ts

CSS_PATH = Path(__file__).resolve().parent / "assets" / "packet.css"


def read_css(path: Path | None = None) -> str:
    return (path or CSS_PATH).read_text(encoding="utf-8")


def _title_block(snap: dict[str, Any], collected_prose: str, auth_window: object, doc_id: str) -> str:
    return f"""<body>
<a class="skip-link" href="#main">Skip to packet content</a>
<div class="sheet">

  <header class="masthead">
    <div class="masthead-row">
      <span class="wordmark">Velari</span>
      <span class="docid">{esc(doc_id)}</span>
    </div>
  </header>

  <div class="title-block">
    <h1>Practice Trust Packet</h1>
    <p class="standfirst">One review pass across identity, data movement, endpoints, and supply chain for {esc(snap.get("lab"))}. What changed, what it means, and the proof to save.</p>
    <dl class="kvb">
      <div><dt>Subject</dt><dd>{esc(snap.get("lab"))}</dd></div>
      <div><dt>Collected</dt><dd>{esc(collected_prose)}</dd></div>
      <div><dt>Auth window</dt><dd>{esc(auth_window)} hours</dd></div>
      <div><dt>Collector</dt><dd>{esc(snap.get("collector"))}</dd></div>
      <div><dt>Prepared for</dt><dd>Practice owner &middot; MSP &middot; counsel</dd></div>
      <div><dt>Schema</dt><dd>{esc(snap.get("schema"))}</dd></div>
    </dl>
    <p class="see-also">Boundaries and limitations: see &sect;6. Synthetic lab data; no real patient information.</p>
  </div>"""


def render(snap: dict[str, Any], *, now: datetime | None = None, ledger_head: dict[str, Any] | None = None) -> str:
    """Render a snapshot dict to a single self-contained HTML document.

    `now` is injectable so golden tests can pin the "Generated" timestamp.
    `ledger_head` (from `practice_evidence.ledger.head_summary`) adds the evidence
    ledger head to the footer; omit it for snapshots that are not from this ledger.
    """
    collected = snap.get("collected_at", "")
    collected_prose = prose_ts(collected)
    doc_id = document_id(collected)
    generated_at = now or datetime.now(timezone.utc)
    generated = generated_at.strftime("%d %b %Y, %H:%M UTC").lstrip("0")

    rows = build_rows(snap, collected)
    decisions = build_decisions(rows)
    lanes = build_lanes(rows)
    drift_sentence = drift_block(snap.get("drift", {}), collected_prose)

    body = "\n\n".join(
        [
            _title_block(snap, collected_prose, snap.get("auth", {}).get("window_hours", 24), doc_id),
            '<main id="main">',
            summary_section(snap.get("finding_counts", {}), len(decisions), drift_sentence),
            decisions_section(decisions),
            schedule_section(rows, collected_prose),
            lanes_section(lanes),
            supporting_section(snap, rows),
            limitations_section(snap, collected, generated, ledger_head),
        ]
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Practice Trust Packet &middot; {esc(snap.get("lab"))}</title>
<style>
{read_css()}</style>
</head>
{body}
</main>

</div>
</body>
</html>
"""
