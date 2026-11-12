"""Golden output for the committed sample snapshot.

The "Generated" timestamp is pinned through the injectable clock so this file
can be compared byte for byte. To regenerate after an intentional visual or
markup change:

    UPDATE_GOLDEN=1 uv run --no-project --with pytest pytest -q tests/test_render_golden.py

Then review the diff in tests/golden/sample-packet.html before committing it.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import render_practice_snapshot as r

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "examples" / "sample-snapshot.json"
GOLDEN = Path(__file__).resolve().parent / "golden" / "sample-packet.html"
FIXED_NOW = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)


def rendered() -> str:
    return r.render(json.loads(SAMPLE.read_text(encoding="utf-8")), now=FIXED_NOW)


def test_golden_packet_matches():
    actual = rendered()
    if os.environ.get("UPDATE_GOLDEN") == "1":
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(actual, encoding="utf-8")
    expected = GOLDEN.read_text(encoding="utf-8")
    assert actual == expected, (
        "rendered packet differs from tests/golden/sample-packet.html; "
        "regenerate with UPDATE_GOLDEN=1 if the change is intentional"
    )


def test_render_is_deterministic_with_a_fixed_clock():
    assert rendered() == rendered()


def test_injected_clock_sets_generated_stamp():
    out = r.render(json.loads(SAMPLE.read_text(encoding="utf-8")), now=FIXED_NOW)
    assert "Generated 12 Nov 2026, 12:00 UTC" in out


def test_golden_file_exists_and_is_self_contained():
    text = GOLDEN.read_text(encoding="utf-8")
    assert text.startswith("<!doctype html>")
    assert "<style>" in text
    assert "http://" not in text and "https://" not in text
