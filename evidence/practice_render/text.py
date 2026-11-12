"""Small, dependency-free text helpers shared by the packet sections."""

from __future__ import annotations

import html
import re
from datetime import datetime, timedelta
from pathlib import Path

LAB_ROOT = Path(__file__).resolve().parents[2]

_TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def redact(value: object, lab_root: Path | str = LAB_ROOT) -> str:
    """Strip the checkout and home paths from display strings."""
    s = str(value)
    s = s.replace(str(lab_root) + "/", "")
    s = s.replace(str(Path.home()) + "/", "~/")
    return s


def esc(value: object) -> str:
    """HTML-escape user-controlled text (quotes included)."""
    return html.escape(redact(value))


def plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def parse_ts(iso: object) -> datetime | None:
    try:
        return datetime.strptime(str(iso), _TS_FORMAT)
    except (ValueError, TypeError):
        return None


def prose_ts(iso: object) -> str:
    dt = parse_ts(iso)
    if dt is None:
        return str(iso)
    return f"{dt.day} {dt.strftime('%b %Y')}, {dt.strftime('%H:%M')} UTC"


def due_date(collected_iso: object, due_text: str | None) -> str:
    match = re.search(r"(\d+)", due_text or "")
    if not match:
        return due_text or ""
    collected = parse_ts(collected_iso)
    if collected is None:
        return due_text or ""
    dt = collected + timedelta(days=int(match.group(1)))
    return f"{dt.day} {dt.strftime('%b %Y')}"


def document_id(collected_iso: object) -> str:
    stamp = str(collected_iso).replace("-", "").replace("T", "-").replace(":", "").replace("Z", "")
    return "VLR-PTP-" + stamp[:13]


def extract_item(group: str, detail: str) -> str:
    """The per-finding bullet shown under a consolidated evidence row."""
    if group in ("dormant", "disabled"):
        return detail.split(":")[0].strip()
    if group == "endpoint":
        match = re.match(r"([^(]+)\(([^)]+)\):\s*(\d+)", detail)
        if match:
            n = int(match.group(3))
            return f"{match.group(1).strip()} \u2014 {plural(n, 'file')}"
        return detail.split(":")[0].strip()
    if group == "shares":
        return detail.split(":", 1)[1].strip() if ":" in detail else detail
    return detail
