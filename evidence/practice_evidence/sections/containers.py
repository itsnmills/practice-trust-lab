"""Lab container inventory (never reports unrelated containers on a shared host)."""

from __future__ import annotations

from typing import Any

from ..config import LAB_CONTAINERS
from ..runner import sh


def parse(raw: str) -> list[dict[str, Any]]:
    out = []
    for line in raw.splitlines():
        parts = line.split("|")
        if len(parts) == 3 and parts[0] in LAB_CONTAINERS:
            out.append({"name": parts[0], "status": parts[1], "ports": parts[2]})
    return out


def collect() -> list[dict[str, Any]]:
    return parse(sh(["docker", "ps", "--format", "{{.Names}}|{{.Status}}|{{.Ports}}"]))
