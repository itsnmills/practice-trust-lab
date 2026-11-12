"""Supply chain: optional Bumblebee package-exposure scan."""

from __future__ import annotations

import json
from typing import Any

from ..config import BUMBLEBEE_DIR, EVIDENCE_DIR, LAB_ROOT, SCAN_ROOTS
from ..models import Finding, dump_findings
from ..runner import ERROR_PREFIX, sh

BIN = BUMBLEBEE_DIR / "bin" / "bumblebee"
CATALOGS = BUMBLEBEE_DIR / "catalogs" / "vendor" / "bumblebee"


def map_severity(raw: str) -> str:
    return "high" if raw in ("critical", "high") else ("medium" if raw == "medium" else "low")


def _relative(raw: Any, lab_root: str) -> Any:
    """Strip the lab root so generated artifacts never carry an absolute host path."""
    if isinstance(raw, str) and raw.startswith(lab_root):
        return raw[len(lab_root) :].lstrip("/")
    return raw


def parse_findings(raw: str, lab_root: str = str(LAB_ROOT)) -> list[Finding]:
    out = []
    for line in raw.splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict) or rec.get("record_type") != "finding":
            continue
        proj = _relative(rec.get("project_path") or "", lab_root)
        out.append(
            Finding(
                map_severity(rec.get("severity", "medium")),
                f"Known-compromised package {rec.get('package_name')}@{rec.get('version')} "
                f"({rec.get('ecosystem')}) in {proj}",
                rule_id="SUPPLY-KNOWN-BAD-PACKAGE",
                subject=rec.get("package_name"),
                extra={
                    "package": rec.get("package_name"),
                    "version": rec.get("version"),
                    "ecosystem": rec.get("ecosystem"),
                    "catalog": rec.get("catalog_name"),
                    "project": proj,
                    "source_file": _relative(rec.get("source_file"), lab_root),
                },
            )
        )
    return out


def skipped(detail: str | None = None) -> dict[str, Any]:
    return {"scanner": "bumblebee", "status": "skipped", "findings": [], "detail": detail}


def collect(timeout: int = 180) -> dict[str, Any]:
    if not BIN.exists():
        return skipped("bumblebee binary not installed")
    catalog_files = [p for p in CATALOGS.glob("*.json") if p.name != "sync-manifest.json"]
    if not catalog_files:
        return skipped("no exposure catalogs found")
    merged = EVIDENCE_DIR / ".catalogs"
    merged.mkdir(exist_ok=True)
    for stale in merged.glob("*.json"):
        stale.unlink()
    for cat in sorted(catalog_files):
        (merged / cat.name).symlink_to(cat)
    cmd = [str(BIN), "scan", "--findings-only", "--max-duration", "90s"]
    for root in SCAN_ROOTS:
        if root.exists():
            cmd += ["--root", str(root)]
    cmd += ["--exposure-catalog", str(merged)]
    raw = sh(cmd, timeout=timeout)
    if raw.startswith(ERROR_PREFIX):
        return {**skipped(raw[:200]), "status": "error"}
    return {
        "scanner": "bumblebee",
        "status": "complete",
        "detail": None,
        "findings": dump_findings(parse_findings(raw)),
    }
