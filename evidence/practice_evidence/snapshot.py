"""Assemble a full snapshot from every section.

Sections are independent: a crash in one must not lose the rest of the evidence
pass. Each section is collected inside a guard. On failure the section keeps a
schema-compatible empty shape, the error is recorded in ``section_errors``, and a
medium finding explains the gap. The run still writes a snapshot and exits 0.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

from . import SCHEMA
from .models import SEVERITY_ORDER
from .sections import (
    acls,
    auth,
    containers,
    ehr,
    endpoints,
    hygiene,
    identity,
    policy,
    privilege,
    shares,
    supply_chain,
)

FINDING_SECTIONS = (
    "identity",
    "policy",
    "shares",
    "acls",
    "auth",
    "ehr",
    "endpoints",
    "privilege",
    "hygiene",
    "supply_chain",
)


def merge_findings(snapshot: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Flatten per-section findings, tag them with their section, sort by severity, count."""
    merged = []
    for section in FINDING_SECTIONS:
        for f in snapshot[section].get("findings", []):
            merged.append({**f, "section": section})
    for section, error in snapshot.get("section_errors", {}).items():
        merged.append(
            {
                "severity": "medium",
                "detail": f"{section} section failed: {error}",
                "section": section,
            }
        )
    merged.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 9))
    counts: dict[str, int] = {}
    for f in merged:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return merged, counts


def _empty_identity() -> dict[str, Any]:
    return {"password_policy": {}, "users": [], "privileged_groups": {}, "findings": []}


def _empty_shares() -> dict[str, Any]:
    return {"shares": [], "files": [], "findings": []}


def _empty_auth() -> dict[str, Any]:
    return {
        "window_hours": 0,
        "success": 0,
        "failures": 0,
        "by_user": {},
        "failure_reasons": {},
        "findings": [],
    }


def _empty_ehr() -> dict[str, Any]:
    return {
        "health": {},
        "events": {},
        "scribe_transmissions": 0,
        "intake_submissions": 0,
        "findings": [],
    }


def _empty_endpoints() -> dict[str, Any]:
    return {"hosts": [], "findings": []}


def _empty_supply_chain() -> dict[str, Any]:
    return {"scanner": "bumblebee", "status": "error", "detail": None, "findings": []}


def _empty_policy() -> dict[str, Any]:
    return {"baseline": {}, "settings": {}, "evaluated": {}, "findings": []}


def _empty_acls() -> dict[str, Any]:
    return {"shares": [], "findings": []}


def _empty_privilege() -> dict[str, Any]:
    return {"role_groups": {}, "accounts": [], "findings": []}


def _empty_hygiene() -> dict[str, Any]:
    return {"functional_level": {}, "smb": {}, "krbtgt": {}, "findings": []}


def build(ts: datetime, hours: int = 24, skip_supply_chain: bool = False) -> dict[str, Any]:
    collected: dict[str, Any] = {}
    jobs: dict[str, tuple[Callable[[], Any], Callable[[], Any]]] = {
        "containers": (containers.collect, list),
        "identity": (identity.collect, _empty_identity),
        "policy": (policy.collect, _empty_policy),
        "shares": (shares.collect, _empty_shares),
        "acls": (acls.collect, _empty_acls),
        "auth": (lambda: auth.collect(hours), _empty_auth),
        "ehr": (ehr.collect, _empty_ehr),
        "endpoints": (endpoints.collect, _empty_endpoints),
        # auth is collected before privilege, so its summary is available here.
        "privilege": (lambda: privilege.collect(collected.get("auth")), _empty_privilege),
        "hygiene": (hygiene.collect, _empty_hygiene),
        "supply_chain": (
            supply_chain.skipped if skip_supply_chain else supply_chain.collect,
            _empty_supply_chain,
        ),
    }
    snapshot: dict[str, Any] = {
        "collector": "collect_practice_evidence.py",
        "schema": SCHEMA,
        "collected_at": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "lab": "millslab.internal (synthetic)",
    }
    errors: dict[str, str] = {}
    for name, (collect, fallback) in jobs.items():
        try:
            value = collect()
        except Exception as exc:  # noqa: BLE001 - one bad section must not sink the pass
            errors[name] = f"{type(exc).__name__}: {exc}"
            value = fallback()
        collected[name] = value
        snapshot[name] = value
    if errors:
        snapshot["section_errors"] = errors
    snapshot["findings"], snapshot["finding_counts"] = merge_findings(snapshot)
    return snapshot
