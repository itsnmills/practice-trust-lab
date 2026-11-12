"""Typed building blocks shared by every section."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass(frozen=True)
class Finding:
    """One observation. Serialises to the flat dict used in the snapshot JSON.

    `rule_id` is a stable identifier from `practice_render.rules` (for example
    ``IDN-DORMANT-ACCOUNT``) and `subject` names the entity the finding is
    about (account name, file path, host, package). Both are optional so old
    snapshots and any third-party producer keep working; the renderer falls
    back to the legacy substring rules when `rule_id` is absent.
    """

    severity: str
    detail: str
    rule_id: str | None = None
    subject: str | None = None
    ref_key: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_ORDER:
            raise ValueError(f"unknown severity: {self.severity!r}")

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"severity": self.severity, "detail": self.detail}
        if self.rule_id:
            out["rule_id"] = self.rule_id
        if self.subject:
            out["subject"] = self.subject
        if self.ref_key:
            out["ref_key"] = self.ref_key
        out.update(self.extra)
        return out


def dump_findings(findings: list[Finding]) -> list[dict[str, Any]]:
    return [f.to_dict() for f in findings]
