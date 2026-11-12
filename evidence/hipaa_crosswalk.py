"""HIPAA citation crosswalk for packet finding groups.

Informational mapping from the lab's finding groups to the HIPAA Security Rule
(45 CFR Part 164 Subpart C) and, where a finding is about disclosure, the
Privacy Rule. It shows which provisions an item is *relevant to* so a reviewer
can route it. It is not a compliance determination, a gap assessment, or legal
advice. `kind` follows the regulation text: "standard", "required" or
"addressable" implementation specification, or "privacy" for Privacy Rule cites.

The mapping and citation objects now live in the single rules registry
(`practice_render.rules`); this module is the stable import path used by tests
and downstream scripts.
"""

from __future__ import annotations

from practice_render.rules import (  # noqa: F401 - re-exported public surface
    ACCESS_CONTROL,
    ACCESS_MGMT,
    ACTIVITY_REVIEW,
    AUDIT_CONTROLS,
    AUTHENTICATION,
    BA_ARRANGEMENTS,
    BA_DISCLOSURE,
    DEVICE_MEDIA,
    ENCRYPTION,
    HIPAA_BY_GROUP,
    LOGIN_MONITORING,
    MALWARE,
    MIN_NECESSARY,
    PWD_MANAGEMENT,
    RISK_ANALYSIS,
    RISK_MGMT,
    TERMINATION,
    TRANSMISSION,
    Cite,
    cites_for,
    format_cites,
)

CROSSWALK: dict[str, tuple[Cite, ...]] = HIPAA_BY_GROUP

__all__ = [
    "ACCESS_CONTROL",
    "ACCESS_MGMT",
    "ACTIVITY_REVIEW",
    "AUDIT_CONTROLS",
    "AUTHENTICATION",
    "BA_ARRANGEMENTS",
    "BA_DISCLOSURE",
    "CROSSWALK",
    "Cite",
    "DEVICE_MEDIA",
    "ENCRYPTION",
    "LOGIN_MONITORING",
    "MALWARE",
    "MIN_NECESSARY",
    "PWD_MANAGEMENT",
    "RISK_ANALYSIS",
    "RISK_MGMT",
    "TERMINATION",
    "TRANSMISSION",
    "cites_for",
    "format_cites",
]
