"""Domain password and lockout policy evaluation against a documented baseline.

The baseline is a frozen dataclass (`PolicyBaseline`) so a caller can override
any threshold without editing detection logic.  The lab's own policy is
deliberately weak in places (minimum length 10, 42-day maximum age) and is
expected to trip the minimum-length rule and the excessive-rotation rule.

Read-only commands (safe for the collector allowlist):

    docker exec samba-dc samba-tool domain passwordsettings show

Titles, severities, owner lanes and HIPAA cites for this section's rule ids live in
`practice_render.rules`, the single registry.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any

from ..models import Finding, dump_findings, tagged_finding
from ..runner import ERROR_PREFIX, dexec


@dataclass(frozen=True)
class PolicyBaseline:
    """Documented small-clinic baseline.  Every value can be overridden.

    This is a conventional Windows/insurer-style baseline (complexity on, bounded
    expiry, history 24).  It is NOT aligned with NIST SP 800-63B-4, which says
    verifiers SHALL NOT impose composition rules or periodic changes and requires
    15 characters for single-factor passwords.  See docs/ARCHITECTURE.md.
    """

    min_length: int = 12
    complexity_required: bool = True
    history_min: int = 24
    max_age_ceiling_days: int = 365
    min_max_age_days: int = 90  # very short expiry breeds predictable password changes
    min_age_days: int = 1
    lockout_threshold_max: int = 10
    lockout_duration_min: int = 15
    lockout_reset_max: int = 15
    allow_plaintext: bool = False


DEFAULT_BASELINE = PolicyBaseline()

_FIELDS = {
    "min_length": ("Minimum password length", "min password length"),
    "complexity": ("Password complexity", "complexity"),
    "history": ("Password history length", "password history"),
    "max_age": ("Maximum password age (days)", "maximum password age"),
    "min_age": ("Minimum password age (days)", "minimum password age"),
    "lockout_threshold": ("Account lockout threshold (attempts)", "lockout threshold"),
    "lockout_duration": ("Account lockout duration (mins)", "lockout duration"),
    "lockout_reset": ("Reset account lockout after (mins)", "reset account lockout after"),
    "plaintext": ("Store plaintext passwords", "store plaintext passwords"),
}

_UNLIMITED = {"", "unlimited", "none", "never", "not set", "n/a", "unknown"}
_TRUE = {"on", "yes", "true", "enabled", "1"}
_FALSE = {"off", "no", "false", "disabled", "0"}


def parse_settings(raw: str) -> dict[str, str]:
    """Parse ``Key: value`` lines, dropping command errors and blank keys."""
    settings: dict[str, str] = {}
    for line in raw.splitlines():
        if line.startswith(ERROR_PREFIX) or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        if key:
            settings[key] = value.strip()
    return settings


def _lookup(settings: dict[str, str], aliases: tuple[str, ...]) -> str | None:
    lowered = {k.lower(): v for k, v in settings.items()}
    for alias in aliases:
        if alias.lower() in lowered:
            return lowered[alias.lower()]
    return None


def parse_number(raw: str | None) -> int | None:
    """First integer in a value; ``unlimited``/``none``/empty become ``None``."""
    if raw is None:
        return None
    text = str(raw).strip().lower()
    if text in _UNLIMITED:
        return None
    match = re.search(r"-?\d+", text)
    return int(match.group(0)) if match else None


def parse_bool(raw: str | None) -> bool | None:
    if raw is None:
        return None
    text = str(raw).strip().lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    return None


def _cite(*sections: str) -> str:
    return "HIPAA " + ", ".join(f"§{s}" for s in sections)


def _observed(settings: dict[str, str], key: str) -> int | None:
    return parse_number(_lookup(settings, _FIELDS[key]))


def normalized(settings: dict[str, str]) -> dict[str, Any]:
    """Stable, JSON-friendly view of the policy for the snapshot."""
    return {
        "min_length": _observed(settings, "min_length"),
        "max_age_days": _observed(settings, "max_age"),
        "min_age_days": _observed(settings, "min_age"),
        "history": _observed(settings, "history"),
        "lockout_threshold": _observed(settings, "lockout_threshold"),
        "lockout_duration_mins": _observed(settings, "lockout_duration"),
        "lockout_reset_mins": _observed(settings, "lockout_reset"),
        "complexity": parse_bool(_lookup(settings, _FIELDS["complexity"])),
        "plaintext": parse_bool(_lookup(settings, _FIELDS["plaintext"])),
    }


def evaluate(settings: dict[str, str], baseline: PolicyBaseline = DEFAULT_BASELINE) -> list[Finding]:
    """Compare parsed settings to the baseline; one finding per failed control."""
    findings: list[Finding] = []

    def add(severity: str, rule_id: str, detail: str, **extra: Any) -> None:
        findings.append(tagged_finding(severity, detail, rule_id, "domain", **extra))

    min_len = _observed(settings, "min_length")
    if min_len is None:
        add("medium", "POL-MIN-LENGTH", f"domain password minimum length not reported; baseline {baseline.min_length}")
    elif min_len < baseline.min_length:
        severity = "high" if min_len < 8 else "medium"
        add(
            severity,
            "POL-MIN-LENGTH",
            f"domain password minimum length {min_len} is below baseline {baseline.min_length}",
            observed=min_len,
            baseline=baseline.min_length,
        )

    complexity = parse_bool(_lookup(settings, _FIELDS["complexity"]))
    if baseline.complexity_required and complexity is None:
        add("low", "POL-COMPLEXITY", "domain password complexity not reported; baseline requires it")
    elif baseline.complexity_required and not complexity:
        add("medium", "POL-COMPLEXITY", "domain password complexity is disabled; baseline requires it")

    history = _observed(settings, "history")
    if history is None or history < baseline.history_min:
        observed = "unlimited" if history is None else history
        add(
            "low",
            "POL-HISTORY",
            f"domain password history {observed} is below baseline {baseline.history_min}",
            observed=history,
            baseline=baseline.history_min,
        )

    max_age = _observed(settings, "max_age")
    if max_age is None:
        add(
            "low",
            "POL-MAX-AGE",
            f"domain passwords never expire; baseline ceiling {baseline.max_age_ceiling_days} days",
        )
    elif max_age > baseline.max_age_ceiling_days:
        add(
            "low",
            "POL-MAX-AGE",
            f"domain password maximum age {max_age} days exceeds baseline {baseline.max_age_ceiling_days}",
            observed=max_age,
            baseline=baseline.max_age_ceiling_days,
        )
    elif 0 < max_age < baseline.min_max_age_days:
        add(
            "low",
            "POL-MAX-AGE",
            f"domain password maximum age {max_age} days forces frequent rotation; "
            f"baseline floor {baseline.min_max_age_days} days",
            observed=max_age,
            baseline=baseline.min_max_age_days,
        )

    min_age = _observed(settings, "min_age")
    if min_age is not None and min_age < baseline.min_age_days:
        add(
            "info",
            "POL-MIN-AGE",
            f"domain password minimum age {min_age} days allows immediate reuse",
            observed=min_age,
            baseline=baseline.min_age_days,
        )

    threshold = _observed(settings, "lockout_threshold")
    if threshold is None or threshold == 0:
        add(
            "high",
            "POL-LOCKOUT-THRESHOLD",
            f"domain account lockout is disabled (threshold {threshold if threshold is not None else 'unset'}); "
            f"baseline 1-{baseline.lockout_threshold_max} attempts",
            observed=threshold,
            baseline=baseline.lockout_threshold_max,
        )
    elif threshold > baseline.lockout_threshold_max:
        add(
            "medium",
            "POL-LOCKOUT-THRESHOLD",
            f"domain account lockout threshold {threshold} exceeds baseline {baseline.lockout_threshold_max}",
            observed=threshold,
            baseline=baseline.lockout_threshold_max,
        )

    duration = _observed(settings, "lockout_duration")
    reset = _observed(settings, "lockout_reset")
    if duration is None:
        add("low", "POL-LOCKOUT-DURATION", "domain lockout duration not reported")
    elif duration != 0 and duration < baseline.lockout_duration_min:
        add(
            "low",
            "POL-LOCKOUT-DURATION",
            f"domain lockout duration {duration} min is below baseline {baseline.lockout_duration_min}",
            observed=duration,
            baseline=baseline.lockout_duration_min,
        )
    if reset is not None and duration is not None and duration > 0 and reset > duration:
        add(
            "medium",
            "POL-LOCKOUT-RESET",
            f"lockout reset counter {reset} min exceeds lockout duration {duration} min, so lockouts clear early",
            observed_reset=reset,
            observed_duration=duration,
        )
    elif reset is not None and reset > baseline.lockout_reset_max:
        add(
            "low",
            "POL-LOCKOUT-RESET",
            f"lockout reset counter {reset} min exceeds baseline {baseline.lockout_reset_max}",
            observed=reset,
            baseline=baseline.lockout_reset_max,
        )

    plaintext = parse_bool(_lookup(settings, _FIELDS["plaintext"]))
    if plaintext is None:
        add(
            "low",
            "POL-PLAINTEXT",
            "plaintext password storage setting not reported; baseline off",
        )
    elif plaintext and not baseline.allow_plaintext:
        add(
            "high",
            "POL-PLAINTEXT",
            "domain stores passwords with reversible (plaintext-equivalent) encryption",
        )

    return findings


def collect(baseline: PolicyBaseline = DEFAULT_BASELINE) -> dict[str, Any]:
    raw = dexec(["samba-tool", "domain", "passwordsettings", "show"])
    settings = parse_settings(raw)
    if raw.startswith(ERROR_PREFIX) or not settings:
        finding = tagged_finding(
            "info",
            f"password policy could not be read: {raw[:200]}",
            "POL-UNAVAILABLE",
            "domain",
        )
        return {
            "baseline": asdict(baseline),
            "settings": settings,
            "evaluated": {},
            "findings": dump_findings([finding]),
        }
    return {
        "baseline": asdict(baseline),
        "settings": settings,
        "evaluated": normalized(settings),
        "findings": dump_findings(evaluate(settings, baseline)),
    }
