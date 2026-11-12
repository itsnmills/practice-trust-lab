"""Identity: users, password policy, privileged groups."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from ..config import PRIVILEGED_GROUPS, STALE_DAYS
from ..models import Finding, dump_findings
from ..runner import ERROR_PREFIX, dexec

BUILTIN_ACCOUNTS = ("Administrator", "Guest", "krbtgt")
UAC_ACCOUNTDISABLE = 0x2
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def parse_key_value(raw: str) -> dict[str, str]:
    """Parse `Key: value` lines (samba-tool output) into a dict."""
    out: dict[str, str] = {}
    for line in raw.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            out[key.strip()] = val.strip()
    return out


def filetime_to_datetime(value: str | int | None) -> datetime | None:
    """Windows FILETIME (100ns ticks since 1601) -> aware datetime; None if unset/invalid."""
    try:
        ticks = int(value or 0)
    except (TypeError, ValueError):
        return None
    if ticks <= 0:
        return None
    return _FILETIME_EPOCH + timedelta(microseconds=ticks // 10)


def parse_user_list(raw: str) -> list[str]:
    return [
        line.strip()
        for line in raw.splitlines()
        if line.strip() and not line.startswith(ERROR_PREFIX) and line.strip() not in BUILTIN_ACCOUNTS
    ]


def classify_user(sam: str, attrs: dict[str, str], now: datetime) -> dict[str, Any]:
    uac = int(attrs.get("userAccountControl", "0") or 0)
    enabled = not bool(uac & UAC_ACCOUNTDISABLE)
    last = filetime_to_datetime(attrs.get("lastLogonTimestamp"))
    return {
        "sam": sam,
        "enabled": enabled,
        "last_logon": last.strftime("%Y-%m-%dT%H:%M:%SZ") if last else None,
        "stale": bool(enabled and last and (now - last).days > STALE_DAYS),
        "never_logged_on": bool(enabled and (last is None or last.year == 1601)),
    }


def user_findings(entry: dict[str, Any]) -> list[Finding]:
    sam, out = entry["sam"], []
    if not entry["enabled"]:
        out.append(
            Finding(
                "info",
                f"{sam}: disabled account present (verify it is required)",
                rule_id="IDN-DISABLED-ACCOUNT",
                subject=sam,
            )
        )
    if entry["stale"]:
        out.append(
            Finding(
                "medium",
                f"{sam}: no logon in >{STALE_DAYS} days",
                rule_id="IDN-STALE-ACCOUNT",
                subject=sam,
            )
        )
    if entry["never_logged_on"]:
        out.append(
            Finding(
                "low",
                f"{sam}: enabled account has never logged on",
                rule_id="IDN-DORMANT-ACCOUNT",
                subject=sam,
            )
        )
    return out


def collect() -> dict[str, Any]:
    policy = parse_key_value(dexec(["samba-tool", "domain", "passwordsettings", "show"]))
    now = datetime.now(timezone.utc)
    users, findings = [], []
    for sam in parse_user_list(dexec(["samba-tool", "user", "list"])):
        entry = classify_user(sam, parse_key_value(dexec(["samba-tool", "user", "show", sam])), now)
        users.append(entry)
        findings += user_findings(entry)

    groups = {}
    for group in PRIVILEGED_GROUPS:
        members = dexec(["samba-tool", "group", "listmembers", group]).splitlines()
        groups[group] = [m.strip() for m in members if m.strip()]
    if groups.get("SG-IT"):
        findings.append(
            Finding(
                "medium",
                "SG-IT membership = local admin equivalent; confirm business need and MFA path",
                rule_id="IDN-ADMIN-GROUP",
                subject="SG-IT",
            )
        )
    return {
        "password_policy": policy,
        "users": users,
        "privileged_groups": groups,
        "findings": dump_findings(findings),
    }
