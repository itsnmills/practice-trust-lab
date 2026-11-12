"""Domain-controller hygiene signals available without changing anything.

Covers the domain functional level, krbtgt password age, and the SMB/LDAP
protocol settings in smb.conf that decide whether signing, strong LDAP
authentication, NTLMv1, and SMB1 are permitted.

Read-only commands (safe for the collector allowlist):

    docker exec samba-dc samba-tool domain level show
    docker exec samba-dc samba-tool user show krbtgt
    docker exec samba-dc cat /etc/samba/smb.conf

HIPAA routing: §164.312(e)(1) transmission security, §164.312(d) authentication,
§164.308(a)(5)(ii)(D) password management, §164.312(a)(1) access control.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

from ..config import KRBTGT_MAX_AGE_DAYS, MIN_DOMAIN_FUNCTION_LEVEL
from ..models import Finding, dump_findings
from ..runner import ERROR_PREFIX, dexec
from .policy import tagged_finding

TRANSMISSION = "164.312(e)(1)"
AUTHENTICATION = "164.312(d)"
PWD_MANAGEMENT = "164.308(a)(5)(ii)(D)"
ACCESS_CONTROL = "164.312(a)(1)"

RULES: dict[str, dict[str, Any]] = {
    "HYG-DOMAIN-FUNCTION-LEVEL": {"group": "hygiene", "title": "Domain functional level below baseline"},
    "HYG-KRBTGT-AGE": {"group": "hygiene", "title": "krbtgt password older than baseline"},
    "HYG-SMB-SIGNING": {"group": "hygiene", "title": "SMB signing not required"},
    "HYG-LDAP-STRONG-AUTH": {"group": "hygiene", "title": "LDAP strong authentication not required"},
    "HYG-NTLM-AUTH": {"group": "hygiene", "title": "NTLMv1 authentication permitted"},
    "HYG-SMB1": {"group": "hygiene", "title": "SMB1 protocol permitted"},
    "HYG-UNAVAILABLE": {"group": "hygiene", "title": "Hygiene signal could not be read"},
}

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_SMB1_VALUES = {"nt1", "smb1", "core", "coreplus"}
_SMB_SIGNING_REQUIRED = {"mandatory", "required"}
_LDAP_STRONG_ENABLED = {"yes", "true", "on", "1"}
_NTLM_SAFE = {"no", "false", "off", "0", "ntlmv2-only", "ntlmv2_only"}


def filetime_to_datetime(value: str | int | None) -> datetime | None:
    try:
        ticks = int(value or 0)
    except (TypeError, ValueError):
        return None
    if ticks <= 0:
        return None
    return _FILETIME_EPOCH + timedelta(microseconds=ticks // 10)


def parse_global(conf: str) -> dict[str, str]:
    """Return lower-cased ``[global]`` options; other sections are ignored."""
    options: dict[str, str] = {}
    in_global = False
    for line in conf.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_global = stripped[1:-1].strip().lower() == "global"
            continue
        if not in_global or not stripped or stripped[0] in "#;" or "=" not in line:
            continue
        key, _, value = line.partition("=")
        options[key.strip().lower()] = value.strip()
    return options


def parse_function_level(raw: str) -> dict[str, str]:
    levels: dict[str, str] = {}
    for line in raw.splitlines():
        if line.startswith(ERROR_PREFIX) or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        if "function level" in key:
            levels[key] = value.strip()
    return levels


def level_rank(text: str | None) -> tuple[int, int] | None:
    """Rank a functional-level string such as ``(Windows) 2016`` or ``2008 R2``."""
    if not text:
        return None
    match = re.search(r"(2000|2003|2008|2012|2016)", text)
    if not match:
        return None
    year = int(match.group(1))
    r2 = 1 if re.search(r"\bR2\b", text, re.I) else 0
    return (year, r2)


def krbtgt_age_days(raw: str, now: datetime | None = None) -> int | None:
    for line in raw.splitlines():
        if line.lower().startswith("pwdlastset:"):
            changed = filetime_to_datetime(line.partition(":")[2].strip())
            if changed is None:
                return None
            current = now or datetime.now(timezone.utc)
            return max((current - changed).days, 0)
    return None


def smb1_setting(settings: dict[str, str]) -> str | None:
    """Return the option name that enables SMB1, or None."""
    for key in ("server min protocol", "client min protocol", "protocol"):
        value = settings.get(key)
        if value and value.strip().lower() in _SMB1_VALUES:
            return key
    max_protocol = settings.get("server max protocol")
    if max_protocol and max_protocol.strip().lower() in _SMB1_VALUES:
        return "server max protocol"
    return None


def evaluate(
    levels: dict[str, str],
    smb: dict[str, str],
    krbtgt_days: int | None,
    min_level: str = MIN_DOMAIN_FUNCTION_LEVEL,
    krbtgt_max_age: int = KRBTGT_MAX_AGE_DAYS,
) -> list[Finding]:
    findings: list[Finding] = []

    domain_level = levels.get("domain function level")
    observed = level_rank(domain_level)
    baseline = level_rank(min_level)
    if observed is None:
        findings.append(
            tagged_finding(
                "low",
                f"domain functional level could not be parsed ({domain_level or 'unset'})",
                "HYG-DOMAIN-FUNCTION-LEVEL",
                "domain",
            )
        )
    elif baseline is not None and observed < baseline:
        findings.append(
            tagged_finding(
                "low",
                f"domain functional level {domain_level} is below baseline {min_level} ",
                "HYG-DOMAIN-FUNCTION-LEVEL",
                "domain",
                observed=domain_level,
                baseline=min_level,
            )
        )

    if krbtgt_days is None:
        findings.append(
            tagged_finding(
                "low",
                f"krbtgt password age could not be determined; baseline rotation every {krbtgt_max_age} days ",
                "HYG-KRBTGT-AGE",
                "krbtgt",
            )
        )
    elif krbtgt_days > krbtgt_max_age:
        findings.append(
            tagged_finding(
                "medium",
                f"krbtgt password is {krbtgt_days} days old, above the {krbtgt_max_age}-day rotation baseline ",
                "HYG-KRBTGT-AGE",
                "krbtgt",
                observed_days=krbtgt_days,
                baseline_days=krbtgt_max_age,
            )
        )

    signing = smb.get("server signing")
    if signing is None:
        findings.append(
            tagged_finding(
                "low",
                "SMB signing is not explicitly required",
                "HYG-SMB-SIGNING",
                "global",
            )
        )
    elif signing.strip().lower() not in _SMB_SIGNING_REQUIRED:
        findings.append(
            tagged_finding(
                "medium",
                f"SMB signing is '{signing}', not mandatory, so traffic can be relayed ",
                "HYG-SMB-SIGNING",
                "global",
                observed=signing,
            )
        )

    strong_auth = smb.get("ldap server require strong auth")
    if strong_auth is not None and strong_auth.strip().lower() not in _LDAP_STRONG_ENABLED:
        severity = "high" if strong_auth.strip().lower() in ("no", "false", "off", "0") else "medium"
        findings.append(
            tagged_finding(
                severity,
                f"LDAP strong authentication is '{strong_auth}', permitting unsigned or cleartext binds ",
                "HYG-LDAP-STRONG-AUTH",
                "global",
                observed=strong_auth,
            )
        )

    ntlm = smb.get("ntlm auth")
    if ntlm is not None and ntlm.strip().lower() not in _NTLM_SAFE:
        findings.append(
            tagged_finding(
                "medium",
                f"NTLM authentication is '{ntlm}', which permits weaker NTLMv1 responses ",
                "HYG-NTLM-AUTH",
                "global",
                observed=ntlm,
            )
        )

    smb1 = smb1_setting(smb)
    if smb1 is not None:
        severity = "high" if smb1.startswith("server") or smb1 == "protocol" else "medium"
        findings.append(
            tagged_finding(
                severity,
                f"SMB1 is permitted by '{smb1} = {smb[smb1]}'",
                "HYG-SMB1",
                smb1,
                observed=smb[smb1],
            )
        )

    return findings


def collect() -> dict[str, Any]:
    levels = parse_function_level(dexec(["samba-tool", "domain", "level", "show"]))
    krbtgt_raw = dexec(["samba-tool", "user", "show", "krbtgt"])
    conf = dexec(["cat", "/etc/samba/smb.conf"])
    smb = parse_global(conf)

    if not levels and not smb:
        finding = tagged_finding(
            "info",
            f"domain hygiene signals could not be read ({krbtgt_raw[:120]})",
            "HYG-UNAVAILABLE",
            "domain",
        )
        return {"functional_level": {}, "smb": smb, "krbtgt": {}, "findings": dump_findings([finding])}

    days = None if krbtgt_raw.startswith(ERROR_PREFIX) else krbtgt_age_days(krbtgt_raw)
    krbtgt = {
        "sam": "krbtgt",
        "password_age_days": days,
        "baseline_days": KRBTGT_MAX_AGE_DAYS,
    }
    settings = {
        key: smb[key]
        for key in (
            "server signing",
            "ldap server require strong auth",
            "ntlm auth",
            "server min protocol",
            "client min protocol",
            "server max protocol",
            "protocol",
        )
        if key in smb
    }
    return {
        "functional_level": levels,
        "smb": settings,
        "krbtgt": krbtgt,
        "findings": dump_findings(evaluate(levels, smb, days)),
    }
