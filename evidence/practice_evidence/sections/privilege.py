"""Privileged-account hygiene: role-group membership, nesting, UAC flags, SPNs.

The section expands role groups recursively (with cycle protection), decodes
``userAccountControl`` into named flags, and evaluates both privileged users and
service accounts.  It never reads credentials, hashes, or password values.

Read-only commands (safe for the collector allowlist):

    docker exec samba-dc samba-tool group list
    docker exec samba-dc samba-tool group listmembers <group>
    docker exec samba-dc samba-tool user list
    docker exec samba-dc samba-tool user show <sam>

Titles, severities, owner lanes and HIPAA cites for this section's rule ids live in
`practice_render.rules`, the single registry.
establishment and modification, §164.308(a)(3)(ii)(C) termination procedures,
§164.308(a)(5)(ii)(D) password management, §164.312(a)(2)(iv) encryption.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from ..config import ENDPOINTS, ROLE_GROUPS
from ..models import Finding, dump_findings, tagged_finding
from ..runner import ERROR_PREFIX, dexec

# userAccountControl bits (Microsoft 2.2.1.10 / LDAP uAC values).
UAC_FLAGS: dict[int, str] = {
    0x00000001: "SCRIPT",
    0x00000002: "ACCOUNTDISABLE",
    0x00000008: "HOMEDIR_REQUIRED",
    0x00000010: "LOCKOUT",
    0x00000020: "PASSWD_NOTREQD",
    0x00000040: "PASSWD_CANT_CHANGE",
    0x00000080: "ENCRYPTED_TEXT_PASSWORD_ALLOWED",
    0x00000100: "TEMP_DUPLICATE_ACCOUNT",
    0x00000200: "NORMAL_ACCOUNT",
    0x00000800: "INTERDOMAIN_TRUST_ACCOUNT",
    0x00001000: "WORKSTATION_TRUST_ACCOUNT",
    0x00002000: "SERVER_TRUST_ACCOUNT",
    0x00010000: "DONT_EXPIRE_PASSWORD",
    0x00020000: "MNS_LOGON_ACCOUNT",
    0x00040000: "SMARTCARD_REQUIRED",
    0x00080000: "TRUSTED_FOR_DELEGATION",
    0x00100000: "NOT_DELEGATED",
    0x00200000: "USE_DES_KEY_ONLY",
    0x00400000: "DONT_REQUIRE_PREAUTH",
    0x00800000: "PASSWORD_EXPIRED",
    0x01000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
    0x04000000: "PARTIAL_SECRETS_ACCOUNT",
}

UAC_DONT_EXPIRE_PASSWORD = 0x00010000
UAC_DONT_REQUIRE_PREAUTH = 0x00400000
UAC_ENCRYPTED_TEXT_PASSWORD = 0x00000080
UAC_ACCOUNTDISABLE = 0x00000002

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def parse_attributes(raw: str) -> dict[str, list[str]]:
    """Parse ``Key: value`` output, keeping every value of multi-valued attrs."""
    attrs: dict[str, list[str]] = {}
    for line in raw.splitlines():
        if line.startswith(ERROR_PREFIX) or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        if key:
            attrs.setdefault(key, []).append(value.strip())
    return attrs


def first(attrs: dict[str, list[str]], key: str) -> str | None:
    values = attrs.get(key)
    return values[0] if values else None


def parse_uac(value: str | int | None) -> int:
    if value is None:
        return 0
    text = str(value).strip()
    if not text:
        return 0
    try:
        return int(text, 0)
    except ValueError:
        try:
            return int(text)
        except ValueError:
            return 0


def decode_uac(value: str | int | None) -> list[str]:
    """Return the named flags set in a userAccountControl value, lowest bit first."""
    uac = parse_uac(value)
    return [name for bit, name in sorted(UAC_FLAGS.items()) if uac & bit]


def has_flag(value: str | int | None, flag: int) -> bool:
    return bool(parse_uac(value) & flag)


def filetime_to_datetime(value: str | int | None) -> datetime | None:
    try:
        ticks = int(value or 0)
    except (TypeError, ValueError):
        return None
    if ticks <= 0:
        return None
    return _FILETIME_EPOCH + timedelta(microseconds=ticks // 10)


def _parse_names(raw: str) -> list[str]:
    return [line.strip() for line in raw.splitlines() if line.strip() and not line.startswith(ERROR_PREFIX)]


def expand_group(
    group: str,
    members_by_group: dict[str, list[str]],
    group_names: set[str],
) -> dict[str, Any]:
    """Expand a group to effective users, recording nested groups and cycles."""
    direct = sorted({m for m in members_by_group.get(group, []) if m})
    users: set[str] = set()
    nested: set[str] = set()

    def walk(current: str, path: frozenset[str]) -> None:
        for member in members_by_group.get(current, []):
            if member in group_names:
                if member in path:
                    continue
                nested.add(member)
                walk(member, path | {member})
            else:
                users.add(member)

    walk(group, frozenset({group}))
    return {"direct": direct, "nested_groups": sorted(nested), "effective_users": sorted(users)}


def is_service_account(sam: str, attrs: dict[str, list[str]], uac: int) -> bool:
    if attrs.get("servicePrincipalName"):
        return True
    if sam.lower().startswith(("svc-", "svc_", "service-")):
        return True
    return bool(uac & 0x00002000)  # SERVER_TRUST_ACCOUNT


def classify_account(sam: str, attrs: dict[str, list[str]]) -> dict[str, Any]:
    uac = parse_uac(first(attrs, "userAccountControl"))
    last_logon = filetime_to_datetime(first(attrs, "lastLogonTimestamp")) or filetime_to_datetime(
        first(attrs, "lastLogon")
    )
    enabled = not bool(uac & UAC_ACCOUNTDISABLE)
    spns = attrs.get("servicePrincipalName", [])
    return {
        "sam": sam,
        "enabled": enabled,
        "uac": uac,
        "uac_flags": decode_uac(uac),
        "spn_count": len(spns),
        "service_account": is_service_account(sam, attrs, uac),
        "password_never_expires": bool(uac & UAC_DONT_EXPIRE_PASSWORD),
        "no_preauth": bool(uac & UAC_DONT_REQUIRE_PREAUTH),
        "reversible_encryption": bool(uac & UAC_ENCRYPTED_TEXT_PASSWORD),
        "password_expired": bool(uac & 0x00800000),
        "last_logon": last_logon.strftime("%Y-%m-%dT%H:%M:%SZ") if last_logon else None,
        "never_logged_on": enabled and last_logon is None,
    }


def account_findings(account: dict[str, Any], privileged: bool) -> list[Finding]:
    """Risk findings for one account; service risks apply to any service account."""
    sam = account["sam"]
    out: list[Finding] = []
    if not account["enabled"]:
        return out

    def add(severity: str, rule_id: str, detail: str, **extra: Any) -> None:
        out.append(tagged_finding(severity, detail, rule_id, sam, **extra))

    if account["spn_count"]:
        severity = "high" if privileged else "medium"
        add(
            severity,
            "PRIV-KERBEROASTABLE",
            f"{sam}: {account['spn_count']} service principal name(s) exposed to Kerberoasting",
            spn_count=account["spn_count"],
        )
    if account["no_preauth"]:
        add(
            "high",
            "PRIV-NO-PREAUTH",
            f"{sam}: Kerberos pre-authentication not required, so the account is AS-REP roastable ",
        )
    if account["reversible_encryption"]:
        add(
            "high",
            "PRIV-REVERSIBLE-ENCRYPTION",
            f"{sam}: account permits reversible password encryption ",
        )
    if (privileged or account["service_account"]) and account["password_never_expires"]:
        add(
            "medium",
            "PRIV-PASSWORD-NEVER-EXPIRES",
            f"{sam}: password is set to never expire ",
        )
    if privileged and account["never_logged_on"]:
        add(
            "medium",
            "PRIV-ADMIN-NEVER-LOGON",
            f"{sam}: privileged account is enabled but has never logged on; confirm the entitlement ",
        )
    return out


def interactive_admin_findings(
    accounts: list[dict[str, Any]],
    auth: dict[str, Any] | None,
    endpoint_names: set[str],
) -> list[Finding]:
    """Flag privileged accounts seen authenticating from endpoint hosts.

    Falls back to nothing when the auth summary has no per-workstation data; the
    current auth section records only per-user counts, so this stays quiet rather
    than guessing.
    """
    if not auth or not endpoint_names:
        return []
    by_user = auth.get("by_user") or {}
    by_workstation = auth.get("by_user_workstation") or {}
    out: list[Finding] = []
    for account in accounts:
        if not account.get("privileged"):
            continue
        sam = account["sam"]
        hosts: list[str] = []
        entry = by_user.get(sam)
        if isinstance(entry, dict) and isinstance(entry.get("workstations"), list):
            hosts += [str(h) for h in entry["workstations"]]
        if isinstance(by_workstation.get(sam), list):
            hosts += [str(h) for h in by_workstation[sam]]
        hits = sorted({h for h in hosts if h in endpoint_names})
        if hits:
            out.append(
                tagged_finding(
                    "medium",
                    f"{sam}: privileged account authenticated from endpoint(s) {', '.join(hits)}; "
                    f"use a separate admin account",
                    "PRIV-ADMIN-INTERACTIVE",
                    sam,
                    workstations=hits,
                )
            )
    return out


def collect(auth: dict[str, Any] | None = None) -> dict[str, Any]:
    group_names = set(_parse_names(dexec(["samba-tool", "group", "list"])))
    members_by_group: dict[str, list[str]] = {}
    findings: list[Finding] = []

    pending = [g for g in ROLE_GROUPS if g]
    fetched: set[str] = set()
    while pending:
        group = pending.pop(0)
        if group in fetched:
            continue
        fetched.add(group)
        raw = dexec(["samba-tool", "group", "listmembers", group])
        if raw.startswith(ERROR_PREFIX):
            findings.append(
                tagged_finding(
                    "info",
                    f"{group}: membership could not be read ({raw[:120]})",
                    "PRIV-GROUP-UNAVAILABLE",
                    group,
                )
            )
            members_by_group[group] = []
            continue
        members = _parse_names(raw)
        members_by_group[group] = members
        for member in members:
            if member in group_names and member not in fetched:
                pending.append(member)

    roles: dict[str, Any] = {}
    privileged: set[str] = set()
    for group in ROLE_GROUPS:
        expansion = expand_group(group, members_by_group, group_names)
        roles[group] = expansion
        privileged.update(expansion["effective_users"])
        for nested in expansion["nested_groups"]:
            findings.append(
                tagged_finding(
                    "low",
                    f"{group}: privileged membership reaches '{nested}' through group nesting; "
                    f"review the nested entitlement",
                    "PRIV-NESTED-ADMIN",
                    group,
                    nested_group=nested,
                )
            )

    accounts: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for sam in _parse_names(dexec(["samba-tool", "user", "list"])):
        raw = dexec(["samba-tool", "user", "show", sam])
        if raw.startswith(ERROR_PREFIX) or not raw.strip():
            # Do not guess at flags from a failed lookup; an empty UAC would
            # otherwise look like an enabled, never-logged-on account.
            continue
        account = classify_account(sam, parse_attributes(raw))
        is_privileged = sam in privileged
        account["privileged"] = is_privileged
        account["role_groups"] = [g for g, info in roles.items() if sam in info["effective_users"]]
        accounts.append(account)
        for finding in account_findings(account, is_privileged):
            key = (finding.rule_id or "", finding.subject or "")
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)

    endpoint_names = {host["name"] for host in ENDPOINTS}
    findings += interactive_admin_findings(accounts, auth, endpoint_names)

    return {"role_groups": roles, "accounts": accounts, "findings": dump_findings(findings)}
