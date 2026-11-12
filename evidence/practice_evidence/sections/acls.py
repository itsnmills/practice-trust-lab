"""Effective file-share ACLs parsed from SDDL, plus least-privilege comparison.

Samba's ``ntacl`` command can render the effective NT ACL of a path as SDDL
without changing anything, which makes share exposure observable instead of
inferred from the smb.conf ``valid users`` line alone.

Read-only commands (safe for the collector allowlist):

    docker exec samba-dc cat /etc/samba/smb.conf
    docker exec samba-dc samba-tool ntacl get <path> --as-sddl
    docker exec samba-dc wbinfo -s <SID>
    docker exec samba-dc samba-tool group list
    docker exec samba-dc samba-tool user list

The SDDL parser is deliberately small and strict: owner/group tags, DACL flags,
allow vs deny ACEs, inheritance flags, numeric and common alphabetic masks, and
well-known/domain SIDs.  Anything it cannot parse is reported, never guessed.

Titles, severities, owner lanes and HIPAA cites for this section's rule ids live in
`practice_render.rules`, the single registry.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from ..config import SHARE_ACCESS_MODEL
from ..models import Finding, dump_findings, tagged_finding
from ..runner import ERROR_PREFIX, dexec
from .shares import parse_smb_conf

# --- well-known principals -------------------------------------------------

SID_NAMES: dict[str, str] = {
    "S-1-1-0": "Everyone",
    "S-1-2-0": "Local",
    "S-1-3-0": "CREATOR OWNER",
    "S-1-3-1": "CREATOR GROUP",
    "S-1-3-4": "OWNER RIGHTS",
    "S-1-5-7": "Anonymous",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-18": "Local System",
    "S-1-5-19": "Local Service",
    "S-1-5-20": "Network Service",
    "S-1-22-2-0": "UNIX root group",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-5-32-547": "Power Users",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-552": "Replicators",
    "S-1-5-32-554": "Pre-Windows 2000 Compatible Access",
    "S-1-5-32-555": "Remote Desktop Users",
    "S-1-5-32-556": "Network Configuration Operators",
    "S-1-5-32-562": "Distributed COM Users",
}

USER_RIDS = {500, 501}

# Domain-relative RIDs that have stable names in every AD domain.
DOMAIN_RID_NAMES: dict[int, str] = {
    500: "Administrator",
    501: "Guest",
    512: "Domain Admins",
    513: "Domain Users",
    514: "Domain Guests",
    515: "Domain Computers",
    516: "Domain Controllers",
    517: "Cert Publishers",
    518: "Schema Admins",
    519: "Enterprise Admins",
    520: "Group Policy Creator Owners",
    521: "Read-only Domain Controllers",
    522: "Cloneable Domain Controllers",
    525: "Protected Users",
    526: "Key Admins",
    527: "Enterprise Key Admins",
}

SDDL_ALIASES: dict[str, str] = {
    "WD": "S-1-1-0",
    "AN": "S-1-5-7",
    "AU": "S-1-5-11",
    "SY": "S-1-5-18",
    "LS": "S-1-5-19",
    "NS": "S-1-5-20",
    "BA": "S-1-5-32-544",
    "BU": "S-1-5-32-545",
    "BG": "S-1-5-32-546",
    "PU": "S-1-5-32-547",
    "AO": "S-1-5-32-548",
    "SO": "S-1-5-32-549",
    "PO": "S-1-5-32-550",
    "BO": "S-1-5-32-551",
    "RE": "S-1-5-32-552",
    "RU": "S-1-5-32-554",
    "CO": "S-1-3-0",
    "CG": "S-1-3-1",
    "OW": "S-1-3-4",
    "PS": "S-1-5-10",
    "ED": "S-1-5-9",
    "LA": "RID:500",
    "LG": "RID:501",
    "DA": "RID:512",
    "DU": "RID:513",
    "DG": "RID:514",
    "DC": "RID:515",
    "DD": "RID:516",
    "SA": "RID:518",
    "EA": "RID:519",
}

BROAD_READ_WRITE_SIDS = {"S-1-1-0", "S-1-5-11", "S-1-5-32-545"}
# Principals that are expected on every share and never a finding by themselves:
# built-in administrators, SYSTEM, and the CREATOR GROUP/OWNER template entries
# (which are substituted with a real principal when a child object is created).
ADMIN_NAMES = {
    "Administrator",
    "UNIX root group",
    "CREATOR GROUP",
    "Administrators",
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Local System",
    "CREATOR OWNER",
    "OWNER RIGHTS",
}

# --- access masks ----------------------------------------------------------

FILE_ALL_ACCESS = 0x1F01FF
GENERIC_WRITE = 0x40000000
GENERIC_ALL = 0x10000000
WRITE_BITS = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | GENERIC_WRITE | GENERIC_ALL

MASK_ALIASES: dict[str, int] = {
    "FA": FILE_ALL_ACCESS,
    "FR": 0x120089,
    "FW": 0x120116,
    "FX": 0x1200A0,
    "GA": GENERIC_ALL,
    "GR": 0x80000000,
    "GW": GENERIC_WRITE,
    "GE": 0x20000000,
    "RC": 0x20000,
    "WD": 0x2,  # write data / add file (also used for WRITE_DAC in some contexts)
    "WO": 0x80000,
    "RD": 0x1,
    "AD": 0x4,
    "REA": 0x8,
    "WEA": 0x10,
    "X": 0x20,
    "DC": 0x40,
    "RA": 0x80,
    "WA": 0x100,
    "SD": 0x10000,
}

_TAG_RE = re.compile(r"([OGDS]):")
_ACE_RE = re.compile(r"\(([^)]*)\)")


def domain_rid(sid: str) -> int | None:
    """Return the last RID of a ``S-1-5-21-a-b-c-rid`` SID, else None."""
    parts = sid.split("-")
    if len(parts) == 8 and parts[:4] == ["S", "1", "5", "21"] and parts[-1].isdigit():
        return int(parts[-1])
    return None


def normalize_sid(token: str) -> str:
    """Map an SDDL alias (WD/BA/AU/DA...) to a SID; pass SIDs through."""
    token = token.strip()
    alias = SDDL_ALIASES.get(token.upper())
    if alias is None:
        return token
    if alias.startswith("RID:"):
        return alias  # resolved later against the domain SID
    return alias


def parse_mask(raw: str) -> int | None:
    """Parse a numeric or alphabetic SDDL access mask; None when unparseable."""
    text = (raw or "").strip()
    if not text:
        return 0
    lowered = text.lower()
    try:
        if lowered.startswith("0x"):
            return int(text, 16)
        if text.isdigit():
            return int(text)
    except ValueError:
        return None
    total, index = 0, 0
    while index < len(text):
        for size in (3, 2, 1):
            chunk = text[index : index + size].upper()
            if chunk in MASK_ALIASES:
                total |= MASK_ALIASES[chunk]
                index += size
                break
        else:
            return None
    return total


def is_write(mask: int | None) -> bool:
    if not mask:
        return False
    return bool(mask & WRITE_BITS) or (mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS


def is_full_control(mask: int | None) -> bool:
    if not mask:
        return False
    return bool(mask & GENERIC_ALL) or (mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS


def _bare(name: str | None) -> str:
    """Strip a ``DOMAIN\\`` prefix and surrounding whitespace."""
    if not name:
        return ""
    return name.rsplit("\\", 1)[-1].strip()


def principal_name(sid: str, names: dict[str, str] | None = None) -> str:
    if sid in SID_NAMES:
        return SID_NAMES[sid]
    rid = domain_rid(sid)
    if rid is not None and rid in DOMAIN_RID_NAMES:
        return DOMAIN_RID_NAMES[rid]
    if names and sid in names:
        return _bare(names[sid])
    return sid


def _split_tags(text: str) -> dict[str, str]:
    """Split a compact SDDL string into its O:/G:/D:/S: tag values."""
    matches = list(_TAG_RE.finditer(text))
    values: dict[str, str] = {}
    for i, match in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        values[match.group(1)] = text[match.end() : end]
    return values


def parse_sddl(
    sddl: str,
    names: dict[str, str] | None = None,
    kinds: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Parse an SDDL security descriptor into owner/group/DACL/ACEs.

    Raises ``ValueError`` when the string is empty, an error sentinel, or has no
    recognizable owner/group/DACL tag.
    """
    if not sddl or sddl.startswith(ERROR_PREFIX):
        raise ValueError("no SDDL to parse")
    compact = "".join("".join(line.split()) for line in sddl.splitlines() if not line.lstrip().startswith("#"))
    tags = _split_tags(compact)
    if not tags:
        raise ValueError("no SDDL tags found")

    parsed: dict[str, Any] = {
        "owner": tags.get("O", ""),
        "group": tags.get("G", ""),
        "dacl_flags": "",
        "aces": [],
        "null_dacl": False,
    }
    if "D" not in tags:
        parsed["dacl_flags"] = "absent"
        return parsed

    dacl = tags["D"]
    flag_match = re.match(r"([A-Z]*)", dacl)
    flags = flag_match.group(1) if flag_match else ""
    parsed["dacl_flags"] = flags
    ace_blobs = _ACE_RE.findall(dacl[flag_match.end() :] if flag_match else dacl)
    # "D:" with no ACEs, or the explicit NO_ACCESS_CONTROL marker, is a null
    # DACL (everyone full control).  An empty DACL that carries flags such as
    # "AI" is different: it denies everything and is not a null DACL.
    if not ace_blobs and (dacl == "" or dacl.upper().startswith("NO_ACCESS")):
        parsed["null_dacl"] = True

    for blob in ace_blobs:
        parts = blob.split(";")
        if len(parts) < 6:
            continue
        ace_type, ace_flags, mask_raw, _object, _inherit_object, sid_raw = parts[:6]
        sid = normalize_sid(sid_raw)
        rid = None
        if sid.startswith("RID:"):
            rid = int(sid.split(":", 1)[1])
            sid = f"RID:{rid}"
            principal = DOMAIN_RID_NAMES.get(rid, sid)
        else:
            principal = principal_name(sid, names)
        kind = (kinds or {}).get(sid)
        if kind is None and rid in DOMAIN_RID_NAMES:
            kind = "user" if rid in USER_RIDS else "group"
        mask = parse_mask(mask_raw)
        parsed["aces"].append(
            {
                "type": {
                    "A": "allow",
                    "OA": "allow",
                    "D": "deny",
                    "OD": "deny",
                }.get(ace_type.upper(), ace_type.lower() or "unknown"),
                "flags": ace_flags,
                "mask": mask,
                "mask_hex": f"0x{mask:x}" if mask is not None else None,
                "sid": sid,
                "rid": rid,
                "principal": principal,
                "kind": kind,
                "inherited": "ID" in ace_flags,
                "inherit_only": "IO" in ace_flags,
                "object_inherit": "OI" in ace_flags,
                "container_inherit": "CI" in ace_flags,
                "write": is_write(mask),
                "full_control": is_full_control(mask),
            }
        )
    return parsed


def apply_principals(parsed: dict[str, Any], names: dict[str, str], kinds: dict[str, str]) -> None:
    """Fill display names/kinds on a descriptor parsed without a directory."""
    for ace in parsed["aces"]:
        sid = ace["sid"]
        ace["principal"] = principal_name(sid, names) if sid.startswith("S-1-") else ace["principal"]
        ace["kind"] = kinds.get(sid, ace.get("kind") or "unknown")


# --- share model comparison -----------------------------------------------


def parse_valid_users(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [_bare(token.lstrip("@+&")) for token in raw.split() if token.strip()]


def _same(left: str, right: str) -> bool:
    return _bare(left).casefold() == _bare(right).casefold()


def _in(name: str, values: set[str] | list[str]) -> bool:
    return any(_same(name, value) for value in values)


def evaluate_share(
    share: dict[str, Any],
    parsed: dict[str, Any],
    model: dict[str, Any] | None,
) -> list[Finding]:
    """Compare one parsed share descriptor to the documented access model."""
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    name = share.get("name") or share.get("path") or "share"

    def add(severity: str, rule_id: str, detail: str, subject: str, **extra: Any) -> None:
        key = (rule_id, subject)
        if key in seen:
            return
        seen.add(key)
        findings.append(tagged_finding(severity, detail, rule_id, subject, **extra))

    if parsed.get("null_dacl"):
        add("high", "ACL-NULL-DACL", f"{name}: null DACL grants full control to everyone", name)

    valid_users = parse_valid_users(share.get("valid users"))
    if not valid_users:
        add("medium", "ACL-NO-VALID-USERS", f"{name}: no smb.conf valid users gate", name)
    if model is None:
        add("info", "ACL-UNMODELED-SHARE", f"{name}: share is not in the documented least-privilege model", name)

    acl_allow: set[str] = set()
    unresolved: set[str] = set()
    for ace in parsed.get("aces", []):
        principal = ace.get("principal") or ace.get("sid") or "unknown"
        if principal in ADMIN_NAMES:
            continue
        if ace["type"] == "deny":
            continue
        # Inherit-only ACEs still apply to files under the share root, which is
        # what exposure is about, so they are evaluated too.
        acl_allow.add(principal)
        sid = ace.get("sid", "")
        identified = (
            ace.get("kind") in ("group", "user") or principal in ADMIN_NAMES or not str(principal).startswith("S-1-")
        )
        if ace.get("write"):
            if sid == "S-1-1-0":
                add("high", "ACL-EVERYONE-WRITE", f"{name}: Everyone has write access", f"{name}:Everyone")
            elif sid == "S-1-5-11":
                add(
                    "high",
                    "ACL-AUTHENTICATED-WRITE",
                    f"{name}: Authenticated Users has write access",
                    f"{name}:Authenticated Users",
                )
            elif (
                sid in BROAD_READ_WRITE_SIDS
                or domain_rid(sid) == 513
                or ace.get("rid") == 513
                or principal in ("Users", "Domain Users")
            ):
                add(
                    "medium",
                    "ACL-DOMAIN-USERS-WRITE",
                    f"{name}: broad built-in/domain principals have write access",
                    f"{name}:{principal}",
                )

        if not identified:
            unresolved.add(str(principal))
            continue

        if ace.get("kind") == "user":
            add(
                "medium",
                "ACL-USER-PRINCIPAL",
                f"{name}: ACL grants '{principal}' directly to a user account, not an AGDLP group",
                f"{name}:{principal}",
            )
        elif ace.get("kind") == "group" and not principal.startswith(("DL-", "SG-")):
            add(
                "low",
                "ACL-NON-AGDLP-GROUP",
                f"{name}: ACL grants '{principal}', which is outside the SG-/DL- naming model",
                f"{name}:{principal}",
            )

        if model is not None:
            if ace.get("write") and not _in(principal, model.get("write", set())):
                add(
                    "medium",
                    "ACL-UNDOCUMENTED-WRITE",
                    f"{name}: '{principal}' has write access but is not in the documented write set "
                    f"({', '.join(sorted(model.get('write', set()))) or 'none'})",
                    f"{name}:{principal}",
                )
            if not ace.get("write") and sid in BROAD_READ_WRITE_SIDS:
                add(
                    "medium",
                    "ACL-BROAD-READ",
                    f"{name}: '{principal}' can read the directory in the filesystem ACL, so access control "
                    f"rests only on the smb.conf valid users gate",
                    f"{name}:{principal}",
                )
            elif not ace.get("write") and not _in(principal, model.get("allow", set())):
                add(
                    "low",
                    "ACL-UNDOCUMENTED-READ",
                    f"{name}: '{principal}' can read but is not in the documented access set "
                    f"({', '.join(sorted(model.get('allow', set()))) or 'none'})",
                    f"{name}:{principal}",
                )
        if valid_users and ace.get("write") and not _in(principal, valid_users):
            add(
                "medium",
                "ACL-BROADER-THAN-VALID-USERS",
                f"{name}: ACL grants write to '{principal}', which smb.conf valid users does not list",
                f"{name}:{principal}",
            )

    for sid in sorted(unresolved):
        add(
            "info",
            "ACL-UNRESOLVED-PRINCIPAL",
            f"{name}: ACL principal {sid} could not be resolved to a name; the directory lookup may be unavailable",
            f"{name}:{sid}",
        )

    if valid_users:
        for required in valid_users:
            if not _in(required, acl_allow):
                add(
                    "medium",
                    "ACL-VALID-USERS-NOT-GRANTED",
                    f"{name}: valid user '{required}' has no matching allow entry in the filesystem ACL",
                    f"{name}:{required}",
                )
    return findings


# --- collection ------------------------------------------------------------


def _command_names(cmd: list[str]) -> set[str]:
    raw = dexec(cmd)
    return {_bare(line) for line in raw.splitlines() if line.strip() and not line.startswith(ERROR_PREFIX)}


def parse_wbinfo_name(raw: str) -> str:
    """Extract the account name from `wbinfo -s` output.

    Real output is ``DOMAIN\\name <sid-type>`` (e.g. ``MILLSLAB\\SG-IT 2``); a trailing
    ``(sid)`` is also tolerated. Failures (``failed to call wbcLookupSid``) give "".
    """
    line = raw.strip().splitlines()[0] if raw.strip() else ""
    if not line or line.lower().startswith(("failed", "could not", "error")):
        return ""
    line = line.split("(", 1)[0].strip()
    return re.sub(r"\s+\d+$", "", line)


def resolve_sids(sids: set[str], resolver: Callable[[str], str] | None = None) -> dict[str, str]:
    """Resolve non-well-known SIDs to names; unresolvable SIDs are omitted."""
    names: dict[str, str] = {}
    for sid in sorted(sids):
        if sid in SID_NAMES or domain_rid(sid) in DOMAIN_RID_NAMES:
            continue
        if resolver is not None:
            name = resolver(sid)
        else:
            raw = dexec(["wbinfo", "-s", sid])
            name = "" if raw.startswith(ERROR_PREFIX) else parse_wbinfo_name(raw)
        if name:
            names[sid] = _bare(name)
    return names


def kinds_for(names: dict[str, str], group_names: set[str], user_names: set[str]) -> dict[str, str]:
    kinds: dict[str, str] = {}
    for sid, name in names.items():
        bare = _bare(name)
        if bare in group_names:
            kinds[sid] = "group"
        elif bare in user_names:
            kinds[sid] = "user"
    return kinds


def collect() -> dict[str, Any]:
    conf = dexec(["cat", "/etc/samba/smb.conf"])
    if conf.startswith(ERROR_PREFIX):
        return {
            "shares": [],
            "findings": dump_findings(
                [
                    tagged_finding(
                        "info",
                        f"share ACLs could not be collected because smb.conf is unreadable ({conf[:120]})",
                        "ACL-UNAVAILABLE",
                        "smb.conf",
                    )
                ]
            ),
        }
    share_defs = parse_smb_conf(conf)
    group_names = _command_names(["samba-tool", "group", "list"])
    user_names = _command_names(["samba-tool", "user", "list"])
    findings: list[Finding] = []
    shares_out: list[dict[str, Any]] = []

    for share in share_defs:
        name = share.get("name", "")
        path = share.get("path")
        record: dict[str, Any] = {
            "name": name,
            "path": path,
            "valid_users": share.get("valid users", ""),
            "status": "ok",
            "aces": [],
        }
        if not path:
            record["status"] = "no-path"
            shares_out.append(record)
            continue
        sddl = dexec(["samba-tool", "ntacl", "get", path, "--as-sddl"])
        if sddl.startswith(ERROR_PREFIX):
            record["status"] = "unavailable"
            record["error"] = sddl[:200]
            findings.append(
                tagged_finding(
                    "info",
                    f"{name}: filesystem ACL could not be read ({sddl[:120]})",
                    "ACL-UNAVAILABLE",
                    name,
                )
            )
            shares_out.append(record)
            continue
        try:
            parsed = parse_sddl(sddl)
        except ValueError as exc:
            record["status"] = "parse-error"
            record["error"] = str(exc)
            findings.append(
                tagged_finding(
                    "medium",
                    f"{name}: filesystem ACL could not be parsed ({exc}); raw ACL withheld",
                    "ACL-PARSE-ERROR",
                    name,
                )
            )
            shares_out.append(record)
            continue

        sids = {ace["sid"] for ace in parsed["aces"] if ace["sid"].startswith("S-1-")}
        names = resolve_sids(sids)
        kinds = kinds_for(names, group_names, user_names)
        apply_principals(parsed, names, kinds)
        record.update(
            {
                "owner": principal_name(parsed["owner"], names),
                "group": principal_name(parsed["group"], names),
                "dacl_flags": parsed["dacl_flags"],
                "null_dacl": parsed["null_dacl"],
                "aces": parsed["aces"],
            }
        )
        findings += evaluate_share(share, parsed, SHARE_ACCESS_MODEL.get(name))
        shares_out.append(record)

    return {"shares": shares_out, "findings": dump_findings(findings)}
