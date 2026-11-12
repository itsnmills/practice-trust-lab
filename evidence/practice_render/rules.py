"""Single registry of reviewer-facing rules, keyed by stable rule id.

Every finding the collector emits carries a `rule_id` from this module plus a
`subject` (the account, file, host, or package the finding is about). The packet
renderer and the HIPAA crosswalk both read this table, so rewording a finding's
human-readable `detail` no longer changes its grouping, owner lane, due window,
or citations.

Snapshots written before `rule_id` existed still render: each rule keeps the
substring it used to match on (`legacy_matches`) and the renderer falls back to
that for findings without a rule id.

This is a routing aid, not a compliance determination or legal advice.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, NamedTuple

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
SEVERITY_TAG = {"high": "P1", "medium": "P2", "low": "P3", "info": "P4"}

# Canonical display order for grouped rows; unmapped groups sort last.
GROUP_ORDER = [
    "supply",
    "scribe",
    "endpoint",
    "shares",
    "intake",
    "auth",
    "admin",
    "proto",
    "dormant",
    "disabled",
    "cached",
    "policy",
    "acl",
    "svc",
    "hygiene",
    "other",
]

# Groups that collapse multiple findings into one evidence row.
CONSOLIDATED_GROUPS = frozenset(
    {"supply", "scribe", "endpoint", "shares", "intake", "auth", "admin", "dormant", "disabled", "cached"}
)


class Cite(NamedTuple):
    """One HIPAA provision: section, heading, and implementation-spec kind."""

    section: str
    title: str
    kind: str


RISK_ANALYSIS = Cite("164.308(a)(1)(ii)(A)", "Risk analysis", "required")
RISK_MGMT = Cite("164.308(a)(1)(ii)(B)", "Risk management", "required")
ACTIVITY_REVIEW = Cite("164.308(a)(1)(ii)(D)", "Information system activity review", "required")
ACCESS_MGMT = Cite("164.308(a)(4)(ii)(C)", "Access establishment and modification", "addressable")
TERMINATION = Cite("164.308(a)(3)(ii)(C)", "Termination procedures", "addressable")
MALWARE = Cite("164.308(a)(5)(ii)(B)", "Protection from malicious software", "addressable")
LOGIN_MONITORING = Cite("164.308(a)(5)(ii)(C)", "Log-in monitoring", "addressable")
PWD_MANAGEMENT = Cite("164.308(a)(5)(ii)(D)", "Password management", "addressable")
BA_ARRANGEMENTS = Cite("164.308(b)(1)", "Business associate contracts and other arrangements", "standard")
BA_DISCLOSURE = Cite("164.502(e)(1)", "Disclosures to business associates", "privacy")
MIN_NECESSARY = Cite("164.502(b)", "Minimum necessary", "privacy")
DEVICE_MEDIA = Cite("164.310(d)(1)", "Device and media controls", "standard")
ACCESS_CONTROL = Cite("164.312(a)(1)", "Access control", "standard")
ENCRYPTION = Cite("164.312(a)(2)(iv)", "Encryption and decryption", "addressable")
AUDIT_CONTROLS = Cite("164.312(b)", "Audit controls", "standard")
AUTHENTICATION = Cite("164.312(d)", "Person or entity authentication", "standard")
TRANSMISSION = Cite("164.312(e)(1)", "Transmission security", "standard")

# Provisions each finding group is relevant to. Kept as the group-level table
# that the crosswalk has always exposed; individual rules inherit from it.
HIPAA_BY_GROUP: dict[str, tuple[Cite, ...]] = {
    "supply": (RISK_ANALYSIS, RISK_MGMT, MALWARE),
    "scribe": (BA_ARRANGEMENTS, BA_DISCLOSURE),
    "endpoint": (DEVICE_MEDIA, ACCESS_CONTROL, ENCRYPTION),
    "shares": (ACCESS_CONTROL, MIN_NECESSARY),
    "intake": (TRANSMISSION, ACCESS_CONTROL),
    "auth": (LOGIN_MONITORING, AUDIT_CONTROLS, ACTIVITY_REVIEW),
    "admin": (AUTHENTICATION, ACCESS_MGMT),
    "dormant": (TERMINATION, ACCESS_MGMT),
    "disabled": (TERMINATION,),
    "cached": (DEVICE_MEDIA, ACCESS_CONTROL),
    "policy": (PWD_MANAGEMENT, AUTHENTICATION),
    "acl": (ACCESS_CONTROL, MIN_NECESSARY),
    "svc": (AUTHENTICATION, ACCESS_MGMT, PWD_MANAGEMENT),
    "hygiene": (TRANSMISSION, AUTHENTICATION, ACCESS_CONTROL),
}


def cites_for(group: str) -> tuple[Cite, ...]:
    """Citations for a finding group; empty for unmapped groups."""
    return HIPAA_BY_GROUP.get(group, ())


def format_cites(cites: tuple[Cite, ...]) -> str:
    return "; ".join(f"\u00a7{c.section}" for c in cites)


@dataclass(frozen=True)
class Rule:
    """Reviewer-facing fields for one stable rule id."""

    rule_id: str
    group: str
    title: str | None
    lane: str
    ask: str
    proof: str
    due: str
    confidence: str
    severity: str
    hipaa: tuple[Cite, ...] = ()
    legacy_matches: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Flat view for callers that used the old dict-based rule table."""
        return {
            "rule_id": self.rule_id,
            "group": self.group,
            "title": self.title,
            "lane": self.lane,
            "ask": self.ask,
            "proof": self.proof,
            "due": self.due,
            "confidence": self.confidence,
            "severity": self.severity,
            "legacy_matches": self.legacy_matches,
        }


def _rule(
    rule_id: str,
    group: str,
    *,
    title: str | None,
    lane: str,
    ask: str,
    proof: str,
    due: str,
    confidence: str,
    severity: str,
    legacy_matches: tuple[str, ...] = (),
) -> Rule:
    return Rule(
        rule_id=rule_id,
        group=group,
        title=title,
        lane=lane,
        ask=ask,
        proof=proof,
        due=due,
        confidence=confidence,
        severity=severity,
        hipaa=cites_for(group),
        legacy_matches=legacy_matches,
    )


# Order is documentation only; legacy matching uses LEGACY_ORDER below.
RULES: dict[str, Rule] = {
    rule.rule_id: rule
    for rule in (
        _rule(
            "SUPPLY-KNOWN-BAD-PACKAGE",
            "supply",
            title="Known-compromised package on an endpoint",
            lane="MSP + practice owner",
            ask="Remove or replace the flagged package, then re-scan the endpoint.",
            proof="Remediated lockfile + clean scan receipt",
            due="7 days",
            confidence="Verified",
            severity="high",
            legacy_matches=("known-compromised package",),
        ),
        _rule(
            "EHR-SCRIBE-NO-BAA",
            "scribe",
            title="AI scribe transmissions without verified BAA",
            lane="Practice owner + scribe vendor",
            ask="Obtain a signed BAA and subprocessor list before any expansion.",
            proof="Signed BAA + subprocessor list",
            due="7 days",
            confidence="Observed",
            severity="high",
            legacy_matches=("scribe transmission",),
        ),
        _rule(
            "EP-ADJACENT-EXPORT",
            "endpoint",
            title="Patient-adjacent exports cached on endpoints",
            lane="MSP + front office",
            ask="Remove local copies and document a share-only workflow.",
            proof="Cleanup confirmation + workflow note",
            due="7 days",
            confidence="Verified",
            severity="high",
            legacy_matches=("on local desktop",),
        ),
        _rule(
            "SHR-PATIENT-ADJACENT",
            "shares",
            title="Patient-adjacent data on file shares",
            lane="Practice owner + MSP",
            ask="Confirm business need per export; move to minimal-access share or remove.",
            proof="Share ACL export + owner signoff",
            due="14 days",
            confidence="Verified",
            severity="high",
            legacy_matches=("patient-adjacent data on file share",),
        ),
        _rule(
            "EHR-PUBLIC-INTAKE",
            "intake",
            title="Public web intake form in use",
            lane="MSP + web vendor",
            ask="Confirm TLS, retention, and access control for the intake form.",
            proof="Vendor security page + retention statement",
            due="30 days",
            confidence="Observed",
            severity="medium",
            legacy_matches=("public web intake submission",),
        ),
        _rule(
            "AUTH-FAILURES",
            "auth",
            title="Authentication failures in the review window",
            lane="MSP",
            ask="Review the failure source and any inbound authentication attempts.",
            proof="Auth log summary",
            due="14 days",
            confidence="Observed",
            severity="medium",
            legacy_matches=("auth failures",),
        ),
        _rule(
            "IDN-ADMIN-GROUP",
            "admin",
            title="Admin-equivalent group membership",
            lane="MSP",
            ask="Confirm business need; enforce MFA on admin-equivalent access.",
            proof="Access review signoff + MFA evidence",
            due="30 days",
            confidence="Verified",
            severity="medium",
            legacy_matches=("SG-IT membership",),
        ),
        _rule(
            "IDN-DORMANT-ACCOUNT",
            "dormant",
            title="Dormant enabled accounts",
            lane="MSP",
            ask="Disable or document each unused account.",
            proof="Account disposition list",
            due="30 days",
            confidence="Verified",
            severity="low",
            legacy_matches=("never logged on",),
        ),
        _rule(
            "IDN-DISABLED-ACCOUNT",
            "disabled",
            title="Disabled accounts still present",
            lane="Practice owner",
            ask="Confirm disabled accounts are still required; remove if not.",
            proof="Offboarding record",
            due="90 days",
            confidence="Verified",
            severity="info",
            legacy_matches=("disabled account present",),
        ),
        _rule(
            "EP-CACHED-SHARE-FILE",
            "cached",
            title="Share files cached on supporting endpoints",
            lane="Practice owner",
            ask="Confirm endpoint access scope; remove cached data if not needed.",
            proof="Access decision note",
            due="60 days",
            confidence="Verified",
            severity="info",
            legacy_matches=("cached locally",),
        ),
        # Rules whose findings stay as individual "other" rows. Their title is
        # the finding detail, so the specific account/path/error is never lost.
        _rule(
            "AUTH-NONPASSWORD-FAILURE",
            "other",
            title=None,
            lane="MSP",
            ask="Identify the source of the non-password authentication failure.",
            proof="Auth log summary",
            due="14 days",
            confidence="Observed",
            severity="low",
        ),
        _rule(
            "AUTH-LOG-READ-FAILED",
            "other",
            title=None,
            lane="MSP",
            ask="Restore access to the domain controller audit log and re-run the pass.",
            proof="Successful collection receipt",
            due="7 days",
            confidence="Unverified",
            severity="info",
        ),
        _rule(
            "EHR-PORTAL-UNREACHABLE",
            "other",
            title=None,
            lane="Web vendor",
            ask="Confirm the clinic portal is reachable from the collector and re-run.",
            proof="Portal health check",
            due="7 days",
            confidence="Unverified",
            severity="medium",
        ),
        _rule(
            "EP-UNREADABLE-COPY",
            "other",
            title=None,
            lane="MSP",
            ask="Confirm the file is not patient-adjacent or explain why it is unreadable.",
            proof="Access decision note",
            due="30 days",
            confidence="Observed",
            severity="low",
        ),
        _rule(
            "IDN-STALE-ACCOUNT",
            "other",
            title=None,
            lane="MSP",
            ask="Confirm the account is still needed; disable or document it.",
            proof="Account disposition list",
            due="30 days",
            confidence="Verified",
            severity="medium",
        ),
    )
}

# Rules contributed by the policy, ACL, privilege and hygiene sections. Each
# group shares a lane/ask/proof/due; the per-rule title and severity carry the
# specific control so consolidated rows stay meaningful.
_CONTRIBUTED = {
    "policy": (
        "MSP + practice owner",
        "Review the domain password and lockout policy against the baseline and update it.",
        "Updated password policy export",
        "30 days",
        "Verified",
        {
            "POL-MIN-LENGTH": ("Password minimum length below baseline", "medium"),
            "POL-COMPLEXITY": ("Password complexity disabled or unknown", "low"),
            "POL-HISTORY": ("Password history shorter than baseline", "low"),
            "POL-MAX-AGE": ("Password maximum age outside baseline", "low"),
            "POL-MIN-AGE": ("Password minimum age allows immediate reuse", "info"),
            "POL-LOCKOUT-THRESHOLD": ("Account lockout threshold weak or disabled", "high"),
            "POL-LOCKOUT-DURATION": ("Account lockout duration weak", "low"),
            "POL-LOCKOUT-RESET": ("Lockout reset counter defeats the lockout", "medium"),
            "POL-PLAINTEXT": ("Plaintext password storage enabled or unknown", "high"),
            "POL-UNAVAILABLE": ("Password policy could not be read", "info"),
        },
    ),
    "acl": (
        "MSP + practice owner",
        "Confirm the business need for share access and tighten the ACL to the documented groups.",
        "Share ACL export + owner signoff",
        "14 days",
        "Verified",
        {
            "ACL-EVERYONE-WRITE": ("Everyone can write to a share", "high"),
            "ACL-AUTHENTICATED-WRITE": ("Authenticated Users can write to a share", "high"),
            "ACL-DOMAIN-USERS-WRITE": ("Domain Users can write to a share", "medium"),
            "ACL-USER-PRINCIPAL": ("ACL grants access directly to a user account", "medium"),
            "ACL-NON-AGDLP-GROUP": ("ACL grants access to an undocumented group", "low"),
            "ACL-UNDOCUMENTED-WRITE": ("Share grants write outside the access model", "medium"),
            "ACL-UNDOCUMENTED-READ": ("Share grants read outside the access model", "low"),
            "ACL-BROAD-READ": ("Everyone-style principal can read the share directory", "medium"),
            "ACL-BROADER-THAN-VALID-USERS": ("Filesystem ACL broader than valid users", "medium"),
            "ACL-VALID-USERS-NOT-GRANTED": ("Valid user has no matching ACL entry", "medium"),
            "ACL-NO-VALID-USERS": ("Share has no valid users gate", "medium"),
            "ACL-UNMODELED-SHARE": ("Share is not in the documented access model", "info"),
            "ACL-NULL-DACL": ("Null DACL grants full control to everyone", "high"),
            "ACL-PARSE-ERROR": ("Share ACL could not be parsed", "medium"),
            "ACL-UNAVAILABLE": ("Share ACL could not be read", "info"),
            "ACL-UNRESOLVED-PRINCIPAL": ("ACL principal SID could not be resolved", "info"),
        },
    ),
    "svc": (
        "MSP",
        "Rotate the credential, remove unnecessary SPNs or pre-auth exemptions, and restrict the account.",
        "Account configuration export",
        "7 days",
        "Verified",
        {
            "PRIV-KERBEROASTABLE": ("Service principal exposed to Kerberoasting", "medium"),
            "PRIV-PASSWORD-NEVER-EXPIRES": ("Privileged/service password never expires", "medium"),
            "PRIV-NO-PREAUTH": ("Account does not require Kerberos pre-authentication", "high"),
            "PRIV-REVERSIBLE-ENCRYPTION": ("Account permits reversible password encryption", "high"),
        },
    ),
    "admin": (
        "MSP",
        "Confirm the privileged entitlement and use a separate admin account for endpoints.",
        "Access review signoff",
        "30 days",
        "Verified",
        {
            "PRIV-ADMIN-NEVER-LOGON": ("Privileged account has never logged on", "medium"),
            "PRIV-ADMIN-INTERACTIVE": ("Privileged account used on an endpoint", "medium"),
            "PRIV-NESTED-ADMIN": ("Privileged group reached through nesting", "low"),
            "PRIV-GROUP-UNAVAILABLE": ("Privileged group membership could not be read", "info"),
        },
    ),
    "hygiene": (
        "MSP",
        "Harden the flagged protocol or signing setting and re-run the evidence pass.",
        "Configuration export / receipt",
        "30 days",
        "Verified",
        {
            "HYG-DOMAIN-FUNCTION-LEVEL": ("Domain functional level below baseline", "low"),
            "HYG-KRBTGT-AGE": ("krbtgt password older than baseline", "medium"),
            "HYG-SMB-SIGNING": ("SMB signing not required", "medium"),
            "HYG-LDAP-STRONG-AUTH": ("LDAP strong authentication not required", "high"),
            "HYG-NTLM-AUTH": ("NTLMv1 authentication permitted", "medium"),
            "HYG-SMB1": ("SMB1 protocol permitted", "high"),
            "HYG-UNAVAILABLE": ("Hygiene signal could not be read", "info"),
        },
    ),
}

# A rule inherits its group's cites. Where a rule is plainly about something more
# (or less) specific, override it so a packet row does not cite e.g. encryption
# for a "minimum length too short" finding.
RULE_CITE_OVERRIDES: dict[str, tuple[Cite, ...]] = {
    "PRIV-NO-PREAUTH": (AUTHENTICATION, ACCESS_MGMT),
    "HYG-DOMAIN-FUNCTION-LEVEL": (AUTHENTICATION,),
    "POL-PLAINTEXT": (PWD_MANAGEMENT, AUTHENTICATION, ENCRYPTION),
    "PRIV-REVERSIBLE-ENCRYPTION": (AUTHENTICATION, PWD_MANAGEMENT, ENCRYPTION),
    "HYG-KRBTGT-AGE": (AUTHENTICATION,),
    "HYG-SMB-SIGNING": (TRANSMISSION,),
    "HYG-SMB1": (TRANSMISSION,),
    "HYG-NTLM-AUTH": (TRANSMISSION, AUTHENTICATION),
    "HYG-LDAP-STRONG-AUTH": (TRANSMISSION, AUTHENTICATION),
}

for _group, (_lane, _ask, _proof, _due, _confidence, _entries) in _CONTRIBUTED.items():
    for _rule_id, (_title, _severity) in _entries.items():
        _contributed = _rule(
            _rule_id,
            _group,
            title=_title,
            lane=_lane,
            ask=_ask,
            proof=_proof,
            due=_due,
            confidence=_confidence,
            severity=_severity,
        )
        if _rule_id in RULE_CITE_OVERRIDES:
            _contributed = replace(_contributed, hipaa=RULE_CITE_OVERRIDES[_rule_id])
        RULES[_contributed.rule_id] = _contributed


# Rule ids with no direct match used to render as an unmapped "other" row.
DEFAULT_RULE = _rule(
    "",
    "other",
    title=None,
    lane="Practice owner",
    ask="Review the item and assign an owner.",
    proof="Review note",
    due="30 days",
    confidence="Observed",
    severity="info",
)

# The old substring table's order, preserved so legacy snapshots map exactly as
# they did before rule ids existed.
LEGACY_ORDER = (
    "SUPPLY-KNOWN-BAD-PACKAGE",
    "EHR-SCRIBE-NO-BAA",
    "EP-ADJACENT-EXPORT",
    "SHR-PATIENT-ADJACENT",
    "EHR-PUBLIC-INTAKE",
    "AUTH-FAILURES",
    "IDN-ADMIN-GROUP",
    "IDN-DORMANT-ACCOUNT",
    "IDN-DISABLED-ACCOUNT",
    "EP-CACHED-SHARE-FILE",
)


# Rule ids that were renamed after snapshots carrying them existed. Old evidence
# must keep rendering as the same row, so resolution maps the old id forward.
RENAMED_RULE_IDS: dict[str, str] = {"HYG-KRBTOG-AGE": "HYG-KRBTGT-AGE"}


def rule_for_detail(detail: str) -> Rule:
    """Legacy fallback: map old-style finding detail text to a rule."""
    lowered = (detail or "").lower()
    for rule_id in LEGACY_ORDER:
        rule = RULES[rule_id]
        if any(match.lower() in lowered for match in rule.legacy_matches):
            return rule
    return DEFAULT_RULE


def rule_for_finding(finding: dict[str, Any]) -> Rule:
    """Resolve a finding dict to a rule, preferring its stable rule id."""
    rule_id = finding.get("rule_id")
    rule_id = RENAMED_RULE_IDS.get(rule_id, rule_id) if rule_id else rule_id
    if rule_id and rule_id in RULES:
        return RULES[rule_id]
    return rule_for_detail(finding.get("detail", ""))


def all_groups() -> set[str]:
    return {rule.group for rule in RULES.values()} | {DEFAULT_RULE.group}
