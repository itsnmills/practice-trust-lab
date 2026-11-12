from datetime import datetime, timezone

from practice_evidence.sections import privilege

DOMAIN = "S-1-5-21-100-200-300"
EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


def filetime(dt):
    return str(int((dt - EPOCH).total_seconds() * 10_000_000))


LAB_USER = f"""dn: CN=Noah Mills,OU=IT,OU=Staff,OU=MillsLab,DC=millslab,DC=internal
sAMAccountName: nmills
userAccountControl: 512
lastLogonTimestamp: {filetime(datetime(2026, 5, 30, tzinfo=timezone.utc))}
"""

SVC_USER = """sAMAccountName: svc-backup
userAccountControl: 4260480
servicePrincipalName: backup/dc1.millslab.internal
servicePrincipalName: cifs/backup.millslab.internal
"""


def rules(findings):
    return [f.extra["rule_id"] for f in findings]


# --- UAC -------------------------------------------------------------------


def test_decode_uac_named_flags_lowest_bit_first():
    assert privilege.decode_uac("512") == ["NORMAL_ACCOUNT"]
    assert privilege.decode_uac(0x10000) == ["DONT_EXPIRE_PASSWORD"]
    assert privilege.decode_uac("4260480") == [
        "ENCRYPTED_TEXT_PASSWORD_ALLOWED",
        "NORMAL_ACCOUNT",
        "DONT_EXPIRE_PASSWORD",
        "DONT_REQUIRE_PREAUTH",
    ]
    assert privilege.decode_uac("0x200") == ["NORMAL_ACCOUNT"]


def test_parse_uac_tolerates_junk():
    assert privilege.parse_uac(None) == 0
    assert privilege.parse_uac("garbage") == 0
    assert privilege.parse_uac("") == 0


def test_has_flag():
    assert privilege.has_flag(0x2, privilege.UAC_ACCOUNTDISABLE) is True
    assert privilege.has_flag(0x200, privilege.UAC_ACCOUNTDISABLE) is False
    assert privilege.has_flag("4194304", privilege.UAC_DONT_REQUIRE_PREAUTH) is True


# --- parsing / classification ----------------------------------------------


def test_parse_attributes_keeps_multi_valued_and_skips_errors():
    attrs = privilege.parse_attributes(SVC_USER + "__ERROR__ kaboom\nno-colon\n")
    assert attrs["servicePrincipalName"] == ["backup/dc1.millslab.internal", "cifs/backup.millslab.internal"]
    assert attrs["userAccountControl"] == ["4260480"]
    assert "__ERROR__ kaboom" not in str(attrs)


def test_first_and_filetime():
    attrs = privilege.parse_attributes(LAB_USER)
    assert privilege.first(attrs, "missing") is None
    assert privilege.filetime_to_datetime("0") is None
    assert privilege.filetime_to_datetime("bad") is None
    assert privilege.filetime_to_datetime(privilege.first(attrs, "lastLogonTimestamp")).year == 2026


def test_classify_normal_account():
    account = privilege.classify_account("nmills", privilege.parse_attributes(LAB_USER))
    assert account["enabled"] is True
    assert account["service_account"] is False
    assert account["never_logged_on"] is False
    assert account["uac_flags"] == ["NORMAL_ACCOUNT"]


def test_classify_service_account_flags():
    account = privilege.classify_account("svc-backup", privilege.parse_attributes(SVC_USER))
    assert account["service_account"] is True
    assert account["spn_count"] == 2
    assert account["password_never_expires"] is True
    assert account["no_preauth"] is True
    assert account["reversible_encryption"] is True
    assert account["never_logged_on"] is True


def test_classify_disabled_and_prefixed_service():
    disabled = privilege.classify_account("svc-x", {"userAccountControl": ["514"]})
    assert disabled["enabled"] is False
    assert disabled["service_account"] is True
    enabled_prefix = privilege.classify_account("svc-x", {"userAccountControl": ["512"]})
    assert enabled_prefix["service_account"] is True and enabled_prefix["enabled"] is True


# --- group expansion -------------------------------------------------------


def test_expand_group_nesting_and_cycle_protection():
    members = {
        "Domain Admins": ["SG-IT"],
        "SG-IT": ["nmills", "svc-spn"],
        "DL-Clinical": ["SG-IT"],
    }
    result = privilege.expand_group("Domain Admins", members, set(members))
    assert result["direct"] == ["SG-IT"]
    assert result["nested_groups"] == ["SG-IT"]
    assert result["effective_users"] == ["nmills", "svc-spn"]


def test_expand_group_does_not_list_itself_from_a_cycle():
    members = {"A": ["B"], "B": ["A", "u1"]}
    result = privilege.expand_group("A", members, {"A", "B"})
    assert result["nested_groups"] == ["B"]
    assert result["effective_users"] == ["u1"]


def test_expand_group_treats_unknown_members_as_users():
    result = privilege.expand_group("A", {"A": ["somebody"]}, {"A"})
    assert result["effective_users"] == ["somebody"]


# --- findings --------------------------------------------------------------


def account(**overrides):
    base = {
        "sam": "nmills",
        "enabled": True,
        "spn_count": 0,
        "service_account": False,
        "password_never_expires": False,
        "no_preauth": False,
        "reversible_encryption": False,
        "never_logged_on": False,
        "last_logon": "2026-05-30T00:00:00Z",
        "privileged": True,
    }
    base.update(overrides)
    return base


def test_privileged_normal_account_has_no_findings():
    assert privilege.account_findings(account(), privileged=True) == []


def test_kerberoastable_severity_depends_on_privilege():
    [service] = privilege.account_findings(account(spn_count=1, service_account=True), privileged=False)
    assert (service.extra["rule_id"], service.severity) == ("PRIV-KERBEROASTABLE", "medium")
    [admin] = privilege.account_findings(account(spn_count=1), privileged=True)
    assert admin.severity == "high"


def test_no_preauth_and_reversible_are_high():
    found = privilege.account_findings(
        account(no_preauth=True, reversible_encryption=True, service_account=True), privileged=False
    )
    assert {(f.extra["rule_id"], f.severity) for f in found} == {
        ("PRIV-NO-PREAUTH", "high"),
        ("PRIV-REVERSIBLE-ENCRYPTION", "high"),
    }


def test_password_never_expires_only_for_privileged_or_service():
    assert privilege.account_findings(account(password_never_expires=True), privileged=False) == []
    [svc] = privilege.account_findings(account(password_never_expires=True, service_account=True), privileged=False)
    assert svc.extra["rule_id"] == "PRIV-PASSWORD-NEVER-EXPIRES"
    assert svc.severity == "medium"
    [admin] = privilege.account_findings(account(password_never_expires=True), privileged=True)
    assert admin.extra["rule_id"] == "PRIV-PASSWORD-NEVER-EXPIRES"


def test_admin_never_logged_on():
    [finding] = privilege.account_findings(account(never_logged_on=True), privileged=True)
    assert finding.extra["rule_id"] == "PRIV-ADMIN-NEVER-LOGON"
    assert finding.severity == "medium"
    assert privilege.account_findings(account(never_logged_on=True), privileged=False) == []


def test_disabled_account_has_no_findings():
    assert privilege.account_findings(account(enabled=False, no_preauth=True), privileged=True) == []


def test_findings_subject_is_the_account():
    [finding] = privilege.account_findings(account(no_preauth=True), privileged=True)
    assert finding.extra["subject"] == "nmills"


def test_interactive_admin_needs_workstation_attribution():
    accounts = [account(privileged=True)]
    assert (
        privilege.interactive_admin_findings(accounts, {"by_user": {"nmills": {"success": 4}}}, {"ws-clinical-01"})
        == []
    )
    [finding] = privilege.interactive_admin_findings(
        accounts,
        {"by_user": {"nmills": {"success": 4, "workstations": ["ws-clinical-01"]}}},
        {"ws-clinical-01"},
    )
    assert finding.extra["rule_id"] == "PRIV-ADMIN-INTERACTIVE"
    assert finding.severity == "medium"
    [by_ws] = privilege.interactive_admin_findings(
        accounts, {"by_user_workstation": {"nmills": ["msp-jump-01"]}}, {"msp-jump-01"}
    )
    assert by_ws.extra["workstations"] == ["msp-jump-01"]


def test_interactive_admin_ignores_endpoints_outside_the_lab():
    accounts = [account(privileged=True)]
    assert (
        privilege.interactive_admin_findings(
            accounts, {"by_user": {"nmills": {"workstations": ["random-laptop"]}}}, {"ws-clinical-01"}
        )
        == []
    )


# --- collection ------------------------------------------------------------


def fake_env(monkeypatch):
    members = {
        "Domain Admins": "SG-IT\n",
        "Enterprise Admins": "Administrator\n",
        "Schema Admins": "",
        "SG-IT": "nmills\nsvc-spn\n",
        "DL-Clinical": "SG-IT\n",
    }
    shows = {
        "nmills": f"sAMAccountName: nmills\nuserAccountControl: 512\nlastLogonTimestamp: {filetime(NOW)}\n",
        "svc-spn": (
            "sAMAccountName: svc-spn\nuserAccountControl: 4260480\nservicePrincipalName: HTTP/svc.millslab.internal\n"
        ),
        "Administrator": "sAMAccountName: Administrator\nuserAccountControl: 512\n",
    }

    def fake(cmd, timeout=30):
        joined = " ".join(cmd)
        if joined == "samba-tool group list":
            return "\n".join(members) + "\n"
        if joined.startswith("samba-tool group listmembers "):
            return members.get(cmd[-1], "__ERROR__ no such group")
        if joined == "samba-tool user list":
            return "Administrator\nnmills\nsvc-spn\nghost\n"
        if joined.startswith("samba-tool user show "):
            sam = cmd[-1]
            return shows.get(sam, "__ERROR__ no such user")
        return "__ERROR__ unexpected"

    monkeypatch.setattr(privilege, "dexec", fake)


def test_collect_expands_nested_groups_and_flags_service_accounts(monkeypatch):
    fake_env(monkeypatch)
    out = privilege.collect()
    assert out["role_groups"]["Domain Admins"]["nested_groups"] == ["SG-IT"]
    assert out["role_groups"]["Domain Admins"]["effective_users"] == ["nmills", "svc-spn"]
    assert "ghost" not in {a["sam"] for a in out["accounts"]}
    admin = next(a for a in out["accounts"] if a["sam"] == "nmills")
    assert admin["privileged"] is True
    assert admin["role_groups"] == ["Domain Admins", "SG-IT"]
    found_rules = [f["rule_id"] for f in out["findings"]]
    assert "PRIV-NESTED-ADMIN" in found_rules
    assert "PRIV-KERBEROASTABLE" in found_rules
    assert "PRIV-PASSWORD-NEVER-EXPIRES" in found_rules
    assert "PRIV-NO-PREAUTH" in found_rules
    assert "PRIV-REVERSIBLE-ENCRYPTION" in found_rules


def test_collect_reports_unreadable_group(monkeypatch):
    def fake(cmd, timeout=30):
        joined = " ".join(cmd)
        if joined == "samba-tool group list":
            return ""
        if joined.startswith("samba-tool group listmembers "):
            return "__ERROR__ denied"
        return ""

    monkeypatch.setattr(privilege, "dexec", fake)
    out = privilege.collect()
    assert "PRIV-GROUP-UNAVAILABLE" in [f["rule_id"] for f in out["findings"]]
