import pytest
from practice_evidence.sections import acls


def registry_cites(rule_id):
    """HIPAA citations for a rule, as the packet shows them (the registry is the one source)."""
    from practice_render.rules import RULES

    return " ".join(c.section for c in RULES[rule_id].hipaa)


DOMAIN = "S-1-5-21-100-200-300"

SDDL = (
    f"O:{DOMAIN}-512"
    f"G:{DOMAIN}-513"
    "D:PAI"
    f"(A;OICI;0x1f01ff;;;{DOMAIN}-1105)"
    f"(A;CI;0x1200a9;;;{DOMAIN}-513)"
    "(D;;0x2;;;S-1-5-11)"
)


def ace(sddl, index=0):
    return acls.parse_sddl(sddl)["aces"][index]


def rules(findings):
    return [f.rule_id for f in findings]


def test_parse_sddl_owner_group_flags_and_aces():
    parsed = acls.parse_sddl(SDDL)
    assert parsed["owner"] == f"{DOMAIN}-512"
    assert parsed["group"] == f"{DOMAIN}-513"
    assert parsed["dacl_flags"] == "PAI"
    assert parsed["null_dacl"] is False
    assert [a["type"] for a in parsed["aces"]] == ["allow", "allow", "deny"]


def test_parse_sddl_resolves_domain_rids_and_masks():
    parsed = acls.parse_sddl(SDDL)
    first = parsed["aces"][0]
    assert first["principal"] == f"{DOMAIN}-1105"
    assert first["mask"] == 0x1F01FF
    assert first["write"] and first["full_control"]
    assert first["object_inherit"] and first["container_inherit"]
    second = parsed["aces"][1]
    assert second["principal"] == "Domain Users"
    assert second["mask"] == 0x1200A9
    assert not second["write"]
    assert second["container_inherit"] and not second["object_inherit"]
    third = parsed["aces"][2]
    assert third["type"] == "deny"
    assert third["principal"] == "Authenticated Users"
    assert third["write"] is True  # the mask asks for write, but deny is protective


def test_parse_sddl_handles_well_known_aliases():
    everyone = ace("D:(A;;FA;;;WD)")
    assert (everyone["sid"], everyone["principal"]) == ("S-1-1-0", "Everyone")
    admins = ace("D:(A;;FA;;;BA)")
    assert (admins["sid"], admins["principal"]) == ("S-1-5-32-544", "Administrators")
    auth = ace("D:(A;;FR;;;AU)")
    assert (auth["sid"], auth["principal"]) == ("S-1-5-11", "Authenticated Users")
    users = ace("D:(A;;FA;;;DU)")
    assert (users["principal"], users["kind"], users["rid"]) == ("Domain Users", "group", 513)


def test_parse_sddl_object_ace_types_map_to_allow_deny():
    allow = acls.parse_sddl("D:(OA;;FR;;;WD)")["aces"][0]
    deny = acls.parse_sddl("D:(OD;;FR;;;WD)")["aces"][0]
    assert allow["type"] == "allow"
    assert deny["type"] == "deny"


def test_parse_sddl_inherit_only_and_inherited_flags():
    assert ace("D:(A;IO;FR;;;WD)")["inherit_only"] is True
    assert ace("D:(A;ID;FR;;;WD)")["inherited"] is True
    assert ace("D:(A;OICIIO;FR;;;WD)")["container_inherit"] is True


def test_parse_sddl_null_dacl_detection():
    assert acls.parse_sddl("D:")["null_dacl"] is True
    assert acls.parse_sddl("O:S-1-5-18D:NO_ACCESS_CONTROL")["null_dacl"] is True
    assert acls.parse_sddl("D:AI")["null_dacl"] is False


def test_parse_sddl_rejects_garbage():
    for bad in ("", "__ERROR__ nope", "garbage", "# comment only"):
        with pytest.raises(ValueError):
            acls.parse_sddl(bad)


def test_parse_mask_numeric_and_alphabetic():
    assert acls.parse_mask("0x1f01ff") == 0x1F01FF
    assert acls.parse_mask("2032127") == 0x1F01FF
    assert acls.parse_mask("FA") == acls.FILE_ALL_ACCESS
    assert acls.parse_mask("FR") == 0x120089
    assert acls.parse_mask("") == 0
    assert acls.parse_mask("0xZZ") is None
    assert acls.parse_mask("QQ") is None


def test_write_and_full_control_helpers():
    assert acls.is_write(0x2) is True
    assert acls.is_write(0x40000000) is True
    assert acls.is_write(0x120089) is False
    assert acls.is_full_control(acls.FILE_ALL_ACCESS) is True
    assert acls.is_full_control(0x10000000) is True
    assert acls.is_full_control(0x1200A9) is False
    assert acls.is_write(None) is False


def test_inherit_only_ace_is_still_evaluated():
    found = acls.evaluate_share(share(), descriptor("(A;IO;FA;;;WD)"), None)
    assert "ACL-EVERYONE-WRITE" in rules(found)


def test_parse_valid_users_strips_at_and_domain():
    assert acls.parse_valid_users("@DL-ClinicalShare-RW @SG-FrontOffice MILLSLAB\\nmills +@netgroup") == [
        "DL-ClinicalShare-RW",
        "SG-FrontOffice",
        "nmills",
        "netgroup",
    ]
    assert acls.parse_valid_users("") == []


def test_domain_rid_only_matches_domain_sids():
    assert acls.domain_rid(f"{DOMAIN}-1105") == 1105
    assert acls.domain_rid("S-1-1-0") is None
    assert acls.domain_rid("S-1-5-32-544") is None


def test_apply_principals_fills_names_and_kinds():
    parsed = acls.parse_sddl(SDDL)
    names = {f"{DOMAIN}-1105": "MILLSLAB\\DL-ClinicalShare-RW"}
    kinds = {f"{DOMAIN}-1105": "group"}
    acls.apply_principals(parsed, names, kinds)
    assert parsed["aces"][0]["principal"] == "DL-ClinicalShare-RW"
    assert parsed["aces"][0]["kind"] == "group"


def test_resolve_sids_uses_resolver_and_skips_well_known():
    seen = []

    def resolver(sid):
        seen.append(sid)
        return "MILLSLAB\\DL-ClinicalShare-RW"

    names = acls.resolve_sids({"S-1-1-0", f"{DOMAIN}-1105"}, resolver)
    assert names == {f"{DOMAIN}-1105": "DL-ClinicalShare-RW"}
    assert seen == [f"{DOMAIN}-1105"]


def test_kinds_for_classifies_groups_and_users():
    names = {f"{DOMAIN}-1105": "DL-ClinicalShare-RW", f"{DOMAIN}-1106": "malvarez"}
    kinds = acls.kinds_for(names, {"DL-ClinicalShare-RW"}, {"malvarez"})
    assert kinds == {f"{DOMAIN}-1105": "group", f"{DOMAIN}-1106": "user"}


# --- finding evaluation ----------------------------------------------------

MODEL = {"allow": {"DL-ClinicalShare-RW"}, "write": {"DL-ClinicalShare-RW"}}


def share(valid="@DL-ClinicalShare-RW"):
    return {"name": "ClinicalShare", "path": "/srv/samba/shares/clinical", "valid users": valid}


def descriptor(*aces):
    return acls.parse_sddl("D:AI" + "".join(aces))


def test_everyone_write_is_high_even_without_a_model():
    found = acls.evaluate_share(share(), descriptor("(A;;FA;;;WD)"), None)
    [broad] = [f for f in found if f.rule_id == "ACL-EVERYONE-WRITE"]
    assert broad.severity == "high"
    assert broad.subject == "ClinicalShare:Everyone"
    assert "164.312(a)(1)" in registry_cites("ACL-EVERYONE-WRITE")


def test_authenticated_users_write_and_domain_users_write():
    found = acls.evaluate_share(share(), descriptor("(A;;FW;;;AU)", "(A;;0x2;;;DU)"), None)
    found_rules = rules(found)
    assert "ACL-AUTHENTICATED-WRITE" in found_rules
    assert "ACL-DOMAIN-USERS-WRITE" in found_rules


def test_read_only_everyone_is_not_a_write_finding():
    found = acls.evaluate_share(share(), descriptor("(A;;FR;;;WD)"), None)
    assert "ACL-EVERYONE-WRITE" not in rules(found)


def test_user_principal_and_non_agdlp_group():
    parsed = descriptor(f"(A;;FR;;;{DOMAIN}-1106)", f"(A;;FR;;;{DOMAIN}-1107)")
    acls.apply_principals(parsed, {f"{DOMAIN}-1106": "malvarez"}, {f"{DOMAIN}-1106": "user"})
    for item in parsed["aces"]:
        if item["sid"] == f"{DOMAIN}-1107":
            item["principal"], item["kind"] = "SomeOtherGroup", "group"
    found_rules = rules(acls.evaluate_share(share(), parsed, MODEL))
    assert "ACL-USER-PRINCIPAL" in found_rules
    assert "ACL-NON-AGDLP-GROUP" in found_rules


def test_undocumented_write_and_read_against_the_model():
    parsed = descriptor(f"(A;;FA;;;{DOMAIN}-1108)", f"(A;;FR;;;{DOMAIN}-1109)")
    acls.apply_principals(
        parsed,
        {f"{DOMAIN}-1108": "SG-FrontOffice", f"{DOMAIN}-1109": "SG-Clinical"},
        {f"{DOMAIN}-1108": "group", f"{DOMAIN}-1109": "group"},
    )
    found_rules = rules(acls.evaluate_share(share(), parsed, MODEL))
    assert "ACL-UNDOCUMENTED-WRITE" in found_rules
    assert "ACL-UNDOCUMENTED-READ" in found_rules


def test_acl_broader_than_valid_users_and_valid_user_not_granted():
    parsed = descriptor(f"(A;;FA;;;{DOMAIN}-1105)", f"(A;;FA;;;{DOMAIN}-1108)")
    acls.apply_principals(
        parsed,
        {f"{DOMAIN}-1105": "DL-ClinicalShare-RW", f"{DOMAIN}-1108": "SG-FrontOffice"},
        {f"{DOMAIN}-1105": "group", f"{DOMAIN}-1108": "group"},
    )
    found_rules = rules(acls.evaluate_share(share(), parsed, MODEL))
    assert "ACL-BROADER-THAN-VALID-USERS" in found_rules
    # the valid user is granted here, so no "not granted" finding
    assert "ACL-VALID-USERS-NOT-GRANTED" not in found_rules


def test_valid_user_without_acl_entry_is_reported():
    found_rules = rules(acls.evaluate_share(share(), descriptor("(A;;FR;;;WD)"), MODEL))
    assert "ACL-VALID-USERS-NOT-GRANTED" in found_rules


def test_missing_valid_users_and_unmodeled_share():
    parsed = descriptor("(A;;FR;;;WD)")
    plain = {"name": "AdHocShare", "path": "/srv/adhoc", "valid users": ""}
    found_rules = rules(acls.evaluate_share(plain, parsed, None))
    assert "ACL-NO-VALID-USERS" in found_rules
    assert "ACL-UNMODELED-SHARE" in found_rules


def test_admin_principals_and_deny_aces_are_ignored():
    parsed = descriptor("(A;;FA;;;BA)", "(A;;FA;;;DA)", "(D;;FA;;;WD)", f"(A;;FA;;;{DOMAIN}-1105)")
    acls.apply_principals(parsed, {f"{DOMAIN}-1105": "DL-ClinicalShare-RW"}, {f"{DOMAIN}-1105": "group"})
    assert acls.evaluate_share(share(), parsed, MODEL) == []


def test_null_dacl_is_high():
    parsed = acls.parse_sddl("D:")
    [finding] = [f for f in acls.evaluate_share(share(), parsed, MODEL) if f.rule_id == "ACL-NULL-DACL"]
    assert finding.severity == "high"


def test_findings_dedupe_by_rule_and_subject():
    parsed = descriptor("(A;;FA;;;WD)", "(A;;FA;;;WD)")
    found_rules = rules(acls.evaluate_share(share(), parsed, None))
    assert found_rules.count("ACL-EVERYONE-WRITE") == 1


def test_unresolved_principal_is_reported_and_skips_model_checks():
    parsed = descriptor(f"(A;;FA;;;{DOMAIN}-1199)")
    found = acls.evaluate_share(share(), parsed, MODEL)
    found_rules = rules(found)
    assert "ACL-UNRESOLVED-PRINCIPAL" in found_rules
    assert "ACL-UNDOCUMENTED-WRITE" not in found_rules


# --- collection ------------------------------------------------------------


def fake_env(monkeypatch):
    conf = """
[global]
workgroup = MILLSLAB
[ClinicalShare]
path = /srv/samba/shares/clinical
valid users = @DL-ClinicalShare-RW
"""
    sddl = f"O:{DOMAIN}-512G:{DOMAIN}-513D:AI(A;OICI;0x1f01ff;;;{DOMAIN}-1105)(A;OICI;0x1200a9;;;{DOMAIN}-1106)"

    def fake(cmd, timeout=30):
        joined = " ".join(cmd)
        if cmd[:2] == ["cat", "/etc/samba/smb.conf"]:
            return conf
        if joined == "samba-tool group list":
            return "DL-ClinicalShare-RW\nSG-FrontOffice\nSG-IT\n"
        if joined == "samba-tool user list":
            return "malvarez\n"
        if joined.startswith("samba-tool ntacl get /srv/samba/shares/clinical"):
            return sddl
        if joined == f"wbinfo -s {DOMAIN}-1105":
            return "MILLSLAB\\DL-ClinicalShare-RW 2"
        if joined == f"wbinfo -s {DOMAIN}-1106":
            return "MILLSLAB\\malvarez 1"
        return "__ERROR__ unexpected command"

    monkeypatch.setattr(acls, "dexec", fake)


def test_collect_parses_share_and_resolves_names(monkeypatch):
    fake_env(monkeypatch)
    out = acls.collect()
    [record] = out["shares"]
    assert record["status"] == "ok"
    assert record["owner"] == "Domain Admins"
    principals = {a["principal"] for a in record["aces"]}
    assert principals == {"DL-ClinicalShare-RW", "malvarez"}
    kinds = {a["principal"]: a["kind"] for a in record["aces"]}
    assert kinds == {"DL-ClinicalShare-RW": "group", "malvarez": "user"}
    found_rules = [f["rule_id"] for f in out["findings"]]
    assert "ACL-USER-PRINCIPAL" in found_rules
    assert "ACL-UNDOCUMENTED-READ" in found_rules
    # DL-ClinicalShare-RW is exactly the documented model, so no write finding
    assert "ACL-UNDOCUMENTED-WRITE" not in found_rules


def test_collect_reports_unreadable_acl(monkeypatch):
    def fake(cmd, timeout=30):
        joined = " ".join(cmd)
        if cmd[:2] == ["cat", "/etc/samba/smb.conf"]:
            return "[ClinicalShare]\npath = /srv/clinical\nvalid users = @DL-x\n"
        if joined in ("samba-tool group list", "samba-tool user list"):
            return ""
        return "__ERROR__ cannot read"

    monkeypatch.setattr(acls, "dexec", fake)
    out = acls.collect()
    assert out["shares"][0]["status"] == "unavailable"
    assert out["findings"][0]["rule_id"] == "ACL-UNAVAILABLE"


def test_collect_reports_unreadable_smb_conf(monkeypatch):
    monkeypatch.setattr(acls, "dexec", lambda cmd, timeout=30: "__ERROR__ cannot read smb.conf")
    out = acls.collect()
    assert out["shares"] == []
    assert out["findings"][0]["rule_id"] == "ACL-UNAVAILABLE"
    assert out["findings"][0]["subject"] == "smb.conf"


# --- regression: the exact ACL a freshly bootstrapped lab returns -----------------
#
# Captured from `samba-tool ntacl get /srv/samba/shares/clinical --as-sddl` on a live
# lab. Every share directory has this same descriptor. Earlier fixtures were invented
# and never contained LA, an inherit-only CREATOR GROUP entry, or the UNIX root group
# SID, so those produced six false-positive "undocumented write" findings per lab.
LIVE_SDDL = "O:LAG:S-1-22-2-0D:(A;;FA;;;LA)(A;;0x1200a9;;;S-1-22-2-0)(A;;0x1200a9;;;WD)(A;OICIIO;FA;;;CO)(A;OICIIO;0x1200a9;;;CG)(A;OICIIO;0x1200a9;;;WD)"


def _live_findings(share_name="ClinicalShare", valid="@DL-ClinicalShare-RW"):
    parsed = acls.parse_sddl(LIVE_SDDL)
    acls.apply_principals(parsed, {}, {})
    share = {"name": share_name, "valid users": valid}
    return acls.evaluate_share(share, parsed, acls.SHARE_ACCESS_MODEL.get(share_name))


def test_live_sddl_local_administrator_is_not_an_undocumented_writer():
    rules = {(f.rule_id, f.subject) for f in _live_findings()}
    assert not any(r == "ACL-UNDOCUMENTED-WRITE" for r, _ in rules)
    assert not any(r == "ACL-BROADER-THAN-VALID-USERS" for r, _ in rules)


def test_live_sddl_resolves_la_alias_to_administrator_rid_500():
    parsed = acls.parse_sddl(LIVE_SDDL)
    first = parsed["aces"][0]
    assert (first["rid"], first["principal"], first["kind"]) == (500, "Administrator", "user")


def test_live_sddl_template_and_unix_root_entries_are_ignored():
    subjects = {f.subject for f in _live_findings()}
    assert not any("CREATOR" in s or "root" in s.lower() for s in subjects)


def test_live_sddl_reports_everyone_read_once_as_a_real_finding():
    found = [f for f in _live_findings() if f.rule_id == "ACL-BROAD-READ"]
    assert len(found) == 1, "direct and inherit-only Everyone ACEs must collapse to one finding"
    assert found[0].severity == "medium"
    assert found[0].subject == "ClinicalShare:Everyone"
    assert "valid users" in found[0].detail


def test_live_sddl_flags_valid_user_group_missing_from_filesystem_acl():
    found = {f.subject for f in _live_findings() if f.rule_id == "ACL-VALID-USERS-NOT-GRANTED"}
    assert found == {"ClinicalShare:DL-ClinicalShare-RW"}


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("MILLSLAB\\SG-IT 2", "MILLSLAB\\SG-IT"),
        ("Unix Group\\root 2", "Unix Group\\root"),
        ("MILLSLAB\\malvarez 1", "MILLSLAB\\malvarez"),
        ("MILLSLAB\\SG-IT (S-1-5-21-1-2-3-1105)", "MILLSLAB\\SG-IT"),  # tolerated legacy shape
        ("failed to call wbcLookupSid: WBC_ERR_DOMAIN_NOT_FOUND", ""),
        ("", ""),
    ],
)
def test_parse_wbinfo_name_handles_real_output(raw, expected):
    assert acls.parse_wbinfo_name(raw) == expected
