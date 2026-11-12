from datetime import datetime, timezone

from practice_evidence.sections import hygiene

EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime(dt):
    return str(int((dt - EPOCH).total_seconds() * 10_000_000))


CONF = """# generated
[global]
    workgroup = MILLSLAB
    server signing = mandatory
    ldap server require strong auth = yes
    ntlm auth = ntlmv2-only
    server min protocol = SMB2
    ; comment = ignored
[ClinicalShare]
    server signing = disabled
    path = /srv/samba/shares/clinical
"""

LEVELS = """Domain and forest function level for domain 'DC=millslab,DC=internal'

Forest function level: (Windows) 2008 R2
Domain function level: (Windows) 2016
Lowest function level of a DC: (Windows) 2008 R2
"""


def rules(findings):
    return [f.rule_id for f in findings]


# --- parsing ---------------------------------------------------------------


def test_parse_global_only_reads_global_and_ignores_comments():
    parsed = hygiene.parse_global(CONF)
    assert parsed["workgroup"] == "MILLSLAB"
    assert parsed["server signing"] == "mandatory"
    assert "path" not in parsed
    assert "comment" not in parsed


def test_parse_function_level_variants():
    parsed = hygiene.parse_function_level(LEVELS)
    assert parsed == {
        "forest function level": "(Windows) 2008 R2",
        "domain function level": "(Windows) 2016",
        "lowest function level of a dc": "(Windows) 2008 R2",
    }
    assert hygiene.parse_function_level("__ERROR__ no") == {}


def test_level_rank_ordering():
    assert hygiene.level_rank("(Windows) 2008 R2") == (2008, 1)
    assert hygiene.level_rank("(Windows) 2016") == (2016, 0)
    assert hygiene.level_rank("2012") == (2012, 0)
    assert hygiene.level_rank("2012 R2") > hygiene.level_rank("2012")
    assert hygiene.level_rank("2016") > hygiene.level_rank("2012 R2")
    assert hygiene.level_rank("unknown") is None
    assert hygiene.level_rank(None) is None


def test_krbtgt_age_days():
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    raw = f"dn: CN=krbtgt\npwdLastSet: {filetime(datetime(2026, 1, 1, tzinfo=timezone.utc))}\n"
    assert hygiene.krbtgt_age_days(raw, now) == 151
    assert hygiene.krbtgt_age_days("pwdLastSet: 0", now) is None
    assert hygiene.krbtgt_age_days("no attribute here") is None


def test_smb1_setting_detection():
    assert hygiene.smb1_setting({"server min protocol": "NT1"}) == "server min protocol"
    assert hygiene.smb1_setting({"client min protocol": "SMB1"}) == "client min protocol"
    assert hygiene.smb1_setting({"protocol": "NT1"}) == "protocol"
    assert hygiene.smb1_setting({"server max protocol": "NT1"}) == "server max protocol"
    assert hygiene.smb1_setting({"server min protocol": "SMB2"}) is None
    assert hygiene.smb1_setting({}) is None


# --- evaluation ------------------------------------------------------------


GOOD_SMB = {
    "server signing": "mandatory",
    "ldap server require strong auth": "yes",
    "ntlm auth": "ntlmv2-only",
    "server min protocol": "SMB2",
}


def test_clean_hygiene_has_no_findings():
    assert hygiene.evaluate({"domain function level": "(Windows) 2016"}, GOOD_SMB, 30) == []


def test_function_level_below_baseline_and_unparseable():
    [old] = hygiene.evaluate({"domain function level": "(Windows) 2008 R2"}, GOOD_SMB, 30)
    assert (old.rule_id, old.severity) == ("HYG-DOMAIN-FUNCTION-LEVEL", "low")
    [unknown] = hygiene.evaluate({}, GOOD_SMB, 30)
    assert unknown.rule_id == "HYG-DOMAIN-FUNCTION-LEVEL"
    assert "could not be parsed" in unknown.detail


def test_krbtgt_age_boundaries():
    assert hygiene.evaluate({"domain function level": "2016"}, GOOD_SMB, 180) == []
    [old] = hygiene.evaluate({"domain function level": "2016"}, GOOD_SMB, 181)
    assert (old.rule_id, old.severity) == ("HYG-KRBTGT-AGE", "medium")
    [unknown] = hygiene.evaluate({"domain function level": "2016"}, GOOD_SMB, None)
    assert unknown.rule_id == "HYG-KRBTGT-AGE"
    assert unknown.severity == "low"


def test_smb_signing_missing_and_not_mandatory():
    smb = dict(GOOD_SMB)
    del smb["server signing"]
    [missing] = [
        f for f in hygiene.evaluate({"domain function level": "2016"}, smb, 30) if f.rule_id == "HYG-SMB-SIGNING"
    ]
    assert missing.severity == "low"
    smb["server signing"] = "auto"
    [weak] = [f for f in hygiene.evaluate({"domain function level": "2016"}, smb, 30) if f.rule_id == "HYG-SMB-SIGNING"]
    assert weak.severity == "medium"


def test_ldap_strong_auth_is_high_when_disabled():
    smb = dict(GOOD_SMB, **{"ldap server require strong auth": "no"})
    [finding] = [
        f for f in hygiene.evaluate({"domain function level": "2016"}, smb, 30) if f.rule_id == "HYG-LDAP-STRONG-AUTH"
    ]
    assert finding.severity == "high"
    smb["ldap server require strong auth"] = "allow_sasl_over_tls"
    [partial] = [
        f for f in hygiene.evaluate({"domain function level": "2016"}, smb, 30) if f.rule_id == "HYG-LDAP-STRONG-AUTH"
    ]
    assert partial.severity == "medium"


def test_ldap_strong_auth_absent_uses_samba_default():
    smb = dict(GOOD_SMB)
    del smb["ldap server require strong auth"]
    assert "HYG-LDAP-STRONG-AUTH" not in rules(hygiene.evaluate({"domain function level": "2016"}, smb, 30))


def test_ntlm_auth_policy():
    smb = dict(GOOD_SMB, **{"ntlm auth": "yes"})
    [finding] = [
        f for f in hygiene.evaluate({"domain function level": "2016"}, smb, 30) if f.rule_id == "HYG-NTLM-AUTH"
    ]
    assert finding.severity == "medium"
    smb["ntlm auth"] = "no"
    assert "HYG-NTLM-AUTH" not in rules(hygiene.evaluate({"domain function level": "2016"}, smb, 30))


def test_smb1_severity_depends_on_which_side():
    [server] = [
        f
        for f in hygiene.evaluate({"domain function level": "2016"}, {"server min protocol": "NT1"}, 30)
        if f.rule_id == "HYG-SMB1"
    ]
    assert server.severity == "high"
    [client] = [
        f
        for f in hygiene.evaluate({"domain function level": "2016"}, {"client min protocol": "SMB1"}, 30)
        if f.rule_id == "HYG-SMB1"
    ]
    assert client.severity == "medium"


# --- collection ------------------------------------------------------------


def fake_env(monkeypatch, conf=CONF, levels=LEVELS, krbtgt=None):
    krbtgt = krbtgt or f"pwdLastSet: {filetime(datetime(2026, 5, 1, tzinfo=timezone.utc))}\n"

    def fake(cmd, timeout=30):
        joined = " ".join(cmd)
        if joined == "samba-tool domain level show":
            return levels
        if joined == "samba-tool user show krbtgt":
            return krbtgt
        if cmd[:2] == ["cat", "/etc/samba/smb.conf"]:
            return conf
        return "__ERROR__ unexpected"

    monkeypatch.setattr(hygiene, "dexec", fake)


def test_collect_reports_settings_and_findings(monkeypatch):
    fake_env(monkeypatch)
    out = hygiene.collect()
    assert out["functional_level"]["domain function level"] == "(Windows) 2016"
    assert out["smb"]["server signing"] == "mandatory"
    assert out["smb"]["server min protocol"] == "SMB2"
    assert out["krbtgt"]["password_age_days"] is not None
    assert "HYG-SMB1" not in [f["rule_id"] for f in out["findings"]]


def test_collect_flags_smb1_and_weak_settings(monkeypatch):
    conf = CONF.replace("server min protocol = SMB2", "server min protocol = NT1").replace(
        "server signing = mandatory", "server signing = auto"
    )
    fake_env(monkeypatch, conf=conf)
    found_rules = [f["rule_id"] for f in hygiene.collect()["findings"]]
    assert "HYG-SMB1" in found_rules
    assert "HYG-SMB-SIGNING" in found_rules


def test_collect_handles_totally_unavailable(monkeypatch):
    def fake(cmd, timeout=30):
        return "__ERROR__ no docker"

    monkeypatch.setattr(hygiene, "dexec", fake)
    out = hygiene.collect()
    assert out["findings"][0]["rule_id"] == "HYG-UNAVAILABLE"
    assert out["functional_level"] == {}


def test_collect_still_evaluates_smb_when_level_and_krbtgt_fail(monkeypatch):
    conf = CONF.replace("server signing = mandatory", "server signing = auto")

    def fake(cmd, timeout=30):
        if cmd[:2] == ["cat", "/etc/samba/smb.conf"]:
            return conf
        return "__ERROR__ unavailable"

    monkeypatch.setattr(hygiene, "dexec", fake)
    out = hygiene.collect()
    found_rules = [f["rule_id"] for f in out["findings"]]
    assert "HYG-SMB-SIGNING" in found_rules
    assert "HYG-DOMAIN-FUNCTION-LEVEL" in found_rules
    assert "HYG-KRBTGT-AGE" in found_rules
