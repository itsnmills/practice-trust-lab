from pathlib import Path

import pytest
from practice_evidence.sections import policy


def registry_cites(rule_id):
    """HIPAA citations for a rule, as the packet shows them (the registry is the one source)."""
    from practice_render.rules import RULES

    return " ".join(c.section for c in RULES[rule_id].hipaa)


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "samba" / "passwordsettings.txt"

# Captured shape of `samba-tool domain passwordsettings show` in the lab image.
LAB_POLICY = """Password information for domain 'DC=millslab,DC=internal'

Password complexity: on
Store plaintext passwords: off
Password history length: 24
Minimum password length: 10
Minimum password age (days): 0
Maximum password age (days): 42
Account lockout duration (mins): 15
Account lockout threshold (attempts): 5
Reset account lockout after (mins): 10
"""

COMPLIANT = {
    "Password complexity": "on",
    "Store plaintext passwords": "off",
    "Password history length": "24",
    "Minimum password length": "12",
    "Minimum password age (days)": "1",
    "Maximum password age (days)": "365",
    "Account lockout duration (mins)": "15",
    "Account lockout threshold (attempts)": "5",
    "Reset account lockout after (mins)": "15",
}


def settings(**overrides):
    values = dict(COMPLIANT)
    for key, value in overrides.items():
        # underscore keys map to the human labels used by samba-tool
        label = {
            "min_length": "Minimum password length",
            "max_age": "Maximum password age (days)",
            "min_age": "Minimum password age (days)",
            "history": "Password history length",
            "threshold": "Account lockout threshold (attempts)",
            "duration": "Account lockout duration (mins)",
            "reset": "Reset account lockout after (mins)",
            "complexity": "Password complexity",
            "plaintext": "Store plaintext passwords",
        }[key]
        values[label] = value
    return values


def rules(findings):
    return [f.extra["rule_id"] for f in findings]


def test_parse_settings_ignores_errors_and_blank_lines():
    raw = "__ERROR__ boom\nMinimum password length: 10\nnocolon\n: orphan\nPassword complexity: on"
    assert policy.parse_settings(raw) == {"Minimum password length": "10", "Password complexity": "on"}


def test_parse_number_units_unlimited_and_negative():
    assert policy.parse_number("42") == 42
    assert policy.parse_number("15 mins") == 15
    assert policy.parse_number("unlimited") is None
    assert policy.parse_number("None") is None
    assert policy.parse_number("-1") == -1
    assert policy.parse_number("") is None
    assert policy.parse_number("garbage") is None


def test_parse_bool_variants():
    assert policy.parse_bool("on") is True
    assert policy.parse_bool("OFF") is False
    assert policy.parse_bool("yes") is True
    assert policy.parse_bool("disabled") is False
    assert policy.parse_bool("maybe") is None
    assert policy.parse_bool(None) is None


def test_normalized_lab_policy():
    assert policy.normalized(policy.parse_settings(LAB_POLICY)) == {
        "min_length": 10,
        "max_age_days": 42,
        "min_age_days": 0,
        "history": 24,
        "lockout_threshold": 5,
        "lockout_duration_mins": 15,
        "lockout_reset_mins": 10,
        "complexity": True,
        "plaintext": False,
    }


def test_compliant_policy_has_no_findings():
    assert policy.evaluate(COMPLIANT) == []


def test_lab_policy_trips_min_length_rotation_and_min_age():
    found = rules(policy.evaluate(policy.parse_settings(LAB_POLICY)))
    assert found == ["POL-MIN-LENGTH", "POL-MAX-AGE", "POL-MIN-AGE"]
    [length] = [f for f in policy.evaluate(policy.parse_settings(LAB_POLICY)) if f.extra["rule_id"] == "POL-MIN-LENGTH"]
    assert length.severity == "medium"
    assert "below baseline 12" in length.detail
    assert "164.308(a)(5)(ii)(D)" in registry_cites("POL-MIN-LENGTH")


@pytest.mark.parametrize(
    "value, severity, expected",
    [
        ("7", "high", "POL-MIN-LENGTH"),
        ("8", "medium", "POL-MIN-LENGTH"),
        ("11", "medium", "POL-MIN-LENGTH"),
        ("12", None, None),
        ("16", None, None),
    ],
)
def test_minimum_length_boundary(value, severity, expected):
    found = policy.evaluate(settings(min_length=value))
    assert rules(found) == ([expected] if expected else [])
    if expected:
        assert found[0].severity == severity


def test_missing_minimum_length_is_reported():
    values = settings()
    del values["Minimum password length"]
    [finding] = policy.evaluate(values)
    assert finding.extra["rule_id"] == "POL-MIN-LENGTH"
    assert finding.severity == "medium"
    assert "not reported" in finding.detail


@pytest.mark.parametrize(
    "value, expected",
    [("23", "low"), ("24", None), ("unlimited", "low"), ("0", "low")],
)
def test_history_boundary(value, expected):
    found = policy.evaluate(settings(history=value))
    assert (found[0].severity if found else None) == expected
    if found:
        assert found[0].extra["rule_id"] == "POL-HISTORY"


@pytest.mark.parametrize(
    "value, expected",
    [
        ("30", "low"),  # too-frequent forced rotation
        ("89", "low"),
        ("90", None),
        ("365", None),
        ("366", "low"),  # too long
        ("unlimited", "low"),
    ],
)
def test_maximum_age_boundaries(value, expected):
    found = policy.evaluate(settings(max_age=value))
    assert (found[0].severity if found else None) == expected
    if found:
        assert found[0].extra["rule_id"] == "POL-MAX-AGE"


def test_minimum_age_boundary():
    assert policy.evaluate(settings(min_age="1")) == []
    [finding] = policy.evaluate(settings(min_age="0"))
    assert finding.extra["rule_id"] == "POL-MIN-AGE"
    assert finding.severity == "info"


@pytest.mark.parametrize(
    "value, severity, expected",
    [
        ("0", "high", "POL-LOCKOUT-THRESHOLD"),
        ("1", None, None),
        ("10", None, None),
        ("11", "medium", "POL-LOCKOUT-THRESHOLD"),
    ],
)
def test_lockout_threshold_boundary(value, severity, expected):
    found = policy.evaluate(settings(threshold=value))
    assert rules(found) == ([expected] if expected else [])
    if expected:
        assert found[0].severity == severity


def test_missing_or_unlimited_lockout_threshold_is_high():
    values = settings()
    del values["Account lockout threshold (attempts)"]
    [finding] = policy.evaluate(values)
    assert finding.extra["rule_id"] == "POL-LOCKOUT-THRESHOLD"
    assert finding.severity == "high"
    [unlimited] = policy.evaluate(settings(threshold="unlimited"))
    assert unlimited.severity == "high"


def test_lockout_duration_boundary_and_zero_means_admin_unlock():
    assert policy.evaluate(settings(duration="15", reset="15")) == []
    assert policy.evaluate(settings(duration="0", reset="10")) == []
    [short] = policy.evaluate(settings(duration="14", reset="10"))
    assert short.extra["rule_id"] == "POL-LOCKOUT-DURATION"
    assert short.severity == "low"


def test_lockout_reset_defeating_duration_is_medium():
    found = policy.evaluate(settings(duration="15", reset="20"))
    [finding] = [f for f in found if f.extra["rule_id"] == "POL-LOCKOUT-RESET"]
    assert finding.severity == "medium"
    assert "exceeds lockout duration" in finding.detail


def test_lockout_reset_above_baseline_is_low_when_duration_zero():
    found = policy.evaluate(settings(duration="0", reset="16"))
    [finding] = [f for f in found if f.extra["rule_id"] == "POL-LOCKOUT-RESET"]
    assert finding.severity == "low"


def test_complexity_off_and_unknown():
    [off] = policy.evaluate(settings(complexity="off"))
    assert (off.extra["rule_id"], off.severity) == ("POL-COMPLEXITY", "medium")
    values = settings()
    del values["Password complexity"]
    [unknown] = policy.evaluate(values)
    assert (unknown.extra["rule_id"], unknown.severity) == ("POL-COMPLEXITY", "low")


def test_plaintext_on_is_high_and_missing_is_low():
    [on] = policy.evaluate(settings(plaintext="on"))
    assert (on.extra["rule_id"], on.severity) == ("POL-PLAINTEXT", "high")
    assert "164.308(a)(5)(ii)(D)" in registry_cites("POL-PLAINTEXT")
    values = settings()
    del values["Store plaintext passwords"]
    [missing] = policy.evaluate(values)
    assert (missing.extra["rule_id"], missing.severity) == ("POL-PLAINTEXT", "low")


def test_baseline_is_overridable_data():
    permissive = policy.PolicyBaseline(min_length=8, min_max_age_days=30, min_age_days=0)
    found = policy.evaluate(policy.parse_settings(LAB_POLICY), permissive)
    assert "POL-MIN-LENGTH" not in rules(found)
    assert "POL-MAX-AGE" not in rules(found)
    assert "POL-MIN-AGE" not in rules(found)


def test_tagged_finding_serialises_rule_id_and_subject():
    finding = policy.tagged_finding("low", "x", "POL-TEST", "domain", observed=1)
    assert finding.to_dict() == {
        "severity": "low",
        "detail": "x",
        "rule_id": "POL-TEST",
        "subject": "domain",
        "observed": 1,
    }


def test_collect_reports_unavailable_policy(monkeypatch):
    monkeypatch.setattr(policy, "dexec", lambda cmd, timeout=30: "__ERROR__ docker not running")
    out = policy.collect()
    assert out["findings"][0]["rule_id"] == "POL-UNAVAILABLE"
    assert out["evaluated"] == {}


def test_collect_evaluates_full_output(monkeypatch):
    monkeypatch.setattr(policy, "dexec", lambda cmd, timeout=30: LAB_POLICY)
    out = policy.collect()
    assert out["evaluated"]["min_length"] == 10
    assert "POL-MIN-LENGTH" in [f["rule_id"] for f in out["findings"]]


def test_lab_fixture_matches_the_documented_weak_policy():
    if not FIXTURE.exists():
        pytest.skip("collector fixture not recorded")
    found = rules(policy.evaluate(policy.parse_settings(FIXTURE.read_text(encoding="utf-8"))))
    assert "POL-MIN-LENGTH" in found
    assert "POL-MAX-AGE" in found


def test_all_section_rule_ids_are_registered_with_matching_groups():
    from practice_evidence.sections import acls, hygiene, privilege
    from practice_render.rules import RULES as REGISTRY

    for module in (policy, acls, privilege, hygiene):
        missing = set(module.RULES) - set(REGISTRY)
        assert not missing, f"{module.__name__} rule ids not registered: {sorted(missing)}"
        for rule_id, meta in module.RULES.items():
            assert REGISTRY[rule_id].group == meta["group"], rule_id
