"""The rules registry is the single source of truth for reviewer-facing fields."""

import ast
import re
from dataclasses import fields
from pathlib import Path

import pytest
from practice_evidence.sections import auth, ehr, endpoints, identity, shares, supply_chain
from practice_render.rules import (
    DEFAULT_RULE,
    LEGACY_ORDER,
    RULES,
    SEVERITY_ORDER,
    Cite,
    all_groups,
    rule_for_detail,
    rule_for_finding,
)

SECTIONS_DIR = Path(__file__).resolve().parent.parent / "evidence" / "practice_evidence" / "sections"
RULE_FIELDS = {
    "rule_id",
    "group",
    "title",
    "lane",
    "ask",
    "proof",
    "due",
    "confidence",
    "severity",
    "hipaa",
    "legacy_matches",
}


def emitted_rule_ids() -> set[str]:
    """Rule ids written as string literals in any section's Finding(...) call."""
    found: set[str] = set()
    for path in SECTIONS_DIR.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            if name != "Finding":
                continue
            for keyword in node.keywords:
                if keyword.arg == "rule_id" and isinstance(keyword.value, ast.Constant):
                    if isinstance(keyword.value.value, str) and keyword.value.value:
                        found.add(keyword.value.value)
    return found


def dynamic_rule_ids() -> set[str]:
    """Rule ids produced by running the pure section helpers on sample input."""
    findings = []
    findings += identity.user_findings({"sam": "u", "enabled": False, "stale": True, "never_logged_on": True})
    findings += shares.share_findings([{"path": "/s/patient.csv"}])
    findings += ehr.event_findings({"scribe_transmission": 1, "intake_submitted": 1})
    findings += endpoints.host_findings(
        {"name": "host", "role": "role"},
        [{"file": "patient.csv", "readable": True}, {"file": "x.txt", "readable": False}],
    )
    findings += endpoints.host_findings({"name": "host", "role": "role"}, [{"file": "x.txt", "readable": True}])
    findings += auth.summarize(
        "\n".join(
            [f"user [D]\\[{i}] at [x] status [NT_STATUS_WRONG_PASSWORD]" for i in range(5)]
            + ["user [D]\\[u] at [x] status [NT_STATUS_ACCOUNT_LOCKED_OUT]"]
        ),
        24,
    )["findings"]
    findings += supply_chain.parse_findings(
        '{"record_type":"finding","severity":"critical","package_name":"p","version":"1",'
        '"ecosystem":"npm","catalog_name":"c","project_path":"/lab/x","source_file":"/lab/f"}',
        lab_root="/lab",
    )
    return {f.rule_id for f in findings if getattr(f, "rule_id", None)}


def test_every_rule_entry_has_all_fields():
    for rule_id, rule in RULES.items():
        assert rule_id == rule.rule_id
        for name in RULE_FIELDS:
            assert hasattr(rule, name), f"{rule_id} missing {name}"
        assert rule.title is None or rule.title.strip(), rule_id
        assert rule.lane and rule.ask and rule.proof and rule.due and rule.confidence, rule_id
        assert rule.severity in SEVERITY_ORDER, rule_id
        assert rule.group in all_groups(), rule_id


def test_rule_ids_are_unique_uppercase_and_descriptive():
    for rule_id in RULES:
        assert rule_id == rule_id.upper()
        assert rule_id.replace("-", "").isalnum()
        assert rule_id.count("-") >= 1
        assert len(rule_id) <= 40


def test_no_duplicate_legacy_substring_matches():
    seen: dict[str, str] = {}
    for rule in RULES.values():
        for match in rule.legacy_matches:
            key = match.lower()
            assert key not in seen, f"{match!r} used by {seen.get(key)} and {rule.rule_id}"
            seen[key] = rule.rule_id
    assert set(LEGACY_ORDER) == {rule.rule_id for rule in RULES.values() if rule.legacy_matches}


@pytest.mark.parametrize("rule", sorted(RULES.values(), key=lambda item: item.rule_id), ids=lambda r: r.rule_id)
def test_rule_has_valid_hipaa_cites(rule):
    if rule.group == "other":
        assert rule.hipaa == ()
    else:
        assert rule.hipaa, f"{rule.rule_id} needs HIPAA cites"
    for cite in rule.hipaa:
        assert isinstance(cite, Cite)
        assert cite.section.startswith("164.")
        assert cite.kind in {"standard", "required", "addressable", "privacy"}


def test_every_emitted_rule_id_is_registered():
    emitted = emitted_rule_ids()
    assert emitted, "expected at least one Finding(rule_id=...) in the sections"
    assert emitted <= set(RULES), f"unregistered rule ids: {sorted(emitted - set(RULES))}"


def test_running_sections_only_emits_registered_rule_ids():
    emitted = dynamic_rule_ids()
    assert emitted
    assert emitted <= set(RULES), f"unregistered rule ids: {sorted(emitted - set(RULES))}"


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_registered_rules_are_reachable_by_id(rule_id):
    assert rule_for_finding({"rule_id": rule_id, "detail": "irrelevant"}) is RULES[rule_id]


def test_legacy_matches_round_trip():
    for rule in RULES.values():
        for match in rule.legacy_matches:
            assert rule_for_detail(f"x {match} y") is rule


def test_unknown_rule_id_falls_back_to_legacy_text():
    assert (
        rule_for_finding({"rule_id": "NOPE-NOT-REAL", "detail": "x never logged on"}).rule_id == "IDN-DORMANT-ACCOUNT"
    )
    assert rule_for_finding({"detail": "unmapped"}).rule_id == DEFAULT_RULE.rule_id


def test_registry_fields_are_stable_exports():
    assert {field.name for field in fields(DEFAULT_RULE)} == RULE_FIELDS
    assert DEFAULT_RULE.group == "other"
    assert DEFAULT_RULE.severity in SEVERITY_ORDER


RULE_ID_RE = re.compile(r"^(?:POL|ACL|PRIV|HYG|IDN|SHR|EP|EHR|AUTH|SUPPLY)-[A-Z0-9]+(?:-[A-Z0-9]+)*$")


def declared_rule_ids() -> set[str]:
    """Rule-id string literals anywhere in the section modules (what the collector can emit)."""
    declared: set[str] = set()
    for path in SECTIONS_DIR.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), filename=str(path))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and RULE_ID_RE.match(node.value):
                declared.add(node.value)
    return declared


def test_registry_has_no_rule_the_collector_cannot_emit():
    assert set(RULES) <= declared_rule_ids()


def test_every_section_declared_rule_id_is_registered():
    declared = declared_rule_ids()
    assert len(declared) >= 40, "expected the section modules to emit their rule ids"
    assert declared <= set(RULES), f"unregistered rule ids: {sorted(declared - set(RULES))}"
