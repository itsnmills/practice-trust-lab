"""Snapshot contract tests: version policy, validation, migration, schema fidelity."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest
from practice_evidence import SCHEMA, schema

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "examples" / "sample-snapshot.json"

SUPPORTED_KEYWORDS = {
    "$schema",
    "$id",
    "title",
    "description",
    "$comment",
    "$defs",
    "$ref",
    "type",
    "required",
    "properties",
    "items",
    "enum",
    "pattern",
    "additionalProperties",
    "minimum",
    "oneOf",
    "anyOf",
}


@pytest.fixture(scope="module")
def sample() -> dict:
    return json.loads(SAMPLE.read_text(encoding="utf-8"))


def doc_at(sample: dict, version: str) -> dict:
    doc = copy.deepcopy(sample)
    doc["schema"] = version
    return doc


def errors(problems: list[schema.Problem]) -> list[schema.Problem]:
    return [p for p in problems if p.severity == "error"]


def warnings(problems: list[schema.Problem]) -> list[schema.Problem]:
    return [p for p in problems if p.severity == "warning"]


def codes(problems: list[schema.Problem]) -> set[str]:
    return {p.code for p in problems}


# --------------------------------------------------------------------------
# The committed sample and the current version
# --------------------------------------------------------------------------


def test_current_schema_version_is_0_3():
    assert SCHEMA == "velari.practice-snapshot/0.3"
    assert schema.parse_version(SCHEMA) == (0, 3, 0)


def test_committed_sample_validates(sample):
    assert errors(schema.validate_snapshot(sample)) == []


def test_schema_file_is_valid_json_and_matches_draft():
    raw = schema.SCHEMA_PATH.read_text(encoding="utf-8")
    loaded = json.loads(raw)
    assert loaded["$schema"] == "https://json-schema.org/draft/2020-12/schema"


def test_schema_uses_only_supported_keywords():
    def walk(node):
        if not isinstance(node, dict):
            return
        yield from node.keys()
        for definition in node.get("$defs", {}).values():
            yield from walk(definition)
        for subschema in node.get("properties", {}).values():
            yield from walk(subschema)
        if isinstance(node.get("items"), dict):
            yield from walk(node["items"])
        if isinstance(node.get("additionalProperties"), dict):
            yield from walk(node["additionalProperties"])
        for key in ("oneOf", "anyOf"):
            for subschema in node.get(key, []):
                yield from walk(subschema)

    used = set(walk(schema.load_schema()))
    assert used <= SUPPORTED_KEYWORDS
    assert schema._SUPPORTED_KEYWORDS == SUPPORTED_KEYWORDS


# --------------------------------------------------------------------------
# Structural validator
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda d: d.pop("drift"), id="missing-required-top-level"),
        pytest.param(lambda d: d.__setitem__("containers", {}), id="containers-not-array"),
        pytest.param(lambda d: d["findings"][0].__setitem__("severity", "critical"), id="bad-severity"),
        pytest.param(lambda d: d["findings"][0].__setitem__("detail", 7), id="detail-not-string"),
        pytest.param(lambda d: d["identity"]["users"][0].__setitem__("enabled", "yes"), id="enabled-not-bool"),
        pytest.param(
            lambda d: d["identity"]["users"][0].__setitem__("last_logon", "yesterday"),
            id="bad-last-logon",
        ),
        pytest.param(
            lambda d: d["shares"]["files"][0].__setitem__("sha256_16", "NOT-A-HASH"),
            id="bad-hash-pattern",
        ),
        pytest.param(lambda d: d["auth"].__setitem__("success", -1), id="negative-count"),
        pytest.param(lambda d: d["drift"].__setitem__("status", "unknown"), id="bad-drift-status"),
        pytest.param(lambda d: d["supply_chain"].__setitem__("status", "half-done"), id="bad-scanner-status"),
        pytest.param(lambda d: d.__setitem__("section_errors", "oops"), id="section-errors-not-object"),
    ],
)
def test_invalid_documents_produce_errors(sample, mutate):
    doc = copy.deepcopy(sample)
    mutate(doc)
    found = schema.validate_snapshot(doc)
    assert errors(found), f"expected an error, got {found}"
    assert any(p.path.startswith("$") for p in found)


def test_non_object_document_is_rejected():
    [problem] = schema.validate_snapshot([])
    assert problem.severity == "error"
    assert problem.code == "type"


def test_extra_finding_fields_and_sections_are_tolerated(sample):
    doc = doc_at(sample, SCHEMA)
    doc["findings"][0]["rule_id"] = "shares.patient_adjacent"
    doc["findings"][0]["subject"] = "/srv/samba/shares/clinical/x.csv"
    doc["findings"][0]["future_field"] = {"anything": [1, 2, 3]}
    doc["policy"] = {"findings": [], "documents": [{"name": "Sanction policy"}]}
    doc["acls"] = []
    doc["privilege"] = {"findings": []}
    doc["hygiene"] = {"findings": [], "score": 1}
    doc["future_section"] = {"whatever": True}
    doc["section_errors"] = {"acls": "CommandRefused: unsupported command"}
    assert errors(schema.validate_snapshot(doc)) == []


def test_optional_finding_fields_are_typed(sample):
    doc = doc_at(sample, SCHEMA)
    doc["findings"][0]["rule_id"] = 42
    assert any(p.path.endswith(".rule_id") and p.code == "type" for p in schema.validate_snapshot(doc))


# --------------------------------------------------------------------------
# Version policy
# --------------------------------------------------------------------------


def test_newer_minor_validates_with_a_warning(sample):
    doc = doc_at(sample, "velari.practice-snapshot/0.4")
    doc["unknown_from_the_future"] = {"new": "section"}
    found = schema.validate_snapshot(doc)
    assert errors(found) == []
    assert [p.code for p in warnings(found)] == ["version_minor_newer"]


def test_unknown_major_is_rejected_with_a_clear_message(sample):
    found = schema.validate_snapshot(doc_at(sample, "velari.practice-snapshot/1.0"))
    assert len(found) == 1
    assert found[0].code == "version_major"
    assert "MAJOR 1" in found[0].message
    assert "refusing" in found[0].message


def test_malformed_version_is_rejected(sample):
    found = schema.validate_snapshot(doc_at(sample, "practice-snapshot/0.3"))
    assert codes(found) == {"version"}
    assert found[0].severity == "error"


def test_too_old_minor_is_rejected(sample):
    found = schema.validate_snapshot(doc_at(sample, "velari.practice-snapshot/0.1"))
    assert len(found) == 1
    assert found[0].code == "version_minor_old"


def test_current_minor_has_no_version_warning(sample):
    assert schema.validate_snapshot(doc_at(sample, SCHEMA)) == []


def test_patch_versions_are_structurally_compatible(sample):
    assert errors(schema.validate_snapshot(doc_at(sample, "velari.practice-snapshot/0.3.7"))) == []


# --------------------------------------------------------------------------
# Migration
# --------------------------------------------------------------------------


def test_migrate_0_2_to_0_3(sample):
    legacy = doc_at(sample, "velari.practice-snapshot/0.2")
    migrated = schema.migrate(legacy)
    assert migrated["schema"] == "velari.practice-snapshot/0.3"
    assert migrated is not legacy
    assert legacy["schema"] == "velari.practice-snapshot/0.2", "input must not be mutated"
    assert errors(schema.validate_snapshot(migrated)) == []


def test_migrate_is_idempotent(sample):
    once = schema.migrate(doc_at(sample, "velari.practice-snapshot/0.2"))
    twice = schema.migrate(once)
    assert once == twice
    assert twice["schema"] == SCHEMA


def test_migrate_preserves_sections_and_findings(sample):
    legacy = doc_at(sample, "velari.practice-snapshot/0.2")
    migrated = schema.migrate(legacy)
    for key in ("identity", "shares", "auth", "ehr", "endpoints", "supply_chain", "findings", "drift"):
        assert migrated[key] == legacy[key]


def test_migrate_passes_newer_minor_through(sample):
    doc = doc_at(sample, "velari.practice-snapshot/0.5")
    migrated = schema.migrate(doc)
    assert migrated["schema"] == "velari.practice-snapshot/0.5"


@pytest.mark.parametrize(
    "version",
    ["velari.practice-snapshot/1.0", "velari.practice-snapshot/0.1", "not-a-version", None],
)
def test_migrate_rejects_unreadable_versions(sample, version):
    doc = doc_at(sample, version)
    with pytest.raises(ValueError):
        schema.migrate(doc)


# --------------------------------------------------------------------------
# load_snapshot helper
# --------------------------------------------------------------------------


def test_load_snapshot_migrates_and_validates(sample, tmp_path):
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(sample), encoding="utf-8")
    loaded = schema.load_snapshot(path)
    assert loaded["schema"] == SCHEMA


def test_load_snapshot_raises_on_invalid(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"schema": SCHEMA}), encoding="utf-8")
    with pytest.raises(schema.SnapshotValidationError) as excinfo:
        schema.load_snapshot(path)
    assert excinfo.value.problems
    assert all(p.severity == "error" for p in excinfo.value.problems)


def test_load_snapshot_warns_on_newer_minor(sample, tmp_path):
    doc = doc_at(sample, "velari.practice-snapshot/0.9")
    path = tmp_path / "future.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.warns(UserWarning, match="newer MINOR"):
        loaded = schema.load_snapshot(path)
    assert loaded["schema"] == "velari.practice-snapshot/0.9"


def test_collector_validate_flag(sample, tmp_path, capsys):
    from practice_evidence import cli

    good = tmp_path / "good.json"
    good.write_text(json.dumps(sample), encoding="utf-8")
    assert cli.main(["--validate", str(good), "--quiet"]) == 0

    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"schema": SCHEMA}), encoding="utf-8")
    assert cli.main(["--validate", str(bad), "--quiet"]) == 1
    assert "required property is missing" in capsys.readouterr().err

    assert cli.main(["--validate", str(tmp_path / "missing.json")]) == 2


# --------------------------------------------------------------------------
# Keyword-level unit tests
# --------------------------------------------------------------------------


def test_type_keyword_distinguishes_bool_from_integer():
    assert schema.validate_instance(1, {"type": "integer"}) == []
    assert schema.validate_instance(True, {"type": "integer"})
    assert schema.validate_instance(1, {"type": "number"}) == []
    assert schema.validate_instance(1, {"type": ["string", "null"]})


def test_enum_is_type_aware():
    assert schema.validate_instance(True, {"enum": [1]})
    assert schema.validate_instance(1, {"enum": [1]}) == []


def test_additional_properties_false_rejects_unknown():
    [problem] = schema.validate_instance(
        {"a": 1, "b": 2}, {"properties": {"a": {"type": "integer"}}, "additionalProperties": False}
    )
    assert problem.code == "additional"


def test_ref_items_and_pattern():
    doc = {"$defs": {"hex": {"type": "string", "pattern": "^[0-9a-f]+$"}}, "items": {"$ref": "#/$defs/hex"}}
    assert schema.validate_instance(["abc123"], doc) == []
    assert schema.validate_instance(["XYZ"], doc)


def test_one_of_and_any_of():
    one = {"oneOf": [{"type": "integer"}, {"type": "string"}]}
    assert schema.validate_instance(1, one) == []
    both = {"oneOf": [{"type": "integer"}, {"type": "number"}]}
    assert schema.validate_instance(1, both)
    either = {"anyOf": [{"type": "integer"}, {"type": "null"}]}
    assert schema.validate_instance(None, either) == []
    assert schema.validate_instance(True, either)


def test_minimum_ignores_non_numbers():
    assert schema.validate_instance(-1, {"minimum": 0})
    assert schema.validate_instance(0, {"minimum": 0}) == []
    assert schema.validate_instance("x", {"minimum": 0}) == []


# --------------------------------------------------------------------------
# Optional agreement with the real jsonschema package
# --------------------------------------------------------------------------


def test_stdlib_validator_agrees_with_jsonschema(sample):
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.Draft202012Validator.check_schema(schema.load_schema())
    validator = jsonschema.Draft202012Validator(schema.load_schema())

    optional = doc_at(sample, SCHEMA)
    optional["findings"][0]["rule_id"] = "x"
    optional["policy"] = {"findings": []}
    optional["future_section"] = [1, 2]

    bad_severity = copy.deepcopy(sample)
    bad_severity["findings"][0]["severity"] = "critical"

    missing = copy.deepcopy(sample)
    missing.pop("drift")

    bad_hash = copy.deepcopy(sample)
    bad_hash["shares"]["files"][0]["sha256_16"] = "XYZ"

    corpus = [
        sample,
        doc_at(sample, SCHEMA),
        optional,
        doc_at(sample, "velari.practice-snapshot/0.4"),
        bad_severity,
        missing,
        bad_hash,
        {"schema": SCHEMA},
        [],
    ]
    for index, doc in enumerate(corpus):
        real = validator.is_valid(doc)
        ours = not errors(schema.validate_structurally(doc))
        assert ours == real, f"validators disagree on corpus[{index}]"


# --------------------------------------------------------------------------
# A freshly collected snapshot (all sections, including extension sections)
# --------------------------------------------------------------------------


def test_freshly_built_snapshot_validates(tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / "tests" / "e2e"))
    from practice_evidence import snapshot
    from practice_evidence.drift import compute_drift
    from practice_evidence.runner import use_runner
    from support import NOW, FakeLab

    lab = FakeLab(tmp_path, monkeypatch)
    lab.set_ehr("run1")
    with use_runner(lab.runner("run1")):
        doc = snapshot.build(NOW, hours=24)
    doc["drift"] = compute_drift(None, doc)

    assert doc["schema"] == SCHEMA
    assert "policy" in doc and "acls" in doc and "privilege" in doc and "hygiene" in doc
    assert errors(schema.validate_snapshot(doc)) == []
