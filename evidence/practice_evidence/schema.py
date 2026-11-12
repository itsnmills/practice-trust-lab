"""Snapshot contract: version policy, a small stdlib validator, and migration.

The authoritative schema lives in ``evidence/practice_evidence/data/practice-snapshot.schema.json``
(draft 2020-12).  Runtime validation deliberately has no third-party dependency:
:func:`validate_instance` implements exactly the keywords this schema uses.

Public API
----------
``SCHEMA_PATH``                  path of the JSON Schema file
``Problem``                      one validation message (severity: error/warning)
``validate_snapshot(doc)``       version policy + structural validation
``validate_structurally(doc)``   schema validation only (no version policy)
``validate_instance(value, schema)``
``parse_version(text)``          -> (major, minor, patch) or None
``migrate(doc)``                 0.2 -> 0.3; 0.3 and newer MINOR pass through
``load_snapshot(path)``          read + migrate + validate; raises on errors
``SnapshotValidationError``      raised by :func:`load_snapshot`

Run the validator from the ``evidence`` directory::

    python -m practice_evidence.schema ../examples/sample-snapshot.json
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
import warnings
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from . import SCHEMA

SCHEMA_PATH = Path(__file__).resolve().parent / "data" / "practice-snapshot.schema.json"

_VERSION_RE = re.compile(r"^velari\.practice-snapshot/(\d+)\.(\d+)(?:\.(\d+))?$")
_CURRENT_MAJOR = 0
_CURRENT_MINOR = 3
_MIN_READABLE_MINOR = 2

_METADATA_KEYWORDS = {"$schema", "$id", "title", "description", "$comment"}
_SUPPORTED_KEYWORDS = _METADATA_KEYWORDS | {
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

_TYPE_NAMES = {"object", "array", "string", "integer", "number", "boolean", "null"}


@dataclass(frozen=True)
class Problem:
    """One validation message. ``severity`` is ``error`` or ``warning``."""

    path: str
    message: str
    severity: str = "error"
    code: str = "invalid"

    def __str__(self) -> str:
        where = self.path or "$"
        return f"{self.severity}: {where}: {self.message}"


class SnapshotValidationError(ValueError):
    """Raised by :func:`load_snapshot` when the document has error-level problems."""

    def __init__(self, problems: list[Problem]):
        self.problems = problems
        super().__init__("; ".join(str(p) for p in problems))


def parse_version(text: Any) -> tuple[int, int, int] | None:
    """Parse ``velari.practice-snapshot/MAJOR.MINOR[.PATCH]``; None if malformed."""
    if not isinstance(text, str):
        return None
    match = _VERSION_RE.match(text)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)


@lru_cache(maxsize=1)
def load_schema() -> dict[str, Any]:
    """Load and cache the JSON Schema document."""
    schema: dict[str, Any] = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return schema


# --------------------------------------------------------------------------
# Validator
# --------------------------------------------------------------------------


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"


def _type_matches(value: Any, expected: str) -> bool:
    actual = _json_type(value)
    if expected == "number":
        return actual in ("integer", "number")
    return actual == expected


def _json_equal(left: Any, right: Any) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left == right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left == right
    return type(left) is type(right) and left == right


def _child(path: str, key: Any) -> str:
    text = str(key)
    if text.isidentifier():
        return f"{path}.{text}"
    return f"{path}[{text!r}]"


def _index(path: str, index: int) -> str:
    return f"{path}[{index}]"


def _resolve_ref(ref: str, root: Any) -> Any:
    if not isinstance(ref, str) or not ref.startswith("#/"):
        raise ValueError(f"unsupported $ref {ref!r}; only local JSON pointers are supported")
    node = root
    for raw in ref[2:].split("/"):
        part = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and part in node:
            node = node[part]
        elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
            node = node[int(part)]
        else:
            raise ValueError(f"unresolvable $ref {ref!r}")
    return node


def validate_instance(value: Any, schema: Any, *, path: str = "$", root: Any | None = None) -> list[Problem]:
    """Validate ``value`` against ``schema`` using the supported keyword subset."""
    if root is None:
        root = schema
    return _validate(value, schema, root, path)


def _validate(value: Any, schema: Any, root: Any, path: str) -> list[Problem]:
    problems: list[Problem] = []
    if schema is True:
        return problems
    if schema is False:
        return [Problem(path, "no value is allowed here", code="not_allowed")]
    if not isinstance(schema, dict):
        return [Problem(path, "schema node is not an object", code="schema")]

    if "$ref" in schema:
        try:
            target = _resolve_ref(schema["$ref"], root)
        except ValueError as exc:
            return [Problem(path, str(exc), code="schema")]
        # The project schema always uses a lone $ref; sibling keywords are ignored.
        return _validate(value, target, root, path)

    expected = schema.get("type")
    if expected is not None:
        names = expected if isinstance(expected, list) else [expected]
        if not any(_type_matches(value, name) for name in names):
            problems.append(
                Problem(
                    path,
                    f"expected type {'/'.join(str(n) for n in names)}, got {_json_type(value)}",
                    code="type",
                )
            )
            return problems

    if "enum" in schema:
        allowed = schema["enum"]
        if not any(_json_equal(value, candidate) for candidate in allowed):
            problems.append(Problem(path, f"value {value!r} is not one of {allowed!r}", code="enum"))

    if "pattern" in schema and isinstance(value, str):
        try:
            matched = re.search(schema["pattern"], value) is not None
        except re.error as exc:
            problems.append(Problem(path, f"invalid schema pattern: {exc}", code="schema"))
        else:
            if not matched:
                problems.append(Problem(path, f"value {value!r} does not match {schema['pattern']!r}", code="pattern"))

    if "minimum" in schema and isinstance(value, (int, float)) and not isinstance(value, bool):
        if value < schema["minimum"]:
            problems.append(
                Problem(path, f"value {value!r} is less than minimum {schema['minimum']!r}", code="minimum")
            )

    if isinstance(value, dict):
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            properties = {}
        for name in schema.get("required", []):
            if name not in value:
                problems.append(Problem(_child(path, name), "required property is missing", code="required"))
        for name, subschema in properties.items():
            if name in value:
                problems.extend(_validate(value[name], subschema, root, _child(path, name)))
        extra = set(value) - set(properties)
        additional = schema.get("additionalProperties", True)
        if additional is False:
            for name in sorted(extra, key=str):
                problems.append(Problem(_child(path, name), "additional property is not allowed", code="additional"))
        elif isinstance(additional, dict):
            for name in sorted(extra, key=str):
                problems.extend(_validate(value[name], additional, root, _child(path, name)))
    elif isinstance(value, list) and "items" in schema:
        for index, item in enumerate(value):
            problems.extend(_validate(item, schema["items"], root, _index(path, index)))

    if "oneOf" in schema:
        branches = schema["oneOf"]
        matches = sum(1 for branch in branches if not _errors(_validate(value, branch, root, path)))
        if matches != 1:
            problems.append(
                Problem(path, f"expected exactly one of {len(branches)} alternatives, matched {matches}", code="oneOf")
            )
    if "anyOf" in schema:
        branches = schema["anyOf"]
        if not any(not _errors(_validate(value, branch, root, path)) for branch in branches):
            problems.append(Problem(path, f"value does not match any of {len(branches)} alternatives", code="anyOf"))

    return problems


def _errors(problems: list[Problem]) -> list[Problem]:
    return [p for p in problems if p.severity == "error"]


# --------------------------------------------------------------------------
# Snapshot validation and version policy
# --------------------------------------------------------------------------


def validate_structurally(doc: Any) -> list[Problem]:
    """Validate the document against the schema, ignoring the version policy."""
    return validate_instance(doc, load_schema())


def _version_problems(doc: dict[str, Any]) -> tuple[list[Problem], bool]:
    """Return (problems, may_continue). ``may_continue`` is False for fatal versions."""
    raw = doc.get("schema")
    if not isinstance(raw, str):
        return [Problem("$.schema", "schema version must be a string", code="version")], False
    parsed = parse_version(raw)
    if parsed is None:
        return [
            Problem(
                "$.schema",
                "schema version must look like velari.practice-snapshot/MAJOR.MINOR",
                code="version",
            )
        ], False
    major, minor, _patch = parsed
    if major != _CURRENT_MAJOR:
        return [
            Problem(
                "$.schema",
                f"unsupported schema MAJOR {major}: this build reads "
                f"velari.practice-snapshot/{_CURRENT_MAJOR}.x only; refusing to guess at "
                "breaking changes",
                code="version_major",
            )
        ], False
    problems: list[Problem] = []
    if minor > _CURRENT_MINOR:
        problems.append(
            Problem(
                "$.schema",
                f"newer MINOR version {major}.{minor} accepted with a warning; "
                f"fields this build ({SCHEMA}) does not know are ignored",
                severity="warning",
                code="version_minor_newer",
            )
        )
    elif minor < _MIN_READABLE_MINOR:
        return [
            Problem(
                "$.schema",
                f"unsupported old schema MINOR {minor}: the oldest readable version is "
                f"{_CURRENT_MAJOR}.{_MIN_READABLE_MINOR}",
                code="version_minor_old",
            )
        ], False
    return problems, True


def validate_snapshot(doc: Any) -> list[Problem]:
    """Validate a snapshot, applying version policy and structural checks.

    Returns a list of :class:`Problem`. Empty means clean. ``error`` problems make
    the document invalid; ``warning`` problems (for a newer MINOR) do not.
    """
    if not isinstance(doc, dict):
        return [Problem("$", "snapshot must be a JSON object", code="type")]
    problems, may_continue = _version_problems(doc)
    if not may_continue:
        return problems
    return problems + validate_structurally(doc)


# --------------------------------------------------------------------------
# Migration and loading
# --------------------------------------------------------------------------


def migrate(doc: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``doc`` at the current schema version.

    Today the only migration is 0.2 -> 0.3. It is a version stamp because every
    0.3 addition is optional and additive; no field is renamed or removed.
    Documents at 0.3 (or an unknown newer MINOR of major 0) pass through
    unchanged. Unknown MAJOR and unreadably old MINOR versions raise ValueError.
    """
    if not isinstance(doc, dict):
        raise ValueError("snapshot must be a JSON object")
    raw = doc.get("schema")
    parsed = parse_version(raw)
    if parsed is None:
        raise ValueError(f"missing or malformed schema version: {raw!r}")
    major, minor, _patch = parsed
    if major != _CURRENT_MAJOR:
        raise ValueError(
            f"cannot migrate schema MAJOR {major}; this build reads velari.practice-snapshot/{_CURRENT_MAJOR}.x"
        )
    if minor < _MIN_READABLE_MINOR:
        raise ValueError(
            f"cannot migrate schema {major}.{minor}; the oldest readable version is "
            f"{_CURRENT_MAJOR}.{_MIN_READABLE_MINOR}"
        )
    migrated = copy.deepcopy(doc)
    if minor < _CURRENT_MINOR:
        migrated["schema"] = SCHEMA
    return migrated


def load_snapshot(path: str | Path) -> dict[str, Any]:
    """Read, migrate, and validate a snapshot file.

    Error-level problems raise :class:`SnapshotValidationError`. Warnings (newer
    MINOR) are emitted through :mod:`warnings` and the migrated document is
    returned. Renderers and drift code should use this helper rather than calling
    :func:`migrate` directly, so version handling stays in one place.
    """
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    migrated = migrate(doc)
    problems = validate_snapshot(migrated)
    errors = _errors(problems)
    if errors:
        raise SnapshotValidationError(errors)
    for problem in problems:
        warnings.warn(str(problem), stacklevel=2)
    return migrated


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a Velari practice snapshot")
    parser.add_argument("snapshot", help="path to a snapshot JSON file")
    args = parser.parse_args(argv)
    try:
        doc = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: {args.snapshot}: {exc}", file=sys.stderr)
        return 2
    try:
        doc = migrate(doc)
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    problems = validate_snapshot(doc)
    for problem in problems:
        print(str(problem))
    errors = _errors(problems)
    if errors:
        print(f"FAIL: {len(errors)} error(s), {len(problems) - len(errors)} warning(s)", file=sys.stderr)
        return 1
    print(f"ok: {args.snapshot} validates as {doc.get('schema')}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
