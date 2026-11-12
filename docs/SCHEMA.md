# Snapshot contract and no-PHI guard

This page is the formal contract for the JSON snapshot that the evidence collector
writes, plus the scanner that checks generated artifacts for PHI and credentials.
The machine-readable schema is
[`evidence/practice_evidence/data/practice-snapshot.schema.json`](../evidence/practice_evidence/data/practice-snapshot.schema.json)
(JSON Schema draft 2020-12). Runtime code validates with a small stdlib validator in
[`evidence/practice_evidence/schema.py`](../evidence/practice_evidence/schema.py);
`jsonschema` is never a runtime dependency.

The contract is deliberately **metadata-only**: users, group membership, policy
strings, counts, paths, and truncated hashes. The collector never reads file
contents (except to hash them), request bodies, message bodies, or credentials.

## Version policy

The version is the string in the top-level `schema` field:

```
velari.practice-snapshot/MAJOR.MINOR[.PATCH]
```

| Part | Meaning | Reader behaviour |
|---|---|---|
| `MAJOR` | Breaking change: removed/renamed field, changed type or meaning, new required field | Unknown major is **rejected** with a clear error |
| `MINOR` | Additive change: new optional field or new optional section | A **newer** minor of the same major is accepted with a warning; unknown fields are ignored |
| `PATCH` | Documentation, description, or schema-comment change; no structural change | Accepted, no warning |

Current version: **`velari.practice-snapshot/0.3`** (`SCHEMA` in
`evidence/practice_evidence/__init__.py`). The oldest readable version is `0.2`;
`0.1` and below are rejected rather than guessed at.

### Why 0.3 instead of 0.2

0.3 formalises two additive changes made by the wider pipeline:

- optional finding fields `rule_id` and `subject` (stable rule identity and the
  account/host/path the finding is about);
- optional top-level sections `policy`, `acls`, `privilege`, and `hygiene`.

Every 0.3 addition is optional and no 0.2 field changed type or meaning, so a 0.2
document is a valid 0.3 document. The committed sample is a 0.2 document, and
`tests/test_schema.py` keeps an explicit 0.2 migration fixture even if the sample
is later regenerated at 0.3.

## Document structure

Required top-level keys: `collector`, `schema`, `collected_at`, `lab`,
`containers`, `identity`, `shares`, `auth`, `ehr`, `endpoints`, `supply_chain`,
`findings`, `finding_counts`, `drift`. Unknown top-level keys are allowed, so a
newer MINOR can add sections without breaking older readers.

| Field | Type | Meaning |
|---|---|---|
| `collector` | string | Entry point that produced the snapshot |
| `schema` | string | Version, per the policy above |
| `collected_at` | string | UTC time, `YYYY-MM-DDTHH:MM:SSZ` |
| `lab` | string | Human label, e.g. `millslab.internal (synthetic)` |
| `containers` | array | Lab container inventory (allowlisted names only) |
| `identity` | object | Users, password policy, privileged groups |
| `shares` | object | Share definitions, file inventory, truncated hashes |
| `auth` | object | Parsed domain auth audit for a time window |
| `ehr` | object | Mock EHR health, intake, and scribe-egress counts |
| `endpoints` | object | Local copies per endpoint, hash-matched against shares |
| `supply_chain` | object | Optional Bumblebee package-exposure result |
| `findings` | array | Merged, severity-sorted findings, tagged with `section` |
| `finding_counts` | object | Severity → count |
| `drift` | object | Diff against the previous snapshot; added before writing |
| `section_errors` | object of string | Optional: section name → collection error for a degraded run |
| `policy`, `acls`, `privilege`, `hygiene` | object or array | Optional 0.3 sections; shape owned by the section module |

### `containers[]`

| Field | Type | Meaning |
|---|---|---|
| `name` | string | Lab container name |
| `status` | string | `docker ps` status text |
| `ports` | string | Published port text (`""` when none) |

### `identity`

| Field | Type | Meaning |
|---|---|---|
| `password_policy` | object of string | Raw `samba-tool domain passwordsettings show` pairs |
| `users[]` | array | One entry per account |
| `users[].sam` | string | SAM account name |
| `users[].enabled` | boolean | Account is not disabled |
| `users[].last_logon` | string or null | UTC timestamp, or null when unset |
| `users[].stale` | boolean | Enabled and no logon for more than `STALE_DAYS` |
| `users[].never_logged_on` | boolean | Enabled with no usable last-logon value |
| `privileged_groups` | object of string[] | Group → member list |
| `findings` | array | Section findings (see below) |

### `shares`

| Field | Type | Meaning |
|---|---|---|
| `shares[]` | array | Non-system Samba share sections |
| `shares[].name` | string | Share name; other keys are raw `key = value` strings |
| `files[]` | array | Files below `/srv/samba/shares` |
| `files[].path` | string | Absolute container path |
| `files[].sha256_16` | string or null | First 16 hex characters of SHA-256 |
| `findings` | array | Section findings |

### `auth`

| Field | Type | Meaning |
|---|---|---|
| `window_hours` | integer ≥ 0 | Requested log window |
| `success`, `failures` | integer ≥ 0 | Totals in the window |
| `by_user` | object | User → `{success, fail}` counters |
| `failure_reasons` | object | Status string → count |
| `findings` | array | Section findings |

### `ehr`

| Field | Type | Meaning |
|---|---|---|
| `health` | object | Parsed `/healthz` body, or `{"error": ...}` |
| `events` | object | Event name → all-time count |
| `scribe_transmissions` | integer ≥ 0 | Convenience counter for scribe events |
| `intake_submissions` | integer ≥ 0 | Convenience counter for intake events |
| `findings` | array | Section findings |

### `endpoints`

| Field | Type | Meaning |
|---|---|---|
| `hosts[]` | array | One entry per lab endpoint |
| `hosts[].name`, `role` | string | Host and its modelled role |
| `hosts[].local_copies[]` | array | Files found on the local desktop |
| `local_copies[].file` | string | File name only (not the full path) |
| `local_copies[].sha256_16` | string or null | Truncated hash; null when unreadable |
| `local_copies[].readable` | boolean | Whether the collector could read it |
| `hosts[].activity` | object | Activity event name → count |
| `findings` | array | Section findings |

### `supply_chain`

| Field | Type | Meaning |
|---|---|---|
| `scanner` | string | Scanner name (`bumblebee`) |
| `status` | enum | `complete`, `skipped`, or `error` |
| `detail` | string or null | Reason for a skip/error |
| `findings` | array | Section findings, with package metadata in extra fields |

### `findings[]` and `finding_counts`

Every finding, both per-section and merged at the top level, requires
`severity` and `detail`:

| Field | Type | Meaning |
|---|---|---|
| `severity` | enum | `high`, `medium`, `low`, `info` |
| `detail` | string | Human-readable observation; synthetic data only |
| `ref_key` | string, optional | Stable evidence ref used by the packet |
| `rule_id` | string, optional | Stable rule identifier (0.3) |
| `subject` | string, optional | Account, host, or path the finding is about (0.3) |
| `section` | string, optional | Source section; present on merged top-level findings |
| extra fields | any | Allowed by design (e.g. supply-chain package metadata) |

`finding_counts` is an object whose values are non-negative integers. Unknown
severity keys are not forbidden at that level, but `findings[].severity` is an
enum.

### `drift`

| Field | Type | Meaning |
|---|---|---|
| `compared_to` | string or null | Previous snapshot timestamp |
| `status` | enum | `baseline` or `compared` |
| `user_changes`, `group_changes`, `share_changes`, `endpoint_changes` | string[] | Human-readable changes |
| `findings_new`, `findings_resolved` | string[] | `[severity] detail` lines |
| `counter_deltas` | object | Metric → signed integer delta |
| `compared_to_path` | string or null, optional | Previous snapshot path, relative to the artifacts parent directory |

## Extensibility rules

- Unknown fields are allowed on findings, sections, and at the top level.
- A new section is a new top-level key. The schema defines the 0.3 sections as
  object-or-array so a section module owns its own shape; future sections need no
  schema change to be readable.
- Adding a value to `severity`, `supply_chain.status`, or `drift.status` is a
  MAJOR change: readers switch on those values, so an unknown value is not a
  harmless extra field. They are intentionally strict today.
- Removing a field, changing a type, or adding a required field is a MAJOR change.

## Validation

Validate a file:

```bash
# from the repository root
PYTHONPATH=evidence uv run --no-project python -m practice_evidence.schema \
  examples/sample-snapshot.json

# from the evidence directory
cd evidence && uv run --no-project python -m practice_evidence.schema artifacts/2026-11-12/snapshot-....json
```

Exit codes: `0` valid (warnings allowed), `1` validation or version failure, `2`
file/JSON read error. Problems print as `error|warning: $.path: message`; a newer
MINOR emits a warning, not a failure.

Python API:

```python
from practice_evidence.schema import load_snapshot, migrate, validate_snapshot

problems = validate_snapshot(doc)  # list[Problem]; empty = clean
errors = [p for p in problems if p.severity == "error"]
doc = migrate(doc)  # 0.2 -> 0.3, input not mutated
doc = load_snapshot(path)  # read + migrate + validate, raises on errors
```

`Problem` has `path`, `message`, `severity` (`error`/`warning`), and `code`.

### Integration points

- **Collector (`cli.py`, owned by agent A).** After `snapshot["drift"]` is set and
  before `json_path.write_text(...)`, call:

  ```python
  from .schema import validate_snapshot

  problems = validate_snapshot(snapshot)
  errors = [p for p in problems if p.severity == "error"]
  if errors:
      for problem in problems:
          print(problem)
      return 1
  ```

  Add a `--validate FILE` flag that loads JSON, calls `validate_snapshot`, prints
  every problem, and exits `0` when there are no errors (warnings are fine), `1`
  otherwise. The CLI should never write a snapshot that fails validation.
- **Renderer and drift (owned by agent B).** Use `load_snapshot(path)` instead of
  `json.loads(path.read_text(...))` so 0.2 files are migrated and newer MINOR files
  are accepted. For drift's `previous_snapshot`, load the candidate with
  `migrate(json.loads(...))` (or `load_snapshot`) before comparing; `migrate` never
  mutates its input. Do not call internal validation helpers directly.
- **Snapshot assembly (`snapshot.py`, agent A).** `build()` itself has no drift yet;
  validate at the CLI boundary after drift is added. If validation is moved into
  `build()`, add `drift` first or call `validate_structurally` on the base document
  and `validate_snapshot` after drift.

## Migration

`migrate(doc)` returns a deep copy:

| From | To | Action |
|---|---|---|
| `0.2` | `0.3` | Stamp `schema` to `velari.practice-snapshot/0.3`; all 0.3 additions are optional, so nothing else changes |
| `0.3.x` | `0.3.x` | Return an unchanged copy |
| newer `0.x` | same | Return an unchanged copy (forward-compatible; no down-migration) |
| `1.x` | — | Raise `ValueError` (unknown MAJOR) |
| `0.0` / `0.1` | — | Raise `ValueError` (too old to read) |

The migration is idempotent and is covered by `tests/test_schema.py`.

## No-PHI guard

`evidence/practice_evidence/redaction.py` scans generated artifacts (snapshot JSON,
Markdown, and the HTML packet) for PHI-shaped and credential-shaped text. It is
stdlib-only and also runs as a script:

```bash
python evidence/practice_evidence/redaction.py \
  examples/sample-snapshot.json examples/sample-packet.html
# clean: 2 file(s)                                         (exit 0)
# path:line:col: ssn: 12***89                             (exit 1)
# error: path: [Errno 2] No such file or directory        (exit 2)
```

Matched values are **masked** in output, so the scanner never reprints a suspected
secret or identifier into a terminal or CI log. Exit codes: `0` clean, `1` one or
more findings, `2` unreadable file or usage error.

### Patterns

| Rule | Catches |
|---|---|
| `ssn` | Dashed US SSN shape, `###-##-####` |
| `dob` | A date value under a key such as `dob`, `date_of_birth`, `birthdate` |
| `name` | A capitalized multi-word value under a patient/member/first/last/full-name key |
| `phone` | North-American 10-digit phone shapes |
| `email` | Any address whose domain is not `millslab.internal` (case-insensitive) |
| `mrn` | An `mrn:` value not prefixed `SYN-`, and `MRN-####` tokens |
| `secret` | `password=`, `api_key:`, `token:`, `client_secret:`, bearer tokens |
| `private_key` | PEM `-----BEGIN ... PRIVATE KEY-----` blocks |
| `long_token` | 32+ hex or 40+ base64 characters, unless in a whitelisted hash field |
| `home_path` | `/home/<user>`, `/Users/<user>`, `/root`, `C:\Users\<user>` |

Whitelisted synthetic markers: the `millslab.internal` mail domain, MRNs prefixed
`SYN-`, phone numbers in the `555-01xx` range, relative lab paths such as
`frontdesk-01/home/...`, container paths under `/srv/samba/...`, and values of
hash fields (`sha256`, `sha256_16`, `sha256_full`, `entry_hash`,
`snapshot_sha256`, `prev`, `file_hash`, `content_hash`, `digest`).

### What the guard does not do

This is a shape detector, not a data-loss-prevention engine. It proves the
absence of the patterns below, not the absence of PHI.

False positives to expect:

- any dotted 3-2-4 number (invoice, ticket, test fixture) is reported as an SSN;
- any NANP-shaped 10-digit number outside `555-01xx` is reported as a phone,
  including account numbers;
- any real-looking institutional email is reported; only `millslab.internal` is
  allowed, so vendor contacts in a future template will need an explicit decision;
- `mrn` keys with non-`SYN-` values of three or more characters are reported even
  when the value is a word;
- capitalized two-word values under patient-ish keys are reported even when they
  are place names or synthetic names;
- prose like `token: none` is reported as a secret;
- 32+ hex or 40+ base64 tokens outside a whitelisted hash field are reported:
  git SHAs, dashless UUIDs, and inline data blobs will trip it;
- `/home/x` style examples in documentation or templates are reported;
- absolute host paths in third-party tool metadata are reported, even though they
  are not patient data; the collector relativises Bumblebee `project_path` and
  `source_file` against the lab root so normal runs stay clean.

False negatives to expect:

- names in free text, in filenames, or under keys this scanner does not know;
- dates of birth not adjacent to a DOB-named key, non-ISO date formats, and
  two-digit years outside the supported shapes;
- SSNs written with spaces or dots, international phone formats, and phone
  numbers without separators;
- MRNs with prefixes other than `MRN`, or values under non-`mrn` keys;
- secrets shorter than the thresholds, split across lines, encoded/obfuscated, or
  hidden in URL query strings;
- hashes deliberately placed under a whitelisted hash key (by design);
- binary or non-UTF-8 payloads (undecodable bytes become replacement characters);
- any PHI that does not match a known shape.

The guard is a regression net for the known failure modes, not a substitute for
the collector's metadata-only design. Run it on every generated artifact, and treat
a clean scan as one signal among several, not as proof.

### Tests

`tests/test_phi_guard.py` scans the committed sample snapshot and packet, a full
renderer output, and a Markdown render (all must be clean); exercises a positive
case for every rule; verifies the synthetic allowlist; asserts masked output; and
runs the scanner through the CLI, including exit codes. `tests/test_schema.py`
checks the sample, a corpus of invalid documents, version-policy cases, migration,
the stdlib keyword subset, and — when the optional `jsonschema` package is
installed — that the stdlib validator agrees with the reference implementation.

Run the whole gate:

```bash
uv run --no-project --with pytest --with ruff --with jsonschema \
  sh -c 'ruff check . && pytest -q'
```
