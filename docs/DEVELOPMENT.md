# Development

How to work on Practice Trust Lab: run it, test it, extend the evidence
pipeline, and understand what CI enforces. For what the lab is and what it
guarantees, read [ARCHITECTURE](ARCHITECTURE.md) and
[THREAT-MODEL](THREAT-MODEL.md) first. For contribution rules, read
[CONTRIBUTING](../CONTRIBUTING.md).

## Prerequisites

| Tool | Needed for | Notes |
|---|---|---|
| Python 3.10+ | everything | CI runs 3.10, 3.11, 3.12, and 3.13 |
| [uv](https://docs.astral.sh/uv/) | recommended dev loop | `make` falls back to `python3 -m` when uv is absent |
| Docker + Compose v2 | the lab and heavy CI workflow | not needed for the unit suite |
| `openssl` | `scripts/bootstrap.sh` credential generation | |
| `shellcheck` | local pre-commit hook / CI parity | `apt install shellcheck` |
| `pre-commit` | local git hooks | optional |

## Setup

```bash
make setup
# equivalent: uv venv && uv pip install -e ".[dev]"
```

That installs the project in editable mode with pytest, pytest-cov, ruff, mypy,
and (on Python 3.10) tomli. There are **zero runtime dependencies**; the
collector and verifier are standard library only.

Install the git hooks once, if you want them:

```bash
uv tool install pre-commit     # or: python3 -m pip install pre-commit
pre-commit install
pre-commit validate-config     # syntax check without running hooks
```

## Daily loop

```bash
make help          # list every target
make lint          # ruff check .
make format-check  # ruff format --check (advisory in CI today)
make format        # apply ruff formatting
make typecheck     # mypy over evidence/practice_evidence
make test          # pytest, no Docker
make cov           # branch coverage, threshold, XML + JSON reports
make render-sample # render examples/sample-snapshot.json -> build/sample-packet.html
```

The gate CI enforces on every push is:

```bash
uv run --no-project --with pytest --with ruff sh -c 'ruff check . && pytest -q'
```

### Lint and format

Ruff is configured in `pyproject.toml` (`line-length = 120`, target `py310`,
rules `E,F,I,B,UP`). `ruff check` is blocking. `ruff format --check` is
**advisory** in CI until a formatting-only pass lands; do not mix formatting
changes into behavior changes.

### Type checking

mypy checks `evidence/practice_evidence` with `disallow_untyped_defs`. The
config lives in `pyproject.toml`. CI keeps the step **advisory**
(`continue-on-error`) while in-flight workstreams finish annotating their
modules; make it blocking once `make typecheck` is clean. Do not silence errors
with blanket `ignore_errors`; annotate the code or use a narrowly scoped
per-module override with a TODO.

### Tests

- `tests/` — unit tests for section parsers, drift, ledger, renderer, rules,
  HIPAA crosswalk, and packaging.
- `tests/e2e/` — end-to-end snapshot and CLI runs against `FakeRunner` and
  fixtures; still no Docker.
- `tests/fixtures/` — synthetic fixtures, including `run2/` overrides used to
  exercise drift.
- `tests/golden/` — committed golden output for the packet renderer.

Useful selections:

```bash
uv run --no-project --with pytest pytest -q tests/test_sections.py
uv run --no-project --with pytest pytest -q -k ledger
```

### Coverage and the badge

`make cov` runs with branch coverage and `fail_under` from
`pyproject.toml`. The threshold is deliberately a few points under the measured
number (82% branch coverage on 2026-11-12, threshold 75) so in-flight modules
do not turn the build red; **raise it as tests land, never lower it to fix a red
build**.

CI writes `coverage.xml`, `coverage.json`, and a shields-compatible
`badges/coverage.json` (`{"schemaVersion":1,"label":"coverage","message":"82%",...}`)
and uploads all three as the `coverage` artifact. No third-party badge service
is involved. To publish a badge later, host that small JSON file (for example on
a `badges` branch or GitHub Pages) and point shields at its raw URL; until then,
read the number from the CI step summary/artifact.

## CI jobs

`.github/workflows/ci.yml` (push + pull request) runs, each with a timeout and
`permissions: contents: read`, under a `concurrency` group that cancels
superseded runs:

| Job | What it does | Local equivalent |
|---|---|---|
| `lint` | `ruff check`, advisory `ruff format --check` | `make lint`, `make format-check` |
| `tests` | matrix 3.10-3.13; branch coverage + artifacts on 3.12 | `make test`, `make cov` |
| `typecheck` | mypy (advisory today) | `make typecheck` |
| `package` | editable install, both entry styles, `uv build`, wheel contents | `make setup`, `uv build` |
| `shellcheck` | `shellcheck --severity=error scripts/*.sh samba-dc/*.sh endpoint/*.sh` | see below |
| `hadolint` | `hadolint --failure-threshold error` on all Dockerfiles | Docker-only, CI-only |
| `packet` | render the sample packet, then stdlib HTML well-formedness + no-external-reference check | `make render-sample` |
| `compose-config` | `docker compose config --quiet` for each stack | Docker-only |

Other workflows:

- `scheduled.yml` — weekly (Mondays) tests plus `pip-audit` over the dev
  toolchain. Runtime dependencies are empty, so the audit is a cheap tripwire.
- `lab-evidence.yml` — **manual, heavy**. `workflow_dispatch` only. Boots the
  full lab, runs one evidence pass, verifies the ledger, uploads the packet,
  and tears the lab down. 5-10 minutes plus cold image builds.
- `.github/dependabot.yml` — weekly grouped PRs for GitHub Actions and pip
  (dev tools).

Action tags use major versions and are updated by Dependabot; container lint
images are pinned by release tag. If the repo ever gains outside workflow
writers, move to full commit SHAs.

ShellCheck locally without a system install:

```bash
uv run --no-project --with shellcheck-py shellcheck --severity=error \
  scripts/*.sh samba-dc/*.sh endpoint/*.sh
```

## Project layout

```
samba-dc/                 AD DC image, domain population, shares, compose
clinic-ehr/               mock EHR app (stdlib) + compose
endpoint/                 shared domain-joined endpoint image
workstation-01/           clinical endpoint compose + local data
frontdesk-01/             front-office endpoint compose + local data
msp-jump-01/              MSP admin endpoint compose + local data
evidence/
  collect_practice_evidence.py   thin collector entry point
  render_practice_snapshot.py    thin renderer entry point
  verify_evidence.py             standalone stdlib verifier (copyable)
  hipaa_crosswalk.py             stable import path for the citation table
  practice_evidence/             collector package (config, runner, models,
                                 sections/, snapshot, drift, ledger, report,
                                 checkpoint, schema, redaction)
  practice_render/               renderer package (rules registry, data,
                                 sections, text, HTML, assets/packet.css)
  schema/                        JSON Schema for the snapshot
scripts/                  bootstrap, scenario seed, evidence runner
examples/                 sanitized sample snapshot + rendered packet
tests/                    unit + e2e + fixtures + golden (no Docker)
docs/                     architecture, threat model, this guide
```

The two `evidence/*.py` entry points stay runnable as scripts
(`python3 evidence/collect_practice_evidence.py ...`), and the same code is
installed as console scripts:

| Console script | Target | Use |
|---|---|---|
| `velari-collect` | `practice_evidence.cli:main` | collect a snapshot |
| `velari-render` | `render_practice_snapshot:main` | render a snapshot to a packet |
| `velari-verify` | `verify_evidence:main` | verify a ledger/snapshots/checkpoint |

Editable installs preserve the checkout-relative paths the collector relies on
(`evidence/artifacts`, `evidence/ledger.jsonl`, lab directories). A wheel built
by `uv build` installs the packages and console scripts for packaging checks and
for `velari-render`/`velari-verify`; `velari-collect` is meant to run from a
checkout because the lab itself lives there.

## Adding an evidence section, end to end

1. **Write the parser and collector** in
   `evidence/practice_evidence/sections/<name>.py`. Keep the pattern used by the
   other sections: a pure `parse_*`/evaluation function that takes text or
   already-collected data, and a thin `collect()` that performs read-only I/O
   through `runner` and returns a schema-shaped dict with a `findings` list.
2. **Emit findings with stable ids.** Build `Finding` objects (`models.py`) and
   serialise with `dump_findings`. Give every finding a `rule_id` and `subject`
   (usually via a helper like `tagged_finding`) so the renderer and crosswalk
   never depend on the human-readable detail text.
3. **Register it in `snapshot.py`.** Add the module to the `jobs` dict with an
   empty-shape fallback, and add the section to `FINDING_SECTIONS` if it emits
   findings. Sections are isolated: one failure must produce `section_errors`
   plus a medium gap finding, not lose the rest of the pass.
4. **Package it.** Anything under `evidence/practice_evidence/` is discovered by
   the existing `packages.find` rule. If you add a new top-level package or
   entry module, update `pyproject.toml` and `tests/test_packaging.py`.
5. **Route it in the packet.** Add or reuse a group in
   `evidence/practice_render/rules.py` (`HIPAA_BY_GROUP` for citations, `RULES`
   for lane/ask/proof/due), then surface the section in
   `evidence/practice_render/sections.py` and the HTML renderer.
6. **Test it.** Add a synthetic fixture under `tests/fixtures/`, positive and
   negative parser tests, and a finding-severity test. Add an e2e assertion in
   `tests/e2e/` if the section participates in `snapshot.build()`.
7. **Document it.** Update the module table in `docs/ARCHITECTURE.md`, the
   planted-weakness/limitations tables in `docs/THREAT-MODEL.md` if the trust
   boundary changes, the packet README section if reviewer-facing, and
   `CHANGELOG.md`.

## Adding a detection rule

- Choose a stable `rule_id` (for example `POL-MIN-LENGTH`) and one group; the
  registry lives in `practice_render/rules.py`.
- Decide the fixed severity. Severities are per-rule and not risk-scored; "high"
  means "the lab planted this and it matters in a clinic".
- Keep the detail text free of patient data, credentials, and full file contents.
  Filenames and hash prefixes are allowed.
- Add both directions of test: a fixture that fires and one that does not (for
  example a compliant policy value, a share the role may legitimately read, or
  an unreadable file count).
- If the rule is reviewer-facing, add the lane/ask/proof/due fields and its
  citations. If the group has no citations yet, add it to `HIPAA_BY_GROUP` and
  justify each provision.
- Update the crosswalk table in the README/index docs and the changelog.

## Regenerating golden files

The packet golden lives at `tests/golden/sample-packet.html` and is checked by
`tests/test_render_golden.py`. Regenerate only when the HTML change is
intentional, then review the diff before committing:

```bash
UPDATE_GOLDEN=1 uv run --no-project --with pytest pytest -q tests/test_render_golden.py
git diff -- tests/golden/sample-packet.html
```

If a future golden set gets its own variable or script, follow the docstring at
the top of that test module; do not hand-edit golden output.

## Verifying evidence and checkpoints

```bash
# in-repo chain check
python3 evidence/collect_practice_evidence.py --verify-ledger

# standalone verifier (copy this file + ledger + snapshots anywhere, Python 3.10+)
python3 evidence/verify_evidence.py evidence/ledger.jsonl

# optional off-host checkpoint (HMAC / SSH / OpenSSL signatures)
python3 evidence/collect_practice_evidence.py --checkpoint
python3 evidence/verify_evidence.py evidence/ledger.jsonl \
  --checkpoint evidence/checkpoints/checkpoint-<ts>.json
```

`--checkpoint` writes the checkpoint; `--verify-checkpoint` (on the collector)
and the standalone verifier check it. The ledger is tamper-evident, not
tamper-proof; see `docs/THREAT-MODEL.md`.

## Snapshot schema

The snapshot schema version is checked by `practice_evidence/schema.py` against
`evidence/practice_evidence/data/practice-snapshot.schema.json`:

```bash
cd evidence && python3 -m practice_evidence.schema ../examples/sample-snapshot.json
```

Bump the schema version and add a migration when fields change incompatibly, and
update `docs/ARCHITECTURE.md`.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `docker: command not found` or preflight exit `2` | Docker isn't installed/running. The collector needs it; the unit suite does not. |
| `DC container ... is not running` | Run `make lab-up` (or `./scripts/bootstrap.sh`) first. |
| `samba-dc/.env` missing | Run `./scripts/bootstrap.sh`; it generates credentials with mode `0600`. Never commit it. |
| `make test` fails in `tests/e2e` | A section changed shape; the fake fixtures need updating with the parser. |
| `make typecheck` reports errors in a module you own | Add annotations; the package target is `disallow_untyped_defs`. |
| `ruff format --check` lists many files | Expected until the formatting-only pass lands; do not reformat unrelated files. |
| Coverage below threshold | Add tests for the new module; do not lower `fail_under`. |

## Release checklist

1. `make lint && make typecheck && make test && make cov` clean.
2. `uv build` succeeds and `tests/test_packaging.py` passes against an installed
   environment.
3. `python3 evidence/collect_practice_evidence.py --verify-ledger` passes on the
   committed evidence (if included).
4. `CHANGELOG.md` has an entry; `docs/ARCHITECTURE.md` matches the code.
5. Tag, then let Dependabot keep actions and dev tools current.
