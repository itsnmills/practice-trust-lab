# Contributing to Practice Trust Lab

Thanks for helping. This is a small, deliberately scoped lab: a synthetic clinic
plus a read-only evidence pipeline. Contributions should keep it runnable on one
Linux machine with Docker and Python 3.10+.

## Ground rules

- **Synthetic data only.** No real patient data, clinic names, credentials, or
  third-party system details, in code, fixtures, tests, issues, or screenshots.
- **Metadata only.** The collector reads policy, counts, group membership, and
  hashes. It never reads patient content, credentials, or message bodies.
- **Read-only.** Do not add remediation or write operations to the evidence
  pass. State the ask and the proof needed instead.
- **Brand.** The product name stays **Velari**, and the snapshot schema stays
  `velari.practice-snapshot/...`.
- **Lab scope.** The collector only reports the lab's own containers and paths.
  Never widen it to the whole Docker host.

## Development setup

Requirements: Python 3.10+, and `uv` (recommended) or `pip`. Docker is only
needed for the lab targets.

```bash
make setup            # uv venv + editable install with dev tools
# or, without make:
uv venv && uv pip install -e ".[dev]"
```

Optional tools: `shellcheck` (shell hooks and CI parity), `pre-commit`.

```bash
uv tool install pre-commit   # or: python3 -m pip install pre-commit
pre-commit install
```

## Quality gate

Run this before every commit. It is what CI runs, minus the Docker jobs:

```bash
uv run --no-project --with pytest --with ruff sh -c 'ruff check . && pytest -q'
```

Then, when the tools are installed:

```bash
make lint           # ruff check
make format-check   # ruff format --check (informational until the format pass lands)
make typecheck      # mypy over evidence/practice_evidence
make test           # pytest, no Docker
make cov            # branch coverage + threshold from pyproject.toml
```

`mypy` is advisory in CI while the collector's in-flight workstreams settle; it
should become blocking once those files are annotated. Do not lower the coverage
threshold to make a red build green — add tests.

## Tests

- The default suite needs **no Docker**. Section parsers are pure functions and
  the end-to-end tests use a `FakeRunner` with fixtures under `tests/fixtures/`.
- Add a regression test for every bug fix and at least one negative test for
  every new detection rule (the boundary that should *not* fire).
- Keep fixtures synthetic and small. Prefer a hand-written fixture that shows
  the exact format quirk over a captured real-world log.
- `tests/test_packaging.py` guards the install/entry-point contract. If you
  rename a module or entry point, update `pyproject.toml` and that test.

## Adding a detection rule or an evidence section

`docs/DEVELOPMENT.md` has the end-to-end walkthrough: section module, snapshot
registration, findings, renderer lane, HIPAA crosswalk entry, fixtures, and
docs. Read it before adding a section.

## Style

- Ruff enforces lint and import order (`line-length = 120`, target `py310`).
- Prefer standard library. New **runtime** dependencies are not accepted; dev
  dependencies need a good reason.
- Match the surrounding code: section modules expose a pure `parse_*` plus a
  thin `collect_*` that does I/O.
- No comments that restate the code. Explain *why* when a decision is
  non-obvious.
- Update `CHANGELOG.md` under `[Unreleased]` for user-visible changes, and
  `docs/ARCHITECTURE.md` when a module, schema field, or ledger entry changes.

## Docker lab changes

- Keep published ports bound to `127.0.0.1` by default (`LAB_BIND_IP`).
- Keep credentials out of images and compose files; generate them into
  `samba-dc/.env` (mode `0600`, gitignored).
- `make lab-up` / `make evidence` / `make lab-down` are the documented local
  loop. The heavy CI workflow is manual-only; do not add it to `push`.
- If you change a compose file, run `docker compose -f <dir>/docker-compose.yml
  config` and update the compose-validation job if you add a new stack.

## Pull requests

- Keep changes focused; separate refactors from behavior changes.
- Describe the behavior change and how you tested it (commands and results).
- Confirm no PHI, secrets, or generated evidence are staged
  (`samba-dc/.env`, `evidence/artifacts/`, `evidence/ledger.jsonl` are blocked
  by pre-commit and gitignored).
- CI must be green except where a step is explicitly marked advisory.

Security issues follow `SECURITY.md`, not the public issue tracker.
