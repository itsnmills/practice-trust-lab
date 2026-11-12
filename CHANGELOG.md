# Changelog

All notable changes to Practice Trust Lab are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The snapshot schema
version (`velari.practice-snapshot/0.3`) is versioned separately from the
package.

## [Unreleased]

### Added

- **New detections:** domain password/lockout policy against an overridable
  baseline, share ACLs parsed from SDDL (compared with `smb.conf` and the
  documented group model), privileged-account hygiene, and DC hygiene signals.
- **Stable rule IDs.** Findings carry `rule_id` and `subject`; one registry
  (`practice_render/rules.py`) drives titles, owner lanes, due dates and HIPAA
  citations. Drift keys on them, so a changed count is one changed finding.
- **Renderer package** (`evidence/practice_render/`), golden-file and
  accessibility tests, and the ledger head in the packet footer.
- **Read-only runner.** The collector can only run an exact allowlist of
  read-only commands; a `FakeRunner` lets the whole pipeline run without Docker.
- **Ledger checkpoints and a standalone verifier** (`evidence/verify_evidence.py`);
  see `docs/EVIDENCE-INTEGRITY.md`.
- **Snapshot JSON Schema** (`velari.practice-snapshot/0.3`), a validate-before-write
  step, and a no-PHI/credential scanner (`docs/SCHEMA.md`).
- **Lab hardening and checks:** hardened mock EHR with tests, `teardown.sh`,
  `verify-boundaries.sh`, healthchecks, secrets kept out of `docker inspect`
  (`docs/LAB-SECURITY.md`).
- **IT is read-only on `FrontOfficeShare`.** Dropped `force group` from the share
  definitions: Samba adds a forced group to every connecting user's token, which
  silently overrode the read-only NT ACL entry. Verified live with real users
  (read, overwrite, delete and subdirectory writes), covered by new
  `verify-boundaries.sh` probes. Re-running provisioning removes the line from
  existing labs.
- **Real NT ACLs on the share directories.** The old `chgrp` failed silently and left
  every share world-readable at the filesystem layer, gated only by `smb.conf`.

- **Test suite** (`tests/`): drift detection, auth-log parsing, container
  scoping, ledger tamper detection, section parsers, renderer escaping, HIPAA
  crosswalk citations, and a packaging contract. Runs without Docker.
- **Hash-chained evidence ledger.** Every entry pins the snapshot's SHA-256 and
  the previous entry hash; `--verify-ledger` detects edited, deleted, reordered,
  or inserted entries and modified snapshot files. Tamper-evident, not
  tamper-proof (see `docs/THREAT-MODEL.md`).
- **HIPAA crosswalk.** Finding groups are routed to the 45 CFR Part 164
  provisions they are relevant to (`evidence/hipaa_crosswalk.py`), rendered as
  section 5.8 of the packet.
- **Collector package refactor.** `evidence/collect_practice_evidence.py` is now
  a thin entry point over the `evidence/practice_evidence/` package (config,
  runner, models, sections, snapshot, drift, ledger, report).
- **Client-facing packet renderer.** `evidence/render_practice_snapshot.py`
  produces the self-contained, no-PHI HTML review packet.
- **Documentation.** `docs/ARCHITECTURE.md` (module map, snapshot and ledger
  formats), `docs/THREAT-MODEL.md` (planted weaknesses, trust boundaries,
  limitations), and `docs/DEVELOPMENT.md` (workflows, rules, golden files).
- **Engineering infrastructure.** Installable `pyproject.toml` with the
  `velari-collect`, `velari-render`, and `velari-verify` console scripts (zero
  runtime dependencies), CI matrix on Python 3.10-3.13, ruff lint/format gates, mypy
  over the collector package, branch coverage with a measured threshold,
  ShellCheck, Hadolint, compose validation, packet HTML validation, a weekly
  dependency audit, a manual heavy lab-evidence workflow, Dependabot, a
  `Makefile`, pre-commit hooks, and this changelog.

### Changed

- `README.md` Development section now points at the make targets, packaging, and
  `docs/DEVELOPMENT.md`.
- `.gitignore` covers virtualenvs, build/test/coverage artifacts, and mypy
  caches.

### Fixed

- Mock EHR audit-log page is hardened against malformed lines and HTML injection
  (`4200b80`).
- Credentials are generated with mode `0600` (`9c472cb`).
- The collector fails fast when Docker or the domain controller is unavailable
  (`319b3e1`).

### Security

- Added `SECURITY.md` describing scope, the intentionally weak lab, and how to
  report a vulnerability privately.

## [0.1.0] - 2026-09-13

### Added

- Initial synthetic small-clinic lab: Samba AD domain (`millslab.internal`) with
  AGDLP groups, least-privilege share ACLs, lockout policy, three domain-joined
  endpoints, and a mock EHR with public intake and AI-scribe egress simulation
  (`b8de9e1`).
- Read-only, metadata-only evidence collector producing JSON and Markdown
  snapshots plus a client-facing HTML packet.
- Supply-chain demo: a planted shadow-IT app pinned to a known-compromised npm
  release, scan optional via Bumblebee.
- Bootstrap, scenario seed, and evidence runner scripts.
- CI smoke workflow: lint, tests, script compilation, sample packet render, and
  shell syntax checks (`62ffe23`).
- Fresh-clone setup fixes for the endpoint base image, runtime directories, and
  the EHR bind IP (`7e99466`).
- Clone URL, requirements, and teardown notes in the README.
