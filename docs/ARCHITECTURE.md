# Architecture

Practice Trust Lab has two halves: a **synthetic clinic** that runs in Docker, and
an **evidence pipeline** that reads it and produces a dated review packet.

```
                       ┌───────────────────────── mills-lab (172.31.13.0/24) ─────────────────────────┐
                       │                                                                              │
 synthetic clinic      │  samba-dc  (AD DC, millslab.internal, 172.31.13.10)                          │
                       │   ├─ OUs / AGDLP groups / lockout policy                                     │
                       │   └─ shares: ClinicalShare · FrontOfficeShare · ITShare  (AD-group ACLs)     │
                       │                                                                              │
                       │  ws-clinical-01   ─┐                                                         │
                       │  fd-frontdesk-01  ─┼─ domain-joined; sync loop copies share files to a       │
                       │  msp-jump-01      ─┘  local desktop every 300s, like a real clinic machine   │
                       │                                                                              │
                       │  clinic-ehr  (mock EHR: roster, public intake form, AI-scribe egress sim)    │
                       └──────────────────────────────────────────────────────────────────────────────┘
                                   │ read-only: docker exec / docker logs / bind-mounted dirs / HTTP
                                   ▼
 evidence pipeline     collect_practice_evidence.py ──► snapshot-*.json + .md ──► ledger.jsonl (hash chain)
                                                              │
                                                              ▼
                       render_practice_snapshot.py ──► client-facing HTML packet (+ HIPAA crosswalk)
```

## Lab runtime

`scripts/bootstrap.sh` owns the lab lifecycle and is idempotent: it creates the
`mills-lab` network (`172.31.13.0/24`), the `mills-lab-shares` volume, runtime
directories, a 0600 `samba-dc/.env`, then brings each compose project up with
`docker compose up --build --wait`. Order matters: DC healthy, domain populated,
shares provisioned, then EHR and endpoints. `scripts/teardown.sh` is the inverse,
supports `--dry-run`/`--yes`/`--purge-data`, and only removes lab-named resources.
`scripts/verify-boundaries.sh` asserts the documented SMB boundaries plus the
credential-exposure check described in [LAB-SECURITY.md](LAB-SECURITY.md).

Compose layout:

| Project | Container | Notes |
|---|---|---|
| `samba-dc/` | `samba-dc` | AD DC; pinned `ubuntu:24.04` digest; allow-listed capabilities (incl. `SYS_ADMIN`); healthcheck on `samba-tool domain info`; publishes 88/389/636/464/3268 on `LAB_BIND_IP` (loopback by default) |
| `clinic-ehr/` | `clinic-ehr` | stdlib mock EHR; non-root, read-only rootfs, all capabilities dropped, publishes 8095 on `LAB_BIND_IP` |
| `workstation-01/`, `frontdesk-01/`, `msp-jump-01/` | one each | share the `endpoint/` image (`FROM practice-lab-dc:0.1`); root inside the container for domain join/winbind; healthcheck on the join marker |

Passwords are generated per clone into `samba-dc/.env` (0600, gitignored) and
mounted into containers as the read-only compose secret `lab_env` at
`/run/secrets/lab_env`, so they are absent from `docker inspect`/`docker ps`
output. `populate-domain.sh` reads that secret when no positional passwords are
given. Healthchecks are liveness checks only; access boundaries are proven by
`verify-boundaries.sh`, not by the health status.

## Evidence pipeline

`evidence/collect_practice_evidence.py` is a thin entry point. The implementation is
the `evidence/practice_evidence/` package:

| Module | Responsibility |
|---|---|
| `config.py` | Paths, container names, thresholds (`STALE_DAYS`, `PRIVILEGED_GROUPS`, `ROLE_GROUPS`), the documented `SHARE_ACCESS_MODEL`, and hygiene baselines |
| `runner.py` | `Runner` protocol, real `DockerRunner` with the read-only command allowlist, `FakeRunner` for tests, `docker exec`/`docker logs` helpers, and the Docker/DC preflight |
| `models.py` | `Finding` dataclass (severity, detail, stable `rule_id`, `subject`) and severity ordering |
| `sections/identity.py` | Users, FILETIME logon parsing, password policy, privileged groups |
| `sections/policy.py` | Password/lockout baseline evaluation (`PolicyBaseline`), units/`unlimited` parsing, HIPAA-routed findings |
| `sections/acls.py` | `ntacl --as-sddl` collection, SDDL owner/DACL/ACE parser, SID/alias resolution, least-privilege and `valid users` comparison |
| `sections/privilege.py` | Role-group nesting (cycle-safe), UAC flag decoding, SPN/pre-auth/reversible-encryption and admin-account hygiene |
| `sections/hygiene.py` | Domain functional level, krbtgt password age, SMB signing, LDAP strong auth, NTLMv1 and SMB1 settings |
| `sections/shares.py` | `smb.conf` parse, file inventory with SHA-256 prefixes, patient-adjacent detection |
| `sections/auth.py` | Parse the DC audit log into success/failure counts and reasons |
| `sections/ehr.py` | Portal health, intake and scribe-transmission event counts |
| `sections/endpoints.py` | Local copies per endpoint, hash-matched against shares |
| `sections/supply_chain.py` | Optional Bumblebee package-exposure scan |
| `sections/containers.py` | Lab container inventory (filters out unrelated containers) |
| `snapshot.py` | Assemble sections, merge and rank findings |
| `drift.py` | Change monitor: diff against the previous snapshot, keyed by `(rule_id, subject)` |
| `ledger.py` | Hash-chained ledger: locking, fsync, torn-tail recovery, typed verification report, `head_summary` |
| `checkpoint.py` | Off-host checkpoint create/verify, HMAC-SHA256 and optional SSH/OpenSSL signatures |
| `report.py` | Markdown snapshot |
| `schema.py` | Snapshot contract: stdlib JSON Schema validator, version policy, migration, `load_snapshot` |
| `redaction.py` | No-PHI/no-credential scanner for generated JSON, Markdown, and HTML artifacts |

`evidence/verify_evidence.py` sits beside the package, not inside it: it is a
standalone stdlib-only verifier for third parties and deliberately does not import
`practice_evidence`.

Each section is a pure parse function plus a thin `collect()` that does the I/O. The
parse functions are what the tests exercise, so the suite needs no Docker.

The only path from the collector to the operating system is a `runner.Runner`. The
production `DockerRunner` validates every argv against a positive read-only allowlist
before calling `subprocess.run` (never with a shell): `docker info/ps/inspect/logs`
scoped to lab containers, and `docker exec samba-dc` limited to the read commands the
sections use (`samba-tool user/group/domain`, `ntacl get`, `wbinfo -s`, `cat
/etc/samba/smb.conf`, `find -type f`, `sha256sum`), plus the Bumblebee scan. Anything
else raises `CommandRefused` without executing and surfaces as an `__ERROR__` string,
so the section records an evidence gap instead of crashing. `FakeRunner` serves
recorded stdout keyed by exact argv, and `set_runner()` / the `use_runner()` context
manager swap it in without editing a section module.

`tests/e2e/` drives `snapshot.build()` and `cli.main()` end to end against
`FakeRunner`, using temporary artifact and ledger roots and two recorded lab states to
exercise drift (accounts, groups, share files/hashes, scribe events).

### CLI contract

`cli.py` accepts `--artifacts-dir` and `--ledger`, or `EVIDENCE_ARTIFACTS_DIR` and
`EVIDENCE_LEDGER`. Exit codes are stable: `0` snapshot written or ledger verified, `1`
ledger verification failed, `2` preflight failed (nothing collected). A section that
raises is a degraded run, not a fatal one: the snapshot is still written, the failure
is recorded in `section_errors` and a medium finding, and the exit code stays `0`.
With `--strict` the snapshot and ledger entry are still written, but the exit code is
`3`, so cron and CI can tell a degraded run from a clean one.

The packet renderer is `evidence/practice_render/`:

| Module | Responsibility |
|---|---|
| `rules.py` | Single registry: `rule_id` → group, title, lane, ask, proof, due, confidence, default severity, HIPAA cites, and legacy substring aliases |
| `data.py` | Shape findings into consolidated evidence rows, decisions, and owner lanes |
| `sections.py` | One small HTML function per packet section |
| `text.py` | Escaping, path redaction, shared date/number formatting |
| `render.py` | Document assembly and the injectable clock used by golden tests |
| `assets/packet.css` | The print stylesheet, embedded into the single-file output at render time |

`evidence/render_practice_snapshot.py` is the unchanged CLI entry point; it imports the
package and keeps the old helper names working. `evidence/hipaa_crosswalk.py` re-exports
the group citation table from `practice_render.rules`, so there is no second copy to drift.

The renderer reads `rule_id`/`subject` when present and otherwise falls back to the
registry's legacy substring aliases, so pre-0.3 snapshots render exactly as before. The
change monitor uses the same identity: a reworded detail or a changed count on the same
rule/subject is reported as a changed finding (with a numeric delta when the count moved),
not as one new plus one resolved finding. Old-format snapshots keep their
`(section, detail)` key, with count-bearing auth/EHR/endpoint findings paired after the fact.

## Snapshot schema

`velari.practice-snapshot/0.3`. Top-level keys: `containers`, `identity`, `policy`,
`shares`, `acls`, `auth`, `ehr`, `endpoints`, `privilege`, `hygiene`, `supply_chain`,
then the derived `findings`, `finding_counts` and `drift`. The four newer sections are
registered as optional extension sections, so an older producer without them still
validates. Every finding is `{severity, detail, section}` plus
optional `ref_key` and section-specific fields. Findings also carry optional `rule_id`
(stable id from the rules registry) and `subject` (the account, path, host, or package
the finding is about). Both fields are additive: snapshots without them still render and
still drift, using the registry's legacy substring aliases.
See [`examples/sample-snapshot.json`](../examples/sample-snapshot.json). The
machine-readable contract is
[`evidence/practice_evidence/data/practice-snapshot.schema.json`](../evidence/practice_evidence/data/practice-snapshot.schema.json);
version policy, migration, validation commands, per-field documentation, and the
no-PHI guard are in [`SCHEMA.md`](SCHEMA.md).

## Policy, ACL, privilege and hygiene

These four sections deepen detection without changing the read-only contract. Every
command they issue is in the section module's docstring and on the collector allowlist:

- `samba-tool domain passwordsettings show` — compared to `PolicyBaseline` (minimum
  length 12, lockout threshold 1–10, history 24, max age 90–365 days, complexity,
  no plaintext storage). The lab's own minimum length 10 and 42-day maximum age trip
  `POL-MIN-LENGTH` and `POL-MAX-AGE` by design. The baseline is a frozen dataclass and
  tests cover each threshold on both sides.

  The baseline is a conventional Windows/insurer-style policy, not a NIST one. Checked
  against SP 800-63B-4 (2025): NIST says verifiers SHALL NOT impose composition rules
  or require periodic password changes, and requires 15 characters for single-factor
  passwords. So `POL-COMPLEXITY` and `POL-MAX-AGE` (never-expires) flag things NIST
  would accept, and a 12-character minimum is below NIST's single-factor floor. Keep
  the defaults if your insurer or auditor expects them; override the dataclass if you
  follow NIST. Lockout (NIST requires rate limiting, at most 100 failures) is stricter
  here by design.
- `samba-tool ntacl get <path> --as-sddl`, `wbinfo -s <SID>`, `samba-tool group list`
  and `samba-tool user list` — the SDDL parser handles owner/group tags, allow/deny
  ACEs, `OI`/`CI`/`IO`/`ID` inheritance, numeric and alphabetic masks, well-known
  aliases (`WD`, `AU`, `BA`, `SY`, `DU`, `DA`, …), and domain RIDs. Findings cover
  broad write access, direct user ACEs, non-`SG-`/`DL-` groups, shares outside the
  documented model, filesystem ACLs broader than `valid users`, and null DACLs.
- `samba-tool group list`/`listmembers <group>`/`user list`/`user show <sam>` —
  role-group expansion is cycle-safe; `userAccountControl` is decoded into named
  flags (`0x10000` never-expires, `0x400000` no pre-auth, `0x80` reversible). Service
  accounts with SPNs, no pre-auth, reversible encryption, or never-expiring passwords
  produce findings. Interactive-admin detection uses per-workstation auth data only
  when the auth section provides it; today it reports per-user counts only.
- `samba-tool domain level show`, `samba-tool user show krbtgt`, and `cat
  /etc/samba/smb.conf` — functional level, krbtgt age, SMB signing, LDAP strong auth,
  `ntlm auth`, and SMB1 minimum/maximum protocol settings.

A section that cannot read its source still returns a schema-compatible shape with an
`info` finding; a section that raises is caught by `snapshot.build`, recorded in
`section_errors`, and the rest of the pass continues.

## Ledger format

One JSON object per line in `evidence/ledger.jsonl`:

```json
{"v": 1, "ts": "...", "json": "artifacts/2026-11-12/snapshot-....json", "md": "...",
 "findings": {"high": 8}, "snapshot_sha256": "<sha256 of the JSON bytes>",
 "prev": "<entry_hash of the previous line, or 64 zeros>", "entry_hash": "<sha256 of this entry>"}
```

`v` is the chain format version. Entries written before it existed have no `v`
and still verify; unknown future versions fail. `--verify-ledger` recomputes every
`entry_hash`, checks each `prev` link, and re-hashes each snapshot file. Lines
written before the chain existed are skipped and reported.

`verify_ledger_report` is the structured API behind the CLI: problems carry a
severity (`error` fails, `warning` does not), a stable `code`, a 1-based line, and
a message. A partial final line from a crash is a `truncated_tail` warning and is
not counted; the next append copies it to `ledger.jsonl.recovered` and truncates
it. Appends and the read of `prev` share an exclusive `fcntl.flock` on
`ledger.jsonl.lock`, and are fsynced (`append_chained` is the concurrency-safe
path the collector uses). `head_summary` returns the current head hash, count,
timestamp and whole-file hash for display.

## Checkpoint format

`--checkpoint` writes a small JSON anchor with the chain length (`entry_count`),
the `head_entry_hash` at that position, the ledger's byte size and SHA-256,
`created_at`, and an optional `signature`. It is meant to be stored off-host.
`--verify-checkpoint` (or the standalone verifier) detects truncation, rewritten
history, a rebuilt chain, and a detached extension. See
[Evidence integrity](EVIDENCE-INTEGRITY.md) for the field-by-field semantics,
signing key handling, and what a checkpoint cannot prove.

## Design constraints

- **Metadata only.** Counts, hashes, group membership and policy. Never file contents,
  credentials, or message bodies.
- **Read-only.** The collector never changes the lab; it states the ask and the proof
  needed to close it.
- **Lab-scoped output.** Only the lab's own containers appear in a snapshot.
