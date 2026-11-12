# Threat model and limitations

This lab is a portfolio and practice environment. It is deliberately weak in
specific, documented ways so the evidence pipeline has real things to detect. This
page separates those planted weaknesses from the real limits of the tooling, so a
reader can tell which is which. The lab side — which weaknesses are intentional,
what hardening the containers and scripts apply, and what risk remains — is
covered in [LAB-SECURITY.md](LAB-SECURITY.md).

## Planted weaknesses (the point of the lab)

| Weakness | Where it lives | Detected as |
|---|---|---|
| Patient-adjacent exports on a share that all clinical staff can read | `ClinicalShare` | `shares`: patient-adjacent data on file share |
| Those exports copied to endpoint desktops, including the front desk and MSP box | endpoint sync loop | `endpoints`: patient-adjacent files on local desktop |
| AI scribe sends encounter fields to vendors with unverified BAA status | `clinic-ehr` `/scribe` | `ehr`: scribe transmission events |
| Public web intake form with no stated retention or TLS | `clinic-ehr` `/intake` | `ehr`: public web intake submission |
| Shadow-IT app pinned to a known-compromised npm release | `seed-scenario.sh` | `supply_chain`: known-compromised package |
| Admin-equivalent group (`SG-IT`) with no MFA path modeled | AD | `identity`: SG-IT membership |
| Disabled service account left in place; accounts that never logged on | AD | `identity` info/low findings |

## What the collector is trusted to do

| Property | How it is enforced | Limit |
|---|---|---|
| No PHI in output | Reads metadata only; never opens share file contents except to hash them | Hash prefixes and filenames are still derived from the data. Filenames could themselves be sensitive in a real clinic. |
| Read-only | Only `docker exec` of read commands, `docker logs`, HTTP GET, local file reads | Enforced by code review and tests, not by a sandbox. A bug could add a write. |
| Lab-scoped output | `containers.parse` allowlists lab container names | Applies to the container inventory only. Other sections are scoped by their own paths. |
| Evidence integrity | Hash-chained ledger plus snapshot byte hashes | See below. |

## Known limitations

1. **Docker access is root-equivalent.** The collector shells out to `docker`. Whoever can
   run it can effectively act as root on the host. Fine for a local lab; unacceptable
   for a production collector, which would use a scoped read-only agent instead.
2. **The ledger is tamper-evident, not tamper-proof.** It catches an edited snapshot,
   an edited, deleted or reordered entry. A checkpoint anchors the head off-host and
   detects truncation, rewritten history, and a fully rebuilt chain, but only up to
   the checkpointed position and only if the checkpoint is stored somewhere the
   ledger attacker cannot rewrite. An unsigned checkpoint proves custody, not
   authorship; HMAC proves key possession (symmetric); SSH/OpenSSL signatures let a
   third party verify. Not covered: an attacker who controls both the ledger and
   every off-host copy, or the signing key, or a trusted timestamp. A remote
   append-only store or RFC 3161 timestamping service would close the remaining gap.
   See [Evidence integrity](EVIDENCE-INTEGRITY.md), including the exact detection
   table and honest limits.
3. **Detection of "patient-adjacent" data is a filename regex** (`patient|intake|insurance|schedule`).
   It will miss data under other names and flag benign files that happen to match. It is a
   triage heuristic, not data classification. Real work would use content-aware DLP
   run inside the data owner's boundary.
4. **Severities are fixed per rule**, not risk-scored. There is no likelihood, asset value, or
   compensating-control input. "High" means "the lab planted this and it matters in
   a clinic", not a calculated risk.
5. **Auth analysis depends on Samba's log format.** The regex targets `auth_audit` lines
   from this Samba version. A format change would silently produce zero counts. The
   `window_hours` window is also bounded by Docker log retention.
6. **Single domain controller, no MFA, no real network segmentation.** The lab cannot
   demonstrate conditional access, EDR telemetry, patch state, backup restore tests, or
   physical safeguards. The packet does not claim to cover them.
7. **Credentials are generated per clone and kept in `samba-dc/.env`** (mode 0600, gitignored).
   Containers receive the file as a read-only compose secret mounted at
   `/run/secrets/lab_env`, not as environment variables, so lab passwords no longer
   appear in `docker inspect` or `docker ps` output (verified by
   `scripts/verify-boundaries.sh`). Anyone who can read the host file, the secret
   mount, or drive Docker can still use the lab's accounts, and every endpoint
   container can read the domain admin password from the shared secret. Acceptable
   for a synthetic lab only; see [LAB-SECURITY.md](LAB-SECURITY.md).
8. **Short hash prefixes.** File hashes are truncated to 16 hex characters (64 bits). That is
   enough to show two copies are identical in a demo and not enough for forensic use.
9. **The HIPAA crosswalk is a routing aid.** It lists provisions a finding is relevant to. It
   does not assert that a provision is violated, and it is not a gap assessment. Verify
   citations against the current text of 45 CFR Part 164 before relying on them.

## Out of scope

Real patient data, real clinics, remediation actions, penetration testing of anything outside
`mills-lab`, and any compliance certification or legal determination.
