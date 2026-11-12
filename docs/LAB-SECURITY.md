# Lab security notes

This page is about the **lab itself** — the Docker clinic and its scripts — not the
evidence collector. It separates three things that are easy to confuse:

1. weaknesses that are **planted on purpose** because the evidence packet needs
   something real to find,
2. **hardening this repository actually applies** so a demo does not fall over,
   corrupt its own audit trail, or leak credentials by accident, and
3. **remaining risk** that is accepted for a synthetic lab and would have to
   change before anything like this touched real data.

The collector's own guarantees and limits are in
[THREAT-MODEL.md](THREAT-MODEL.md).

## Planted weaknesses (intentional)

| Weakness | Where | Why it stays |
|---|---|---|
| Plain HTTP, no TLS | `clinic-ehr` publishes `:8095` over HTTP | Transmission-security finding (`§164.312(e)(1)`); the packet reports it |
| No authentication anywhere in the portal | all `clinic-ehr` routes | Public-intake finding; demonstrates why an unauthenticated patient surface is a risk |
| Patient roster (names, DOBs, payer) served on the dashboard | `clinic-ehr` `/` | Makes "patient-adjacent data" concrete; it is synthetic |
| Public intake stores names/DOBs indefinitely | `clinic-ehr` `/intake` → `intakes` table | No-retention finding; the form is the point |
| AI-scribe egress to vendors with unverified/absent BAA | `clinic-ehr` `/scribe/run` | `ehr` findings and the scribe vendor group |
| No MFA path for `SG-IT` (admin-equivalent) | `samba-dc/populate-domain.sh` | Admin-equivalent finding |
| Anonymous LDAP/global-catalog listeners and a plaintext directory | `samba-dc` published ports | Realistic AD lab surface; the lab never claims LDAP hardening |
| Endpoint working copies of clinical exports | sync loop in `endpoint/entrypoint.sh` | Endpoint-copy finding |
| Single DC, no segmentation, no EDR/backup telemetry | whole lab | Stated out of scope in THREAT-MODEL.md |

The mock EHR also stores whatever synthetic names and reasons a visitor submits.
Asking it to reject *real* patient data outright would break the intake demo, so
instead the form carries a visible synthetic banner and rejects obviously real
identifier shapes (SSN-formatted and 13–19 digit card-formatted values). That is a
guard-rail against accidental real data, not a compliance control.

## Hardening applied (real, not planted)

### Mock EHR (`clinic-ehr/app.py`)

- **Request bodies are bounded.** Missing `Content-Length` → 411, non-numeric or
  negative → 400, over `MAX_BODY_BYTES` (8 KiB) → 413 without reading the body.
  Truncated bodies and non-UTF-8 bodies → 400. Wrong content type → 415.
- **Slow clients cannot pin threads forever.** `Handler.timeout` (default 10 s,
  `READ_TIMEOUT`) closes a socket that stalls mid-request. Concurrent request
  slots are capped (`MAX_CONCURRENCY`, default 32); excess connections get a
  minimal 503 instead of an unbounded thread pile-up.
- **SQLite is safe under the threaded server.** WAL journal mode, a 5 s busy
  timeout, `timeout=10` on connect, and one process-wide write lock around the
  two write paths. The test suite hammers 30 concurrent submissions and expects
  30 successes.
- **The audit log stays JSON-lines.** Appends are serialised by a lock, control
  characters and newlines in event text are stripped, details are truncated
  (`MAX_AUDIT_DETAIL = 300`), and `json.dumps` supplies escaping. Rejection
  logging is rate-limited so a hostile client cannot trivially flood the file.
- **Output is escaped and headers are constrained.** Patient and audit fields are
  HTML-escaped; pages send `Content-Security-Policy`, `X-Content-Type-Options:
  nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` and
  `Cache-Control: no-store`. URLs are mapped by exact path, so traversal and
  encoded CRLF never reach a header or the filesystem.
- **Errors are generic.** Unhandled exceptions return `500 internal error` and
  log only the exception type; no traceback or SQLite detail reaches the client.
- **Methods are explicit.** Only GET, HEAD and POST are routed; PUT/DELETE/PATCH/
  OPTIONS/TRACE get 405 with an `Allow` header.
- **Bind address is configurable** (`HOST`, default `0.0.0.0` inside the
  container, which is required for a published port). The host-side exposure is
  controlled by `LAB_BIND_IP` and defaults to loopback.
- **Input is validated**: DOB must parse as ISO and fall in 1900..today, phone
  must contain at least seven digits, lengths are capped before storage, and
  unknown scribe vendors are rejected instead of silently defaulting to the
  first vendor.

Evidence: `tests/test_ehr_app.py` starts the real server on an ephemeral port
against a temporary data directory and covers every route plus oversized,
negative, missing and non-numeric lengths, truncated bodies, a slow partial
request, traversal, CRLF-in-path, SQL-injection-shaped names, stored XSS, audit
injection, concurrent writes, and error-leak checks.

### Containers

- Base images are pinned by digest (`alpine:3.20@sha256:…`,
  `ubuntu:24.04@sha256:…`); the endpoint image inherits the DC image so Samba
  client tools cannot drift from the DC version.
- The EHR container runs as the host uid/gid (`LAB_UID`/`LAB_GID` from
  `samba-dc/.env`), has `read_only: true`, a 16 MiB `/tmp` tmpfs, `cap_drop:
  [ALL]`, `no-new-privileges`, and memory/CPU/PID limits.
- The DC and endpoints need root inside the container (Samba provisions, chowns,
  sets ACLs/xattrs, switches uid/gid and binds LDAP/Kerberos ports). They use
  `cap_drop: [ALL]` plus an explicit allow-list (`SYS_ADMIN`, `CHOWN`,
  `DAC_OVERRIDE`, `FOWNER`, `SETUID`, `SETGID`, `NET_BIND_SERVICE`, `KILL`) and
  `no-new-privileges`. `SYS_ADMIN` is the one capability that is broader than
  ideal and is documented as accepted lab risk.
- Every lab service has a healthcheck; `bootstrap.sh` uses
  `docker compose up --wait` instead of a hand-rolled `sleep` loop. All services
  have `restart: unless-stopped`, resource limits and PID limits.
- Passwords are no longer passed as `docker exec` arguments (they used to be
  visible in the host process list for the duration of the domain seed) and are
  no longer in the container environment. Compose mounts `samba-dc/.env` as a
  read-only secret and the entrypoints read it from `/run/secrets/lab_env`;
  `scripts/verify-boundaries.sh` asserts that no lab password appears in
  `docker inspect` output for any lab container.

### Scripts and lifecycle

- All shell scripts use `set -euo pipefail` and pass `bash -n`; the test suite
  also runs `shellcheck --severity=warning` when shellcheck is installed (it is
  skipped, not silently passed, when absent).
- `scripts/bootstrap.sh` is idempotent: network/volume/dirs/credentials/
  symlinks/users/shares are all check-then-create. Re-running it twice in a row
  is part of the manual verification for this change.
- `scripts/teardown.sh` implements the README teardown, only touches
  `workstation-01`, `frontdesk-01`, `msp-jump-01`, `clinic-ehr`, `samba-dc`, the
  `mills-lab` network and the `mills-lab-shares` volume, is safe to re-run, and
  supports `--dry-run`, `--yes` and `--purge-data`.
- `scripts/verify-boundaries.sh` exits non-zero unless the advertised access
  boundaries are true: a clinical user reads `ClinicalShare`, IT is denied there
  with `NT_STATUS_ACCESS_DENIED` but reads `ITShare`, IT reads `FrontOfficeShare` but is
  denied writing there while still writing `ITShare` (the control), a temporary-password user
  fails with `NT_STATUS_PASSWORD_MUST_CHANGE`, anonymous SMB is denied, and no
  container config leaks a lab password.
- `scripts/seed-scenario.sh` fails with a clear message if the front desk
  container is not running and is safe to re-run.

## Accidental issues found and fixed during this review

| Issue | Impact before | Fix |
|---|---|---|
| `int(Content-Length)` with no cap | huge values allocated memory; `-1` made `rfile.read(-1)` block until EOF | explicit 400/411/413 handling and an 8 KiB cap |
| No socket timeout, unbounded threads | a few stalled connections exhausted the server | `Handler.timeout` plus a concurrency semaphore (503 when full) |
| SQLite default connection settings | concurrent writes could return `database is locked` | WAL, busy timeout, serialised writes |
| Audit text was not sanitised/bounded | control characters and unbounded details; no write serialisation | clean, truncate, lock, rate-limited rejection logging |
| Patient fields rendered unescaped | stored XSS if a row was tampered with | `html.escape` on all dynamic fields; template title escaped |
| Unknown `/scribe/run` vendor fell back to the first vendor | silent wrong-vendor egress | 400 |
| DOM change: `?ok=1` did nothing | no feedback after intake | success banner |
| Bootstrap passed passwords on the `docker exec` command line | visible in host `ps` | passwords read from the container secret |
| Endpoint join used `|| true` | an endpoint could run permanently unjoined and silently sync nothing | 5 retries, then fail loudly |
| Endpoint audit JSON built by `printf` | a quote/newline in an env label could break JSON lines | escaped before printing |
| No scripted teardown | easy to leave containers, network and volume behind | `scripts/teardown.sh` |
| Moving base tags (`latest`, `24.04`, `3.20`) | a rebuild could silently change the OS | digest pins |
| `chgrp "MILLSLAB\\DL-ClinicalShare-RW"` always failed (the name does not resolve to a gid) and was hidden by `\|\| true` | every share directory stayed `root 0755`, readable by any authenticated user; access rested only on `smb.conf` `valid users`, so the "least-privilege ACLs" claim was not true at the filesystem layer. Found by the ACL collector on a live run | `provision-shares.sh` now applies NT ACLs (`samba-tool ntacl set`) per share, idempotently; the collector confirms the change (7 findings resolved on the next run) |

## Remaining accepted risk

- **No TLS and no authentication** on the portal; `LAB_BIND_IP=0.0.0.0` publishes
  it (and anonymous-able LDAP, Kerberos, kpasswd on 464 and the global catalog)
  to every interface. Bootstrap prints a loud warning for a non-loopback bind.
- **Root in the DC/endpoints and `SYS_ADMIN`** remain. Docker access is already
  root-equivalent on the host (see THREAT-MODEL.md); a lab that needs Samba
  provisioning cannot meaningfully contain a malicious root process.
- **Credentials live in `samba-dc/.env` (mode 0600, gitignored).** Any process or
  user that can read that file, read the containers' `/run/secrets/lab_env`, or
  talk to Docker can use the lab's accounts. Endpoints mount the whole env file,
  so an endpoint container can read the domain admin password as well as its own
  sync password; splitting per-service secrets is worthwhile if the lab ever
  grows beyond one trusted host.
- **The endpoint keeps `/root/.smbcred`** for the sync loop (mode 0600 inside the
  container). A long-lived password file is realistic for a lab but not a
  pattern to copy.
- **The audit log grows without retention and is not anchored.** It survives in
  `clinic-ehr/data/access.jsonl`; rate-limited rejection logging bounds abuse,
  not normal traffic. The evidence ledger's hash chain is separate.
- **No CSRF protection or per-client rate limiting** on intake/scribe writes;
  both are unauthenticated by design, so CSRF has no privilege to borrow and the
  write volume is bounded only by the host's resources.
- **Healthchecks prove liveness, not correctness.** They do not assert that the
  domain has the expected users or that sync copied the expected files;
  `verify-boundaries.sh` covers the access boundaries separately.
- **Rare platforms are untested.** Images are digest-pinned multi-arch indexes,
  but the lab was exercised on Linux/amd64 only.

## How to verify

```bash
./scripts/bootstrap.sh                 # twice in a row: second run must also exit 0
./scripts/verify-boundaries.sh         # 14 passed, 0 failed
uv run --no-project --with pytest --with ruff sh -c 'ruff check . && pytest -q'
./scripts/teardown.sh --dry-run        # preview; no Docker calls
./scripts/teardown.sh --yes            # remove containers, network, volume
```
