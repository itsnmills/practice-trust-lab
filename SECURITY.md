# Security policy

Practice Trust Lab is a **synthetic, local-only training and portfolio lab**. It
is not a product, it processes no real patient data, and it must never be
pointed at a production clinic or a system you do not own.

## Supported versions

| Version | Supported |
|---|---|
| `main` (and the latest tagged release) | Yes |
| Older tags | No |

Security fixes land on `main` only.

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub's **Security →
Advisories → Report a vulnerability** on this repository. Do not open a public
issue with exploit details, and do not include real patient data, credentials,
or third-party system details in the report.

Please include:

- the affected file, script, or workflow;
- the impact in the lab's own threat model (for example: a collector read that
  becomes a write, an evidence-integrity bypass, an HTML injection in the packet,
  a credential leak into a committed file);
- reproduction steps using synthetic data only;
- your preferred credit, if any.

Expect a best-effort acknowledgement. This is a personal project with no SLA and
no bug bounty. Please give a reasonable window for a fix before public
disclosure.

## Scope

In scope:

- the collector and renderer (`evidence/`), including metadata-only handling of
  synthetic lab data;
- the ledger hash chain and `--verify-ledger` checks;
- the packet renderer's HTML escaping and self-contained output;
- `scripts/`, the Dockerfiles, and the compose files in this repository;
- CI workflows and repo hygiene that could leak credentials or evidence.

Out of scope:

- vulnerabilities in upstream Samba, Ubuntu, Alpine, Docker, or Bumblebee —
  report those to their projects;
- the host Docker daemon and anything reachable only through root-equivalent
  Docker access (see the threat model);
- findings that require the attacker to already control the host or the
  repository;
- the **intentionally weak** configuration described below.

## What is intentionally weak

The lab exists to produce real detections, so these are features, not
vulnerabilities:

- no MFA anywhere, including the admin-equivalent `SG-IT` group;
- a weak-by-design password and lockout policy in the lab's domain;
- patient-adjacent exports on a share readable by all clinical staff and copied
  to endpoint desktops;
- AI-scribe transmissions to vendors with unverified BAA status;
- a public web intake form with no modeled retention or TLS termination;
- a planted shadow-IT app pinned to a known-compromised npm release;
- credentials generated per clone and stored in the gitignored
  `samba-dc/.env`, passed to containers through environment variables.

`docs/THREAT-MODEL.md` describes each one and how the evidence packet reports
it. Do not report these as bugs; report a **failure to detect** them instead.

## Known accepted risks

- **Docker access is root-equivalent.** Anyone who can run the collector can
  effectively act as root on the host. This is acceptable only for a disposable
  local lab, never for a production collector.
- **The ledger is tamper-evident, not tamper-proof.** Someone who can rewrite
  the entire ledger and every snapshot can rebuild a consistent chain. Anchoring
  the latest entry hash off-host closes that gap; the lab does not do it.
- **Short hash prefixes.** File hashes in packets are truncated to 16 hex
  characters (64 bits): enough to prove two copies match in a demo, not enough
  for forensic use.
- **Filename-based classification.** "Patient-adjacent" data is a filename
  regex, not content-aware DLP; it produces both false positives and false
  negatives.
- **Unpinned build dependencies.** Dockerfiles intentionally do not pin APT/APK
  package versions so the lab keeps building; the Hadolint gate is configured at
  `error` severity for that reason. Do not deploy these images.

## Safe usage

- Run only on a machine you own, with Docker, on a trusted network.
- Keep the default `LAB_BIND_IP=127.0.0.1` unless you deliberately expose the lab
  on a VPN interface.
- Never replace synthetic fixtures with real patient or clinic data.
- Delete `samba-dc/.env`, `*/home/`, `*/logs/`, and `clinic-ehr/data/` before
  sharing a copy of the tree.
