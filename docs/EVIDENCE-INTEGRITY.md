# Evidence integrity

Practice Trust Lab writes a hash-chained ledger beside its snapshots. The chain
makes edits, deletions, reorderings and snapshot rewrites visible. It cannot stop
someone who can rewrite *everything* from producing a new, internally consistent
chain. This document describes the second layer that closes that specific gap: a
small checkpoint anchored off the collector host, optionally signed, plus a
standalone verifier an auditor can run without the collector.

Brand and scope unchanged: synthetic data only, metadata only, no PHI.

## What the ledger proves on its own

Each entry in `evidence/ledger.jsonl` records:

- the snapshot's SHA-256 (`snapshot_sha256`, exact bytes of the JSON file);
- the previous entry's `entry_hash` (`prev`);
- a digest over its own fields (`entry_hash`);
- `"v": 1`, the chain format version. Entries written before versioning existed
  have no `v` and still verify; they are reported as unversioned, not as errors.

`--verify-ledger` recomputes every digest, checks every `prev` link, and re-hashes
every snapshot. It detects:

| Change | Detected by |
|---|---|
| snapshot bytes edited | `snapshot_modified` (error) |
| entry field edited | `entry_digest_mismatch` (error) |
| entry deleted (not the last) | `chain_broken` (error) |
| entries reordered | `chain_broken` (error) |
| entry inserted | `chain_broken` (error) |
| snapshot file removed | `snapshot_missing` (warning; chain still checked) |
| crash mid-write left a partial last line | `truncated_tail` (warning; not counted) |

What it does **not** detect on its own: deleting the newest entries (the remaining
file is a valid shorter chain) or rebuilding the entire file from genesis. Those
are exactly what a checkpoint addresses.

The ledger is not writable by the verifier. Appends by the collector take an
exclusive `fcntl.flock` on `ledger.jsonl.lock`, flush and `fsync` the file, and
fsync the directory entry, so two collectors cannot both chain from the same
head and a crash cannot leave two JSON objects fused on one line. On platforms
without `fcntl` the lock degrades to a no-op; that mode is not safe for
concurrent writers. A torn trailing line is copied to `ledger.jsonl.recovered`
before being truncated, so nothing is silently discarded, and the next append
continues from the last complete entry.

## What a checkpoint is

`--checkpoint` writes a portable JSON anchor like this:

```json
{
  "kind": "velari.evidence-checkpoint/1",
  "created_at": "2026-11-12T04:46:53Z",
  "ledger_name": "ledger.jsonl",
  "entry_count": 2,
  "head_entry_hash": "c467dee6cd3f479cdd1e3ec4cdb8ad637398609ad66a980f11bc76e756bb77f1",
  "head_ts": "2026-11-12T04:31:38Z",
  "head_line": 2,
  "ledger_bytes": 914,
  "ledger_sha256": "1c29f5a6e39c5fc8a4956a39a1f2ddab750a04f0c4605437bca5750e297affa6",
  "note": "Off-host anchor. Verify with evidence/verify_evidence.py; see docs/EVIDENCE-INTEGRITY.md.",
  "signature": {"alg": "hmac-sha256", "key_id": "8b2b37d798c77942", "value": "716b..."}
}
```

It is deliberately small and human-readable: paste it into a ticket comment, an
email to the client, a signed git tag, a printed review binder, or a password
manager note. Store it where the collector host cannot rewrite it. A checkpoint
kept only beside the ledger adds nothing.

`entry_count` counts chained entries only (legacy un-chained lines are not
anchored). `head_line` is the physical line, which differs when legacy lines are
present. `ledger_sha256` hashes the whole file **at checkpoint time**; it is
expected to change on the next append, which is why verification distinguishes an
exact byte match from a still-valid anchor.

## What checkpoint verification detects

| Attack or accident | Result |
|---|---|
| Ledger truncated below the checkpointed count | `checkpoint_truncated` (error) |
| Entry at the checkpointed position replaced | `checkpoint_head_moved` (error) |
| Whole chain rebuilt, same or different length | `checkpoint_head_moved` (error) |
| Detached entries appended after the anchor | `checkpoint_chain_broken` (error) |
| Ledger bytes differ only because entries were appended | `checkpoint_ledger_changed` (warning) |
| Checkpoint body edited after signing | `signature_invalid` (error) |

Verification recomputes the full chain first. If the anchor at position *N* still
has the checkpointed hash, the checkpointed prefix is cryptographically
consistent with what was anchored. If the ledger is longer and entry *N+1*
chains from that hash, the extension is legitimate. Entries after *N* are **not**
covered until you take another checkpoint.

## What a checkpoint cannot prove

- **Authenticity without a signature.** Anyone can produce a JSON file with any
  hash in it. An unsigned checkpoint proves only that *someone* recorded that
  state somewhere off-host. Its value is custody: if the copy you trust predates
  the attack, the attack is visible.
- **A trusted time.** `created_at` is the collector's clock. Without a
  timestamping authority, git tag, or email delivery trail, it asserts a time but
  does not prove one.
- **Tail coverage.** Everything appended after the checkpoint is outside the
  anchor. Checkpoint often enough that the window you could lose is acceptable.
- **Host compromise plus off-host compromise.** If an attacker controls both the
  ledger and every copy of the checkpoint, or the signing key and the storage,
  nothing here helps. Off-host storage and key custody are the actual controls.
- **Ledger anonymity or secrecy.** Hashes, filenames and timestamps are still
  metadata that can itself be sensitive. This is a no-PHI synthetic lab, but a
  production deployment needs its own data-handling review.
- **Disk-level or filesystem tampering.** `fsync` gives durability, not
  immutability. A malicious root can still change bytes; the checkpoint is what
  exposes it.

## Signing

### HMAC-SHA256 baseline

The baseline uses a shared secret, read from a file or the environment. The key
is never written to the ledger or checkpoint, never printed, and never included
in error messages. Checkpoints carry only `key_id`, the first 16 hex characters
of `SHA-256(key)`, so a verifier can identify which key to use.

```bash
umask 077
head -c 32 /dev/urandom > ~/.velari/checkpoint.key
chmod 600 ~/.velari/checkpoint.key

python3 evidence/collect_practice_evidence.py --checkpoint \
  --sign hmac --key-file ~/.velari/checkpoint.key
```

`--sign` defaults to `auto`: HMAC when a key is resolvable, otherwise SSH when
`--ssh-key` is given, otherwise OpenSSL when `--openssl-key` is given, otherwise
unsigned. `--sign none` never reads a key file.

Key handling rules enforced in code:

- key **files** must be mode `0600` on POSIX; group/other access is refused with
  a clear error (the error names the file and mode, never the key);
- `VELARI_CHECKPOINT_KEY` may carry the key instead, for CI or a password-manager
  injection;
- the file is trimmed of a trailing newline; an empty key is refused;
- `--sign hmac` with no resolvable key fails rather than writing an unsigned
  checkpoint.

HMAC is symmetric. It proves possession of the key to someone who also has the
key; it does **not** let an outside auditor verify authorship. It is the right
baseline for a single owner anchoring their own runs, not for a third-party
attestation.

### SSH and OpenSSL signatures (optional)

If `ssh-keygen` or `openssl` is on `PATH`, the checkpoint can be signed
asymmetrically. Commands are built as argument lists with `subprocess.run(...,
shell=False)`; filenames are never interpolated into a shell string.

```bash
# SSH (Ed25519); the default signer identity is "velari-evidence"
python3 evidence/collect_practice_evidence.py --checkpoint anchor.json \
  --sign ssh --ssh-key ~/.ssh/velari_evidence
```

The SSH signature is stored armoured in the checkpoint with the namespace and
identity (`velari-evidence` by default). Verification needs an `allowed_signers`
file whose first field matches that identity:

```
velari-evidence ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...
```

```bash
python3 evidence/verify_evidence.py evidence/ledger.jsonl \
  --checkpoint anchor.json --ssh-allowed-signers allowed_signers
```

OpenSSL uses `openssl dgst -sha256 -sign` / `-verify` and stores a base64
signature; pass the matching public key with `--openssl-pubkey`.

Tool detection is explicit:

- **creating** an explicitly requested SSH/OpenSSL checkpoint when the tool is
  missing fails with a clear message and writes nothing;
- **verifying** such a checkpoint without the tool emits
  `signing_tool_missing` (warning) and says the signature was not checked. It
  never claims a signature is valid when it could not run the tool.

### Key rotation and loss

`key_id` is recorded in every signature (a SHA-256 prefix of the HMAC key, the
key filename for SSH/OpenSSL). Keep old verification keys, or you lose
the ability to verify older anchors. Losing the only key for an HMAC anchor means
the signature can no longer be checked; the anchor's hash values are still
readable, but their authenticity is no longer established.

## Standalone verifier for third parties

`evidence/verify_evidence.py` is one self-contained file that imports only the
Python standard library (it does not import the collector package). Copy it, the
`ledger.jsonl`, the referenced snapshot files, and any checkpoint to another
machine:

```bash
python3 verify_evidence.py ledger.jsonl
# ok: 2 chained entries checked

python3 verify_evidence.py ledger.jsonl --checkpoint anchor.json --key-file key
# checkpoint: 2 entries, head c467dee6cd3f..., exact file match
# ok: 2 chained entries checked

python3 verify_evidence.py ledger.jsonl --checkpoint anchor.json --json
```

Exit codes:

| Code | Meaning |
|---|---|
| `0` | chain, snapshots, and checkpoint anchor (and signature, if a key was supplied) verified |
| `1` | integrity failure: broken chain, changed snapshot, truncation, rewritten history, or bad signature |
| `2` | usage or input error: missing ledger/checkpoint/key, malformed input, or a signature that cannot be evaluated for lack of key material |

Snapshot paths are resolved relative to the ledger's directory. If you moved the
tree, point at the original snapshot root with `--base-dir`. Add `--require-exact`
when auditing a delivered packet: the default accepts a legitimate append after
the checkpoint (as a warning), while `--require-exact` fails on any byte change.

The verifier is tested as a subprocess with `python -I` so it cannot accidentally
rely on the repository's `PYTHONPATH` or the collector package.

## Collector operations

```bash
# write an anchor after a collection (default: <ledger dir>/checkpoints/)
python3 evidence/collect_practice_evidence.py --checkpoint

# explicit path, signed with the baseline HMAC key
python3 evidence/collect_practice_evidence.py --checkpoint /secure/anchors/2026-11-12.json \
  --sign hmac --key-file ~/.velari/checkpoint.key

# verify the local ledger against an anchor
python3 evidence/collect_practice_evidence.py --verify-checkpoint /secure/anchors/2026-11-12.json \
  --key-file ~/.velari/checkpoint.key
```

Both checkpoint operations run before the Docker preflight and do not collect a
snapshot. Checkpointing refuses a ledger that fails chain verification, because
anchoring a broken chain would launder the break. Snapshot warnings (for example
a missing file) do not block it.

A practical cadence: take a checkpoint after every collection, store it with the
ticket or packet delivery trail, and re-anchor on a schedule you can defend. If
you only anchor monthly, a rewrite during that month is invisible until the next
comparison.

## Ledger head in the packet

The renderer can print the head hash and entry count in its attestation footer so
a reader can compare the paper/PDF with a fresh verification. The helper is:

```python
from practice_evidence.ledger import head_summary

summary = head_summary()  # defaults to evidence/ledger.jsonl
summary["head_entry_hash"], summary["entry_count"], summary["ok"]
```

`head_summary` is a display convenience; it is not an anchor. The full verifier,
with a checkpoint, remains the source of truth.

## Threat summary

| Attacker capability | Outcome |
|---|---|
| Edit a snapshot under the collector | detected by chain |
| Edit/delete/reorder/insert ledger entries | detected by chain |
| Rewrite the entire ledger and snapshots | detected against any older checkpoint kept off-host |
| Delete the newest entries | detected against a checkpoint at or after them |
| Append plausible entries after the anchor | extension is accepted, but not covered until re-anchored |
| Read the ledger | metadata-only, but filenames/timestamps are visible |
| Rewrite the ledger and a checkpoint stored on the same host | no detection (storage is the control) |
| Steal the HMAC key | can forge anchors; rotate and use asymmetric keys for third parties |
| Control the signing key and off-host storage | no detection; out of scope |

## Related

- [Threat model](THREAT-MODEL.md): planted weaknesses and remaining limitations.
- [Architecture](ARCHITECTURE.md): ledger and checkpoint formats in context.
- `tests/test_ledger.py`, `tests/test_checkpoint.py`, `tests/test_verify_cli.py`:
  the behaviours above, including a seeded property test that mutates ledger
  lines and snapshot bytes and requires every mutation to be detected.
