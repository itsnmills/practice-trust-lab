#!/usr/bin/env python3
"""collect_practice_evidence.py - dated evidence pass over the Velari practice lab.

Reads the live lab (Samba AD, shares, clinic EHR) and writes one no-PHI
snapshot per run: JSON receipt + Markdown Practice Snapshot + ledger line.

No secrets, no passwords, no patient content - metadata and configuration only.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

LAB_ROOT = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = Path(__file__).resolve().parent
ARTIFACTS = EVIDENCE_DIR / "artifacts"
LEDGER = EVIDENCE_DIR / "ledger.jsonl"
DC = "samba-dc"
EHR_LOG = LAB_ROOT / "clinic-ehr" / "data" / "access.jsonl"

PRIVILEGED_GROUPS = ["Domain Admins", "Enterprise Admins", "SG-IT"]
STALE_DAYS = 45


def sh(args, timeout=30):
    try:
        out = subprocess.run(
            args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout
        )
        return out.stdout.strip()
    except Exception as exc:  # noqa: BLE001
        return f"__ERROR__ {exc}"


def dexec(cmd, timeout=30):
    return sh(["docker", "exec", DC] + cmd, timeout=timeout)


def preflight():
    """Fail fast with a clear message when the lab is not reachable."""
    try:
        probe = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"error: docker CLI not available ({exc})", file=sys.stderr)
        return False
    if probe.returncode != 0:
        detail = (probe.stderr or "").strip().splitlines()
        print(
            "error: docker daemon not reachable"
            + (f" ({detail[-1]})" if detail else "")
            + "; start Docker and retry",
            file=sys.stderr,
        )
        return False
    state = sh(["docker", "inspect", "-f", "{{.State.Running}}", DC]).strip()
    if state != "true":
        print(
            f"error: container '{DC}' is not running; run scripts/bootstrap.sh first",
            file=sys.stderr,
        )
        return False
    return True


def parse_user_list():
    users = []
    for line in dexec(["samba-tool", "user", "list"]).splitlines():
        line = line.strip()
        if line and not line.startswith("__ERROR__") and line not in ("Administrator", "Guest", "krbtgt"):
            users.append(line)
    return users


def user_attrs(sam):
    raw = dexec(["samba-tool", "user", "show", sam])
    attrs = {}
    for line in raw.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            attrs[key.strip()] = val.strip()
    return attrs


def identity_section():
    sect = {"password_policy": {}, "users": [], "privileged_groups": {}, "findings": []}
    pol = dexec(["samba-tool", "domain", "passwordsettings", "show"])
    for line in pol.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            sect["password_policy"][key.strip()] = val.strip()

    now = datetime.now(timezone.utc)
    for sam in parse_user_list():
        a = user_attrs(sam)
        uac = int(a.get("userAccountControl", "0") or 0)
        enabled = not bool(uac & 0x2)
        last = a.get("lastLogonTimestamp", "0")
        last_dt = None
        try:
            v = int(last)
            if v > 0:
                last_dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=v // 10)
        except ValueError:
            pass
        entry = {
            "sam": sam,
            "enabled": enabled,
            "last_logon": last_dt.strftime("%Y-%m-%dT%H:%M:%SZ") if last_dt else None,
            "stale": bool(enabled and last_dt and (now - last_dt).days > STALE_DAYS),
            "never_logged_on": bool(enabled and (last_dt is None or last_dt.year == 1601)),
        }
        sect["users"].append(entry)
        if not enabled:
            sect["findings"].append(
                {"severity": "info", "detail": f"{sam}: disabled account present (verify it is required)"}
            )
        if entry["stale"]:
            sect["findings"].append(
                {"severity": "medium", "detail": f"{sam}: no logon in >{STALE_DAYS} days"}
            )
        if entry["never_logged_on"]:
            sect["findings"].append(
                {"severity": "low", "detail": f"{sam}: enabled account has never logged on"}
            )

    for group in PRIVILEGED_GROUPS:
        members = dexec(["samba-tool", "group", "listmembers", group]).splitlines()
        sect["privileged_groups"][group] = [m.strip() for m in members if m.strip()]
    if sect["privileged_groups"].get("SG-IT"):
        sect["findings"].append(
            {
                "severity": "medium",
                "detail": "SG-IT membership = local admin equivalent; confirm business need and MFA path",
            }
        )
    return sect


def shares_section():
    sect = {"shares": [], "files": [], "findings": []}
    conf = dexec(["cat", "/etc/samba/smb.conf"])
    name = None
    for line in conf.splitlines():
        m = re.match(r"^\[(.+)\]$", line.strip())
        if m:
            name = m.group(1)
            if name not in ("global", "sysvol", "netlogon"):
                sect["shares"].append({"name": name})
        elif name and sect["shares"] and "=" in line:
            key, _, val = line.partition("=")
            sect["shares"][-1][key.strip()] = val.strip()

    raw = dexec(["find", "/srv/samba/shares", "-type", "f"])
    for p in [x.strip() for x in raw.splitlines() if x.strip()]:
        digest = dexec(["sha256sum", p]).split(" ")[0][:16]
        sect["files"].append({"path": p, "sha256_16": digest})

    for f in sect["files"]:
        if re.search(r"patient|intake|insurance|schedule", f["path"], re.I):
            sect["findings"].append(
                {
                    "severity": "high",
                    "detail": f"patient-adjacent data on file share: {f['path']}",
                }
            )
    return sect


AUTH_RE = re.compile(
    r"user \[(?P<dom>[^\]]+)\]\\(?:\[)?(?P<user>[^\s\]]+)\]?.*?status \[(?P<status>[^\]]+)\]"
)


def auth_section(hours=24):
    sect = {"window_hours": hours, "success": 0, "failures": 0, "by_user": {}, "failure_reasons": {}, "findings": []}
    logs = sh(["docker", "logs", "--since", f"{hours}h", DC], timeout=60)
    if logs.startswith("__ERROR__"):
        sect["findings"].append({"severity": "info", "detail": f"auth log read failed: {logs}"})
        return sect
    for line in logs.splitlines():
        m = AUTH_RE.search(line)
        if not m:
            continue
        user = m.group("user")
        status = m.group("status")
        if status == "NT_STATUS_OK":
            sect["success"] += 1
            sect["by_user"].setdefault(user, {"success": 0, "fail": 0})["success"] += 1
        else:
            sect["failures"] += 1
            sect["by_user"].setdefault(user, {"success": 0, "fail": 0})["fail"] += 1
            sect["failure_reasons"][status] = sect["failure_reasons"].get(status, 0) + 1
    if sect["failures"] >= 5:
        sect["findings"].append(
            {"severity": "medium", "detail": f"{sect['failures']} auth failures in last {hours}h; check lockout source"}
        )
    for reason in sect["failure_reasons"]:
        if reason != "NT_STATUS_WRONG_PASSWORD":
            sect["findings"].append(
                {"severity": "low", "detail": f"non-password auth failure observed: {reason}"}
            )
    return sect


def ehr_section():
    sect = {"health": None, "events": {}, "scribe_transmissions": 0, "intake_submissions": 0, "findings": []}
    try:
        import urllib.request

        with urllib.request.urlopen(os.environ.get("EHR_URL", "http://127.0.0.1:8095/healthz"), timeout=5) as resp:
            sect["health"] = json.loads(resp.read().decode())
    except Exception as exc:  # noqa: BLE001
        sect["health"] = {"error": str(exc)}
        sect["findings"].append({"severity": "medium", "detail": f"clinic portal unreachable: {exc}"})

    if EHR_LOG.exists():
        for line in EHR_LOG.read_text(encoding="utf-8").splitlines():
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            sect["events"][ev["event"]] = sect["events"].get(ev["event"], 0) + 1
        sect["scribe_transmissions"] = sect["events"].get("scribe_transmission", 0)
        sect["intake_submissions"] = sect["events"].get("intake_submitted", 0)
    if sect["scribe_transmissions"]:
        sect["findings"].append(
            {
                "severity": "high",
                "detail": f"{sect['scribe_transmissions']} scribe transmission events; verify signed BAA per vendor",
            }
        )
    if sect["intake_submissions"]:
        n = sect["intake_submissions"]
        sect["findings"].append(
            {
                "severity": "medium",
                "detail": f"{n} public web intake submission{'s' if n != 1 else ''}; confirm TLS + retention + access control",
                "ref_key": "ehr-intake",
            }
        )
    return sect


def containers_section():
    raw = sh(["docker", "ps", "--format", "{{.Names}}|{{.Status}}|{{.Ports}}"])
    out = []
    for line in raw.splitlines():
        parts = line.split("|")
        if len(parts) == 3:
            out.append({"name": parts[0], "status": parts[1], "ports": parts[2][:120]})
    return out


ENDPOINTS = [
    {"name": "ws-clinical-01", "dir": "workstation-01", "role": "Clinical workstation"},
    {"name": "fd-frontdesk-01", "dir": "frontdesk-01", "role": "Front office workstation"},
    {"name": "msp-jump-01", "dir": "msp-jump-01", "role": "MSP admin jump box"},
]
PATIENT_ADJACENT = re.compile(r"patient|intake|insurance|schedule", re.I)


ECHO_DIR = Path(os.environ.get("BUMBLEBEE_DIR", Path.home() / "bumblebee"))
ECHO_BIN = ECHO_DIR / "bin" / "bumblebee"
ECHO_CATALOGS = ECHO_DIR / "catalogs" / "vendor" / "bumblebee"
SCAN_ROOTS = [LAB_ROOT / "workstation-01" / "home", LAB_ROOT / "frontdesk-01" / "home", LAB_ROOT / "msp-jump-01" / "home"]


def supply_chain_section(timeout=180):
    sect = {"scanner": "bumblebee", "status": "skipped", "findings": [], "detail": None}
    if not ECHO_BIN.exists():
        sect["detail"] = "bumblebee binary not installed"
        return sect
    catalog_files = [p for p in ECHO_CATALOGS.glob("*.json") if p.name != "sync-manifest.json"]
    if not catalog_files:
        sect["detail"] = "no exposure catalogs found"
        return sect
    merged_dir = EVIDENCE_DIR / ".catalogs"
    merged_dir.mkdir(exist_ok=True)
    for stale in merged_dir.glob("*.json"):
        stale.unlink()
    for cat in sorted(catalog_files):
        (merged_dir / cat.name).symlink_to(cat)
    cmd = [str(ECHO_BIN), "scan", "--findings-only", "--max-duration", "90s"]
    for root in SCAN_ROOTS:
        if root.exists():
            cmd += ["--root", str(root)]
    cmd += ["--exposure-catalog", str(merged_dir)]
    raw = sh(cmd, timeout=timeout)
    if raw.startswith("__ERROR__"):
        sect["status"] = "error"
        sect["detail"] = raw[:200]
        return sect
    sect["status"] = "complete"
    for line in raw.splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("record_type") == "finding":
            raw_sev = rec.get("severity", "medium")
            sev = "high" if raw_sev in ("critical", "high") else ("medium" if raw_sev == "medium" else "low")
            proj = rec.get("project_path") or ""
            if proj.startswith(str(LAB_ROOT)):
                proj = proj[len(str(LAB_ROOT)):].lstrip("/")
            sect["findings"].append(
                {
                    "severity": sev,
                    "detail": (
                        f"Known-compromised package {rec.get('package_name')}@{rec.get('version')} "
                        f"({rec.get('ecosystem')}) in {proj}"
                    ),
                    "package": rec.get("package_name"),
                    "version": rec.get("version"),
                    "ecosystem": rec.get("ecosystem"),
                    "catalog": rec.get("catalog_name"),
                    "project": proj,
                    "source_file": rec.get("source_file"),
                }
            )
    return sect


def endpoints_section():
    sect = {"hosts": [], "findings": []}
    for spec in ENDPOINTS:
        host = {
            "name": spec["name"],
            "role": spec["role"],
            "local_copies": [],
            "activity": {},
        }
        desktop = LAB_ROOT / spec["dir"] / "home" / "Desktop" / "incoming"
        if desktop.exists():
            for p in sorted(desktop.glob("*")):
                if p.is_file():
                    try:
                        digest = hashlib.sha256(p.read_bytes()).hexdigest()[:16]
                        readable = True
                    except PermissionError:
                        digest = None
                        readable = False
                    host["local_copies"].append(
                        {"file": p.name, "sha256_16": digest, "readable": readable}
                    )
                    if not readable:
                        sect["findings"].append(
                            {
                                "severity": "low",
                                "detail": f"{spec['name']}: copy not readable by evidence collector: {p.name}",
                            }
                        )
        act = LAB_ROOT / spec["dir"] / "logs" / "activity.jsonl"
        if act.exists():
            for line in act.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                key = ev.get("event", "unknown")
                host["activity"][key] = host["activity"].get(key, 0) + 1
        if host["local_copies"]:
            adjacent = [c for c in host["local_copies"] if PATIENT_ADJACENT.search(c["file"])]
            if adjacent:
                sect["findings"].append(
                    {
                        "severity": "high",
                        "detail": (
                            f"{spec['name']} ({spec['role']}): {len(adjacent)} patient-adjacent "
                            f"file{'s' if len(adjacent) != 1 else ''} on local desktop"
                        ),
                        "ref_key": f"endpoint-{spec['name']}",
                    }
                )
            else:
                sect["findings"].append(
                    {
                        "severity": "info",
                        "detail": f"{spec['name']} ({spec['role']}): {len(host['local_copies'])} share "
                        f"file{'s' if len(host['local_copies']) != 1 else ''} cached locally",
                    }
                )
        sect["hosts"].append(host)
    return sect


def legacy_endpoint_copies(snap):
    copies = {}
    if "endpoints" in snap:
        for host in snap["endpoints"].get("hosts", []):
            for c in host.get("local_copies", []):
                copies[f"{host['name']}:{c['file']}"] = c.get("sha256_16")
        return copies
    for c in snap.get("workstation", {}).get("local_copies", []):
        copies[f"ws-clinical-01:{c['file']}"] = c.get("sha256_16")
    return copies


def previous_snapshot(current_path):
    candidates = sorted(p for p in ARTIFACTS.glob("*/*.json") if p != current_path)
    for path in reversed(candidates):
        try:
            return path, json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
    return None, None


def compute_drift(prev, cur):
    drift = {
        "compared_to": prev.get("collected_at") if prev else None,
        "status": "baseline" if not prev else "compared",
        "user_changes": [],
        "group_changes": [],
        "share_changes": [],
        "endpoint_changes": [],
        "findings_new": [],
        "findings_resolved": [],
        "counter_deltas": {},
    }
    if not prev:
        return drift

    prev_users = {u["sam"]: u for u in prev.get("identity", {}).get("users", [])}
    cur_users = {u["sam"]: u for u in cur.get("identity", {}).get("users", [])}
    for sam in sorted(set(cur_users) - set(prev_users)):
        drift["user_changes"].append(f"account added: {sam}")
    for sam in sorted(set(prev_users) - set(cur_users)):
        drift["user_changes"].append(f"account removed: {sam}")
    for sam in sorted(set(prev_users) & set(cur_users)):
        if prev_users[sam]["enabled"] != cur_users[sam]["enabled"]:
            state = "enabled" if cur_users[sam]["enabled"] else "disabled"
            drift["user_changes"].append(f"account {state}: {sam}")

    prev_groups = prev.get("identity", {}).get("privileged_groups", {})
    cur_groups = cur.get("identity", {}).get("privileged_groups", {})
    for group in sorted(set(prev_groups) | set(cur_groups)):
        before = set(prev_groups.get(group, []))
        after = set(cur_groups.get(group, []))
        for member in sorted(after - before):
            drift["group_changes"].append(f"{group}: {member} added")
        for member in sorted(before - after):
            drift["group_changes"].append(f"{group}: {member} removed")

    prev_files = {f["path"]: f.get("sha256_16") for f in prev.get("shares", {}).get("files", [])}
    cur_files = {f["path"]: f.get("sha256_16") for f in cur.get("shares", {}).get("files", [])}
    for path in sorted(set(cur_files) - set(prev_files)):
        drift["share_changes"].append(f"file added: {path}")
    for path in sorted(set(prev_files) - set(cur_files)):
        drift["share_changes"].append(f"file removed: {path}")
    for path in sorted(set(prev_files) & set(cur_files)):
        if prev_files[path] != cur_files[path]:
            drift["share_changes"].append(f"file content changed: {path}")

    prev_copies = legacy_endpoint_copies(prev)
    cur_copies = legacy_endpoint_copies(cur)
    for name in sorted(set(cur_copies) - set(prev_copies)):
        drift["endpoint_changes"].append(f"new local copy: {name}")
    for name in sorted(set(prev_copies) - set(cur_copies)):
        drift["endpoint_changes"].append(f"local copy removed: {name}")
    for name in sorted(set(prev_copies) & set(cur_copies)):
        if prev_copies[name] != cur_copies[name]:
            drift["endpoint_changes"].append(f"local copy changed: {name}")

    def key(f):
        return (f.get("section", ""), f.get("detail", ""))

    prev_findings = {key(f): f for f in prev.get("findings", [])}
    cur_findings = {key(f): f for f in cur.get("findings", [])}
    for k in sorted(set(cur_findings) - set(prev_findings)):
        drift["findings_new"].append(f"[{cur_findings[k]['severity']}] {cur_findings[k]['detail']}")
    for k in sorted(set(prev_findings) - set(cur_findings)):
        drift["findings_resolved"].append(f"[{prev_findings[k]['severity']}] {prev_findings[k]['detail']}")

    for metric in ("intake_submissions", "scribe_transmissions"):
        before = prev.get("ehr", {}).get(metric, 0)
        after = cur.get("ehr", {}).get(metric, 0)
        if after != before:
            drift["counter_deltas"][metric] = after - before
    for metric in ("success", "failures"):
        before = prev.get("auth", {}).get(metric, 0)
        after = cur.get("auth", {}).get(metric, 0)
        if after != before:
            drift["counter_deltas"][f"auth_{metric}"] = after - before

    return drift


def main():
    ap = argparse.ArgumentParser(description="Collect a dated practice-lab evidence snapshot")
    ap.add_argument("--hours", type=int, default=24, help="auth log window in hours")
    ap.add_argument("--skip-supply-chain", action="store_true", help="skip the Bumblebee scan section")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if not preflight():
        return 2

    ts = datetime.now(timezone.utc)
    snapshot = {
        "collector": "collect_practice_evidence.py",
        "schema": "velari.practice-snapshot/0.2",
        "collected_at": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "lab": "millslab.internal (synthetic)",
        "containers": containers_section(),
        "identity": identity_section(),
        "shares": shares_section(),
        "auth": auth_section(args.hours),
        "ehr": ehr_section(),
        "endpoints": endpoints_section(),
        "supply_chain": supply_chain_section() if not args.skip_supply_chain else {"status": "skipped", "findings": []},
    }

    all_findings = []
    for section in ("identity", "shares", "auth", "ehr", "endpoints", "supply_chain"):
        for f in snapshot[section].get("findings", []):
            f = dict(f)
            f["section"] = section
            all_findings.append(f)
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    all_findings.sort(key=lambda f: order.get(f.get("severity", "info"), 9))
    snapshot["findings"] = all_findings
    counts = {}
    for f in all_findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    snapshot["finding_counts"] = counts

    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    day = ts.strftime("%Y-%m-%d")
    outdir = ARTIFACTS / day
    outdir.mkdir(exist_ok=True)
    stem = f"snapshot-{ts.strftime('%Y%m%dT%H%M%SZ')}"
    json_path = outdir / f"{stem}.json"
    prev_path, prev = previous_snapshot(json_path)
    drift = compute_drift(prev, snapshot)
    drift["compared_to_path"] = str(prev_path) if prev_path else None
    snapshot["drift"] = drift
    json_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")

    lines = [
        f"# Practice Snapshot - {day}",
        "",
        f"Collected: {snapshot['collected_at']} | Lab: `{snapshot['lab']}` | Findings: "
        + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())),
        "",
    ]

    drift = snapshot["drift"]
    if drift["status"] == "baseline":
        lines += ["## Changes since last run", "", "_Baseline snapshot - no previous run to compare._", ""]
    else:
        total_changes = sum(
            len(drift[k])
            for k in (
                "user_changes",
                "group_changes",
                "share_changes",
                "endpoint_changes",
                "findings_new",
                "findings_resolved",
            )
        )
        lines += [
            "## Changes since last run",
            "",
            f"Compared to: {drift['compared_to']} | {total_changes} change(s)",
            "",
        ]
        labels = [
            ("findings_new", "New findings"),
            ("findings_resolved", "Resolved findings"),
            ("user_changes", "Identity changes"),
            ("group_changes", "Group changes"),
            ("share_changes", "Share changes"),
            ("endpoint_changes", "Endpoint changes"),
        ]
        any_changes = False
        for key, label in labels:
            if drift[key]:
                any_changes = True
                lines.append(f"**{label}**")
                for item in drift[key]:
                    lines.append(f"- {item}")
                lines.append("")
        if drift["counter_deltas"]:
            any_changes = True
            lines.append("**Activity deltas**")
            for metric, delta in drift["counter_deltas"].items():
                lines.append(f"- {metric}: {'+' if delta >= 0 else ''}{delta}")
            lines.append("")
        if not any_changes:
            lines += ["_No changes since last run._", ""]

    lines += ["## Findings", ""]
    for f in all_findings:
        lines.append(f"- **[{f['severity'].upper()}]** ({f['section']}) {f['detail']}")
    lines += [
        "",
        "## Identity",
        "",
        f"- Password policy: {json.dumps(snapshot['identity']['password_policy'])}",
        f"- Enabled users: {sum(1 for u in snapshot['identity']['users'] if u['enabled'])}"
        f" / disabled: {sum(1 for u in snapshot['identity']['users'] if not u['enabled'])}",
    ]
    for g, members in snapshot["identity"]["privileged_groups"].items():
        lines.append(f"- {g}: {', '.join(members) if members else '(empty)'}")
    lines += [
        "",
        "## File shares (patient-adjacent data outside the EHR)",
        "",
    ]
    for f in snapshot["shares"]["files"]:
        lines.append(f"- `{f['path']}` (sha256:{f['sha256_16']}...)")
    lines += [
        "",
        "## Auth activity",
        "",
        f"- Success: {snapshot['auth']['success']} | Failures: {snapshot['auth']['failures']}"
        f" (window {snapshot['auth']['window_hours']}h)",
    ]
    for reason, n in snapshot["auth"]["failure_reasons"].items():
        lines.append(f"- {reason}: {n}")
    lines += [
        "",
        "## EHR surface",
        "",
        f"- Portal health: {snapshot['ehr']['health']}",
        f"- Public intake submissions (all time): {snapshot['ehr']['intake_submissions']}",
        f"- Scribe transmission events (all time): {snapshot['ehr']['scribe_transmissions']}",
        "",
        "## Endpoint exposure (unmanaged workstations)",
        "",
    ]
    for host in snapshot["endpoints"]["hosts"]:
        if host["local_copies"]:
            for c in host["local_copies"]:
                digest = f"sha256:{c['sha256_16']}..." if c.get("sha256_16") else "hash unavailable (root-only)"
                lines.append(f"- {host['name']} ({host['role']}): `{c['file']}` ({digest})")
        else:
            lines.append(f"- {host['name']} ({host['role']}): no local copies detected")
        if host["activity"]:
            lines.append(f"  - activity events: {json.dumps(host['activity'])}")
    sc = snapshot["supply_chain"]
    lines += [
        "",
        "## Supply chain (Bumblebee scan)",
        "",
        f"- Scanner status: {sc.get('status')}"
        + (f" - {sc.get('detail')}" if sc.get("detail") else ""),
    ]
    for f in sc.get("findings", []):
        lines.append(f"- **[{f['severity'].upper()}]** {f['detail']}")
    lines += [
        "",
        "---",
        "",
        "_Synthetic lab data. No real patient information. Metadata-only evidence._",
    ]
    md_path = outdir / f"{stem}.md"
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ledger_entry = {
        "ts": snapshot["collected_at"],
        "json": str(json_path),
        "md": str(md_path),
        "findings": counts,
        "sha256": hashlib.sha256(json.dumps(snapshot, sort_keys=True).encode()).hexdigest()[:16],
    }
    with LEDGER.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(ledger_entry) + "\n")

    if not args.quiet:
        print(f"snapshot: {json_path}")
        print(f"markdown: {md_path}")
        summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none"
        print(f"findings: {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
