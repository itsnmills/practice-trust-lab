"""Change monitor: diff the current snapshot against the previous one."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .config import ARTIFACTS
from .schema import migrate

# Findings in these sections carry a count in their detail string; for legacy
# snapshots (no rule_id) a pure (section, detail) key would otherwise report a
# count change as one new plus one resolved finding.
LEGACY_COUNT_SECTIONS = frozenset({"auth", "ehr", "endpoints"})
COUNT_RULES = frozenset(
    {
        "AUTH-FAILURES",
        "EHR-SCRIBE-NO-BAA",
        "EHR-PUBLIC-INTAKE",
        "EP-ADJACENT-EXPORT",
        "EP-CACHED-SHARE-FILE",
    }
)


def legacy_endpoint_copies(snap: dict[str, Any]) -> dict[str, str | None]:
    copies: dict[str, str | None] = {}
    if "endpoints" in snap:
        for host in snap["endpoints"].get("hosts", []):
            for c in host.get("local_copies", []):
                copies[f"{host['name']}:{c['file']}"] = c.get("sha256_16")
        return copies
    for c in snap.get("workstation", {}).get("local_copies", []):
        copies[f"ws-clinical-01:{c['file']}"] = c.get("sha256_16")
    return copies


def previous_snapshot(
    current_path: Path, artifacts: Path | None = None
) -> tuple[Path, dict[str, Any]] | tuple[None, None]:
    candidates = sorted(p for p in (artifacts or ARTIFACTS).glob("*/*.json") if p != current_path)
    for path in reversed(candidates):
        try:
            # migrate() is a version stamp today, but it also rejects documents from an
            # unknown MAJOR version, which must never be diffed as if they were comparable.
            return path, migrate(json.loads(path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError, ValueError):
            continue
    return None, None


def finding_key(finding: dict[str, Any]) -> tuple[str, str]:
    """Stable identity for a finding.

    New snapshots key on the rule id and subject, so rewording the detail or a
    changing count does not look like a different finding. Old snapshots fall
    back to the (section, detail) pair they were born with.
    """
    rule_id = finding.get("rule_id")
    if rule_id:
        return ("rule", f"{rule_id}\x00{finding.get('subject') or ''}")
    return ("legacy", f"{finding.get('section', '')}\x00{finding.get('detail', '')}")


def _numbers(text: str) -> list[int]:
    return [int(n) for n in re.findall(r"\d+", text or "")]


def _detail_delta(before: str, after: str) -> int | None:
    """Difference of the first changed number, when the two details align."""
    old, new = _numbers(before), _numbers(after)
    if not old or len(old) != len(new):
        return None
    for before_n, after_n in zip(old, new, strict=True):
        if before_n != after_n:
            return after_n - before_n
    return None


def _normalized_detail(detail: str) -> str:
    return re.sub(r"\d+", "#", detail or "")


def _change_line(before: dict[str, Any], after: dict[str, Any]) -> str:
    old_sev, new_sev = before.get("severity", "info"), after.get("severity", "info")
    prefix = f"[{new_sev}]" if old_sev == new_sev else f"[{old_sev}->{new_sev}]"
    return f"{prefix} {before.get('detail', '')} -> {after.get('detail', '')}"


def _counter_label(key: tuple[str, str], finding: dict[str, Any]) -> str:
    rule_id = finding.get("rule_id")
    if rule_id:
        subject = finding.get("subject")
        return f"finding:{rule_id}" + (f":{subject}" if subject else "")
    return f"finding:{finding.get('section', 'other')}"


def _matched_changes(
    prev_findings: dict[tuple[str, str], dict[str, Any]],
    cur_findings: dict[tuple[str, str], dict[str, Any]],
    drift: dict[str, Any],
) -> None:
    """Report same-key findings whose detail or severity moved."""
    for key in sorted(set(prev_findings) & set(cur_findings)):
        before, after = prev_findings[key], cur_findings[key]
        if before.get("detail") == after.get("detail") and before.get("severity") == after.get("severity"):
            continue
        drift["findings_changed"].append(_change_line(before, after))
        if after.get("rule_id") in COUNT_RULES or after.get("section") in LEGACY_COUNT_SECTIONS:
            delta = _detail_delta(before.get("detail", ""), after.get("detail", ""))
            if delta is not None:
                drift["counter_deltas"][_counter_label(key, after)] = delta


def _legacy_count_changes(
    new_keys: set[tuple[str, str]],
    resolved_keys: set[tuple[str, str]],
    prev_findings: dict[tuple[str, str], dict[str, Any]],
    cur_findings: dict[tuple[str, str], dict[str, Any]],
    drift: dict[str, Any],
) -> None:
    """Pair old-format count findings (e.g. 12 -> 15 auth failures) as changes."""
    paired_new: set[tuple[str, str]] = set()
    paired_old: set[tuple[str, str]] = set()
    for new_key in sorted(new_keys):
        after = cur_findings[new_key]
        section = after.get("section", "")
        if section not in LEGACY_COUNT_SECTIONS or not _numbers(after.get("detail", "")):
            continue
        wanted = _normalized_detail(after.get("detail", ""))
        for old_key in sorted(resolved_keys - paired_old):
            before = prev_findings[old_key]
            if before.get("section") != section:
                continue
            if _normalized_detail(before.get("detail", "")) != wanted:
                continue
            paired_new.add(new_key)
            paired_old.add(old_key)
            drift["findings_changed"].append(_change_line(before, after))
            delta = _detail_delta(before.get("detail", ""), after.get("detail", ""))
            if delta is not None:
                drift["counter_deltas"][_counter_label(new_key, after)] = delta
            break
    new_keys -= paired_new
    resolved_keys -= paired_old


def compute_drift(prev: dict[str, Any] | None, cur: dict[str, Any]) -> dict[str, Any]:
    drift: dict[str, Any] = {
        "compared_to": prev.get("collected_at") if prev else None,
        "status": "baseline" if not prev else "compared",
        "user_changes": [],
        "group_changes": [],
        "share_changes": [],
        "endpoint_changes": [],
        "findings_new": [],
        "findings_resolved": [],
        "findings_changed": [],
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

    prev_findings = {finding_key(f): f for f in prev.get("findings", [])}
    cur_findings = {finding_key(f): f for f in cur.get("findings", [])}
    new_keys = set(cur_findings) - set(prev_findings)
    resolved_keys = set(prev_findings) - set(cur_findings)

    _matched_changes(prev_findings, cur_findings, drift)
    _legacy_count_changes(new_keys, resolved_keys, prev_findings, cur_findings, drift)

    for key in sorted(new_keys):
        drift["findings_new"].append(f"[{cur_findings[key]['severity']}] {cur_findings[key]['detail']}")
    for key in sorted(resolved_keys):
        drift["findings_resolved"].append(f"[{prev_findings[key]['severity']}] {prev_findings[key]['detail']}")

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
