"""Authentication: parse the DC's audit log for success/failure counts."""

from __future__ import annotations

import re
from typing import Any

from ..config import DC
from ..models import Finding, dump_findings
from ..runner import ERROR_PREFIX, sh

AUTH_RE = re.compile(r"user \[(?P<dom>[^\]]+)\]\\(?:\[)?(?P<user>[^\s\]]+)\]?.*?status \[(?P<status>[^\]]+)\]")
FAILURE_THRESHOLD = 5


def summarize(log_text: str, hours: int) -> dict[str, Any]:
    sect: dict[str, Any] = {
        "window_hours": hours,
        "success": 0,
        "failures": 0,
        "by_user": {},
        "failure_reasons": {},
        "findings": [],
    }
    for line in log_text.splitlines():
        m = AUTH_RE.search(line)
        if not m:
            continue
        stats = sect["by_user"].setdefault(m.group("user"), {"success": 0, "fail": 0})
        status = m.group("status")
        if status == "NT_STATUS_OK":
            sect["success"] += 1
            stats["success"] += 1
        else:
            sect["failures"] += 1
            stats["fail"] += 1
            sect["failure_reasons"][status] = sect["failure_reasons"].get(status, 0) + 1

    findings = []
    if sect["failures"] >= FAILURE_THRESHOLD:
        findings.append(
            Finding(
                "medium",
                f"{sect['failures']} auth failures in last {hours}h; check lockout source",
                rule_id="AUTH-FAILURES",
            )
        )
    findings += [
        Finding(
            "low",
            f"non-password auth failure observed: {reason}",
            rule_id="AUTH-NONPASSWORD-FAILURE",
            subject=reason,
        )
        for reason in sect["failure_reasons"]
        if reason != "NT_STATUS_WRONG_PASSWORD"
    ]
    sect["findings"] = dump_findings(findings)
    return sect


def collect(hours: int = 24) -> dict[str, Any]:
    logs = sh(["docker", "logs", "--since", f"{hours}h", DC], timeout=60)
    if logs.startswith(ERROR_PREFIX):
        empty = summarize("", hours)
        empty["findings"] = dump_findings(
            [Finding("info", f"auth log read failed: {logs}", rule_id="AUTH-LOG-READ-FAILED", subject=DC)]
        )
        return empty
    return summarize(logs, hours)
