#!/usr/bin/env python3
"""Conservative no-PHI scanner for generated evidence artifacts.

The project claims that snapshots, Markdown and HTML packets contain no PHI and
no credentials.  This module turns that claim into a testable check.

Usage::

    python evidence/practice_evidence/redaction.py FILE [FILE ...]

Exit codes: ``0`` clean, ``1`` findings, ``2`` could not read a file.

The scanner is intentionally conservative about what it reports, not clever:
see ``docs/SCHEMA.md`` for the documented false-positive and false-negative
limits.  Matched values are masked in output so running the scanner never
reprints the suspected PHI to a terminal or CI log.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

SYNTHETIC_DOMAIN = "millslab.internal"
SYNTHETIC_MRN_PREFIX = "syn-"
SYNTHETIC_PHONE_PREFIX = "55501"  # 555-0100 .. 555-0199

ALLOWED_HASH_KEYS = (
    "sha256_16",
    "sha256_full",
    "sha256",
    "entry_hash",
    "snapshot_sha256",
    "prev",
    "file_hash",
    "content_hash",
    "digest",
)

SSN_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
DOB_RE = re.compile(
    r"(?i)\b(?:dob|d\.o\.b\.?|date[_ -]?of[_ -]?birth|birth[_ -]?date|birthdate)\b"
    r"[\"']?\s*[:=]\s*[\"']?"
    r"((?:19|20)\d{2}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}/\d{1,2}/(?:19|20)\d{2})"
)
NAME_RE = re.compile(
    r"(?i)\b(?:patient[_ -]?name|patient|member[_ -]?name|subscriber[_ -]?name|"
    r"first[_ -]?name|last[_ -]?name|full[_ -]?name|given[_ -]?name|surname)\b"
    r"[\"']?\s*[:=]\s*[\"']?"
    r"([A-Z][A-Za-z'’.-]*(?:\s+[A-Z][A-Za-z'’.-]*){1,3})"
)
PHONE_RE = re.compile(r"(?<![\w.-])(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}(?![\w-])")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
MRN_KEY_RE = re.compile(r"(?i)\bmrn\b[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9][A-Za-z0-9_-]{2,})")
MRN_TOKEN_RE = re.compile(r"\bMRN[-_ ]([0-9][0-9-]{4,})\b")
SECRET_RE = re.compile(
    r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|"
    r"client[_-]?secret|auth[_-]?token|token)\b[\"']?\s*[:=]\s*[\"']?"
    r"([^\s\"'<>]{3,})"
)
BEARER_RE = re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+/-]{20,})")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")
LONG_HEX_RE = re.compile(r"(?<![0-9A-Za-z_])[0-9a-fA-F]{32,}(?![0-9A-Za-z_])")
LONG_B64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
HOME_PATH_RE = re.compile(r"(?<![\w.-])/(?:home|Users)/[A-Za-z0-9._-]+")
ROOT_PATH_RE = re.compile(r"(?<![\w.-])/root(?=[/\s\"']|$)")
WINDOWS_HOME_RE = re.compile(r"(?i)\b[A-Z]:\\Users\\[A-Za-z0-9._-]+")
HASH_PREFIX_RE = re.compile(
    r"(?i)(?:^|[^A-Za-z0-9_])(?:"
    + "|".join(re.escape(key) for key in ALLOWED_HASH_KEYS)
    + r")\s*[\"']?\s*[:=]\s*[\"']?\s*$"
)


@dataclass(frozen=True)
class PhiFinding:
    """One suspected PHI/credential pattern. The excerpt is masked."""

    rule: str
    path: str
    line: int
    column: int
    excerpt: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}:{self.column}: {self.rule}: {self.excerpt}"


def _mask(value: str) -> str:
    value = value.strip()
    if len(value) <= 4:
        return "***"
    return f"{value[:2]}***{value[-2:]}"


def _value(match: re.Match[str]) -> str:
    return match.group(1) if match.re.groups else match.group(0)


def _is_synthetic_email(value: str) -> bool:
    domain = value.rsplit("@", 1)[-1].lower()
    return domain == SYNTHETIC_DOMAIN or domain.endswith("." + SYNTHETIC_DOMAIN)


def _is_synthetic_phone(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    return len(digits) >= 7 and digits[-7:].startswith(SYNTHETIC_PHONE_PREFIX)


def _is_synthetic_mrn(value: str) -> bool:
    return value.lower().startswith(SYNTHETIC_MRN_PREFIX)


def _is_whitelisted_hash(line: str, start: int) -> bool:
    return HASH_PREFIX_RE.search(line[:start]) is not None


def _is_base64_hex_duplicate(value: str) -> bool:
    return re.fullmatch(r"[0-9a-fA-F]+", value) is not None


def _scan_line(line: str, source: str, lineno: int) -> list[PhiFinding]:
    out: list[PhiFinding] = []

    def add(rule: str, match: re.Match[str], value: str) -> None:
        out.append(
            PhiFinding(
                rule=rule,
                path=source,
                line=lineno,
                column=match.start() + 1,
                excerpt=_mask(value),
            )
        )

    for match in SSN_RE.finditer(line):
        add("ssn", match, match.group(0))
    for match in DOB_RE.finditer(line):
        add("dob", match, _value(match))
    for match in NAME_RE.finditer(line):
        add("name", match, _value(match))
    for match in PHONE_RE.finditer(line):
        value = match.group(0)
        if not _is_synthetic_phone(value):
            add("phone", match, value)
    for match in EMAIL_RE.finditer(line):
        value = match.group(0)
        if not _is_synthetic_email(value):
            add("email", match, value)
    for regex in (MRN_KEY_RE, MRN_TOKEN_RE):
        for match in regex.finditer(line):
            value = _value(match)
            if not _is_synthetic_mrn(value):
                add("mrn", match, value)
    for match in SECRET_RE.finditer(line):
        add("secret", match, _value(match))
    for match in BEARER_RE.finditer(line):
        add("secret", match, _value(match))
    for match in PRIVATE_KEY_RE.finditer(line):
        add("private_key", match, match.group(0))
    for match in LONG_HEX_RE.finditer(line):
        if not _is_whitelisted_hash(line, match.start()):
            add("long_token", match, match.group(0))
    for match in LONG_B64_RE.finditer(line):
        value = match.group(0)
        if _is_base64_hex_duplicate(value):
            continue
        if not _is_whitelisted_hash(line, match.start()):
            add("long_token", match, value)
    for match in HOME_PATH_RE.finditer(line):
        add("home_path", match, match.group(0))
    for match in ROOT_PATH_RE.finditer(line):
        add("home_path", match, match.group(0))
    for match in WINDOWS_HOME_RE.finditer(line):
        add("home_path", match, match.group(0))

    seen = set()
    unique = []
    for finding in out:
        key = (finding.rule, finding.line, finding.column)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return sorted(unique, key=lambda f: (f.line, f.column, f.rule))


def scan_text(text: str, source: str = "<text>") -> list[PhiFinding]:
    """Scan text, returning findings ordered by line and column."""
    findings: list[PhiFinding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        findings.extend(_scan_line(line, source, lineno))
    return findings


def scan_file(path: str | Path) -> list[PhiFinding]:
    """Scan one UTF-8 text file (undecodable bytes are replaced, not fatal)."""
    resolved = Path(path)
    text = resolved.read_text(encoding="utf-8", errors="replace")
    return scan_text(text, source=str(resolved))


def scan_paths(paths: list[str | Path]) -> dict[str, list[PhiFinding]]:
    """Scan many files, keyed by path."""
    return {str(path): scan_file(path) for path in paths}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan generated evidence artifacts for PHI or credentials")
    parser.add_argument("paths", nargs="+", help="snapshot JSON, Markdown, or HTML packet files")
    parser.add_argument("--quiet", action="store_true", help="print only findings, no clean summary")
    args = parser.parse_args(argv)

    results: list[tuple[str, list[PhiFinding]]] = []
    for raw in args.paths:
        try:
            results.append((raw, scan_file(raw)))
        except OSError as exc:
            print(f"error: {raw}: {exc}", file=sys.stderr)
            return 2

    total = 0
    for _path, findings in results:
        for finding in findings:
            print(str(finding))
        total += len(findings)
    if total:
        print(f"{total} finding(s) in {len(results)} file(s)", file=sys.stderr)
        return 1
    if not args.quiet:
        print(f"clean: {len(results)} file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
