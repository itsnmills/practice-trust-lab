"""Practice packet renderer: rules registry, data shaping, sections, HTML."""

from __future__ import annotations

from .data import build_decisions, build_lanes, build_rows
from .render import CSS_PATH, read_css, render
from .rules import (
    DEFAULT_RULE,
    GROUP_ORDER,
    RULES,
    SEVERITY_ORDER,
    SEVERITY_TAG,
    Cite,
    Rule,
    cites_for,
    format_cites,
    rule_for_detail,
    rule_for_finding,
)
from .text import document_id, due_date, esc, extract_item, plural, prose_ts, redact

__all__ = [
    "CSS_PATH",
    "DEFAULT_RULE",
    "GROUP_ORDER",
    "RULES",
    "SEVERITY_ORDER",
    "SEVERITY_TAG",
    "Cite",
    "Rule",
    "build_decisions",
    "build_lanes",
    "build_rows",
    "cites_for",
    "document_id",
    "due_date",
    "esc",
    "extract_item",
    "format_cites",
    "plural",
    "prose_ts",
    "read_css",
    "redact",
    "render",
    "rule_for_detail",
    "rule_for_finding",
]
