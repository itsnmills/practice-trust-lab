"""Pytest fixtures for the no-Docker end-to-end collector tests."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from practice_evidence.sections import identity  # noqa: E402
from support import FakeLab, _FrozenDateTime  # noqa: E402


@pytest.fixture(autouse=True)
def frozen_identity_clock(monkeypatch):
    """Keep identity staleness deterministic regardless of the wall clock."""
    monkeypatch.setattr(identity, "datetime", _FrozenDateTime)


@pytest.fixture
def lab(tmp_path, monkeypatch) -> FakeLab:
    return FakeLab(tmp_path, monkeypatch)
