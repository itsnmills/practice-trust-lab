"""Shared pytest setup.

The collector predates packaging and is normally run as
``python3 evidence/collect_practice_evidence.py``. Keep that layout importable
for the test suite without requiring an editable install.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "evidence"

for path in (ROOT, EVIDENCE):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
