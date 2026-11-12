#!/usr/bin/env python3
"""collect_practice_evidence.py - dated evidence pass over the Velari practice lab.

Reads the live lab (Samba AD, shares, clinic EHR) and writes one no-PHI
snapshot per run: JSON receipt + Markdown Practice Snapshot + ledger line.

No secrets, no passwords, no patient content - metadata and configuration only.
The implementation lives in the `practice_evidence` package beside this file.
"""

import sys

from practice_evidence.cli import main

if __name__ == "__main__":
    sys.exit(main())
