#!/usr/bin/env bash
# Run one evidence pass over the lab and render the review packet.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

python3 evidence/collect_practice_evidence.py "$@"
python3 evidence/render_practice_snapshot.py --latest

echo
echo "Packet: file://$REPO/evidence/latest.html"
