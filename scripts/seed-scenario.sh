#!/usr/bin/env bash
# Plant the shadow-IT scenario on the front desk endpoint:
# a "billing helper" app the front desk downloaded, pinned to a
# known-compromised npm package. The evidence pass will flag it via the
# package-exposure scan (Bumblebee catalogs), if a scanner is configured.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

docker exec fd-frontdesk-01 mkdir -p /home/staff/Desktop/Downloads/billing-helper

docker exec fd-frontdesk-01 sh -c 'cat > /home/staff/Desktop/Downloads/billing-helper/package.json <<EOF
{
  "name": "billing-helper",
  "version": "1.0.0",
  "description": "SYNTHETIC LAB DATA - front desk downloaded utility for insurance reconciliation",
  "dependencies": { "node-ipc": "10.1.1" }
}
EOF
cat > /home/staff/Desktop/Downloads/billing-helper/package-lock.json <<EOF
{
  "name": "billing-helper",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "billing-helper", "version": "1.0.0", "dependencies": { "node-ipc": "10.1.1" } },
    "node_modules/node-ipc": { "version": "10.1.1", "resolved": "https://registry.npmjs.org/node-ipc/-/node-ipc-10.1.1.tgz" }
  }
}
EOF
chmod -R a+r /home/staff/Desktop/Downloads'

echo "planted: fd-frontdesk-01:/home/staff/Desktop/Downloads/billing-helper"
