#!/usr/bin/env bash
set -euo pipefail

echo "=== Aegis Verifiable Software Factory Demo ==="
echo "1) Running 7-Gate Zero-Trust Software Factory Pipeline..."
make factory

echo ""
echo "2) Running 6 Live Untrusted-Developer Red-Team Attack Simulations..."
make simulate-attacks

echo ""
echo "3) Running Fail-Closed Zero-Trust Admission Gatekeeper Check..."
make admit

echo ""
echo "4) Running Self-Attested Binary CLI Verification Probe..."
./dist/aegis-app --eval-cli '{"subject":"release-officer","clearance":3,"subjectCompartments":7,"resourceClassification":3,"resourceCompartments":5,"action":"release","mfaVerified":true,"twoPersonApproved":true,"revoked":false}'
./dist/aegis-app --eval-cli '{"subject":"ghost-admin","clearance":0,"subjectCompartments":0,"resourceClassification":3,"resourceCompartments":1,"action":"release","mfaVerified":false,"twoPersonApproved":false,"revoked":false}'

echo ""
echo "Demo complete! Run 'make serve' to launch the Live Assurance Portal on http://127.0.0.1:8080"
