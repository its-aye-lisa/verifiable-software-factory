---
name: compliance-gate
description: Build verifiable-software-factory and execute full 9-gate FedRAMP Moderate / 20x / DoD IL4 verification, admission, and 6-attack red-team proof against a target repository.
disable-model-invocation: true
---

# Skill: Multi-Target Compliance Gate (`/compliance-gate`)

1. Build the factory CLI cleanly:
   ```bash
   make build
   ```
2. Run the full 9-gate pipeline, Gatekeeper admission, and 6-attack red-team suite against the target repository (default `../new-vision-gaming`):
   ```bash
   ./bin/factory --target ../new-vision-gaming run-all
   ./bin/factory --target ../new-vision-gaming admit
   ./bin/factory --target ../new-vision-gaming simulate-attacks
   ```
3. Confirm `ADMISSION DECISION: ADMITTED` (9/9) and `6 / 6 Untrusted Developer Attacks Detected & Blocked`.
