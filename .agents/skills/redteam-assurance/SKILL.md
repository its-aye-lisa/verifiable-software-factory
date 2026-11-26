---
name: redteam-assurance
description: Execute and extend the Untrusted Developer Red-Team Attack Simulation suite to maintain autonomous defense parity against insider and supply-chain threats.
---

# Skill: Autonomous Defense & Red-Team Assurance

1. **Run Existing 6-Attack Simulation Suite:**
   - Execute `make simulate-attacks`.
   - Confirm `6 / 6 Untrusted Developer Attacks Detected & Blocked` with explicit cryptographic/clean-room proof for every scenario (`ATK-01` through `ATK-06`).
2. **When Adding a New Security Control:**
   - Pair EVERY new control gate with an executable red-team simulation in `factory/internal/redteam/simulator.go` that clones the repo into `os.MkdirTemp`, injects the exact attack payload, and asserts `Blocked == true`.
   - Never mutate the working repository during attack simulations; always clean up temp directories.
3. **Verify Zero False Negatives:**
   - Ensure `ATK-05` proves BOTH Clean-Room hash mismatch AND Gatekeeper binary-tamper rejection.
   - Ensure `ATK-06` proves a clean-syntax logic backdoor is caught by Clean-Room Go/GCC/Clang differential verification even if unit tests are skipped.
