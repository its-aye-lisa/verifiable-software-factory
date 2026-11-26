---
name: dev-cycle
description: Fast iteration cycle for developing and validating new gates, scanners, or OPA rules in verifiable-software-factory against a decoupled target application repository.
---

# Skill: Factory Gate Development Cycle (`/dev-cycle`)

1. Implement or refine the gate in `factory/internal/...` or `policy/opa/fedramp_il4.rego` with zero external Go dependencies.
2. Pair any new security control with a matching adversarial attack scenario in `factory/internal/redteam/simulator.go`.
3. Build and test:
   ```bash
   make build && go test ./...
   ./bin/factory --target ../new-vision-gaming fast-check
   ```
4. Once green, run full end-to-end verification (`run-all`, `admit`, `simulate-attacks`) against `../new-vision-gaming`.
