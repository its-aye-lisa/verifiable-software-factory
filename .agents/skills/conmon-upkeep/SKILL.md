---
name: conmon-upkeep
description: Run Continuous Monitoring (ConMon) regression verification, VRA/OpenVEX validation, and 6-scenario Red-Team simulations from verifiable-software-factory against a target repo.
disable-model-invocation: true
---

# Skill: Factory ConMon & Red-Team Upkeep (`/conmon-upkeep`)

1. Rebuild `bin/factory` (`make build`) and run `go test ./...`.
2. Execute fast-check and all 6 red-team simulations against the target repo:
   ```bash
   ./bin/factory --target ../new-vision-gaming fast-check
   ./bin/factory --target ../new-vision-gaming simulate-attacks
   ```
3. Verify BOD 26-04 / FedRAMP 20x VDR SLA scoring in `factory/internal/vra/vra.go` and OpenVEX schema compliance.
