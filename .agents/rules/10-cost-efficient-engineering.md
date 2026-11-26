---
trigger: glob
globs: "factory/**/*.go, policy/**, .semgrep.yml"
description: "Factory Go control-plane, OPA/Rego policy, and Semgrep authoring guidelines."
---

# Factory Control-Plane & Policy-as-Code Guidelines

1. **Hermetic Hygiene:** Primary and clean-room builds MUST scrub environment variables (`GOPROXY=off`, `GOSUMDB=off`, `CGO_ENABLED=0`, `GOFIPS140=v1.0.0`, `SOURCE_DATE_EPOCH`, `TZ=UTC`, `LC_ALL=C`) and never share build caches between Enclave A and Enclave B.
2. **No Silent Bypasses:** Never add `|| true`, skip flags, or relax severity thresholds in `policy/opa/fedramp_il4.rego`, `.semgrep.yml`, or `factory/internal/attestation/gatekeeper.go`.
3. **Fast Verification:** After editing `factory/`, run `make build` and `./bin/factory --target ../new-vision-gaming fast-check` before running the full `run-all && admit && simulate-attacks` suite.
