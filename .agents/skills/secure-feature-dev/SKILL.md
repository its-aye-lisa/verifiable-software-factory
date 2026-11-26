---
name: secure-feature-dev
description: Spec-driven procedure for adding or modifying application features while maintaining AST confinement, exhaustive invariants, and Clean-Room Go/GCC/Clang equivalence.
---

# Skill: Spec-Driven Secure Feature Development

Follow this exact sequence whenever implementing a GitHub Intent Issue or modifying `app/`:

1. **Update Specification First (`spec/app.spec.json`):**
   - Add or update formal invariants and concrete acceptance vectors (including at least one adversarial/backdoor probe vector).
2. **Update Clean-Room Reference Kernel (`cleanroom/c-verifier/`):**
   - Implement the exact spec change in the independent C verifier (`tictactoe_kernel.c` or `policy_kernel.c`) with zero warnings under `-Wall -Wextra -Werror`.
3. **Update Pure Confined Go Kernel (`app/pkg/tictactoe/` or `app/pkg/policyengine/`):**
   - Keep the package pure (no forbidden imports, no `init()`, no mutable globals, no `unsafe`).
   - Update exhaustive state-space / invariant tests in `*_test.go`.
4. **Update HTTP Adapter (`app/cmd/aegis-app/main.go`) if API/UI changed:**
   - Enforce `http.MaxBytesReader`, `DisallowUnknownFields()`, STIG headers, and structured JSON `AU-2` audit logging.
5. **Run Cost-Efficient Verification Ladder:**
   - Step A: `make fast-check` (< 1s)
   - Step B: `make factory && make admit` (verifies 9/9 Zero-Trust gates, FIPS 140-3, Clean-Room bit-for-bit match, Go/GCC/Clang 3-way equivalence, and live DAST)
   - Step C: Summarize spec-to-test traceability in the PR description linking `Closes #<issue>`.
