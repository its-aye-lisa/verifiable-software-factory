# AGENTS.md — Verifiable Software Factory (Antigravity 2.0 Contract)

Reusable, **Platform One-comparable, Untrusted-Developer-Resilient Software Factory** targeting **FedRAMP Moderate (Rev 5 & 20x KSIs)**, **DoD CC SRG IL4**, **NIST SP 800-218 (SSDF)**, and **SLSA Build Level 4**.

This repository contains **zero application business logic**. It builds, verifies, attests, and admits external target repositories (such as [`../new-vision-gaming`](../new-vision-gaming)) via `--target <dir>`.

---

## 1. Repository Map (Read Only What You Need)

| Path | Trust Zone | Purpose |
| :--- | :--- | :--- |
| `factory/cmd/factory/main.go` | Control Plane CLI | Multi-target CLI (`--target <app-repo>` / `TARGET_DIR`) running `init-keys`, `fast-check`, `run-all`, `dast`, `admit`, `simulate-attacks`. |
| `factory/internal/crypto/` | Cryptographic Root | Role-isolated Ed25519 keys (6 roles), DSSE-style base64 `SignedEnvelope`, deterministic `HashSourceTree`. |
| `factory/internal/scanner/` | SAST & Confinement | Trojan Source BiDi (`CVE-2021-42574`), secrets, zero-dep `go.mod`, AST capability confinement, memory-safety (`unsafe`/`C`), `.s`/`.syso`, `//go:linkname`. |
| `factory/internal/governance/` | 2PI Engine | Cryptographic Two-Person Integrity (`developer != peer_reviewer != security_auditor`). |
| `factory/internal/builder/` | Hermetic Builder | Cold-cache scrubbed env (`GOPROXY=off`, `CGO_ENABLED=0`, `GOFIPS140=v1.0.0`, `SOURCE_DATE_EPOCH`). |
| `factory/internal/cleanroom/` | Independent IV&V | Bit-for-bit Clean-Room Rebuilder + Diverse Compiler (`Go` vs `GCC` vs `Clang`) equivalence verifier. |
| `factory/internal/dast/` | Live Runtime DAST | 13-probe FIPS 140-3, STIG CSP/headers, GoTH/HTMX, A2A v1.0, A2UI v1.0, AU-2 JSON audit verifier. |
| `factory/internal/attestation/` | SLSA & Gatekeeper | SLSA v1.0 provenance, CycloneDX 1.5 SBOM, 9-check Fail-Closed Admission Gatekeeper. |
| `factory/internal/compliance/` & `vra/` | FedRAMP / BOD 26-04 | FedRAMP Moderate / 20x / IL4 evidence JSON, SARIF 2.1.0, OpenVEX v0.2.0, VRA scoring. |
| `factory/internal/redteam/` | Autonomous Defense | 6 executable untrusted-developer attack simulations (`ATK-01`..`ATK-06`). |
| `policy/opa/` & `.semgrep.yml` | Policy-as-Code | OPA/Rego (`fedramp_il4.rego`) and custom Semgrep rules. |
| `.antigravity-plugin/plugin.json` | Antigravity 2.0 Plugin | Makes this factory installable across workspaces via `agy plugin install`. |

---

## 2. Custom Subagents & Verification Ladder

- **Custom Subagents (`.agents/agents/`):**
  - `supply-chain-auditor` (`pro`, `sandbox`, read-only) -> audits SLSA/SBOM/OpenVEX/SARIF/OPA/FedRAMP 20x controls.
  - `redteam-adversary` (`pro`, `sandbox`) -> develops and validates adversarial `ATK-XX` attack simulations.
- **Verification Commands:**
  1. `make build` (`< 2s`) -> compiles `bin/factory` with `CGO_ENABLED=0`.
  2. `go test ./...` (`< 2s`) -> unit-tests factory packages.
  3. `./bin/factory --target ../new-vision-gaming fast-check` (`< 1s`) -> preflight against reference app.
  4. `./bin/factory --target ../new-vision-gaming run-all && ./bin/factory --target ../new-vision-gaming admit && ./bin/factory --target ../new-vision-gaming simulate-attacks` -> full 9-gate + 6-attack proof.
