# Aegis Reusable Verifiable Software Factory

A decoupled, zero-dependency, **Platform One-comparable Software Factory** that builds, scans, clean-room verifies, DAST-tests, attests, admits, and red-teams **any** target Go application repository (such as [`../new-vision-gaming`](file:///home/antigravity/new-vision-gaming)) under an **Untrusted Developer Threat Model** targeting **FedRAMP Moderate (Rev 5 & 20x)**, **DoD CC SRG IL4**, **NIST SP 800-218 (SSDF)**, **CISA/NSA Memory Safety (2026)**, and **SLSA Build Level 4**.

## Usage Against Any Target App Repository

```bash
# Build the reusable factory CLI binary (bin/factory)
make build

# Run against ../new-vision-gaming (or any other --target <repo>)
make fast-check TARGET=../new-vision-gaming
make factory    TARGET=../new-vision-gaming
make admit      TARGET=../new-vision-gaming
make dast       TARGET=../new-vision-gaming
make simulate-attacks TARGET=../new-vision-gaming
```

## Control Gates Enforced on Every Target Repository
1. **Gate 1 — Two-Person Integrity (2PI):** 3 distinct Ed25519 keys (`developer != peer_reviewer != security_auditor`) bound to canonical source+spec SHA-256.
2. **Gate 2 — SAST / Trojan Source / Memory Safety / AST Confinement:** Blocks Unicode BiDi (`CVE-2021-42574`), secrets, unapproved deps, `unsafe`, `cgo`, `//go:linkname`, `.s` assembly, `init()`, and mutable globals in confined game kernels.
3. **Gate 3 — Hermetic FIPS 140-3 Build (`GOFIPS140=v1.0.0`, `GOPROXY=off`, `CGO_ENABLED=0`) + Exhaustive Invariants.**
4. **Gate 4 — Independent Clean-Room Bit-for-Bit Rebuilder** proving identical SHA-256 across isolated enclaves.
5. **Gate 5 — Clean-Room Diverse Compiler Verification (`Go` vs `GCC` vs `Clang`)** catching logic backdoors & single-compiler backdoors.
6. **Gate 6 — Live 13-Probe DAST & DISA STIG Probe** (FIPS 140-3 active, zero-inline CSP, GoTH HTMX/Tailwind, A2A v1.0, A2UI v1.0, `AU-2` JSON audit logs).
7. **Gate 7 — SLSA v1.0 Provenance, CycloneDX 1.5 SBOM, OpenVEX, SARIF 2.1.0, VRA & FedRAMP/IL4 Evidence.**
8. **Gate 8 — Fail-Closed Zero-Trust Admission Gatekeeper (9/9 cryptographic checks).**
9. **Autonomous Defense — 6 Live Untrusted-Developer Red-Team Simulations (`make simulate-attacks`).**
