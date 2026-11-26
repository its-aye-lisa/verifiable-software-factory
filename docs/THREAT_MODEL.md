# Untrusted Developer Threat Model & Control Matrix

This document defines the adversary assumptions, trust boundaries, mitigatable controls, and explicit residual risks for the **Aegis Verifiable Software Factory**.

## 1. Trust Boundaries

| Zone | Trust Assumption | Keys Held | Network Access |
| :--- | :--- | :--- | :--- |
| **Developer Workstation** | **UNTRUSTED** (assumed potentially malicious insider or compromised endpoint) | `developer` key only | Arbitrary (outside factory) |
| **Peer Review & Security Audit** | **SEMI-TRUSTED** (independent identities; single compromised reviewer cannot bypass 2PI) | `peer_reviewer` / `security_auditor` | Isolated identity provider |
| **Primary Software Factory** | **HARDENED / EPHEMERAL** (verified by clean-room; compromise is detected) | `factory_builder` | **NONE during build** (`GOPROXY=off`) |
| **Clean-Room Enclave** | **INDEPENDENTLY OPERATED** (separate infra, separate compilers, separate key) | `cleanroom_verifier` | **NONE** |
| **Production Runtime / Gatekeeper** | **FAIL-CLOSED ZERO TRUST** (verifies public `trust-roots.json` only) | Public keys only | Policy-restricted |

## 2. Mitigatable vs. Residual Risks

- **Deterministically Mitigated:**
  - Single-developer self-approval (blocked by cryptographic 2PI with distinct Ed25519 trust roots).
  - Review obfuscation via Unicode BiDi/invisible characters (blocked by lexical hygiene gate).
  - Undeclared build-time dependencies or network downloads (blocked by zero-dep `go.mod` check + `GOPROXY=off` hermetic staging).
  - Unauthorized I/O, shell execution, `unsafe` memory corruption, or hidden `init()` side effects inside the security-critical core (blocked by Go AST capability confinement).
  - Compromised primary build server tampering with compiled binaries (detected deterministically by Independent Clean-Room Rebuilder bit-for-bit SHA-256 verification).
  - Single-compiler backdoor ("Trusting Trust") or semantic logic backdoor in the core policy kernel (detected by independent Clean-Room C reference implementation compiled with both `gcc` and `clang` + exhaustive invariant & differential equivalence testing).
- **Explicit Residual Risks (Requiring Organizational / Runtime Defense-in-Depth):**
  - Simultaneous collusion of all 3 governance roles *and* the independent IV&V specification team.
  - Hardware microcode / CPU backdoors beneath the OS kernel (mitigated in production via heterogeneous CPU architectures + TEE remote attestation).
  - Side-channel leaks or subtle bugs outside the formally specified core package (mitigated by shrinking the trusted core and isolating I/O adapters).
