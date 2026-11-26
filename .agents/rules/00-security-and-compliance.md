---
trigger: always_on
description: Always-active zero-trust invariants for the decoupled verifiable-software-factory repository.
---

# Verifiable Software Factory Security Invariants

1. **Zero App Coupling:** Never place game or business application logic inside `verifiable-software-factory`. All target-repo operations MUST resolve paths dynamically via `--target <dir>` (`TARGET_DIR`).
2. **Fail-Closed By Default:** Gatekeeper (`admit`), 2PI, Clean-Room Rebuilder, Diverse Compiler, DAST, and OPA policies MUST fail closed on missing artifacts, invalid Ed25519 signatures, or digest mismatches.
3. **Every Control Pairs With a Red-Team Proof:** Any new scanner or gate MUST be accompanied by an executable attack simulation in `factory/internal/redteam/simulator.go` that runs in an isolated temp clone (`os.MkdirTemp`) and proves `Blocked == true`.
4. **Zero Third-Party Go Modules:** Keep `verifiable-software-factory/go.mod` at zero third-party Go dependencies (Go 1.24 stdlib only) to maintain a minimal Trusted Computing Base (TCB).
5. **DSSE Envelope Immutability:** Always store signed payloads as raw `[]byte` (base64 in JSON) so pretty-printing never invalidates Ed25519 signatures.
