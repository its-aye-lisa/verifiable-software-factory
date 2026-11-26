# Government Control Traceability Matrix

Maps U.S. government software supply chain & assurance frameworks directly to executable controls in the **Aegis Verifiable Software Factory**.

| Framework & Practice | Requirement Summary | Implemented Artifact / Gate | Verification Proof |
| :--- | :--- | :--- | :--- |
| **NIST SP 800-218 PO.3** | Implement supporting toolchains to automate security verification | `factory/cmd/factory/main.go`, `policy/factory-policy.json` | Single declarative policy governs all 7 gates |
| **NIST SP 800-218 PS.1** | Protect all forms of code from unauthorized access & tampering | `factory/internal/governance/tpi.go`, `factory/internal/crypto/keys.go` | 3-role Ed25519 2PI bound to source tree SHA-256 (`ATK-01`) |
| **NIST SP 800-218 PS.2** | Provide a mechanism for verifying software release integrity | `factory/internal/attestation/intoto.go`, `gatekeeper.go` | Signed SLSA v1.0 provenance, CycloneDX 1.5 SBOM, fail-closed Gatekeeper |
| **NIST SP 800-218 PS.3** | Archive and protect each software release | `dist/release-bundle.signed.json`, `app/cmd/aegis-app/main.go` | Startup self-attestation hashes `/proc/self/exe` against signed bundle |
| **NIST SP 800-218 PW.4** | Reuse vetted well-secured software components | `factory/internal/scanner/scanner.go` (`checkGoMod`) | Zero-third-party-dependency enforcement (`ATK-04`) |
| **NIST SP 800-218 PW.7 / PW.8** | Review and analyze human-readable code & test executables | `scanner.go`, `app/pkg/policyengine/engine_test.go`, `diverse.go` | Trojan Source + AST confinement (`ATK-02`, `ATK-03`), exhaustive invariants, 3-way Go/GCC/Clang check (`ATK-06`) |
| **OMB M-26-05 (Jan 2026)** | Risk-based assurance with verifiable artifacts & SBOMs | `dist/sbom.cdx.json`, `dist/provenance.slsa.json` | Machine-verifiable CycloneDX 1.5 + SLSA v1.0 evidence package |
| **CISA 2026 SBOM Minimum Elements** | Machine-readable component & hash inventory | `factory/internal/attestation/intoto.go` (`BuildCycloneDXSBOM`) | Includes supplier, version, PURL, SHA-256 hashes, and tool metadata |
| **DoD cATO SSSC (Platform/Process/People)** | Continuous evidence of supply chain provenance & SoD | `dist/admission-report.json`, `.factory-state/keys/trust-roots.json` | Every build produces fresh cryptographic evidence across all 8 controls |
| **SLSA v1.2 Build L3–L4** | Isolated, hermetic, reproducible builds with non-falsifiable provenance | `builder/hermetic.go`, `cleanroom/rebuilder.go` | Networkless `GOPROXY=off` build + independent Clean-Room bit-for-bit SHA-256 match (`ATK-05`) |
| **Wheeler DDC / Clean-Room IV&V** | Mitigate single-compiler backdoors & subtle semantic backdoors | `cleanroom/c-verifier/policy_kernel.c`, `cleanroom/diverse.go` | Independent clean-room C spec compiled with both `gcc` and `clang` vs Go binary (`ATK-06`) |
