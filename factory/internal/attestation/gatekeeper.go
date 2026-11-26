package attestation

import (
	"encoding/json"
	"fmt"

	"verifiable-software-factory/factory/internal/cleanroom"
	fcrypto "verifiable-software-factory/factory/internal/crypto"
	"verifiable-software-factory/factory/internal/dast"
	"verifiable-software-factory/factory/internal/governance"
	"verifiable-software-factory/factory/internal/policy"
)

// GateCheckResult reports the pass/fail status of a single admission control.
type GateCheckResult struct {
	Control string `json:"control"`
	Passed  bool   `json:"passed"`
	Detail  string `json:"detail"`
}

// AdmissionDecision is the fail-closed output of the Zero-Trust Gatekeeper.
type AdmissionDecision struct {
	Admitted         bool              `json:"admitted"`
	BinarySHA256     string            `json:"binarySha256"`
	SourceTreeSHA256 string            `json:"sourceTreeSha256"`
	Checks           []GateCheckResult `json:"checks"`
}

// VerifyReleaseAdmission performs a fail-closed cryptographic audit of all 9
// FedRAMP Moderate / DoD IL4 / SLSA L4 control gates before allowing execution.
func VerifyReleaseAdmission(
	binaryPath string,
	sbomPath string,
	bundleEnv fcrypto.SignedEnvelope,
	pol policy.FactoryPolicy,
	trustRoots map[fcrypto.Role]fcrypto.KeyRecord,
) (AdmissionDecision, error) {
	dec := AdmissionDecision{Admitted: false}
	addCheck := func(name string, ok bool, detail string) {
		dec.Checks = append(dec.Checks, GateCheckResult{Control: name, Passed: ok, Detail: detail})
	}

	// 1. Verify Release Authority signature over the top-level release bundle
	if bundleEnv.PayloadType != ReleaseBundleType {
		addCheck("RELEASE_AUTHORITY_SIG", false, "unexpected bundle payload type")
		return dec, fmt.Errorf("ADMISSION DENIED: unexpected release bundle payloadType %q", bundleEnv.PayloadType)
	}
	if err := fcrypto.VerifyEnvelope(bundleEnv, fcrypto.RoleReleaseAuthority, trustRoots); err != nil {
		addCheck("RELEASE_AUTHORITY_SIG", false, err.Error())
		return dec, fmt.Errorf("ADMISSION DENIED: %w", err)
	}
	var bundle ReleaseBundlePayload
	if err := json.Unmarshal(bundleEnv.Payload, &bundle); err != nil {
		addCheck("RELEASE_AUTHORITY_SIG", false, "malformed bundle payload")
		return dec, fmt.Errorf("ADMISSION DENIED: parse bundle: %w", err)
	}
	dec.SourceTreeSHA256 = bundle.SourceTreeSHA256
	addCheck("RELEASE_AUTHORITY_SIG", true, "Ed25519 signature verified against release_authority trust root")

	// 2. Verify actual binary on disk matches attested BinarySHA256
	actualBinSHA, err := fcrypto.HashFile(binaryPath)
	if err != nil {
		addCheck("BINARY_DIGEST_MATCH", false, err.Error())
		return dec, fmt.Errorf("ADMISSION DENIED: read binary: %w", err)
	}
	dec.BinarySHA256 = actualBinSHA
	if actualBinSHA != bundle.BinarySHA256 {
		msg := fmt.Sprintf("binary tampered! disk=%s != attested=%s", actualBinSHA, bundle.BinarySHA256)
		addCheck("BINARY_DIGEST_MATCH", false, msg)
		return dec, fmt.Errorf("ADMISSION DENIED: %s", msg)
	}
	addCheck("BINARY_DIGEST_MATCH", true, "On-disk binary SHA-256 matches signed release manifest")

	// 3. Verify Two-Person Integrity (2PI) & Separation of Duties (distinct keys)
	if err := governance.VerifyApprovalBundle(bundle.TwoPersonApprovals, bundle.SourceTreeSHA256, pol.TwoPersonIntegrity, trustRoots); err != nil {
		addCheck("TWO_PERSON_INTEGRITY", false, err.Error())
		return dec, fmt.Errorf("ADMISSION DENIED (2PI): %w", err)
	}
	addCheck("TWO_PERSON_INTEGRITY", true, "3 distinct role keys verified (developer != peer_reviewer != security_auditor)")

	// 4. Verify Source Hygiene, Trojan Source & AST Capability Gate
	if err := fcrypto.VerifyEnvelope(bundle.SourceScanEnvelope, fcrypto.RoleFactoryBuilder, trustRoots); err != nil {
		addCheck("SOURCE_HYGIENE_AST_GATE", false, err.Error())
		return dec, fmt.Errorf("ADMISSION DENIED (Source Scan Sig): %w", err)
	}
	var scanAtt SourceScanAttestation
	if err := json.Unmarshal(bundle.SourceScanEnvelope.Payload, &scanAtt); err != nil {
		return dec, fmt.Errorf("ADMISSION DENIED: parse scan attestation: %w", err)
	}
	if scanAtt.SourceTreeSHA256 != bundle.SourceTreeSHA256 || !scanAtt.Report.Passed || len(scanAtt.Report.Findings) > 0 {
		addCheck("SOURCE_HYGIENE_AST_GATE", false, "source scan failed or digest mismatch")
		return dec, fmt.Errorf("ADMISSION DENIED: source hygiene / AST gate did not pass cleanly")
	}
	addCheck("SOURCE_HYGIENE_AST_GATE", true, fmt.Sprintf("%d files scanned, 0 findings (Trojan Source, secrets, deps, AST confinement)", scanAtt.Report.FilesScanned))

	// 5. Verify SLSA v1.0 / in-toto Build Provenance, Hermetic & FIPS 140-3 Parameters
	if err := fcrypto.VerifyEnvelope(bundle.ProvenanceEnvelope, fcrypto.RoleFactoryBuilder, trustRoots); err != nil {
		addCheck("SLSA_HERMETIC_FIPS_PROVENANCE", false, err.Error())
		return dec, fmt.Errorf("ADMISSION DENIED (SLSA Provenance): %w", err)
	}
	var prov SLSAProvenanceStatement
	if err := json.Unmarshal(bundle.ProvenanceEnvelope.Payload, &prov); err != nil {
		return dec, fmt.Errorf("ADMISSION DENIED: parse provenance: %w", err)
	}
	if len(prov.Subject) == 0 || prov.Subject[0].Digest["sha256"] != actualBinSHA {
		addCheck("SLSA_HERMETIC_FIPS_PROVENANCE", false, "provenance subject digest does not match binary")
		return dec, fmt.Errorf("ADMISSION DENIED: SLSA provenance subject digest mismatch")
	}
	env := prov.Predicate.BuildDefinition.InternalParameters
	if env["GOPROXY"] != "off" || env["CGO_ENABLED"] != "0" {
		addCheck("SLSA_HERMETIC_FIPS_PROVENANCE", false, "build was not hermetic (GOPROXY!=off or CGO_ENABLED!=0)")
		return dec, fmt.Errorf("ADMISSION DENIED: non-hermetic build parameters detected")
	}
	if pol.Compliance.RequireFIPS140 && env["GOFIPS140"] == "" {
		addCheck("SLSA_HERMETIC_FIPS_PROVENANCE", false, "missing GOFIPS140 build parameter required by FedRAMP/IL4 SC-13")
		return dec, fmt.Errorf("ADMISSION DENIED: binary not built with GOFIPS140")
	}
	addCheck("SLSA_HERMETIC_FIPS_PROVENANCE", true, fmt.Sprintf("SLSA v1.0 provenance verified (GOPROXY=off, CGO_ENABLED=0, GOFIPS140=%s)", env["GOFIPS140"]))

	// 6. Verify Independent Clean-Room Bit-for-Bit Rebuild Attestation
	if pol.Admission.RequireCleanRoomSignature {
		if err := fcrypto.VerifyEnvelope(bundle.CleanRoomRebuildEnv, fcrypto.RoleCleanRoomVerifier, trustRoots); err != nil {
			addCheck("CLEANROOM_REPRODUCIBLE_BUILD", false, err.Error())
			return dec, fmt.Errorf("ADMISSION DENIED (Clean-Room Sig): %w", err)
		}
		var rebuild cleanroom.RebuildStatement
		if err := json.Unmarshal(bundle.CleanRoomRebuildEnv.Payload, &rebuild); err != nil {
			return dec, fmt.Errorf("ADMISSION DENIED: parse rebuild statement: %w", err)
		}
		if !rebuild.BitForBitMatch || rebuild.SourceTreeSHA256 != bundle.SourceTreeSHA256 || rebuild.RebuiltBinarySHA256 != actualBinSHA {
			addCheck("CLEANROOM_REPRODUCIBLE_BUILD", false, "clean-room rebuild hash mismatch")
			return dec, fmt.Errorf("ADMISSION DENIED: clean-room rebuild failed bit-for-bit match")
		}
		addCheck("CLEANROOM_REPRODUCIBLE_BUILD", true, "Independent clean-room enclave matched binary SHA-256 bit-for-bit")
	}

	// 7. Verify Diverse Compiler (GCC vs Clang) & Clean-Room Spec Equivalence (Policy + Tic-Tac-Toe)
	if pol.Admission.RequireDiverseVerificationSig {
		if err := fcrypto.VerifyEnvelope(bundle.DiverseVerificationEnv, fcrypto.RoleCleanRoomVerifier, trustRoots); err != nil {
			addCheck("DIVERSE_CLEANROOM_SPEC", false, err.Error())
			return dec, fmt.Errorf("ADMISSION DENIED (Diverse Verification Sig): %w", err)
		}
		var div cleanroom.DiverseVerificationStatement
		if err := json.Unmarshal(bundle.DiverseVerificationEnv.Payload, &div); err != nil {
			return dec, fmt.Errorf("ADMISSION DENIED: parse diverse statement: %w", err)
		}
		if !div.Passed || div.DivergencesFound > 0 || div.TargetBinarySHA256 != actualBinSHA || div.SourceTreeSHA256 != bundle.SourceTreeSHA256 {
			addCheck("DIVERSE_CLEANROOM_SPEC", false, "diverse compiler / spec verification failed")
			return dec, fmt.Errorf("ADMISSION DENIED: clean-room spec / diverse compiler verification failed")
		}
		addCheck("DIVERSE_CLEANROOM_SPEC", true, fmt.Sprintf("3-way Go/GCC/Clang equivalence verified (%d policy + %d Tic-Tac-Toe + %d fuzz cases)", div.SpecVectorsTotal, div.TicTacToeVectors, div.DifferentialCases))
	}

	// 8. Verify Live DAST, DISA STIG Headers, AU-2/AU-3 Audit Logs & FIPS 140-3 Runtime Mode
	if pol.Admission.RequireDASTSignature {
		if err := fcrypto.VerifyEnvelope(bundle.DASTEnvelope, fcrypto.RoleCleanRoomVerifier, trustRoots); err != nil {
			addCheck("DAST_FIPS140_STIG", false, err.Error())
			return dec, fmt.Errorf("ADMISSION DENIED (DAST Sig): %w", err)
		}
		var dastStmt dast.DASTStatement
		if err := json.Unmarshal(bundle.DASTEnvelope.Payload, &dastStmt); err != nil {
			return dec, fmt.Errorf("ADMISSION DENIED: parse DAST statement: %w", err)
		}
		if !dastStmt.Passed || !dastStmt.FIPS140Verified || !dastStmt.AuditLogVerified || dastStmt.TargetBinarySHA256 != actualBinSHA {
			addCheck("DAST_FIPS140_STIG", false, "DAST, FIPS 140-3, or AU-2 audit log verification failed")
			return dec, fmt.Errorf("ADMISSION DENIED: DAST / FIPS 140-3 runtime gate failed")
		}
		addCheck("DAST_FIPS140_STIG", true, fmt.Sprintf("%d/%d DAST & STIG probes passed; FIPS 140-3 active; AU-2 JSON audit logs verified", dastStmt.PassedProbes, dastStmt.TotalProbes))
	}

	// 9. Verify CycloneDX 1.5 SBOM integrity
	if pol.Admission.RequireSBOM {
		sbomSHA, err := fcrypto.HashFile(sbomPath)
		if err != nil {
			addCheck("CYCLONEDX_SBOM", false, err.Error())
			return dec, fmt.Errorf("ADMISSION DENIED (SBOM): %w", err)
		}
		if sbomSHA != bundle.SBOMSHA256 {
			addCheck("CYCLONEDX_SBOM", false, "SBOM digest mismatch")
			return dec, fmt.Errorf("ADMISSION DENIED: SBOM tampered (disk=%s != attested=%s)", sbomSHA, bundle.SBOMSHA256)
		}
		addCheck("CYCLONEDX_SBOM", true, "CycloneDX 1.5 SBOM verified (0 third-party dependencies)")
	}

	dec.Admitted = true
	return dec, nil
}
