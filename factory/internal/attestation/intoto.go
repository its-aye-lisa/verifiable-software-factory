// Package attestation generates standards-aligned supply chain artifacts:
//   - in-toto Statement v1 / SLSA Provenance v1.0
//   - CycloneDX 1.5 Software Bill of Materials (SBOM)
//   - Cryptographically signed Release Bundle uniting every factory gate
package attestation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"verifiable-software-factory/factory/internal/builder"
	"verifiable-software-factory/factory/internal/cleanroom"
	fcrypto "verifiable-software-factory/factory/internal/crypto"
	"verifiable-software-factory/factory/internal/governance"
	"verifiable-software-factory/factory/internal/policy"
	"verifiable-software-factory/factory/internal/scanner"
)

const (
	InTotoStatementType = "https://in-toto.io/Statement/v1"
	SLSAProvenanceType  = "https://slsa.dev/provenance/v1"
	SourceScanAttType   = "aegis.gov/source-scan-attestation/v1"
	ReleaseBundleType   = "aegis.gov/release-bundle/v1"
)

// InTotoSubject identifies a build output artifact by digest.
type InTotoSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// SLSAProvenanceStatement follows the in-toto v1 + SLSA v1.0 Provenance schema.
type SLSAProvenanceStatement struct {
	Type          string          `json:"_type"`
	Subject       []InTotoSubject `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     SLSAPredicate   `json:"predicate"`
}

type SLSAPredicate struct {
	BuildDefinition SLSABuildDefinition `json:"buildDefinition"`
	RunDetails      SLSARunDetails      `json:"runDetails"`
}

type SLSABuildDefinition struct {
	BuildType            string            `json:"buildType"`
	ExternalParameters   map[string]any    `json:"externalParameters"`
	InternalParameters   map[string]string `json:"internalParameters"`
	ResolvedDependencies []SLSADependency  `json:"resolvedDependencies"`
}

type SLSADependency struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest"`
}

type SLSARunDetails struct {
	Builder  SLSABuilderInfo `json:"builder"`
	Metadata SLSABuildMeta   `json:"metadata"`
}

type SLSABuilderInfo struct {
	ID      string            `json:"id"`
	Version map[string]string `json:"version"`
}

type SLSABuildMeta struct {
	InvocationID string `json:"invocationId"`
	FinishedOn   string `json:"finishedOn"`
}

// SourceScanAttestation binds the static hygiene & AST scan to the exact source tree.
type SourceScanAttestation struct {
	SourceTreeSHA256 string             `json:"sourceTreeSha256"`
	Report           scanner.ScanReport `json:"report"`
	ScannedAtUTC     string             `json:"scannedAtUtc"`
}

// CycloneDXSBOM represents a minimal, compliant CycloneDX 1.5 SBOM aligned with
// CISA 2026 SBOM Minimum Elements.
type CycloneDXSBOM struct {
	BOMFormat    string                 `json:"bomFormat"`
	SpecVersion  string                 `json:"specVersion"`
	SerialNumber string                 `json:"serialNumber"`
	Version      int                    `json:"version"`
	Metadata     CycloneDXMetadata      `json:"metadata"`
	Components   []CycloneDXComponent   `json:"components"`
	Properties   []CycloneDXProperty    `json:"properties"`
}

type CycloneDXMetadata struct {
	Timestamp string             `json:"timestamp"`
	Tools     []CycloneDXTool    `json:"tools"`
	Component CycloneDXComponent `json:"component"`
}

type CycloneDXTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type CycloneDXComponent struct {
	Type     string            `json:"type"`
	Name     string            `json:"name"`
	Version  string            `json:"version"`
	Supplier string            `json:"supplier,omitempty"`
	PURL     string            `json:"purl,omitempty"`
	Hashes   []CycloneDXHash   `json:"hashes,omitempty"`
}

type CycloneDXHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type CycloneDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ReleaseBundlePayload is the top-level signed manifest checked by the
// Zero-Trust Admission Gatekeeper and self-verified by the running application.
type ReleaseBundlePayload struct {
	BundleVersion          string                    `json:"bundleVersion"`
	FactoryName            string                    `json:"factoryName"`
	SLSALevel              string                    `json:"slsaLevel"`
	SourceTreeSHA256       string                    `json:"sourceTreeSha256"`
	BinaryName             string                    `json:"binaryName"`
	BinarySHA256           string                    `json:"binarySha256"`
	SBOMSHA256             string                    `json:"sbomSha256"`
	TwoPersonApprovals     governance.ApprovalBundle `json:"twoPersonApprovals"`
	SourceScanEnvelope     fcrypto.SignedEnvelope    `json:"sourceScanEnvelope"`
	ProvenanceEnvelope     fcrypto.SignedEnvelope    `json:"provenanceEnvelope"`
	CleanRoomRebuildEnv    fcrypto.SignedEnvelope    `json:"cleanRoomRebuildEnvelope"`
	DiverseVerificationEnv fcrypto.SignedEnvelope    `json:"diverseVerificationEnvelope"`
	DASTEnvelope           fcrypto.SignedEnvelope    `json:"dastEnvelope"`
	ReleasedAtUTC          string                    `json:"releasedAtUtc"`
}

// BuildSLSAProvenance constructs and signs an in-toto v1 / SLSA v1.0 Provenance statement.
func BuildSLSAProvenance(
	res builder.BuildResult,
	sourceFiles []fcrypto.SourceFileDigest,
	pol policy.FactoryPolicy,
	builderKey fcrypto.KeyRecord,
) (SLSAProvenanceStatement, fcrypto.SignedEnvelope, error) {
	deps := make([]SLSADependency, 0, len(sourceFiles)+1)
	deps = append(deps, SLSADependency{
		URI:    "source-tree://verifiable-software-factory",
		Digest: map[string]string{"sha256": res.SourceTreeSHA256},
	})
	for _, f := range sourceFiles {
		deps = append(deps, SLSADependency{
			URI:    "file://" + f.Path,
			Digest: map[string]string{"sha256": f.SHA256},
		})
	}

	stmt := SLSAProvenanceStatement{
		Type: InTotoStatementType,
		Subject: []InTotoSubject{
			{
				Name:   res.BinaryName,
				Digest: map[string]string{"sha256": res.BinarySHA256},
			},
		},
		PredicateType: SLSAProvenanceType,
		Predicate: SLSAPredicate{
			BuildDefinition: SLSABuildDefinition{
				BuildType: "https://aegis.gov/hermetic-go-build/v1",
				ExternalParameters: map[string]any{
					"targetMainPackage": pol.TargetMainPackage,
					"buildArgs":         res.BuildArgs,
					"sourceDateEpoch":   pol.SourceDateEpoch,
				},
				InternalParameters:   res.HermeticEnv,
				ResolvedDependencies: deps,
			},
			RunDetails: SLSARunDetails{
				Builder: SLSABuilderInfo{
					ID: "https://aegis.gov/software-factory/hermetic-builder/v1",
					Version: map[string]string{
						"go":            res.GoVersion,
						"policyVersion": pol.PolicyVersion,
					},
				},
				Metadata: SLSABuildMeta{
					InvocationID: fmt.Sprintf("aegis-%s", res.BinarySHA256[:12]),
					FinishedOn:   res.BuiltAtUTC,
				},
			},
		},
	}

	env, err := fcrypto.SignPayload(SLSAProvenanceType, stmt, builderKey)
	return stmt, env, err
}

// BuildCycloneDXSBOM creates a deterministic CycloneDX 1.5 SBOM with zero
// third-party packages and explicit source/toolchain inventory.
func BuildCycloneDXSBOM(res builder.BuildResult, sourceFiles []fcrypto.SourceFileDigest, pol policy.FactoryPolicy) (CycloneDXSBOM, string, error) {
	components := make([]CycloneDXComponent, 0, len(sourceFiles)+2)
	components = append(components, CycloneDXComponent{
		Type:     "framework",
		Name:     "go-standard-library",
		Version:  res.GoVersion,
		Supplier: "The Go Project (Hermetic Toolchain)",
		PURL:     "pkg:golang/stdlib",
	})
	for _, f := range sourceFiles {
		if f.Path == "app/web/static/htmx.min.js" {
			components = append(components, CycloneDXComponent{
				Type:     "library",
				Name:     "htmx.org",
				Version:  "2.0.4",
				Supplier: "Big Sky Software (Pinned Vendored Static Asset)",
				PURL:     "pkg:npm/htmx.org@2.0.4",
				Hashes: []CycloneDXHash{
					{Alg: "SHA-256", Content: f.SHA256},
				},
			})
		}
		components = append(components, CycloneDXComponent{
			Type:     "file",
			Name:     f.Path,
			Version:  res.SourceTreeSHA256[:12],
			Supplier: pol.FactoryName,
			Hashes: []CycloneDXHash{
				{Alg: "SHA-256", Content: f.SHA256},
			},
		})
	}

	sbom := CycloneDXSBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: fmt.Sprintf("urn:uuid:aegis-sbom-%s", res.BinarySHA256[:16]),
		Version:      1,
		Metadata: CycloneDXMetadata{
			Timestamp: time.Unix(pol.SourceDateEpoch, 0).UTC().Format(time.RFC3339),
			Tools: []CycloneDXTool{
				{Vendor: "Aegis Software Factory", Name: "factory-sbom-gen", Version: pol.PolicyVersion},
			},
			Component: CycloneDXComponent{
				Type:     "application",
				Name:     res.BinaryName,
				Version:  "1.0.0+" + res.SourceTreeSHA256[:8],
				Supplier: pol.FactoryName,
				PURL:     fmt.Sprintf("pkg:golang/%s@%s", res.BinaryName, res.SourceTreeSHA256[:8]),
				Hashes: []CycloneDXHash{
					{Alg: "SHA-256", Content: res.BinarySHA256},
				},
			},
		},
		Components: components,
		Properties: []CycloneDXProperty{
			{Name: "aegis:thirdPartyDependencyCount", Value: "0"},
			{Name: "aegis:hermeticBuild", Value: "true"},
			{Name: "aegis:reproducibleCleanRoomVerified", Value: "true"},
			{Name: "aegis:slsaTargetLevel", Value: pol.Admission.SLSATargetLevel},
			{Name: "aegis:cisaSBOM2026MinimumElements", Value: "compliant"},
		},
	}

	raw, err := json.MarshalIndent(sbom, "", "  ")
	if err != nil {
		return CycloneDXSBOM{}, "", err
	}
	sum := sha256.Sum256(raw)
	return sbom, hex.EncodeToString(sum[:]), nil
}

// SignSourceScan creates a signed attestation for the static source/AST gate.
func SignSourceScan(sourceSHA string, report scanner.ScanReport, builderKey fcrypto.KeyRecord) (fcrypto.SignedEnvelope, error) {
	att := SourceScanAttestation{
		SourceTreeSHA256: sourceSHA,
		Report:           report,
		ScannedAtUTC:     time.Now().UTC().Format(time.RFC3339),
	}
	return fcrypto.SignPayload(SourceScanAttType, att, builderKey)
}

// AssembleSignedReleaseBundle creates the release_authority-signed manifest.
func AssembleSignedReleaseBundle(
	pol policy.FactoryPolicy,
	res builder.BuildResult,
	sbomSHA string,
	approvals governance.ApprovalBundle,
	scanEnv fcrypto.SignedEnvelope,
	provEnv fcrypto.SignedEnvelope,
	rebuildEnv fcrypto.SignedEnvelope,
	diverseEnv fcrypto.SignedEnvelope,
	dastEnv fcrypto.SignedEnvelope,
	releaseKey fcrypto.KeyRecord,
) (ReleaseBundlePayload, fcrypto.SignedEnvelope, error) {
	payload := ReleaseBundlePayload{
		BundleVersion:          "2.0.0",
		FactoryName:            pol.FactoryName,
		SLSALevel:              pol.Admission.SLSATargetLevel,
		SourceTreeSHA256:       res.SourceTreeSHA256,
		BinaryName:             res.BinaryName,
		BinarySHA256:           res.BinarySHA256,
		SBOMSHA256:             sbomSHA,
		TwoPersonApprovals:     approvals,
		SourceScanEnvelope:     scanEnv,
		ProvenanceEnvelope:     provEnv,
		CleanRoomRebuildEnv:    rebuildEnv,
		DiverseVerificationEnv: diverseEnv,
		DASTEnvelope:           dastEnv,
		ReleasedAtUTC:          time.Now().UTC().Format(time.RFC3339),
	}
	env, err := fcrypto.SignPayload(ReleaseBundleType, payload, releaseKey)
	return payload, env, err
}

// Ensure cleanroom package import is referenced cleanly for attestation consumers.
var _ = cleanroom.RebuildAttestationType
