// Package policy defines the declarative Software Factory policy schema and
// Clean-Room formal specification vector schema.
package policy

import (
	"encoding/json"
	"fmt"
	"os"
)

// FactoryPolicy governs every mandatory control gate in the Software Factory.
type FactoryPolicy struct {
	PolicyVersion             string            `json:"policyVersion"`
	FactoryName               string            `json:"factoryName"`
	TargetBinaryName          string            `json:"targetBinaryName"`
	TargetMainPackage         string            `json:"targetMainPackage"`
	SourceDateEpoch           int64             `json:"sourceDateEpoch"`
	RequireZeroThirdPartyDeps bool              `json:"requireZeroThirdPartyDependencies"`
	AllowedExternalModules    []string          `json:"allowedExternalModules"`
	TwoPersonIntegrity        TPIPolicy         `json:"twoPersonIntegrity"`
	ConfinedPackages          []ConfinedPackage `json:"confinedPackages"`
	GlobalForbiddenConstructs GlobalForbidden   `json:"globalForbiddenConstructs"`
	CleanRoom                 CleanRoomPolicy   `json:"cleanRoom"`
	Compliance                CompliancePolicy  `json:"compliance"`
	Admission                 AdmissionPolicy   `json:"admission"`
}

type TPIPolicy struct {
	RequiredRoles       []string `json:"requiredRoles"`
	RequireDistinctKeys bool     `json:"requireDistinctKeys"`
}

type ConfinedPackage struct {
	PathPrefix              string   `json:"pathPrefix"`
	AllowedImports          []string `json:"allowedImports"`
	ForbidInitFunctions     bool     `json:"forbidInitFunctions"`
	ForbidGlobalMutableVars bool     `json:"forbidGlobalMutableVars"`
	ForbidUnsafe            bool     `json:"forbidUnsafe"`
	ForbidCgo               bool     `json:"forbidCgo"`
}

type GlobalForbidden struct {
	ForbidUnicodeBidi      bool `json:"forbidUnicodeBidi"`
	ForbidZeroWidthChars   bool `json:"forbidZeroWidthChars"`
	ForbidHardcodedSecrets bool `json:"forbidHardcodedSecrets"`
	ForbidUnsafeAcrossApp  bool `json:"forbidUnsafeAcrossApp"`
}

type CleanRoomPolicy struct {
	RequireBitForBitReproducibleBuild bool     `json:"requireBitForBitReproducibleBuild"`
	RequireDiverseCompilerCheck       bool     `json:"requireDiverseCompilerCheck"`
	RequiredCompilers                 []string `json:"requiredCompilers"`
	SpecVectorsPath                   string   `json:"specVectorsPath"`
	CReferenceSource                  string   `json:"cReferenceSource"`
	AppSpecPath                       string   `json:"appSpecPath"`
	TicTacToeCReferenceSource         string   `json:"tictactoeCReferenceSource"`
}

type CompliancePolicy struct {
	TargetBaselines  []string `json:"targetBaselines"`
	RequireFIPS140   bool     `json:"requireFIPS140"`
	GoFIPS140Version string   `json:"goFIPS140Version"`
	RequireDAST      bool     `json:"requireDAST"`
	RequireSARIF     bool     `json:"requireSARIF"`
	RequireOpenVEX   bool     `json:"requireOpenVEX"`
	VulnSLADays      VulnSLAs `json:"vulnSLADays"`
}

type VulnSLAs struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Moderate int `json:"moderate"`
	Low      int `json:"low"`
}

type AdmissionPolicy struct {
	SLSATargetLevel               string `json:"slsaTargetLevel"`
	FailClosed                    bool   `json:"failClosed"`
	RequireCleanRoomSignature     bool   `json:"requireCleanRoomSignature"`
	RequireDiverseVerificationSig bool   `json:"requireDiverseVerificationSignature"`
	RequireDASTSignature          bool   `json:"requireDASTSignature"`
	RequireSBOM                   bool   `json:"requireSBOM"`
}

// AppSpec represents the canonical Spec-Driven single source of truth (spec/app.spec.json).
type AppSpec struct {
	SpecVersion         string   `json:"specVersion"`
	AppName             string   `json:"appName"`
	Description         string   `json:"description"`
	ComplianceBaselines []string `json:"complianceBaselines"`
	GameSpec            GameSpec `json:"gameSpec"`
}

type GameSpec struct {
	BoardSize  int              `json:"boardSize"`
	Invariants []string         `json:"invariants"`
	Vectors    []TTTVector      `json:"vectors"`
}

type TTTVector struct {
	ID               string      `json:"id"`
	Description      string      `json:"description"`
	Input            TTTInput    `json:"input"`
	ExpectedValid    bool        `json:"expectedValid"`
	ExpectedBoard    string      `json:"expectedBoard"`
	ExpectedStatus   string      `json:"expectedStatus"`
	ExpectedWinner   string      `json:"expectedWinner"`
	ExpectedNextTurn string      `json:"expectedNextTurn"`
	ExpectedReason   string      `json:"expectedReason"`
}

type TTTInput struct {
	Board    string `json:"board"`
	Player   string `json:"player"`
	Position int    `json:"position"`
	Actor    string `json:"actor"`
}

// SpecSuite holds the Clean-Room formal specification and test vectors.
type SpecSuite struct {
	SpecVersion string       `json:"specVersion"`
	AuthoredBy  string       `json:"authoredBy"`
	Invariants  []string     `json:"invariants"`
	Vectors     []SpecVector `json:"vectors"`
}

type SpecVector struct {
	ID                 string         `json:"id"`
	Description        string         `json:"description"`
	Input              SpecVectorData `json:"input"`
	ExpectedAllow      bool           `json:"expectedAllow"`
	ExpectedReasonCode string         `json:"expectedReasonCode"`
}

type SpecVectorData struct {
	Subject                string `json:"subject"`
	Clearance              int    `json:"clearance"`
	SubjectCompartments    uint32 `json:"subjectCompartments"`
	ResourceClassification int    `json:"resourceClassification"`
	ResourceCompartments   uint32 `json:"resourceCompartments"`
	Action                 string `json:"action"`
	MFAVerified            bool   `json:"mfaVerified"`
	TwoPersonApproved      bool   `json:"twoPersonApproved"`
	Revoked                bool   `json:"revoked"`
}

// LoadFactoryPolicy reads and parses factory-policy.json.
func LoadFactoryPolicy(path string) (FactoryPolicy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return FactoryPolicy{}, fmt.Errorf("read policy %s: %w", path, err)
	}
	var p FactoryPolicy
	if err := json.Unmarshal(raw, &p); err != nil {
		return FactoryPolicy{}, fmt.Errorf("parse policy %s: %w", path, err)
	}
	return p, nil
}

// LoadSpecSuite reads and parses spec-vectors.json.
func LoadSpecSuite(path string) (SpecSuite, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return SpecSuite{}, fmt.Errorf("read spec vectors %s: %w", path, err)
	}
	var s SpecSuite
	if err := json.Unmarshal(raw, &s); err != nil {
		return SpecSuite{}, fmt.Errorf("parse spec vectors %s: %w", path, err)
	}
	return s, nil
}

// LoadAppSpec reads and parses spec/app.spec.json.
func LoadAppSpec(path string) (AppSpec, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return AppSpec{}, fmt.Errorf("read app spec %s: %w", path, err)
	}
	var s AppSpec
	if err := json.Unmarshal(raw, &s); err != nil {
		return AppSpec{}, fmt.Errorf("parse app spec %s: %w", path, err)
	}
	return s, nil
}
