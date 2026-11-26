// Package cleanroom implements Independent Clean-Room Verification controls:
//   1. Independent Clean-Room Rebuilder (rebuilder.go): rebuilds the release
//      binary in a completely separate clean-room directory/environment and
//      verifies bit-for-bit SHA-256 identity against the primary factory build.
//   2. Diverse Compiler & Clean-Room Spec Verifier (diverse.go): compiles an
//      independent C reference kernel using BOTH gcc and clang, then verifies
//      3-way behavioral equivalence against the compiled Go release binary.
package cleanroom

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"verifiable-software-factory/factory/internal/builder"
	fcrypto "verifiable-software-factory/factory/internal/crypto"
	"verifiable-software-factory/factory/internal/policy"
)

const RebuildAttestationType = "aegis.gov/cleanroom-rebuild-attestation/v1"

// RebuildStatement is signed by cleanroom_verifier to prove bit-for-bit
// reproducibility independent of the primary software factory builder.
type RebuildStatement struct {
	SourceTreeSHA256    string `json:"sourceTreeSha256"`
	PrimaryBinarySHA256 string `json:"primaryBinarySha256"`
	RebuiltBinarySHA256 string `json:"rebuiltBinarySha256"`
	BitForBitMatch      bool   `json:"bitForBitMatch"`
	CleanRoomEnclaveID  string `json:"cleanRoomEnclaveId"`
	GoVersion           string `json:"goVersion"`
	VerifiedAtUTC       string `json:"verifiedAtUtc"`
}

// VerifyReproducibleRebuild performs a clean-room rebuild in a distinct
// ephemeral directory and compares its SHA-256 bit-for-bit against primaryBinaryPath.
func VerifyReproducibleRebuild(
	repoRoot string,
	primaryBinaryPath string,
	pol policy.FactoryPolicy,
	cleanRoomKey fcrypto.KeyRecord,
) (RebuildStatement, fcrypto.SignedEnvelope, error) {
	primarySHA, err := fcrypto.HashFile(primaryBinaryPath)
	if err != nil {
		return RebuildStatement{}, fcrypto.SignedEnvelope{}, fmt.Errorf("hash primary binary: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "aegis-cleanroom-enclave-*")
	if err != nil {
		return RebuildStatement{}, fcrypto.SignedEnvelope{}, err
	}
	defer os.RemoveAll(tmpDir)

	rebuiltPath := filepath.Join(tmpDir, pol.TargetBinaryName+"-cleanroom")
	res, err := builder.HermeticBuild(repoRoot, rebuiltPath, "cleanroom-enclave", pol, false)
	if err != nil {
		return RebuildStatement{}, fcrypto.SignedEnvelope{}, fmt.Errorf("clean-room rebuild failed: %w", err)
	}

	matched := res.BinarySHA256 == primarySHA
	stmt := RebuildStatement{
		SourceTreeSHA256:    res.SourceTreeSHA256,
		PrimaryBinarySHA256: primarySHA,
		RebuiltBinarySHA256: res.BinarySHA256,
		BitForBitMatch:      matched,
		CleanRoomEnclaveID:  "cleanroom-enclave-independent-v1",
		GoVersion:           res.GoVersion,
		VerifiedAtUTC:       time.Now().UTC().Format(time.RFC3339),
	}

	env, err := fcrypto.SignPayload(RebuildAttestationType, stmt, cleanRoomKey)
	if err != nil {
		return stmt, fcrypto.SignedEnvelope{}, err
	}
	if !matched {
		return stmt, env, fmt.Errorf(
			"CLEAN-ROOM REPRODUCIBILITY FAILURE (POSSIBLE BUILD COMPROMISE): primary=%s != cleanroom=%s",
			primarySHA, res.BinarySHA256,
		)
	}
	return stmt, env, nil
}
