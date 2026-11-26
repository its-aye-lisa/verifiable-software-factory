package cleanroom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	fcrypto "verifiable-software-factory/factory/internal/crypto"
	"verifiable-software-factory/factory/internal/policy"
)

const DiverseVerificationType = "aegis.gov/cleanroom-diverse-verification/v1"

// CompilerArtifact records an independently compiled clean-room verifier binary.
type CompilerArtifact struct {
	Compiler       string `json:"compiler"`
	Version        string `json:"version"`
	BinarySHA256   string `json:"binarySha256"`
	VectorsPassed  int    `json:"vectorsPassed"`
	FuzzCasesCheck int    `json:"fuzzCasesChecked"`
}

// DiverseVerificationStatement attests 3-way equivalence across:
//   - Compiled Go Tic-Tac-Toe Binary (tictactoe --eval-cli)
//   - Independent Clean-Room C Reference Kernel compiled with GCC
//   - Independent Clean-Room C Reference Kernel compiled with Clang
type DiverseVerificationStatement struct {
	SourceTreeSHA256   string             `json:"sourceTreeSha256"`
	TargetBinarySHA256 string             `json:"targetBinarySha256"`
	SpecVersion        string             `json:"specVersion"`
	SpecVectorsTotal   int                `json:"specVectorsTotal"`
	TicTacToeVectors   int                `json:"tictactoeVectorsTotal"`
	DifferentialCases  int                `json:"differentialCases"`
	CompilersVerified  []CompilerArtifact `json:"compilersVerified"`
	DivergencesFound   int                `json:"divergencesFound"`
	Passed             bool               `json:"passed"`
	FailureDetails     []string           `json:"failureDetails,omitempty"`
	VerifiedAtUTC      string             `json:"verifiedAtUtc"`
}

// RunDiverseVerification compiles cleanroom/c-verifier/tictactoe_kernel.c with
// BOTH gcc and clang, then verifies 3-way behavioral equivalence against the
// compiled Go Tic-Tac-Toe binary across spec/tictactoe.spec.json + 60
// differential & anti-backdoor fuzz cases.
func RunDiverseVerification(
	repoRoot string,
	targetBinaryPath string,
	pol policy.FactoryPolicy,
	cleanRoomKey fcrypto.KeyRecord,
) (DiverseVerificationStatement, fcrypto.SignedEnvelope, error) {
	sourceSHA, _, err := fcrypto.HashSourceTree(repoRoot)
	if err != nil {
		return DiverseVerificationStatement{}, fcrypto.SignedEnvelope{}, err
	}
	targetSHA, err := fcrypto.HashFile(targetBinaryPath)
	if err != nil {
		return DiverseVerificationStatement{}, fcrypto.SignedEnvelope{}, err
	}

	appSpec, err := policy.LoadAppSpec(filepath.Join(repoRoot, pol.CleanRoom.AppSpecPath))
	if err != nil {
		return DiverseVerificationStatement{}, fcrypto.SignedEnvelope{}, err
	}

	tttCSource := filepath.Join(repoRoot, pol.CleanRoom.TicTacToeCReferenceSource)
	tmpDir, err := os.MkdirTemp("", "aegis-diverse-verify-*")
	if err != nil {
		return DiverseVerificationStatement{}, fcrypto.SignedEnvelope{}, err
	}
	defer os.RemoveAll(tmpDir)

	type compiledRef struct {
		name    string
		version string
		binPath string
		sha256  string
	}
	var refs []compiledRef
	for _, cc := range pol.CleanRoom.RequiredCompilers {
		ccPath, err := exec.LookPath(cc)
		if err != nil {
			return DiverseVerificationStatement{}, fcrypto.SignedEnvelope{}, fmt.Errorf("required diverse compiler %q not found: %w", cc, err)
		}
		verOut, _ := exec.Command(ccPath, "--version").Output()
		verLine := strings.Split(strings.TrimSpace(string(verOut)), "\n")[0]

		outBin := filepath.Join(tmpDir, "tictactoe_kernel_"+cc)
		if err := compileHardenedC(ccPath, tttCSource, outBin); err != nil {
			return DiverseVerificationStatement{}, fcrypto.SignedEnvelope{}, fmt.Errorf("compile tictactoe_kernel with %s failed: %w", cc, err)
		}
		h, err := fcrypto.HashFile(outBin)
		if err != nil {
			return DiverseVerificationStatement{}, fcrypto.SignedEnvelope{}, err
		}
		refs = append(refs, compiledRef{
			name:    cc,
			version: verLine,
			binPath: outBin,
			sha256:  h,
		})
	}

	var failures []string

	// 1. Verify every spec/tictactoe.spec.json acceptance vector across Go + GCC + Clang
	for _, tv := range appSpec.GameSpec.Vectors {
		expStr := formatTTT(tv.ExpectedValid, tv.ExpectedStatus, tv.ExpectedWinner, tv.ExpectedNextTurn, tv.ExpectedReason, tv.ExpectedBoard)
		goOut, err := evalGoTTT(targetBinaryPath, tv.Input)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: Go --eval-cli error: %v", tv.ID, err))
			continue
		}
		if goOut != expStr {
			failures = append(failures, fmt.Sprintf("%s (%s): Go=%q != spec=%q", tv.ID, tv.Description, goOut, expStr))
		}
		for _, r := range refs {
			cOut, err := evalCTTT(r.binPath, tv.Input)
			if err != nil {
				failures = append(failures, fmt.Sprintf("%s: %s ref error: %v", tv.ID, r.name, err))
				continue
			}
			if cOut != expStr || cOut != goOut {
				failures = append(failures, fmt.Sprintf("%s: DIVERGENCE Go=%q %s=%q spec=%q", tv.ID, goOut, r.name, cOut, expStr))
			}
		}
	}

	// 2. Differential Equivalence & Anti-Backdoor Fuzz Matrix across Go + GCC + Clang
	diffCases := generateDifferentialCases()
	for idx, tc := range diffCases {
		goOut, err := evalGoTTT(targetBinaryPath, tc)
		if err != nil {
			failures = append(failures, fmt.Sprintf("DIFF-%03d: Go error: %v", idx, err))
			continue
		}
		var refOutputs []string
		for _, r := range refs {
			cOut, err := evalCTTT(r.binPath, tc)
			if err != nil {
				failures = append(failures, fmt.Sprintf("DIFF-%03d: %s error: %v", idx, r.name, err))
				continue
			}
			refOutputs = append(refOutputs, cOut)
			if cOut != goOut {
				failures = append(failures, fmt.Sprintf(
					"DIFF-%03d (board=%q player=%s pos=%d actor=%q): Go=%q DIVERGES from %s=%q",
					idx, tc.Board, tc.Player, tc.Position, tc.Actor, goOut, r.name, cOut,
				))
			}
		}
		if len(refOutputs) >= 2 && refOutputs[0] != refOutputs[1] {
			failures = append(failures, fmt.Sprintf(
				"DIFF-%03d: DIVERSE COMPILER DIVERGENCE (%s=%q vs %s=%q)",
				idx, refs[0].name, refOutputs[0], refs[1].name, refOutputs[1],
			))
		}
	}

	compilersVerified := make([]CompilerArtifact, 0, len(refs))
	for _, r := range refs {
		compilersVerified = append(compilersVerified, CompilerArtifact{
			Compiler:       r.name,
			Version:        r.version,
			BinarySHA256:   r.sha256,
			VectorsPassed:  len(appSpec.GameSpec.Vectors),
			FuzzCasesCheck: len(diffCases),
		})
	}

	stmt := DiverseVerificationStatement{
		SourceTreeSHA256:   sourceSHA,
		TargetBinarySHA256: targetSHA,
		SpecVersion:        appSpec.SpecVersion,
		SpecVectorsTotal:   len(appSpec.GameSpec.Vectors),
		TicTacToeVectors:   len(appSpec.GameSpec.Vectors),
		DifferentialCases:  len(diffCases),
		CompilersVerified:  compilersVerified,
		DivergencesFound:   len(failures),
		Passed:             len(failures) == 0,
		FailureDetails:     failures,
		VerifiedAtUTC:      time.Now().UTC().Format(time.RFC3339),
	}

	env, err := fcrypto.SignPayload(DiverseVerificationType, stmt, cleanRoomKey)
	if err != nil {
		return stmt, fcrypto.SignedEnvelope{}, err
	}
	if !stmt.Passed {
		return stmt, env, fmt.Errorf("CLEAN-ROOM DIVERSE VERIFICATION FAILED (%d divergences): %s", len(failures), strings.Join(failures, "; "))
	}
	return stmt, env, nil
}

func compileHardenedC(ccPath, srcPath, outBin string) error {
	cmd := exec.Command(ccPath,
		"-O2", "-Wall", "-Wextra", "-Werror",
		"-fstack-protector-strong",
		"-o", outBin,
		srcPath,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s (%w)", stderr.String(), err)
	}
	return nil
}

func evalGoTTT(binPath string, in policy.TTTInput) (string, error) {
	payload, err := json.Marshal(in)
	if err != nil {
		return "", err
	}
	cmd := exec.Command(binPath, "--eval-cli", string(payload))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func evalCTTT(binPath string, in policy.TTTInput) (string, error) {
	cmd := exec.Command(binPath,
		in.Board,
		in.Player,
		strconv.Itoa(in.Position),
		in.Actor,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func formatTTT(valid bool, status, winner, nextTurn, reason, board string) string {
	v := "INVALID"
	if valid {
		v = "VALID"
	}
	if winner == "" {
		winner = "-"
	}
	if nextTurn == "" {
		nextTurn = "-"
	}
	return fmt.Sprintf("%s %s %s %s %s %s", v, status, winner, nextTurn, reason, board)
}

func generateDifferentialCases() []policy.TTTInput {
	boards := []string{
		".........",
		"....X....",
		"X...O....",
		"XX.OO....",
		"XXXOO....",
		"XOXOOXOX.",
		"XXO.O...X",
		"X.O.X.O..",
		"bad",
		"XXXX.....",
	}
	players := []string{"X", "O", "Z"}
	actors := []string{"player-normal", "cheat-win", "ghost-admin", "root", "backdoor"}

	cases := make([]policy.TTTInput, 0, 60)
	var seed uint64 = 0x5EED2026CAFEBABE
	next := func() uint64 {
		seed ^= seed << 13
		seed ^= seed >> 7
		seed ^= seed << 17
		return seed
	}
	for i := 0; i < 60; i++ {
		cases = append(cases, policy.TTTInput{
			Board:    boards[int(next()%uint64(len(boards)))],
			Player:   players[int(next()%uint64(len(players)))],
			Position: int(next()%12) - 1, // -1..10
			Actor:    actors[int(next()%uint64(len(actors)))],
		})
	}
	return cases
}
