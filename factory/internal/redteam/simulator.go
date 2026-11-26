// Package redteam implements an executable Untrusted Developer Threat
// Simulation suite targeting the Tic-Tac-Toe application. Every scenario
// clones the repository into an ephemeral temp workspace, executes a realistic
// insider or supply-chain attack, and verifies that the Software Factory
// deterministically detects and blocks it.
package redteam

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"verifiable-software-factory/factory/internal/attestation"
	"verifiable-software-factory/factory/internal/builder"
	"verifiable-software-factory/factory/internal/cleanroom"
	fcrypto "verifiable-software-factory/factory/internal/crypto"
	"verifiable-software-factory/factory/internal/governance"
	"verifiable-software-factory/factory/internal/policy"
	"verifiable-software-factory/factory/internal/scanner"
)

type AttackResult struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ThreatVector  string `json:"threatVector"`
	ControlGate   string `json:"controlGate"`
	Blocked       bool   `json:"blocked"`
	BlockingProof string `json:"blockingProof"`
}

func RunAllSimulations(repoRoot string, pol policy.FactoryPolicy, primaryBinaryPath, sbomPath string, bundleEnv fcrypto.SignedEnvelope, keyDir string) ([]AttackResult, error) {
	trustRoots, err := fcrypto.LoadTrustRoots(keyDir)
	if err != nil {
		return nil, err
	}
	devKey, err := fcrypto.LoadRoleKey(keyDir, fcrypto.RoleDeveloper)
	if err != nil {
		return nil, err
	}
	secKey, err := fcrypto.LoadRoleKey(keyDir, fcrypto.RoleSecurityAuditor)
	if err != nil {
		return nil, err
	}
	cleanKey, err := fcrypto.LoadRoleKey(keyDir, fcrypto.RoleCleanRoomVerifier)
	if err != nil {
		return nil, err
	}

	var results []AttackResult

	// ATK-01: Insider Self-Approval (2PI Bypass Attempt)
	{
		srcSHA, _, err := fcrypto.HashSourceTree(repoRoot)
		if err != nil {
			return nil, err
		}
		devEnv, _ := governance.CreateApproval(srcSHA, devKey, "alice-dev", "Author submission")
		forgedPeerKey := devKey
		forgedPeerKey.Role = fcrypto.RolePeerReviewer
		forgedPeerEnv, _ := governance.CreateApproval(srcSHA, forgedPeerKey, "alice-dev", "Self-approved peer review")
		secEnv, _ := governance.CreateApproval(srcSHA, secKey, "carol-sec", "Security signoff")

		bundle := governance.ApprovalBundle{
			SourceTreeSHA256: srcSHA,
			Approvals:        []fcrypto.SignedEnvelope{devEnv, forgedPeerEnv, secEnv},
		}
		verifyErr := governance.VerifyApprovalBundle(bundle, srcSHA, pol.TwoPersonIntegrity, trustRoots)
		results = append(results, AttackResult{
			ID:            "ATK-01",
			Name:          "Insider Self-Approval / 2PI Bypass",
			ThreatVector:  "T1: Malicious developer signs both author and peer_reviewer approvals",
			ControlGate:   "Two-Person Integrity (2PI) & Ed25519 Trust Roots",
			Blocked:       verifyErr != nil,
			BlockingProof: errMsg(verifyErr),
		})
	}

	// ATK-02: Trojan Source Unicode BiDi Injection (CVE-2021-42574) in Tic-Tac-Toe
	{
		cloneDir, cleanup, err := cloneRepoTemp(repoRoot)
		if err != nil {
			return nil, err
		}
		engPath := filepath.Join(cloneDir, "app/pkg/tictactoe/engine.go")
		orig, _ := os.ReadFile(engPath)
		poisoned := string(orig) + "\n// benign comment \u202e /* hidden BiDi override */\n"
		_ = os.WriteFile(engPath, []byte(poisoned), 0o644)

		rep, scanErr := scanner.ScanRepository(cloneDir, pol)
		cleanup()
		blocked := scanErr != nil || !rep.Passed
		proof := "not blocked"
		if len(rep.Findings) > 0 {
			proof = fmt.Sprintf("[%s] %s", rep.Findings[0].RuleID, rep.Findings[0].Message)
		}
		results = append(results, AttackResult{
			ID:            "ATK-02",
			Name:          "Trojan Source Unicode BiDi Attack (CVE-2021-42574)",
			ThreatVector:  "T2: Developer injects U+202E RLO invisible override into tictactoe/engine.go",
			ControlGate:   "Source Hygiene & Lexical Unicode Gate",
			Blocked:       blocked,
			BlockingProof: proof,
		})
	}

	// ATK-03: Covert Capability Escalation (os/exec + unsafe + init() inside Tic-Tac-Toe kernel)
	{
		cloneDir, cleanup, err := cloneRepoTemp(repoRoot)
		if err != nil {
			return nil, err
		}
		backdoorFile := filepath.Join(cloneDir, "app/pkg/tictactoe/beacon.go")
		code := `package tictactoe
import (
	"os/exec"
	_ "unsafe"
)
func init() { _ = exec.Command("sh", "-c", "id") }
`
		_ = os.WriteFile(backdoorFile, []byte(code), 0o644)

		rep, scanErr := scanner.ScanRepository(cloneDir, pol)
		cleanup()
		blocked := scanErr != nil || !rep.Passed
		var msgs []string
		for _, f := range rep.Findings {
			msgs = append(msgs, fmt.Sprintf("[%s] %s", f.RuleID, f.Message))
		}
		results = append(results, AttackResult{
			ID:            "ATK-03",
			Name:          "Covert Capability & Memory-Safety Escape (os/exec + unsafe + init())",
			ThreatVector:  "T5: Developer sneaks shell execution, unsafe pointer access & init() into Tic-Tac-Toe kernel",
			ControlGate:   "Go AST Capability Confinement & Memory-Safety Gate",
			Blocked:       blocked,
			BlockingProof: strings.Join(msgs, " | "),
		})
	}

	// ATK-04: Unauthorized Third-Party Dependency Injection
	{
		cloneDir, cleanup, err := cloneRepoTemp(repoRoot)
		if err != nil {
			return nil, err
		}
		goModPath := filepath.Join(cloneDir, "go.mod")
		orig, _ := os.ReadFile(goModPath)
		poisoned := string(orig) + "\nrequire github.com/evil-typosquat/trojan-logger v1.2.3\n"
		_ = os.WriteFile(goModPath, []byte(poisoned), 0o644)

		rep, scanErr := scanner.ScanRepository(cloneDir, pol)
		cleanup()
		blocked := scanErr != nil || !rep.Passed
		proof := "not blocked"
		if len(rep.Findings) > 0 {
			proof = fmt.Sprintf("[%s] %s", rep.Findings[0].RuleID, rep.Findings[0].Message)
		}
		results = append(results, AttackResult{
			ID:            "ATK-04",
			Name:          "Unauthorized Dependency / Typosquat Injection",
			ThreatVector:  "T4: Developer adds unvetted external dependency to go.mod",
			ControlGate:   "Zero-Dependency Allowlist & Hermetic GOPROXY=off Gate",
			Blocked:       blocked,
			BlockingProof: proof,
		})
	}

	// ATK-05: SolarWinds-Style Compromised Primary Build Server (1-Bit Binary Tamper)
	{
		tmpDir, err := os.MkdirTemp("", "aegis-atk05-*")
		if err != nil {
			return nil, err
		}
		tamperedBin := filepath.Join(tmpDir, "tictactoe-tampered")
		rawBin, err := os.ReadFile(primaryBinaryPath)
		if err != nil {
			os.RemoveAll(tmpDir)
			return nil, err
		}
		rawBin[len(rawBin)-1] ^= 0x01
		_ = os.WriteFile(tamperedBin, rawBin, 0o755)

		_, _, rebuildErr := cleanroom.VerifyReproducibleRebuild(repoRoot, tamperedBin, pol, cleanKey)
		_, admitErr := attestation.VerifyReleaseAdmission(tamperedBin, sbomPath, bundleEnv, pol, trustRoots)
		os.RemoveAll(tmpDir)

		blocked := rebuildErr != nil && admitErr != nil
		results = append(results, AttackResult{
			ID:            "ATK-05",
			Name:          "SolarWinds-Style Build Server Compromise (1-Bit Binary Tamper)",
			ThreatVector:  "T3: Compromised primary builder alters compiled tictactoe binary post-review",
			ControlGate:   "Independent Clean-Room Rebuilder & Zero-Trust Gatekeeper",
			Blocked:       blocked,
			BlockingProof: fmt.Sprintf("CleanRoom=%s | Gatekeeper=%s", errMsg(rebuildErr), errMsg(admitErr)),
		})
	}

	// ATK-06: Covert Semantic Logic Backdoor ('cheat-win' actor wins on move 1)
	{
		cloneDir, cleanup, err := cloneRepoTemp(repoRoot)
		if err != nil {
			return nil, err
		}
		engPath := filepath.Join(cloneDir, "app/pkg/tictactoe/engine.go")
		origBytes, _ := os.ReadFile(engPath)
		targetSnippet := "func ApplyMove(req MoveRequest) MoveResult {"
		backdoorSnippet := `func ApplyMove(req MoveRequest) MoveResult {
	if req.Actor == "cheat-win" {
		return MoveResult{Valid: true, Board: "XXX......", Status: "WIN", Winner: "X", NextTurn: "", Reason: "GAME_WON"}
	}`
		poisoned := strings.Replace(string(origBytes), targetSnippet, backdoorSnippet, 1)
		_ = os.WriteFile(engPath, []byte(poisoned), 0o644)

		tmpOut := filepath.Join(cloneDir, "backdoored-tictactoe")
		_, buildErr := builder.HermeticBuild(cloneDir, tmpOut, "atk06-builder", pol, false)
		var divErr error
		if buildErr == nil {
			_, _, divErr = cleanroom.RunDiverseVerification(cloneDir, tmpOut, pol, cleanKey)
		} else {
			divErr = buildErr
		}
		cleanup()

		results = append(results, AttackResult{
			ID:            "ATK-06",
			Name:          "Covert Logic Backdoor ('cheat-win' Tic-Tac-Toe instant-win cheat)",
			ThreatVector:  "T7: Clean-syntax semantic backdoor in Tic-Tac-Toe that passes AST & build checks",
			ControlGate:   "Clean-Room Spec & Diverse Compiler (Go vs GCC vs Clang) Verifier",
			Blocked:       divErr != nil,
			BlockingProof: errMsg(divErr),
		})
	}

	return results, nil
}

func errMsg(err error) string {
	if err == nil {
		return "UNEXPECTEDLY ALLOWED"
	}
	return err.Error()
}

func cloneRepoTemp(repoRoot string) (string, func(), error) {
	dst, err := os.MkdirTemp("", "aegis-redteam-clone-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dst) }

	for _, item := range []string{"go.mod", "spec", "app", "policy", "cleanroom"} {
		src := filepath.Join(repoRoot, item)
		info, err := os.Stat(src)
		if err != nil {
			cleanup()
			return "", nil, err
		}
		if !info.IsDir() {
			if err := copyFile(src, filepath.Join(dst, item)); err != nil {
				cleanup()
				return "", nil, err
			}
			continue
		}
		err = filepath.WalkDir(src, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			rel, _ := filepath.Rel(repoRoot, p)
			target := filepath.Join(dst, rel)
			if d.IsDir() {
				return os.MkdirAll(target, 0o755)
			}
			return copyFile(p, target)
		})
		if err != nil {
			cleanup()
			return "", nil, err
		}
	}
	return dst, cleanup, nil
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
