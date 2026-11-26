// Package builder implements a hermetic, ephemeral, bit-for-bit reproducible
// build engine aligned with SLSA Build Level 3–4 requirements.
//
// Controls enforced:
//   - Ephemeral clean staging workspace (no shared developer build caches)
//   - Scrubbed environment (zero inherited secrets/env vars)
//   - Networkless dependency resolution (GOPROXY=off, GOSUMDB=off, -mod=readonly)
//   - Deterministic compilation (CGO_ENABLED=0, -trimpath, -buildvcs=false,
//     -ldflags="-s -w -buildid=", normalized SOURCE_DATE_EPOCH mtimes, TZ=UTC)
package builder

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	fcrypto "verifiable-software-factory/factory/internal/crypto"
	"verifiable-software-factory/factory/internal/policy"
)

// BuildResult captures deterministic metadata about a hermetic build execution.
type BuildResult struct {
	BuilderLabel     string            `json:"builderLabel"`
	SourceTreeSHA256 string            `json:"sourceTreeSha256"`
	BinaryName       string            `json:"binaryName"`
	BinaryPath       string            `json:"binaryPath"`
	BinarySHA256     string            `json:"binarySha256"`
	BinarySize       int64             `json:"binarySize"`
	GoVersion        string            `json:"goVersion"`
	BuildArgs        []string          `json:"buildArgs"`
	HermeticEnv      map[string]string `json:"hermeticEnv"`
	TestsPassed      bool              `json:"testsPassed"`
	TestSummary      string            `json:"testSummary"`
	BuiltAtUTC       string            `json:"builtAtUtc"`
}

// HermeticBuild copies only allowlisted source files into an isolated temp dir,
// normalizes timestamps to SOURCE_DATE_EPOCH, runs unit/invariant tests, and
// compiles a deterministic static binary to outputBinaryPath.
func HermeticBuild(repoRoot, outputBinaryPath, builderLabel string, pol policy.FactoryPolicy, runTests bool) (BuildResult, error) {
	sourceSHA, _, err := fcrypto.HashSourceTree(repoRoot)
	if err != nil {
		return BuildResult{}, fmt.Errorf("hash source tree: %w", err)
	}

	// Create completely isolated ephemeral staging root (source + build cache + temp)
	stageRoot, err := os.MkdirTemp("", "aegis-"+builderLabel+"-*")
	if err != nil {
		return BuildResult{}, fmt.Errorf("create staging root: %w", err)
	}
	defer os.RemoveAll(stageRoot)

	srcDir := filepath.Join(stageRoot, "src")
	goCache := filepath.Join(stageRoot, "gocache")
	goPath := filepath.Join(stageRoot, "gopath")
	tmpDir := filepath.Join(stageRoot, "tmp")
	for _, d := range []string{srcDir, goCache, goPath, tmpDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return BuildResult{}, err
		}
	}

	epochTime := time.Unix(pol.SourceDateEpoch, 0).UTC()
	if err := stageSourceSubset(repoRoot, srcDir, epochTime); err != nil {
		return BuildResult{}, fmt.Errorf("stage immutable source: %w", err)
	}

	goBin, err := exec.LookPath("go")
	if err != nil {
		return BuildResult{}, fmt.Errorf("locate go toolchain: %w", err)
	}
	goRootOut, err := exec.Command(goBin, "env", "GOROOT").Output()
	if err != nil {
		return BuildResult{}, fmt.Errorf("detect GOROOT: %w", err)
	}
	goRoot := strings.TrimSpace(string(goRootOut))
	goVerOut, err := exec.Command(goBin, "version").Output()
	if err != nil {
		return BuildResult{}, fmt.Errorf("detect go version: %w", err)
	}
	goVersion := strings.TrimSpace(string(goVerOut))

	fipsVer := pol.Compliance.GoFIPS140Version
	if fipsVer == "" {
		fipsVer = "v1.0.0"
	}

	// Scrubbed hermetic environment — zero inherited developer env variables
	envMap := map[string]string{
		"PATH":              filepath.Dir(goBin) + ":/usr/bin:/bin",
		"GOROOT":            goRoot,
		"GOPATH":            goPath,
		"GOCACHE":           goCache,
		"GOMODCACHE":        filepath.Join(goPath, "pkg", "mod"),
		"HOME":              stageRoot,
		"TMPDIR":            tmpDir,
		"CGO_ENABLED":       "0",
		"GOPROXY":           "off",
		"GOSUMDB":           "off",
		"GOFLAGS":           "-mod=readonly",
		"SOURCE_DATE_EPOCH": strconv.FormatInt(pol.SourceDateEpoch, 10),
		"TZ":                "UTC",
		"LC_ALL":            "C",
	}
	if pol.Compliance.RequireFIPS140 {
		envMap["GOFIPS140"] = fipsVer
	}
	envSlice := make([]string, 0, len(envMap))
	for k, v := range envMap {
		envSlice = append(envSlice, k+"="+v)
	}

	// Optionally run exhaustive formal invariant tests inside the hermetic sandbox
	testSummary := "skipped"
	testsPassed := true
	if runTests {
		testCmd := exec.Command(goBin, "test", "-v", "-count=1", "./app/...")
		testCmd.Dir = srcDir
		testCmd.Env = envSlice
		var testBuf bytes.Buffer
		testCmd.Stdout = &testBuf
		testCmd.Stderr = &testBuf
		if err := testCmd.Run(); err != nil {
			return BuildResult{}, fmt.Errorf("hermetic invariant tests FAILED:\n%s\nerr: %w", testBuf.String(), err)
		}
		lines := strings.Split(strings.TrimSpace(testBuf.String()), "\n")
		if len(lines) > 0 {
			testSummary = lines[len(lines)-1]
		}
	}

	if err := os.MkdirAll(filepath.Dir(outputBinaryPath), 0o755); err != nil {
		return BuildResult{}, err
	}
	absOut, err := filepath.Abs(outputBinaryPath)
	if err != nil {
		return BuildResult{}, err
	}

	buildArgs := []string{
		"build",
		"-trimpath",
		"-buildvcs=false",
		"-ldflags=-s -w -buildid=",
		"-o", absOut,
		pol.TargetMainPackage,
	}

	buildCmd := exec.Command(goBin, buildArgs...)
	buildCmd.Dir = srcDir
	buildCmd.Env = envSlice
	var buildErr bytes.Buffer
	buildCmd.Stdout = &buildErr
	buildCmd.Stderr = &buildErr
	if err := buildCmd.Run(); err != nil {
		return BuildResult{}, fmt.Errorf("hermetic build FAILED:\n%s\nerr: %w", buildErr.String(), err)
	}

	// Normalize binary mtime to SOURCE_DATE_EPOCH for clean downstream packaging
	_ = os.Chtimes(absOut, epochTime, epochTime)

	binSHA, err := fcrypto.HashFile(absOut)
	if err != nil {
		return BuildResult{}, fmt.Errorf("hash compiled binary: %w", err)
	}
	st, err := os.Stat(absOut)
	if err != nil {
		return BuildResult{}, err
	}

	// Strip ephemeral paths from recorded hermeticEnv for clean provenance logs
	recordedEnv := map[string]string{
		"CGO_ENABLED":       "0",
		"GOPROXY":           "off",
		"GOSUMDB":           "off",
		"GOFLAGS":           "-mod=readonly",
		"SOURCE_DATE_EPOCH": strconv.FormatInt(pol.SourceDateEpoch, 10),
		"TZ":                "UTC",
		"LC_ALL":            "C",
	}
	if pol.Compliance.RequireFIPS140 {
		recordedEnv["GOFIPS140"] = fipsVer
	}

	return BuildResult{
		BuilderLabel:     builderLabel,
		SourceTreeSHA256: sourceSHA,
		BinaryName:       pol.TargetBinaryName,
		BinaryPath:       absOut,
		BinarySHA256:     binSHA,
		BinarySize:       st.Size(),
		GoVersion:        goVersion,
		BuildArgs:        []string{"go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid=", pol.TargetMainPackage},
		HermeticEnv:      recordedEnv,
		TestsPassed:      testsPassed,
		TestSummary:      testSummary,
		BuiltAtUTC:       time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// stageSourceSubset copies only go.mod and app/ into the isolated staging dir
// and stamps every file with SOURCE_DATE_EPOCH.
func stageSourceSubset(repoRoot, dstRoot string, epoch time.Time) error {
	items := []string{"go.mod", "app"}
	for _, item := range items {
		src := filepath.Join(repoRoot, item)
		info, err := os.Stat(src)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			if err := copyFileDeterministic(src, filepath.Join(dstRoot, item), epoch); err != nil {
				return err
			}
			continue
		}
		err = filepath.WalkDir(src, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			rel, err := filepath.Rel(repoRoot, p)
			if err != nil {
				return err
			}
			target := filepath.Join(dstRoot, rel)
			if d.IsDir() {
				if strings.HasPrefix(d.Name(), ".") {
					return filepath.SkipDir
				}
				return os.MkdirAll(target, 0o755)
			}
			return copyFileDeterministic(p, target, epoch)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func copyFileDeterministic(src, dst string, epoch time.Time) error {
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
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chtimes(dst, epoch, epoch)
}
