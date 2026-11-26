// Package scanner implements static source-hygiene and AST capability
// confinement controls designed specifically for an Untrusted Developer threat
// model:
//   1. Trojan Source detection (CVE-2021-42574): blocks Unicode BiDi override
//      and zero-width invisible control characters that deceive human reviewers.
//   2. Dependency Allowlist / Zero-Dependency Gate: rejects unauthorized
//      external modules in go.mod before any build begins.
//   3. Go AST Capability Confinement: parses Go ASTs to enforce that
//      security-critical packages (e.g. app/pkg/policyengine) cannot import
//      dangerous stdlib capabilities (unsafe, os, os/exec, net, reflect, cgo),
//      cannot define hidden init() hooks, and cannot declare mutable globals.
//   4. Hardcoded Secret / Private Key Material Scanner.
package scanner

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"verifiable-software-factory/factory/internal/policy"
)

// Finding describes a single security policy violation detected during scanning.
type Finding struct {
	RuleID   string `json:"ruleId"`
	Severity string `json:"severity"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Message  string `json:"message"`
}

// ScanReport is the deterministic, attestable result of Gate 1 (Source Hygiene & AST).
type ScanReport struct {
	Passed       bool      `json:"passed"`
	FilesScanned int       `json:"filesScanned"`
	Findings     []Finding `json:"findings"`
}

// Unicode BiDi control characters used in CVE-2021-42574 ("Trojan Source").
var bidiRunes = map[rune]string{
	'\u202A': "LRE (Left-to-Right Embedding)",
	'\u202B': "RLE (Right-to-Left Embedding)",
	'\u202C': "PDF (Pop Directional Formatting)",
	'\u202D': "LRO (Left-to-Right Override)",
	'\u202E': "RLO (Right-to-Left Override)",
	'\u2066': "LRI (Left-to-Right Isolate)",
	'\u2067': "RLI (Right-to-Left Isolate)",
	'\u2068': "FSI (First Strong Isolate)",
	'\u2069': "PDI (Pop Directional Isolate)",
	'\u200E': "LRM (Left-to-Right Mark)",
	'\u200F': "RLM (Right-to-Left Mark)",
	'\u061C': "ALM (Arabic Letter Mark)",
}

var zeroWidthRunes = map[rune]string{
	'\u200B': "ZWSP (Zero-Width Space)",
	'\u200C': "ZWNJ (Zero-Width Non-Joiner)",
	'\u200D': "ZWJ (Zero-Width Joiner)",
	'\uFEFF': "BOM/ZWNBSP (Zero-Width No-Break Space)",
}

var secretPatterns = []struct {
	id string
	re *regexp.Regexp
}{
	{"SEC-PRIVATE-KEY", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"SEC-AWS-KEY", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"SEC-HARDCODED-TOKEN", regexp.MustCompile(`(?i)(api_secret|hardcoded_password|backdoor_token)\s*[:=]\s*"[^"]{8,}"`)},
}

// ScanRepository executes all source hygiene, dependency, and AST capability gates.
func ScanRepository(repoRoot string, pol policy.FactoryPolicy) (ScanReport, error) {
	report := ScanReport{
		Passed:   true,
		Findings: []Finding{},
	}

	// 1. Verify go.mod zero-dependency / allowlist policy
	if err := checkGoMod(repoRoot, pol, &report); err != nil {
		return report, err
	}

	// 2. Walk auditable source directories (spec, app, cleanroom, policy)
	targets := []string{"spec", "app", "cleanroom", "policy"}
	for _, sub := range targets {
		dir := filepath.Join(repoRoot, sub)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				if strings.HasPrefix(d.Name(), ".") {
					return filepath.SkipDir
				}
				return nil
			}
			rel, err := filepath.Rel(repoRoot, path)
			if err != nil {
				return err
			}
			relSlash := filepath.ToSlash(rel)
			report.FilesScanned++

			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			// 2a. Block raw assembly or precompiled object smuggling under app/
			lower := strings.ToLower(relSlash)
			if strings.HasPrefix(lower, "app/") && (strings.HasSuffix(lower, ".s") || strings.HasSuffix(lower, ".syso") || strings.HasSuffix(lower, ".o") || strings.HasSuffix(lower, ".a")) {
				report.Findings = append(report.Findings, Finding{
					RuleID:   "SRC-FORBIDDEN-ASM-OBJECT",
					Severity: "CRITICAL",
					File:     relSlash,
					Line:     1,
					Message:  "Assembly or precompiled object files are prohibited under app/ (memory safety & AST bypass defense)",
				})
				return nil
			}

			// 2b. Trojan Source & Zero-Width character check
			if pol.GlobalForbiddenConstructs.ForbidUnicodeBidi || pol.GlobalForbiddenConstructs.ForbidZeroWidthChars {
				scanUnicode(relSlash, raw, pol.GlobalForbiddenConstructs, &report)
			}

			// 2c. Hardcoded secret scan
			if pol.GlobalForbiddenConstructs.ForbidHardcodedSecrets {
				scanSecrets(relSlash, raw, &report)
			}

			// 2d. Go AST capability confinement & compiler directive escape scan
			if strings.HasSuffix(relSlash, ".go") && !strings.HasSuffix(relSlash, "_test.go") {
				scanGoAST(relSlash, raw, pol, &report)
			}

			return nil
		})
		if err != nil {
			return report, err
		}
	}

	report.Passed = len(report.Findings) == 0
	return report, nil
}

func checkGoMod(repoRoot string, pol policy.FactoryPolicy, report *ScanReport) error {
	goModPath := filepath.Join(repoRoot, "go.mod")
	f, err := os.Open(goModPath)
	if err != nil {
		return fmt.Errorf("open go.mod: %w", err)
	}
	defer f.Close()

	allowed := make(map[string]bool, len(pol.AllowedExternalModules))
	for _, m := range pol.AllowedExternalModules {
		allowed[m] = true
	}

	sc := bufio.NewScanner(f)
	lineNo := 0
	inRequireBlock := false
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if idx := strings.Index(line, "//"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "require (") || line == "require(" {
			inRequireBlock = true
			continue
		}
		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}
		var depMod string
		if inRequireBlock {
			fields := strings.Fields(line)
			if len(fields) >= 1 {
				depMod = fields[0]
			}
		} else if strings.HasPrefix(line, "require ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				depMod = fields[1]
			}
		}
		if depMod != "" {
			if pol.RequireZeroThirdPartyDeps || !allowed[depMod] {
				report.Findings = append(report.Findings, Finding{
					RuleID:   "DEP-UNAUTHORIZED-MODULE",
					Severity: "CRITICAL",
					File:     "go.mod",
					Line:     lineNo,
					Message:  fmt.Sprintf("Unauthorized third-party dependency %q violates zero-dependency/allowlist hermetic policy", depMod),
				})
			}
		}
	}
	return sc.Err()
}

func scanUnicode(relPath string, raw []byte, cfg policy.GlobalForbidden, report *ScanReport) {
	if !utf8.Valid(raw) {
		report.Findings = append(report.Findings, Finding{
			RuleID:   "SRC-INVALID-UTF8",
			Severity: "HIGH",
			File:     relPath,
			Line:     1,
			Message:  "File contains invalid UTF-8 byte sequence (possible binary payload smuggling)",
		})
		return
	}
	line := 1
	for i := 0; i < len(raw); {
		r, size := utf8.DecodeRune(raw[i:])
		if r == '\n' {
			line++
		}
		if cfg.ForbidUnicodeBidi {
			if desc, bad := bidiRunes[r]; bad {
				report.Findings = append(report.Findings, Finding{
					RuleID:   "SRC-TROJAN-SOURCE-BIDI",
					Severity: "CRITICAL",
					File:     relPath,
					Line:     line,
					Message:  fmt.Sprintf("Trojan Source (CVE-2021-42574) forbidden Unicode BiDi character U+%04X (%s)", r, desc),
				})
			}
		}
		if cfg.ForbidZeroWidthChars {
			if desc, bad := zeroWidthRunes[r]; bad {
				report.Findings = append(report.Findings, Finding{
					RuleID:   "SRC-INVISIBLE-CHAR",
					Severity: "HIGH",
					File:     relPath,
					Line:     line,
					Message:  fmt.Sprintf("Forbidden invisible/zero-width Unicode character U+%04X (%s)", r, desc),
				})
			}
		}
		i += size
	}
}

func scanSecrets(relPath string, raw []byte, report *ScanReport) {
	lines := strings.Split(string(raw), "\n")
	for i, line := range lines {
		for _, pat := range secretPatterns {
			if pat.re.MatchString(line) {
				report.Findings = append(report.Findings, Finding{
					RuleID:   pat.id,
					Severity: "CRITICAL",
					File:     relPath,
					Line:     i + 1,
					Message:  fmt.Sprintf("Potential hardcoded secret or private key material matched rule %s", pat.id),
				})
			}
		}
	}
}

func scanGoAST(relPath string, raw []byte, pol policy.FactoryPolicy, report *ScanReport) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, relPath, raw, parser.ParseComments)
	if err != nil {
		report.Findings = append(report.Findings, Finding{
			RuleID:   "AST-PARSE-ERROR",
			Severity: "CRITICAL",
			File:     relPath,
			Line:     1,
			Message:  fmt.Sprintf("Failed to parse Go AST: %v", err),
		})
		return
	}

	// Global unsafe & compiler-directive escape check across app/
	if pol.GlobalForbiddenConstructs.ForbidUnsafeAcrossApp && strings.HasPrefix(relPath, "app/") {
		for _, cg := range file.Comments {
			for _, c := range cg.List {
				for _, badDir := range []string{"//go:linkname", "//go:cgo_", "//go:noescape", "//go:nosplit"} {
					if strings.HasPrefix(c.Text, badDir) {
						pos := fset.Position(c.Pos())
						report.Findings = append(report.Findings, Finding{
							RuleID:   "AST-FORBIDDEN-DIRECTIVE",
							Severity: "CRITICAL",
							File:     relPath,
							Line:     pos.Line,
							Message:  fmt.Sprintf("Forbidden Go compiler directive %q detected (bypasses memory/capability confinement)", badDir),
						})
					}
				}
			}
		}
		for _, imp := range file.Imports {
			impPath, _ := strconv.Unquote(imp.Path.Value)
			if impPath == "unsafe" || impPath == "C" {
				pos := fset.Position(imp.Pos())
				report.Findings = append(report.Findings, Finding{
					RuleID:   "AST-FORBIDDEN-UNSAFE",
					Severity: "CRITICAL",
					File:     relPath,
					Line:     pos.Line,
					Message:  fmt.Sprintf("Package %q is globally forbidden in application code", impPath),
				})
			}
		}
	}

	// Confined package capability rules
	for _, cp := range pol.ConfinedPackages {
		if !strings.HasPrefix(relPath, cp.PathPrefix+"/") && relPath != cp.PathPrefix {
			continue
		}
		allowed := make(map[string]bool, len(cp.AllowedImports))
		for _, a := range cp.AllowedImports {
			allowed[a] = true
		}

		for _, imp := range file.Imports {
			impPath, _ := strconv.Unquote(imp.Path.Value)
			if !allowed[impPath] {
				pos := fset.Position(imp.Pos())
				report.Findings = append(report.Findings, Finding{
					RuleID:   "AST-CAPABILITY-VIOLATION",
					Severity: "CRITICAL",
					File:     relPath,
					Line:     pos.Line,
					Message:  fmt.Sprintf("Confined package %q imported forbidden capability %q (allowed: %v)", cp.PathPrefix, impPath, cp.AllowedImports),
				})
			}
		}

		for _, decl := range file.Decls {
			if cp.ForbidInitFunctions {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "init" {
					pos := fset.Position(fn.Pos())
					report.Findings = append(report.Findings, Finding{
						RuleID:   "AST-FORBIDDEN-INIT",
						Severity: "CRITICAL",
						File:     relPath,
						Line:     pos.Line,
						Message:  fmt.Sprintf("Confined package %q forbids init() side-effect functions", cp.PathPrefix),
					})
				}
			}
			if cp.ForbidGlobalMutableVars {
				if gd, ok := decl.(*ast.GenDecl); ok && gd.Tok == token.VAR {
					pos := fset.Position(gd.Pos())
					report.Findings = append(report.Findings, Finding{
						RuleID:   "AST-FORBIDDEN-GLOBAL-VAR",
						Severity: "HIGH",
						File:     relPath,
						Line:     pos.Line,
						Message:  fmt.Sprintf("Confined package %q forbids mutable package-level var declarations", cp.PathPrefix),
					})
				}
			}
		}
	}
}
