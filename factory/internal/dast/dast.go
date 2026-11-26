// Package dast implements an automated, zero-dependency Dynamic Application
// Security Testing (DAST) and DISA Application Security STIG runtime probe
// targeting the compiled Tic-Tac-Toe binary.
package dast

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	fcrypto "verifiable-software-factory/factory/internal/crypto"
)

const DASTAttestationType = "aegis.gov/dast-stig-attestation/v1"

type ProbeResult struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Control  string `json:"control"`
	Passed   bool   `json:"passed"`
	Detail   string `json:"detail"`
}

type DASTStatement struct {
	TargetBinarySHA256 string        `json:"targetBinarySha256"`
	FIPS140Verified    bool          `json:"fips140Verified"`
	AuditLogVerified   bool          `json:"auditLogVerified"`
	TotalProbes        int           `json:"totalProbes"`
	PassedProbes       int           `json:"passedProbes"`
	Passed             bool          `json:"passed"`
	Probes             []ProbeResult `json:"probes"`
	ExecutedAtUTC      string        `json:"executedAtUtc"`
}

// RunRuntimeDAST launches the compiled Tic-Tac-Toe binary with GODEBUG=fips140=on
// and --require-fips, then runs 10 active runtime security & STIG probes.
func RunRuntimeDAST(binaryPath string, verifierKey fcrypto.KeyRecord) (DASTStatement, fcrypto.SignedEnvelope, error) {
	binSHA, err := fcrypto.HashFile(binaryPath)
	if err != nil {
		return DASTStatement{}, fcrypto.SignedEnvelope{}, fmt.Errorf("hash binary for DAST: %w", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return DASTStatement{}, fcrypto.SignedEnvelope{}, err
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	var stderrBuf bytes.Buffer
	cmd := exec.Command(binaryPath, "--addr", addr, "--require-fips")
	cmd.Env = append(os.Environ(), "GODEBUG=fips140=on")
	cmd.Stderr = &stderrBuf
	if err := cmd.Start(); err != nil {
		return DASTStatement{}, fcrypto.SignedEnvelope{}, fmt.Errorf("start binary for DAST: %w", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	baseURL := "http://" + addr
	client := &http.Client{Timeout: 3 * time.Second}

	var readyResp *http.Response
	for i := 0; i < 30; i++ {
		resp, err := client.Get(baseURL + "/health")
		if err == nil {
			readyResp = resp
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if readyResp == nil {
		return DASTStatement{}, fcrypto.SignedEnvelope{}, fmt.Errorf("DAST target failed to start (stderr=%s)", stderrBuf.String())
	}

	var probes []ProbeResult
	add := func(id, cat, ctrl string, ok bool, detail string) {
		probes = append(probes, ProbeResult{ID: id, Category: cat, Control: ctrl, Passed: ok, Detail: detail})
	}

	// DAST-01: FIPS 140-3 active check
	var healthBody map[string]any
	_ = json.NewDecoder(readyResp.Body).Decode(&healthBody)
	readyResp.Body.Close()
	fipsOK, _ := healthBody["fips140Enabled"].(bool)
	add("DAST-01", "Cryptographic Compliance", "NIST SC-13 / FedRAMP FIPS 140-3", fipsOK,
		fmt.Sprintf("/health reported fips140Enabled=%v", fipsOK))

	// DAST-02: DISA App STIG HTTP Security Headers + ZERO 'unsafe-inline' CSP
	requiredHeaders := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"Referrer-Policy",
		"Permissions-Policy",
		"Cache-Control",
	}
	var missing []string
	for _, h := range requiredHeaders {
		if readyResp.Header.Get(h) == "" {
			missing = append(missing, h)
		}
	}
	csp := readyResp.Header.Get("Content-Security-Policy")
	strictCSP := !strings.Contains(csp, "unsafe-inline") && !strings.Contains(csp, "unsafe-eval")
	add("DAST-02", "HTTP Security Headers", "DISA App STIG / NIST SC-8", len(missing) == 0 && strictCSP,
		fmt.Sprintf("checked %d STIG headers, missing=%v, zeroUnsafeInlineCSP=%v", len(requiredHeaders), missing, strictCSP))

	// DAST-03: HTTP Method Restriction on /api/move
	getMove, err := client.Get(baseURL + "/api/move")
	methodOK := err == nil && getMove.StatusCode == http.StatusMethodNotAllowed
	if getMove != nil {
		getMove.Body.Close()
	}
	add("DAST-03", "HTTP Method Enforcement", "NIST AC-3 / CM-7", methodOK,
		"GET /api/move rejected with 405 Method Not Allowed")

	// DAST-04: Oversized Request Body DoS Guard (> 64 KiB)
	hugePayload := `{"board":".........","player":"X","position":0,"actor":"` + strings.Repeat("A", 70*1024) + `"}`
	dosResp, err := client.Post(baseURL+"/api/move", "application/json", strings.NewReader(hugePayload))
	dosOK := err == nil && (dosResp.StatusCode == http.StatusRequestEntityTooLarge || dosResp.StatusCode == http.StatusBadRequest)
	dosStatus := 0
	if dosResp != nil {
		dosStatus = dosResp.StatusCode
		dosResp.Body.Close()
	}
	add("DAST-04", "Payload Size DoS Guard", "NIST SC-5", dosOK,
		fmt.Sprintf("70 KiB payload rejected with HTTP %d", dosStatus))

	// DAST-05: Strict Schema / Unknown Field Injection Rejection
	extraField := `{"board":".........","player":"X","position":0,"forceWin":true}`
	schemaResp, err := client.Post(baseURL+"/api/move", "application/json", strings.NewReader(extraField))
	schemaOK := err == nil && schemaResp.StatusCode == http.StatusBadRequest
	schemaStatus := 0
	if schemaResp != nil {
		schemaStatus = schemaResp.StatusCode
		schemaResp.Body.Close()
	}
	add("DAST-05", "Strict Schema Validation", "NIST SI-10 / SSDF PW.8", schemaOK,
		fmt.Sprintf("unknown field 'forceWin' rejected with HTTP %d", schemaStatus))

	// DAST-06: SQLi / XSS / Command Injection Payload Fail-Closed Check
	injPayload := `{"board":"';DROP--.","player":"X","position":0,"actor":"<script>alert(1)</script>"}`
	injResp, err := client.Post(baseURL+"/api/move", "application/json", strings.NewReader(injPayload))
	injOK := false
	if err == nil {
		b, _ := io.ReadAll(injResp.Body)
		injResp.Body.Close()
		injOK = injResp.StatusCode == http.StatusOK && strings.Contains(string(b), `"valid":false`) && !strings.Contains(string(b), "panic")
	}
	add("DAST-06", "Injection & Fuzz Resilience", "NIST SI-10 / OWASP Top 10", injOK,
		"SQLi/XSS malformed board safely rejected with valid=false and no crash")

	// DAST-07: Path Traversal & Hidden Debug Endpoint Check
	traversalPaths := []string{"/../../etc/passwd", "/debug/pprof/", "/.env", "/.git/config"}
	travOK := true
	for _, tp := range traversalPaths {
		resp, err := client.Get(baseURL + tp)
		if err != nil {
			travOK = false
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound || strings.Contains(string(b), "root:x:") {
			travOK = false
		}
	}
	add("DAST-07", "Path Traversal & Debug Surface", "NIST CM-7 / DISA STIG", travOK,
		"all traversal and debug endpoints returned 404 without info disclosure")

	// DAST-08: Live Anti-Backdoor Probe ('cheat-win' cannot win on move 1)
	bdPayload := `{"board":".........","player":"X","position":0,"actor":"cheat-win"}`
	bdResp, err := client.Post(baseURL+"/api/move", "application/json", strings.NewReader(bdPayload))
	bdOK := false
	if err == nil {
		b, _ := io.ReadAll(bdResp.Body)
		bdResp.Body.Close()
		bdOK = bdResp.StatusCode == http.StatusOK && strings.Contains(string(b), `"status":"IN_PROGRESS"`)
	}
	add("DAST-08", "Anti-Backdoor Live Kernel Probe", "Untrusted Dev Control", bdOK,
		"actor 'cheat-win' returned IN_PROGRESS (no privileged win backdoor)")

	// DAST-09: Terminal Immutability Live Probe
	termPayload := `{"board":"XXXOO....","player":"O","position":5,"actor":"ghost-admin"}`
	termResp, err := client.Post(baseURL+"/api/move", "application/json", strings.NewReader(termPayload))
	termOK := false
	if err == nil {
		b, _ := io.ReadAll(termResp.Body)
		termResp.Body.Close()
		termOK = termResp.StatusCode == http.StatusOK && strings.Contains(string(b), `"ERR_GAME_ALREADY_OVER"`)
	}
	add("DAST-09", "Terminal State Immutability", "Formal Spec TTT-INV-4", termOK,
		"move on already-won board live-rejected with ERR_GAME_ALREADY_OVER")

	// DAST-10: Embedded Vendored HTMX + Tailwind CSS + HTMX Fragment Swap Check
	cssResp, cssErr := client.Get(baseURL + "/static/tailwind.css")
	jsResp, jsErr := client.Get(baseURL + "/static/htmx.min.js")
	hxResp, hxErr := client.Post(baseURL+"/hx/move", "application/x-www-form-urlencoded", strings.NewReader("board=.........&player=X&position=4&actor=dast"))
	htmxOK := cssErr == nil && cssResp.StatusCode == http.StatusOK && jsErr == nil && jsResp.StatusCode == http.StatusOK && hxErr == nil && hxResp.StatusCode == http.StatusOK
	if cssResp != nil {
		cssResp.Body.Close()
	}
	if jsResp != nil {
		jsResp.Body.Close()
	}
	if hxResp != nil {
		b, _ := io.ReadAll(hxResp.Body)
		hxResp.Body.Close()
		htmxOK = htmxOK && strings.Contains(string(b), `value="....X...."`) && !strings.Contains(string(b), "<script")
	}
	add("DAST-10", "GoTH Stack (tmpl/Tailwind/HTMX)", "Zero-CDN & XSS Safety", htmxOK,
		"embedded /static/tailwind.css, /static/htmx.min.js, and POST /hx/move HTML swap verified")

	// DAST-11: A2A v1.0 Agent Card & JSON-RPC Task Protocol Check
	cardResp, cardErr := client.Get(baseURL + "/.well-known/agent-card.json")
	a2aPayload := `{"jsonrpc":"2.0","id":"dast-1","method":"message/send","params":{"move":{"board":"XX.OO....","player":"X","position":2,"actor":"a2a-dast"}}}`
	a2aResp, a2aErr := client.Post(baseURL+"/a2a", "application/json", strings.NewReader(a2aPayload))
	a2aOK := cardErr == nil && cardResp.StatusCode == http.StatusOK && a2aErr == nil && a2aResp.StatusCode == http.StatusOK
	if cardResp != nil {
		b, _ := io.ReadAll(cardResp.Body)
		cardResp.Body.Close()
		a2aOK = a2aOK && strings.Contains(string(b), `"protocolVersion":"1.0"`)
	}
	if a2aResp != nil {
		b, _ := io.ReadAll(a2aResp.Body)
		a2aResp.Body.Close()
		a2aOK = a2aOK && strings.Contains(string(b), `"state":"completed"`) && strings.Contains(string(b), `"a2ui-v1-surface"`)
	}
	add("DAST-11", "A2A v1.0 Inter-Agent Protocol", "Agent2Agent v1.0 Spec", a2aOK,
		"/.well-known/agent-card.json and POST /a2a JSON-RPC task+A2UI artifact verified")

	// DAST-12: A2UI v1.0 Declarative Surface Protocol Check
	uiResp, uiErr := client.Get(baseURL + "/api/a2ui/surface")
	a2uiOK := uiErr == nil && uiResp.StatusCode == http.StatusOK
	if uiResp != nil {
		b, _ := io.ReadAll(uiResp.Body)
		uiResp.Body.Close()
		a2uiOK = a2uiOK && strings.Contains(string(b), `"a2uiVersion":"1.0"`) && strings.Contains(string(b), `"createSurface"`) && strings.Contains(string(b), `"spec/design-tokens.json"`)
	}
	add("DAST-12", "A2UI v1.0 Declarative UI", "Google A2UI v1.0 + DTCG Tokens", a2uiOK,
		"GET /api/a2ui/surface emitted createSurface/updateComponents/updateDataModel bound to design-tokens.json")

	// DAST-13: Server Fingerprint Minimization & AU-2/AU-3 Structured JSON Audit Log Verification
	serverHdr := readyResp.Header.Get("Server")
	time.Sleep(50 * time.Millisecond)
	logs := stderrBuf.String()
	auditOK := strings.Contains(logs, `"eventType":"GAME_MOVE"`) && strings.Contains(logs, `"fips140Enabled":true`)
	add("DAST-13", "Audit Telemetry & Header Hygiene", "NIST AU-2 / AU-3 / AU-12", serverHdr == "" && auditOK,
		fmt.Sprintf("Server header suppressed=%v, structured JSON audit log emitted=%v", serverHdr == "", auditOK))

	passedCount := 0
	for _, p := range probes {
		if p.Passed {
			passedCount++
		}
	}
	allPassed := passedCount == len(probes)

	stmt := DASTStatement{
		TargetBinarySHA256: binSHA,
		FIPS140Verified:    fipsOK,
		AuditLogVerified:   auditOK,
		TotalProbes:        len(probes),
		PassedProbes:       passedCount,
		Passed:             allPassed,
		Probes:             probes,
		ExecutedAtUTC:      time.Now().UTC().Format(time.RFC3339),
	}

	env, err := fcrypto.SignPayload(DASTAttestationType, stmt, verifierKey)
	if err != nil {
		return stmt, fcrypto.SignedEnvelope{}, err
	}
	if !allPassed {
		return stmt, env, fmt.Errorf("DAST FAILED: only %d/%d runtime security probes passed", passedCount, len(probes))
	}
	return stmt, env, nil
}
