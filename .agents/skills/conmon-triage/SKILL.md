---
name: conmon-triage
description: Perform FedRAMP ConMon / DoD cATO vulnerability triage, Vulnerability Risk Assessment (VRA), OpenVEX dispositioning, and BOD 26-04 SLA remediation.
---

# Skill: Continuous Monitoring (ConMon) & Vulnerability Risk Assessment

1. **Assess Reachability & Exploitability (FedRAMP 20x VER):**
   - Run `govulncheck ./...` (if available) and review Trivy FS/Image SARIF output.
   - Score each finding using `factory/internal/vra/vra.go` criteria: CVSS + Reachability + CISA KEV + IL4 Mission Impact.
2. **Apply Mandatory Remediation SLAs (FedRAMP VDR / BOD 26-04):**
   - **Critical / CISA KEV:** ≤ 15 days (blocks release immediately if reachable)
   - **High:** ≤ 30 days (blocks release if reachable)
   - **Moderate:** ≤ 90 days
   - **Low:** ≤ 180 days
3. **Update OpenVEX or Patch:**
   - If unreachable in static call graph: document `not_affected` (`vulnerable_code_not_in_execute_path`) in OpenVEX and schedule routine Go toolchain / base image upgrade.
   - If reachable: bump Go toolchain version in `go.mod`, `Dockerfile`, and `.github/workflows/`, run `make factory && make admit`, and close the POA&M GitHub Issue with the new verified binary SHA-256.
