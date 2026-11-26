// Package vra implements automated Vulnerability Risk Assessment (VRA) aligned
// with FedRAMP 20x VDR/VER, DoD CC SRG IL4, and CISA BOD 26-04 remediation SLAs.
//
// Autonomous Defense Scoring Formula:
//   - Reachability (govulncheck / static call graph): non-reachable CVEs are
//     marked for OpenVEX tracking rather than false-alarming production deploys.
//   - Exploitability (CISA KEV / active exploitation): escalates priority immediately.
//   - IL4 Mission Impact + CVSS -> SLA days (Critical: 15d, High: 30d, Moderate: 90d, Low: 180d).
package vra

import (
	"fmt"
	"time"

	"verifiable-software-factory/factory/internal/policy"
)

// FindingInput represents a normalized SCA / Container / IaC vulnerability finding.
type FindingInput struct {
	ID               string  `json:"id"`
	Component        string  `json:"component"`
	CVSS             float64 `json:"cvss"`
	Reachable        bool    `json:"reachable"`
	InCISAKEV        bool    `json:"inCisaKev"`
	ExploitAvailable bool    `json:"exploitAvailable"`
	Description      string  `json:"description"`
}

// RiskAssessmentItem is the VRA output with SLA deadline and POA&M guidance.
type RiskAssessmentItem struct {
	ID              string  `json:"id"`
	Component       string  `json:"component"`
	CVSS            float64 `json:"cvss"`
	Reachable       bool    `json:"reachable"`
	InCISAKEV       bool    `json:"inCisaKev"`
	Severity        string  `json:"severity"` // CRITICAL, HIGH, MODERATE, LOW, INFORMATIONAL
	BlockRelease    bool    `json:"blockRelease"`
	SLADays         int     `json:"slaDays"`
	DueDateUTC      string  `json:"dueDateUtc"`
	VEXDisposition  string  `json:"vexDisposition"` // affected, not_affected, under_investigation
	RecommendedAct  string  `json:"recommendedAction"`
}

// VRAReport is the complete Vulnerability Risk Assessment & POA&M posture report.
type VRAReport struct {
	SchemaVersion      string               `json:"schemaVersion"`
	GeneratedAtUTC     string               `json:"generatedAtUtc"`
	Baseline           string               `json:"baseline"`
	ReleaseBlocked     bool                 `json:"releaseBlocked"`
	TotalFindings      int                  `json:"totalFindings"`
	BlockingFindings   int                  `json:"blockingFindings"`
	Items              []RiskAssessmentItem `json:"items"`
	AutonomousDefense  string               `json:"autonomousDefensePosture"`
}

// EvaluateFindings runs deterministic VRA scoring over SCA/container findings.
func EvaluateFindings(findings []FindingInput, sla policy.VulnSLAs) VRAReport {
	now := time.Now().UTC()
	items := make([]RiskAssessmentItem, 0, len(findings))
	blocking := 0

	for _, f := range findings {
		sev := "LOW"
		slaDays := sla.Low
		switch {
		case f.InCISAKEV || f.CVSS >= 9.0:
			sev = "CRITICAL"
			slaDays = sla.Critical
		case f.CVSS >= 7.0 || (f.CVSS >= 6.0 && f.ExploitAvailable):
			sev = "HIGH"
			slaDays = sla.High
		case f.CVSS >= 4.0:
			sev = "MODERATE"
			slaDays = sla.Moderate
		}

		block := f.Reachable && (sev == "CRITICAL" || sev == "HIGH")
		if block {
			blocking++
		}
		vex := "affected"
		action := fmt.Sprintf("Remediate within %d days per FedRAMP VDR / BOD 26-04 SLA and open POA&M issue.", slaDays)
		if !f.Reachable {
			vex = "not_affected"
			action = "Publish OpenVEX not_affected (vulnerable_code_not_in_execute_path); schedule routine dependency patch."
		}

		items = append(items, RiskAssessmentItem{
			ID:             f.ID,
			Component:      f.Component,
			CVSS:           f.CVSS,
			Reachable:      f.Reachable,
			InCISAKEV:      f.InCISAKEV,
			Severity:       sev,
			BlockRelease:   block,
			SLADays:        slaDays,
			DueDateUTC:     now.AddDate(0, 0, slaDays).Format("2006-01-02"),
			VEXDisposition: vex,
			RecommendedAct: action,
		})
	}

	posture := "GREEN (0 reachable CRITICAL/HIGH vulnerabilities; minimal-TCB zero-dep posture)"
	if blocking > 0 {
		posture = fmt.Sprintf("RED (%d blocking findings require immediate autonomous remediation)", blocking)
	}

	return VRAReport{
		SchemaVersion:     "aegis.gov/vra-report/v1",
		GeneratedAtUTC:    now.Format(time.RFC3339),
		Baseline:          "FedRAMP-Moderate + FedRAMP-20x-VDR + DoD-IL4 + BOD-26-04",
		ReleaseBlocked:    blocking > 0,
		TotalFindings:     len(items),
		BlockingFindings:  blocking,
		Items:             items,
		AutonomousDefense: posture,
	}
}
