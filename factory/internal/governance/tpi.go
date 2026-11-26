// Package governance implements cryptographic Two-Person Integrity (2PI) and
// Separation of Duties (SoD) controls for source approvals.
//
// Threat mitigated (Untrusted Developer / Insider Collusion):
//   A single developer cannot push and approve their own code into the trusted
//   build pipeline. Every source tree digest MUST carry distinct, valid Ed25519
//   signatures from:
//     1. developer         (author submission)
//     2. peer_reviewer     (independent code reviewer, KeyID != developer)
//     3. security_auditor  (independent security approver, KeyID != dev && != reviewer)
package governance

import (
	"encoding/json"
	"fmt"
	"time"

	fcrypto "verifiable-software-factory/factory/internal/crypto"
	"verifiable-software-factory/factory/internal/policy"
)

const ApprovalPayloadType = "aegis.gov/tpi-approval/v1"

// ApprovalStatement is the signed payload attesting a role's review of a source tree.
type ApprovalStatement struct {
	SourceTreeSHA256 string       `json:"sourceTreeSha256"`
	Role             fcrypto.Role `json:"role"`
	ReviewerID       string       `json:"reviewerId"`
	Decision         string       `json:"decision"` // "APPROVED"
	TimestampUTC     string       `json:"timestampUtc"`
	Notes            string       `json:"notes"`
}

// ApprovalBundle holds all signed 2PI approvals for a given source tree digest.
type ApprovalBundle struct {
	SourceTreeSHA256 string                   `json:"sourceTreeSha256"`
	Approvals        []fcrypto.SignedEnvelope `json:"approvals"`
}

// CreateApproval signs a single role's approval for the exact sourceTreeSHA256.
func CreateApproval(sourceTreeSHA256 string, keyRec fcrypto.KeyRecord, reviewerID, notes string) (fcrypto.SignedEnvelope, error) {
	stmt := ApprovalStatement{
		SourceTreeSHA256: sourceTreeSHA256,
		Role:             keyRec.Role,
		ReviewerID:       reviewerID,
		Decision:         "APPROVED",
		TimestampUTC:     time.Now().UTC().Format(time.RFC3339),
		Notes:            notes,
	}
	return fcrypto.SignPayload(ApprovalPayloadType, stmt, keyRec)
}

// VerifyApprovalBundle enforces cryptographic Two-Person Integrity & Separation of Duties.
func VerifyApprovalBundle(bundle ApprovalBundle, expectedSourceSHA256 string, pol policy.TPIPolicy, trustRoots map[fcrypto.Role]fcrypto.KeyRecord) error {
	if bundle.SourceTreeSHA256 != expectedSourceSHA256 {
		return fmt.Errorf("2PI source digest mismatch: bundle=%s expected=%s", bundle.SourceTreeSHA256, expectedSourceSHA256)
	}

	satisfiedRoles := make(map[fcrypto.Role]bool)
	seenPubKeys := make(map[string]fcrypto.Role)
	seenReviewers := make(map[string]fcrypto.Role)

	for _, env := range bundle.Approvals {
		if env.PayloadType != ApprovalPayloadType {
			return fmt.Errorf("unexpected payloadType %q", env.PayloadType)
		}
		if err := fcrypto.VerifyEnvelope(env, env.Role, trustRoots); err != nil {
			return fmt.Errorf("2PI signature check failed for %s: %w", env.Role, err)
		}

		var stmt ApprovalStatement
		if err := json.Unmarshal(env.Payload, &stmt); err != nil {
			return fmt.Errorf("unmarshal approval statement: %w", err)
		}
		if stmt.SourceTreeSHA256 != expectedSourceSHA256 {
			return fmt.Errorf("approval for %s bound to wrong source tree %s (expected %s)", env.Role, stmt.SourceTreeSHA256, expectedSourceSHA256)
		}
		if stmt.Role != env.Role {
			return fmt.Errorf("statement role %q mismatches envelope role %q", stmt.Role, env.Role)
		}
		if stmt.Decision != "APPROVED" {
			return fmt.Errorf("role %s did not approve (decision=%q)", env.Role, stmt.Decision)
		}

		if pol.RequireDistinctKeys {
			if prevRole, dup := seenPubKeys[env.PublicKey]; dup {
				return fmt.Errorf("SEPARATION OF DUTIES VIOLATION: public key reused across %s and %s (self-approval blocked)", prevRole, env.Role)
			}
			seenPubKeys[env.PublicKey] = env.Role

			if prevRole, dup := seenReviewers[stmt.ReviewerID]; dup {
				return fmt.Errorf("SEPARATION OF DUTIES VIOLATION: reviewer identity %q reused across %s and %s (self-approval blocked)", stmt.ReviewerID, prevRole, env.Role)
			}
			seenReviewers[stmt.ReviewerID] = env.Role
		}

		satisfiedRoles[env.Role] = true
	}

	for _, reqRole := range pol.RequiredRoles {
		r := fcrypto.Role(reqRole)
		if !satisfiedRoles[r] {
			return fmt.Errorf("2PI quorum incomplete: missing cryptographic approval from role %q", reqRole)
		}
	}

	return nil
}
