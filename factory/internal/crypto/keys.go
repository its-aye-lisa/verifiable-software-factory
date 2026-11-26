// Package crypto provides role-separated Ed25519 key management, canonical
// JSON signing/verification, and deterministic SHA-256 hashing of files and
// immutable source trees.
//
// In a production government Software Factory, each role's private key resides
// in a separate HSM / hardware security token / OIDC keyless Fulcio enclave so
// untrusted developers NEVER possess builder, clean-room, or release keys.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Role identifies a cryptographically isolated actor in the Software Factory.
type Role string

const (
	RoleDeveloper         Role = "developer"
	RolePeerReviewer      Role = "peer_reviewer"
	RoleSecurityAuditor   Role = "security_auditor"
	RoleFactoryBuilder    Role = "factory_builder"
	RoleCleanRoomVerifier Role = "cleanroom_verifier"
	RoleReleaseAuthority  Role = "release_authority"
)

// AllRoles lists every cryptographically distinct role in the trust chain.
var AllRoles = []Role{
	RoleDeveloper,
	RolePeerReviewer,
	RoleSecurityAuditor,
	RoleFactoryBuilder,
	RoleCleanRoomVerifier,
	RoleReleaseAuthority,
}

// KeyRecord is the on-disk JSON representation of a role's Ed25519 keypair.
type KeyRecord struct {
	Role       Role   `json:"role"`
	KeyID      string `json:"keyId"`
	PublicKey  string `json:"publicKey"`  // base64
	PrivateKey string `json:"privateKey"` // base64 (omitted in public trust bundle)
}

// SignedEnvelope wraps any structured payload with an Ed25519 signature.
// Payload is stored as DSSE-style []byte (base64 in JSON) so pretty-printing
// or re-serializing the outer JSON envelope can never alter the signed bytes.
type SignedEnvelope struct {
	PayloadType string `json:"payloadType"`
	Role        Role   `json:"role"`
	KeyID       string `json:"keyId"`
	PublicKey   string `json:"publicKey"`
	Payload     []byte `json:"payload"`
	Signature   string `json:"signature"` // base64(Ed25519(domain || payload))
}

const signatureDomain = "aegis-verifiable-software-factory-v1:"

// InitKeyStore generates fresh Ed25519 keypairs for all roles in keyDir,
// writing separate private key files (0600) and a public trust-roots.json bundle.
func InitKeyStore(keyDir string) (map[Role]KeyRecord, error) {
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return nil, fmt.Errorf("create keystore dir: %w", err)
	}
	records := make(map[Role]KeyRecord, len(AllRoles))
	publicBundle := make(map[Role]KeyRecord, len(AllRoles))

	for _, role := range AllRoles {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate key for %s: %w", role, err)
		}
		pubSum := sha256.Sum256(pub)
		keyID := fmt.Sprintf("%s:%s", role, hex.EncodeToString(pubSum[:8]))

		rec := KeyRecord{
			Role:       role,
			KeyID:      keyID,
			PublicKey:  base64.StdEncoding.EncodeToString(pub),
			PrivateKey: base64.StdEncoding.EncodeToString(priv),
		}
		records[role] = rec
		publicBundle[role] = KeyRecord{
			Role:      role,
			KeyID:     keyID,
			PublicKey: rec.PublicKey,
		}

		privPath := filepath.Join(keyDir, string(role)+".key.json")
		data, err := json.MarshalIndent(rec, "", "  ")
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(privPath, data, 0o600); err != nil {
			return nil, fmt.Errorf("write private key %s: %w", privPath, err)
		}
	}

	pubData, err := json.MarshalIndent(publicBundle, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(keyDir, "trust-roots.json"), pubData, 0o644); err != nil {
		return nil, fmt.Errorf("write trust-roots.json: %w", err)
	}
	return records, nil
}

// LoadRoleKey loads a single role's private KeyRecord from keyDir.
func LoadRoleKey(keyDir string, role Role) (KeyRecord, error) {
	p := filepath.Join(keyDir, string(role)+".key.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		return KeyRecord{}, fmt.Errorf("load key for %s: %w", role, err)
	}
	var rec KeyRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return KeyRecord{}, fmt.Errorf("parse key for %s: %w", role, err)
	}
	return rec, nil
}

// LoadTrustRoots loads the public key trust-roots.json bundle.
func LoadTrustRoots(keyDir string) (map[Role]KeyRecord, error) {
	p := filepath.Join(keyDir, "trust-roots.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("load trust-roots.json: %w", err)
	}
	var roots map[Role]KeyRecord
	if err := json.Unmarshal(raw, &roots); err != nil {
		return nil, fmt.Errorf("parse trust-roots.json: %w", err)
	}
	return roots, nil
}

// SignPayload marshals payload to compact deterministic JSON and signs it using keyRec.
func SignPayload(payloadType string, payload any, keyRec KeyRecord) (SignedEnvelope, error) {
	privBytes, err := base64.StdEncoding.DecodeString(keyRec.PrivateKey)
	if err != nil || len(privBytes) != ed25519.PrivateKeySize {
		return SignedEnvelope{}, fmt.Errorf("invalid private key for role %s", keyRec.Role)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return SignedEnvelope{}, fmt.Errorf("marshal payload: %w", err)
	}
	msg := append([]byte(signatureDomain+payloadType+":"), raw...)
	sig := ed25519.Sign(ed25519.PrivateKey(privBytes), msg)
	return SignedEnvelope{
		PayloadType: payloadType,
		Role:        keyRec.Role,
		KeyID:       keyRec.KeyID,
		PublicKey:   keyRec.PublicKey,
		Payload:     raw,
		Signature:   base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// VerifyEnvelope cryptographically verifies an envelope's Ed25519 signature
// against the expected trusted public key in trustRoots.
func VerifyEnvelope(env SignedEnvelope, expectedRole Role, trustRoots map[Role]KeyRecord) error {
	if env.Role != expectedRole {
		return fmt.Errorf("role mismatch: envelope has %q, expected %q", env.Role, expectedRole)
	}
	trusted, ok := trustRoots[expectedRole]
	if !ok {
		return fmt.Errorf("no trust root configured for role %q", expectedRole)
	}
	if env.PublicKey != trusted.PublicKey {
		return fmt.Errorf("untrusted public key for role %q (got %s, want %s)", expectedRole, env.KeyID, trusted.KeyID)
	}
	pubBytes, err := base64.StdEncoding.DecodeString(trusted.PublicKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return errors.New("corrupt trusted public key")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return errors.New("malformed signature")
	}
	msg := append([]byte(signatureDomain+env.PayloadType+":"), env.Payload...)
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), msg, sigBytes) {
		return fmt.Errorf("Ed25519 signature verification FAILED for role %q (%s)", expectedRole, env.PayloadType)
	}
	return nil
}

// HashFile computes the lowercase hex SHA-256 digest of a file.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SourceFileDigest records a single source file's normalized relative path and SHA-256.
type SourceFileDigest struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// HashSourceTree deterministically hashes all auditable source & policy inputs
// under repoRoot (excluding transient build outputs, .git, and .factory-state).
func HashSourceTree(repoRoot string) (string, []SourceFileDigest, error) {
	includePaths := []string{
		"go.mod",
		"spec",
		"app",
		"policy",
		"cleanroom",
	}

	var files []string
	for _, rel := range includePaths {
		full := filepath.Join(repoRoot, rel)
		info, err := os.Stat(full)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", nil, err
		}
		if !info.IsDir() {
			files = append(files, filepath.ToSlash(rel))
			continue
		}
		err = filepath.WalkDir(full, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				name := d.Name()
				if strings.HasPrefix(name, ".") {
					return filepath.SkipDir
				}
				return nil
			}
			r, err := filepath.Rel(repoRoot, p)
			if err != nil {
				return err
			}
			files = append(files, filepath.ToSlash(r))
			return nil
		})
		if err != nil {
			return "", nil, err
		}
	}

	sort.Strings(files)
	treeHasher := sha256.New()
	digests := make([]SourceFileDigest, 0, len(files))

	for _, rel := range files {
		full := filepath.Join(repoRoot, filepath.FromSlash(rel))
		st, err := os.Stat(full)
		if err != nil {
			return "", nil, err
		}
		sum, err := HashFile(full)
		if err != nil {
			return "", nil, err
		}
		digests = append(digests, SourceFileDigest{
			Path:   rel,
			SHA256: sum,
			Size:   st.Size(),
		})
		fmt.Fprintf(treeHasher, "%s  %s\n", sum, rel)
	}

	return hex.EncodeToString(treeHasher.Sum(nil)), digests, nil
}
