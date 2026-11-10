package approval

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

type unsignedReceiptWire struct {
	SchemaVersion              int    `json:"schema_version"`
	ReceiptID                  string `json:"receipt_id"`
	Nonce                      string `json:"nonce"`
	ChallengeSHA256            string `json:"challenge_sha256"`
	RegistryRevision           int    `json:"registry_revision"`
	AuthorizationContextSHA256 string `json:"authorization_context_sha256"`
	PlanID                     string `json:"plan_id"`
	PlanSHA256                 string `json:"plan_sha256"`
	ProfileIdentitySHA256      string `json:"profile_identity_sha256"`
	AccountID                  string `json:"account_id"`
	ProjectID                  string `json:"project_id"`
	ProjectKey                 string `json:"project_key"`
	SchemaSHA256               string `json:"schema_sha256"`
	RequestSHA256              string `json:"request_sha256"`
	ExpectedSHA256             string `json:"expected_sha256"`
	IssuedAt                   string `json:"issued_at"`
	ExpiresAt                  string `json:"expires_at"`
	KeyGeneration              string `json:"key_generation"`
	KeyFingerprintSHA256       string `json:"key_fingerprint_sha256"`
}

type receiptWire struct {
	SchemaVersion              int    `json:"schema_version"`
	ReceiptID                  string `json:"receipt_id"`
	Nonce                      string `json:"nonce"`
	ChallengeSHA256            string `json:"challenge_sha256"`
	RegistryRevision           int    `json:"registry_revision"`
	AuthorizationContextSHA256 string `json:"authorization_context_sha256"`
	PlanID                     string `json:"plan_id"`
	PlanSHA256                 string `json:"plan_sha256"`
	ProfileIdentitySHA256      string `json:"profile_identity_sha256"`
	AccountID                  string `json:"account_id"`
	ProjectID                  string `json:"project_id"`
	ProjectKey                 string `json:"project_key"`
	SchemaSHA256               string `json:"schema_sha256"`
	RequestSHA256              string `json:"request_sha256"`
	ExpectedSHA256             string `json:"expected_sha256"`
	IssuedAt                   string `json:"issued_at"`
	ExpiresAt                  string `json:"expires_at"`
	KeyGeneration              string `json:"key_generation"`
	KeyFingerprintSHA256       string `json:"key_fingerprint_sha256"`
	Signature                  string `json:"signature"`
}

const receiptFieldCount = 20

// ReceiptBytes returns the deterministic schema-v3 signed receipt JSON.
// Its field order is part of the cross-language contract.
func ReceiptBytes(receipt Receipt) ([]byte, error) {
	if err := validateReceipt(receipt); err != nil {
		return nil, err
	}
	issuedAt, err := canonicalReceiptTime(receipt.IssuedAt)
	if err != nil {
		return nil, err
	}
	expiresAt, err := canonicalReceiptTime(receipt.ExpiresAt)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(receiptWire{
		SchemaVersion: receipt.SchemaVersion, ReceiptID: receipt.ReceiptID,
		Nonce: receipt.Nonce, ChallengeSHA256: receipt.ChallengeSHA256,
		RegistryRevision: receipt.RegistryRevision, AuthorizationContextSHA256: receipt.AuthorizationContextSHA256,
		PlanID: receipt.PlanID, PlanSHA256: receipt.PlanSHA256,
		ProfileIdentitySHA256: receipt.ProfileIdentitySHA256, AccountID: receipt.AccountID,
		ProjectID: receipt.ProjectID, ProjectKey: receipt.ProjectKey,
		SchemaSHA256: receipt.SchemaSHA256, RequestSHA256: receipt.RequestSHA256,
		ExpectedSHA256: receipt.ExpectedSHA256, IssuedAt: issuedAt, ExpiresAt: expiresAt,
		KeyGeneration:        receipt.KeyGeneration,
		KeyFingerprintSHA256: receipt.KeyFingerprintSHA256, Signature: receipt.Signature,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal signed approval receipt: %w", err)
	}
	if len(raw) > MaxReceiptBytes {
		return nil, receiptError("RECEIPT_INVALID", "the signed approval receipt exceeds the protocol limit")
	}
	return raw, nil
}

// ReceiptDigestSHA256 returns lowercase SHA-256 hex over ReceiptBytes.
func ReceiptDigestSHA256(receipt Receipt) (string, error) {
	raw, err := ReceiptBytes(receipt)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

// ParseReceiptBytes parses only the exact canonical schema-v3 receipt JSON.
// The size check happens before decoder, map, or field allocations.
func ParseReceiptBytes(raw []byte) (Receipt, error) {
	if len(raw) == 0 || len(raw) > MaxReceiptBytes {
		return Receipt{}, receiptError("RECEIPT_INVALID", "the signed approval receipt is empty or exceeds the protocol limit")
	}
	if err := decodeExactReceiptObject(raw); err != nil {
		// Decoder diagnostics can include attacker-controlled field names or values.
		return Receipt{}, receiptError("RECEIPT_INVALID", "the signed approval receipt JSON is not canonical")
	}
	var wire receiptWire
	if err := json.Unmarshal(raw, &wire); err != nil {
		return Receipt{}, receiptError("RECEIPT_INVALID", "the signed approval receipt fields are malformed")
	}
	issuedAt, err := parseCanonicalReceiptTime(wire.IssuedAt)
	if err != nil {
		return Receipt{}, err
	}
	expiresAt, err := parseCanonicalReceiptTime(wire.ExpiresAt)
	if err != nil {
		return Receipt{}, err
	}
	receipt := Receipt{
		SchemaVersion: wire.SchemaVersion, ReceiptID: wire.ReceiptID, Nonce: wire.Nonce,
		ChallengeSHA256:  wire.ChallengeSHA256,
		RegistryRevision: wire.RegistryRevision, AuthorizationContextSHA256: wire.AuthorizationContextSHA256,
		PlanID: wire.PlanID, PlanSHA256: wire.PlanSHA256,
		ProfileIdentitySHA256: wire.ProfileIdentitySHA256, AccountID: wire.AccountID,
		ProjectID: wire.ProjectID, ProjectKey: wire.ProjectKey, SchemaSHA256: wire.SchemaSHA256,
		RequestSHA256: wire.RequestSHA256, ExpectedSHA256: wire.ExpectedSHA256,
		IssuedAt: issuedAt, ExpiresAt: expiresAt, KeyGeneration: wire.KeyGeneration,
		KeyFingerprintSHA256: wire.KeyFingerprintSHA256, Signature: wire.Signature,
	}
	canonical, err := ReceiptBytes(receipt)
	if err != nil {
		return Receipt{}, err
	}
	if !bytes.Equal(canonical, raw) {
		return Receipt{}, receiptError("RECEIPT_INVALID", "the signed approval receipt is not in canonical field order and encoding")
	}
	return receipt, nil
}

func decodeExactReceiptObject(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return fmt.Errorf("receipt must be one JSON object")
	}
	fields := make(map[string]struct{}, receiptFieldCount)
	for decoder.More() {
		nameToken, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("read receipt field name: %w", err)
		}
		name, ok := nameToken.(string)
		if !ok {
			return fmt.Errorf("receipt field name is not a string")
		}
		if !isReceiptFieldName(name) {
			return fmt.Errorf("unknown receipt field %q", name)
		}
		if _, duplicate := fields[name]; duplicate {
			return fmt.Errorf("duplicate receipt field %q", name)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return fmt.Errorf("decode receipt field %q: %w", name, err)
		}
		fields[name] = struct{}{}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return fmt.Errorf("receipt object is truncated")
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("receipt has trailing JSON data")
		}
		return fmt.Errorf("read receipt trailing data: %w", err)
	}
	if len(fields) != receiptFieldCount {
		return fmt.Errorf("receipt does not contain every required field")
	}
	return nil
}

func isReceiptFieldName(name string) bool {
	switch name {
	case "schema_version", "receipt_id", "nonce", "challenge_sha256", "registry_revision", "authorization_context_sha256", "plan_id", "plan_sha256",
		"profile_identity_sha256", "account_id", "project_id", "project_key",
		"schema_sha256", "request_sha256", "expected_sha256", "issued_at",
		"expires_at", "key_generation", "key_fingerprint_sha256", "signature":
		return true
	default:
		return false
	}
}

func parseCanonicalReceiptTime(raw string) (time.Time, error) {
	if len(raw) != len("2006-01-02T15:04:05Z") || raw[len(raw)-1] != 'Z' {
		return time.Time{}, receiptError("RECEIPT_TTL_INVALID", "approval receipt time text must be UTC RFC3339 at whole-second precision")
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil || parsed.Nanosecond() != 0 || parsed.Format(time.RFC3339) != raw {
		return time.Time{}, receiptError("RECEIPT_TTL_INVALID", "approval receipt time text must be UTC RFC3339 at whole-second precision")
	}
	return parsed, nil
}
