// Package approval defines the trusted-user-presence boundary for guarded
// mutations. The first release intentionally supplies only a fail-closed
// adapter; receipt types and verification are ready for a separately signed
// native helper once Gate 1A is proven.
package approval

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/intent"
	"github.com/abigotado/youtrack-agent-cli/internal/protocolvalue"
)

const (
	// ReceiptSchemaVersion is the current durable approval receipt schema.
	ReceiptSchemaVersion = 3
	// MaxApprovalDisplayBytes bounds the immutable canonical plan snapshot.
	MaxApprovalDisplayBytes = intent.MaxCanonicalPlanBytes
	// MaxReceiptBytes bounds one canonical signed receipt.
	MaxReceiptBytes = 4 << 10
	// MaxSigningBytes bounds the canonical unsigned receipt signed by the helper.
	MaxSigningBytes = 3 << 10
	// MaxKeyGenerationBytes is the exact width of YTAG- plus twenty decimal digits.
	MaxKeyGenerationBytes = 25
	// MaxRegistryRevision is the largest supported receipt registry revision.
	MaxRegistryRevision = 256
	// MaximumReceiptTTL is the longest receipt lifetime accepted by schema v3.
	MaximumReceiptTTL = 5 * time.Minute

	defaultClockSkew = 30 * time.Second
)

// Receipt is a non-secret, short-lived signed binding to one exact plan.
type Receipt struct {
	SchemaVersion              int       `json:"schema_version"`
	ReceiptID                  string    `json:"receipt_id"`
	Nonce                      string    `json:"nonce"`
	ChallengeSHA256            string    `json:"challenge_sha256"`
	RegistryRevision           int       `json:"registry_revision"`
	AuthorizationContextSHA256 string    `json:"authorization_context_sha256"`
	PlanID                     string    `json:"plan_id"`
	PlanSHA256                 string    `json:"plan_sha256"`
	ProfileIdentitySHA256      string    `json:"profile_identity_sha256"`
	AccountID                  string    `json:"account_id"`
	ProjectID                  string    `json:"project_id"`
	ProjectKey                 string    `json:"project_key"`
	SchemaSHA256               string    `json:"schema_sha256"`
	RequestSHA256              string    `json:"request_sha256"`
	ExpectedSHA256             string    `json:"expected_sha256"`
	IssuedAt                   time.Time `json:"issued_at"`
	ExpiresAt                  time.Time `json:"expires_at"`
	KeyGeneration              string    `json:"key_generation"`
	KeyFingerprintSHA256       string    `json:"key_fingerprint_sha256"`
	Signature                  string    `json:"signature"`
}

// Approver displays one immutable canonical plan snapshot. A successful helper
// hashes those exact bytes into Receipt.PlanSHA256, constructs the remaining
// receipt fields, and signs the exact unsigned-receipt bytes from SigningBytes.
type Approver interface {
	Confirm(ctx context.Context, canonicalPlan []byte) (Receipt, error)
}

// SigningBytes returns the deterministic signature message. The helper first
// displays the canonical plan bytes, stores SHA256(displayed bytes) in
// PlanSHA256, then signs this unsigned-receipt encoding. Signature is excluded.
func SigningBytes(receipt Receipt) ([]byte, error) {
	if err := validateUnsignedReceipt(receipt); err != nil {
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
	raw, err := json.Marshal(unsignedReceiptWire{
		SchemaVersion: receipt.SchemaVersion, ReceiptID: receipt.ReceiptID, Nonce: receipt.Nonce,
		ChallengeSHA256:  receipt.ChallengeSHA256,
		RegistryRevision: receipt.RegistryRevision, AuthorizationContextSHA256: receipt.AuthorizationContextSHA256,
		PlanID: receipt.PlanID, PlanSHA256: receipt.PlanSHA256,
		ProfileIdentitySHA256: receipt.ProfileIdentitySHA256, AccountID: receipt.AccountID,
		ProjectID: receipt.ProjectID, ProjectKey: receipt.ProjectKey, SchemaSHA256: receipt.SchemaSHA256,
		RequestSHA256: receipt.RequestSHA256, ExpectedSHA256: receipt.ExpectedSHA256,
		IssuedAt: issuedAt, ExpiresAt: expiresAt,
		KeyGeneration: receipt.KeyGeneration, KeyFingerprintSHA256: receipt.KeyFingerprintSHA256,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal unsigned approval receipt: %w", err)
	}
	if len(raw) > MaxSigningBytes {
		return nil, receiptError("RECEIPT_INVALID", "the approval signing message exceeds the protocol limit")
	}
	return raw, nil
}

// ValidateApprovalDisplayBytes applies the v2 byte bound before a native
// helper copies, decodes, or renders an immutable approval snapshot.
func ValidateApprovalDisplayBytes(canonicalPlan []byte) error {
	if len(canonicalPlan) == 0 || len(canonicalPlan) > MaxApprovalDisplayBytes {
		return receiptError("APPROVAL_DISPLAY_INVALID", "the approval display snapshot is empty or exceeds the protocol limit")
	}
	return nil
}

// Unsupported is the mandatory adapter until Gate 1A proves a trusted helper.
// It has no terminal, environment, stdin, or command-line confirmation path.
type Unsupported struct{}

func (Unsupported) Confirm(ctx context.Context, canonicalPlan []byte) (Receipt, error) {
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	return Receipt{}, userPresenceUnavailable()
}

func validateReceipt(receipt Receipt) error {
	if err := validateUnsignedReceipt(receipt); err != nil {
		return err
	}
	if _, err := DecodeP256DERSignature(receipt.Signature); err != nil {
		return receiptError("RECEIPT_SIGNATURE_INVALID", "the approval receipt signature is malformed")
	}
	return nil
}

func validateUnsignedReceipt(receipt Receipt) error {
	if receipt.SchemaVersion != ReceiptSchemaVersion || validateCanonicalApprovalID(receipt.ReceiptID, receiptIDPrefix) != nil || validateCanonicalApprovalID(receipt.Nonce, noncePrefix) != nil {
		return receiptError("RECEIPT_INVALID", "the approval receipt identifiers or schema are invalid")
	}
	if intent.ValidatePlanID(receipt.PlanID) != nil || !isCanonicalIdentifier(receipt.AccountID) || !isCanonicalIdentifier(receipt.ProjectID) || !isCanonicalProjectKey(receipt.ProjectKey) {
		return receiptError("RECEIPT_INVALID", "the approval receipt contains a non-canonical plan, account, or project binding")
	}
	if _, err := canonicalReceiptTime(receipt.IssuedAt); err != nil {
		return err
	}
	if _, err := canonicalReceiptTime(receipt.ExpiresAt); err != nil {
		return err
	}
	if !receipt.ExpiresAt.After(receipt.IssuedAt) || receipt.ExpiresAt.Sub(receipt.IssuedAt) > MaximumReceiptTTL {
		return receiptError("RECEIPT_TTL_INVALID", "the approval receipt time window is invalid")
	}
	for _, value := range []string{receipt.AuthorizationContextSHA256, receipt.ChallengeSHA256, receipt.PlanSHA256, receipt.ProfileIdentitySHA256, receipt.SchemaSHA256, receipt.RequestSHA256, receipt.ExpectedSHA256, receipt.KeyFingerprintSHA256} {
		if !isSHA256(value) {
			return receiptError("RECEIPT_INVALID", "the approval receipt contains a non-canonical digest")
		}
	}
	if !validRegistryRevision(receipt.RegistryRevision) || keyGenerationRevision(receipt.KeyGeneration) != receipt.RegistryRevision {
		return receiptError("RECEIPT_INVALID", "the approval receipt key generation is not canonical")
	}
	return nil
}

func canonicalReceiptTime(value time.Time) (string, error) {
	if value.IsZero() || value.Year() < 1 || value.Year() > 9999 || value.Nanosecond() != 0 {
		return "", receiptError("RECEIPT_TTL_INVALID", "approval receipt times must use whole seconds")
	}
	_, offset := value.Zone()
	if offset != 0 {
		return "", receiptError("RECEIPT_TTL_INVALID", "approval receipt times must use UTC")
	}
	encoded := value.UTC().Format(time.RFC3339)
	if len(encoded) != len("2006-01-02T15:04:05Z") {
		return "", receiptError("RECEIPT_TTL_INVALID", "approval receipt times must use four-digit RFC3339 years")
	}
	return encoded, nil
}

func isSHA256(value string) bool {
	return protocolvalue.IsSHA256(value)
}

func receiptError(reason, message string) *errx.Error {
	return &errx.Error{Code: errx.CodeConfirm, Reason: reason, Message: message, Hint: "discard the receipt and obtain a fresh trusted approval"}
}

func userPresenceUnavailable() *errx.Error {
	return &errx.Error{
		Code: errx.CodeConfirm, Reason: "USER_PRESENCE_UNAVAILABLE",
		Message: "trusted user-presence approval is unavailable because Gate 1A has not passed",
		Hint:    "do not apply the mutation; use prepare/status only until the signed native helper is approved",
	}
}
