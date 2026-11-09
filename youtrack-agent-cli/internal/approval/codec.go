package approval

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/abigotado/youtrack-agent-cli/internal/protocolvalue"
)

const (
	receiptIDPrefix          = "YTAR-"
	noncePrefix              = "YTAN-"
	maxP256DERSignatureBytes = 72
	p256X963Bytes            = 65
	p256DERSPKIBytes         = 91
	p256DERSPKIPrefix        = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00"
)

type p256Signature struct {
	R *big.Int
	S *big.Int
}

// DecodeP256DERSignature decodes canonical unpadded base64url text containing
// one strict ASN.1 DER ECDSA P-256 signature. It rejects non-minimal integers,
// zero/out-of-range scalars, trailing bytes, and non-canonical base64url.
func DecodeP256DERSignature(encoded string) ([]byte, error) {
	if encoded == "" || len(encoded) > base64.RawURLEncoding.EncodedLen(maxP256DERSignatureBytes) {
		return nil, fmt.Errorf("P-256 signature text is empty or oversized")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return nil, fmt.Errorf("P-256 signature is not canonical unpadded base64url")
	}
	if err := ValidateP256DERSignature(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// EncodeP256DERSignature validates and encodes a strict DER signature as
// canonical unpadded base64url.
func EncodeP256DERSignature(signature []byte) (string, error) {
	if err := ValidateP256DERSignature(signature); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(signature), nil
}

// ValidateP256DERSignature enforces the protocol-v2 DER representation.
func ValidateP256DERSignature(signature []byte) error {
	if len(signature) == 0 || len(signature) > maxP256DERSignatureBytes {
		return fmt.Errorf("P-256 DER signature is empty or exceeds %d bytes", maxP256DERSignatureBytes)
	}
	var decoded p256Signature
	rest, err := asn1.Unmarshal(signature, &decoded)
	if err != nil || len(rest) != 0 || decoded.R == nil || decoded.S == nil {
		return fmt.Errorf("P-256 signature is not one complete DER sequence")
	}
	order := elliptic.P256().Params().N
	if decoded.R.Sign() <= 0 || decoded.S.Sign() <= 0 || decoded.R.Cmp(order) >= 0 || decoded.S.Cmp(order) >= 0 {
		return fmt.Errorf("P-256 signature scalar is outside the valid range")
	}
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(order), 1)
	if decoded.S.Cmp(halfOrder) > 0 {
		return fmt.Errorf("P-256 signature must use canonical low-S form")
	}
	canonical, err := asn1.Marshal(decoded)
	if err != nil {
		return fmt.Errorf("re-encode P-256 DER signature: %w", err)
	}
	if !bytes.Equal(canonical, signature) {
		return fmt.Errorf("P-256 signature DER is not minimally encoded")
	}
	return nil
}

// P256X963ToDERSPKI converts an exact uncompressed 65-byte P-256 ANSI X9.63
// public point to the protocol-v2 91-byte DER SubjectPublicKeyInfo form.
func P256X963ToDERSPKI(x963 []byte) ([]byte, error) {
	if err := validateP256X963(x963); err != nil {
		return nil, err
	}
	spki := make([]byte, 0, p256DERSPKIBytes)
	spki = append(spki, p256DERSPKIPrefix...)
	spki = append(spki, x963...)
	return spki, nil
}

// P256DERSPKIToX963 validates the exact protocol-v2 SPKI prefix and returns
// its uncompressed P-256 point.
func P256DERSPKIToX963(spki []byte) ([]byte, error) {
	if len(spki) != p256DERSPKIBytes || string(spki[:len(p256DERSPKIPrefix)]) != p256DERSPKIPrefix {
		return nil, fmt.Errorf("P-256 SPKI must use the exact protocol-v2 DER encoding")
	}
	x963 := spki[len(p256DERSPKIPrefix):]
	if err := validateP256X963(x963); err != nil {
		return nil, err
	}
	return append([]byte(nil), x963...), nil
}

// P256SPKIFingerprintSHA256 returns lowercase SHA-256 hex over the exact
// validated 91-byte DER SubjectPublicKeyInfo representation.
func P256SPKIFingerprintSHA256(spki []byte) (string, error) {
	if _, err := P256DERSPKIToX963(spki); err != nil {
		return "", err
	}
	digest := sha256.Sum256(spki)
	return hex.EncodeToString(digest[:]), nil
}

func validateP256X963(x963 []byte) error {
	if len(x963) != p256X963Bytes || x963[0] != 0x04 {
		return fmt.Errorf("P-256 public key must be a 65-byte uncompressed X9.63 point")
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), x963)
	if x == nil || y == nil || !elliptic.P256().IsOnCurve(x, y) {
		return fmt.Errorf("P-256 X9.63 public point is not on the curve")
	}
	return nil
}

func validateCanonicalApprovalID(value, prefix string) error {
	return protocolvalue.ValidateCanonicalBase32ID(value, prefix)
}

func isCanonicalIdentifier(value string) bool {
	return protocolvalue.IsIdentifier(value)
}

func isCanonicalProjectKey(value string) bool {
	return protocolvalue.IsProjectKey(value)
}

func isCanonicalKeyGeneration(value string) bool {
	return keyGenerationRevision(value) != 0
}
