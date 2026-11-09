package approval

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSharedGate1AFixturesMatchGoCodecs(t *testing.T) {
	signing := receiptV3Fixture(t, "signing.json")
	receiptBytes := receiptV3Fixture(t, "receipt.json")
	receipt, err := ParseReceiptBytes(receiptBytes)
	if err != nil {
		t.Fatal(err)
	}

	gotSigning, err := SigningBytes(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotSigning, signing) {
		t.Fatalf("SigningBytes() differs from shared fixture\n got: %s\nwant: %s", gotSigning, signing)
	}
	gotReceipt, err := ReceiptBytes(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotReceipt, receiptBytes) {
		t.Fatalf("ReceiptBytes() differs from shared fixture\n got: %s\nwant: %s", gotReceipt, receiptBytes)
	}
	gotDigest, err := ReceiptDigestSHA256(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if want := string(receiptV3Fixture(t, "receipt.sha256")); gotDigest != want {
		t.Fatalf("ReceiptDigestSHA256() = %q, want %q", gotDigest, want)
	}
	if got := sha256HexForTest(gotSigning); got != string(receiptV3Fixture(t, "signing.sha256")) {
		t.Fatalf("signing digest = %q, want fixture", got)
	}

	signature := mustDecodeHex(t, sharedGate1AFixture(t, "signature.der.hex"))
	encoded, err := EncodeP256DERSignature(signature)
	if err != nil {
		t.Fatal(err)
	}
	if want := string(sharedGate1AFixture(t, "signature.base64url")); encoded != want {
		t.Fatalf("encoded signature = %q, want %q", encoded, want)
	}
	decoded, err := DecodeP256DERSignature(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, signature) {
		t.Fatalf("decoded signature = %x, want %x", decoded, signature)
	}

	x963 := mustDecodeHex(t, sharedGate1AFixture(t, "public-key.x963.hex"))
	spki := mustDecodeHex(t, sharedGate1AFixture(t, "public-key.spki.hex"))
	gotSPKI, err := P256X963ToDERSPKI(x963)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotSPKI, spki) {
		t.Fatalf("SPKI = %x, want shared fixture", gotSPKI)
	}
	gotX963, err := P256DERSPKIToX963(spki)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotX963, x963) {
		t.Fatalf("X9.63 = %x, want shared fixture", gotX963)
	}
	fingerprint, err := P256SPKIFingerprintSHA256(spki)
	if err != nil {
		t.Fatal(err)
	}
	if want := string(sharedGate1AFixture(t, "public-key.fingerprint-sha256")); fingerprint != want {
		t.Fatalf("fingerprint = %q, want %q", fingerprint, want)
	}

	display := mustDecodeHex(t, sharedGate1AFixture(t, "display.hex"))
	if got, want := sha256HexForTest(display), string(sharedGate1AFixture(t, "display.sha256")); got != want {
		t.Fatalf("display digest = %q, want %q", got, want)
	}
}

func TestValidateApprovalDisplayBytesBoundaries(t *testing.T) {
	tests := []struct {
		name    string
		size    int
		wantErr bool
	}{
		{name: "empty", size: 0, wantErr: true},
		{name: "one byte", size: 1},
		{name: "exact maximum", size: MaxApprovalDisplayBytes},
		{name: "one over maximum", size: MaxApprovalDisplayBytes + 1, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateApprovalDisplayBytes(bytes.Repeat([]byte{'x'}, tt.size))
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateApprovalDisplayBytes(size=%d) error = %v, wantErr %v", tt.size, err, tt.wantErr)
			}
		})
	}
}

func TestReceiptIdentifiersRequireCanonical128BitBase32(t *testing.T) {
	valid := gate1AReceipt(t)
	tests := []struct {
		name   string
		mutate func(*Receipt)
	}{
		{name: "receipt wrong prefix", mutate: func(r *Receipt) { r.ReceiptID = "NOPE-AAAQEAYEAUDAOCAJBIFQYDIOB4" }},
		{name: "receipt short payload", mutate: func(r *Receipt) { r.ReceiptID = "YTAR-AAAQEAYEAUDAOCAJBIFQYDIOB" }},
		{name: "receipt lowercase", mutate: func(r *Receipt) { r.ReceiptID = "YTAR-aaaQEAYEAUDAOCAJBIFQYDIOB4" }},
		{name: "receipt padded", mutate: func(r *Receipt) { r.ReceiptID = "YTAR-AAAQEAYEAUDAOCAJBIFQYDIOB=" }},
		{name: "receipt noncanonical final bits", mutate: func(r *Receipt) { r.ReceiptID = "YTAR-AAAQEAYEAUDAOCAJBIFQYDIOB5" }},
		{name: "nonce wrong prefix", mutate: func(r *Receipt) { r.Nonce = "YTAR-6DQNBQFQUCIIA4DAKBADAIAQAA" }},
		{name: "nonce noncanonical final bits", mutate: func(r *Receipt) { r.Nonce = "YTAN-6DQNBQFQUCIIA4DAKBADAIAQAB" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			receipt := valid
			tt.mutate(&receipt)
			if _, err := SigningBytes(receipt); err == nil {
				t.Fatal("SigningBytes() accepted non-canonical identifier")
			}
		})
	}
}

func TestReceiptTimeAndTTLBoundaries(t *testing.T) {
	valid := gate1AReceipt(t)
	tests := []struct {
		name   string
		mutate func(*Receipt)
	}{
		{name: "fractional issue time", mutate: func(r *Receipt) { r.IssuedAt = r.IssuedAt.Add(time.Nanosecond) }},
		{name: "fractional expiry time", mutate: func(r *Receipt) { r.ExpiresAt = r.ExpiresAt.Add(time.Nanosecond) }},
		{name: "non UTC issue time", mutate: func(r *Receipt) { r.IssuedAt = r.IssuedAt.In(time.FixedZone("offset", 3600)) }},
		{name: "non UTC expiry time", mutate: func(r *Receipt) { r.ExpiresAt = r.ExpiresAt.In(time.FixedZone("offset", 3600)) }},
		{name: "year zero", mutate: func(r *Receipt) { r.IssuedAt = time.Date(0, 9, 2, 15, 34, 56, 0, time.UTC) }},
		{name: "zero TTL", mutate: func(r *Receipt) { r.ExpiresAt = r.IssuedAt }},
		{name: "negative TTL", mutate: func(r *Receipt) { r.ExpiresAt = r.IssuedAt.Add(-time.Second) }},
		{name: "one second over maximum", mutate: func(r *Receipt) { r.ExpiresAt = r.IssuedAt.Add(MaximumReceiptTTL + time.Second) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			receipt := valid
			tt.mutate(&receipt)
			if _, err := SigningBytes(receipt); err == nil {
				t.Fatal("SigningBytes() accepted invalid timestamp or TTL")
			}
		})
	}
	for _, ttl := range []time.Duration{time.Second, MaximumReceiptTTL} {
		receipt := valid
		receipt.ExpiresAt = receipt.IssuedAt.Add(ttl)
		if _, err := SigningBytes(receipt); err != nil {
			t.Fatalf("SigningBytes() rejected valid TTL %s: %v", ttl, err)
		}
	}
}

func TestReceiptKeyGenerationBoundaries(t *testing.T) {
	valid := gate1AReceipt(t)
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "revision one", value: "YTAG-00000000000000000001"},
		{name: "legacy short", value: "a", wantErr: true},
		{name: "legacy punctuation", value: "A0._-z", wantErr: true},
		{name: "zero", value: "YTAG-00000000000000000000", wantErr: true},
		{name: "greater than receipt revision", value: "YTAG-00000000000000000002", wantErr: true},
		{name: "overflow", value: "YTAG-99999999999999999999", wantErr: true},
		{name: "24 bytes nineteen digits", value: "YTAG-0000000000000000001", wantErr: true},
		{name: "26 bytes twenty-one digits", value: "YTAG-000000000000000000001", wantErr: true},
		{name: "empty", value: "", wantErr: true},
		{name: "punctuation first", value: "-key", wantErr: true},
		{name: "colon", value: "key:1", wantErr: true},
		{name: "non ASCII", value: "kéy", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			receipt := valid
			receipt.KeyGeneration = tt.value
			_, err := SigningBytes(receipt)
			if (err != nil) != tt.wantErr {
				t.Fatalf("SigningBytes(key_generation=%q) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
		})
	}
}

func TestParseReceiptBytesRejectsNonCanonicalJSON(t *testing.T) {
	valid := receiptV3Fixture(t, "receipt.json")
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "empty", raw: nil},
		{name: "oversized before parsing", raw: bytes.Repeat([]byte{' '}, MaxReceiptBytes+1)},
		{name: "non object", raw: []byte(`[]`)},
		{name: "missing field", raw: bytes.Replace(valid, []byte(`,"signature":"MAYCAQECAQI"`), nil, 1)},
		{name: "duplicate field", raw: bytes.Replace(valid, []byte(`{"schema_version":3`), []byte(`{"schema_version":3,"schema_version":3`), 1)},
		{name: "unknown field", raw: bytes.Replace(valid, []byte(`,"signature":`), []byte(`,"unknown":"x","signature":`), 1)},
		{name: "reordered fields", raw: bytes.Replace(valid, []byte(`{"schema_version":3,"receipt_id":"YTAR-AAAQEAYEAUDAOCAJBIFQYDIOB4"`), []byte(`{"receipt_id":"YTAR-AAAQEAYEAUDAOCAJBIFQYDIOB4","schema_version":3`), 1)},
		{name: "leading whitespace", raw: append([]byte(" "), valid...)},
		{name: "internal whitespace", raw: bytes.Replace(valid, []byte(`,"receipt_id"`), []byte(`, "receipt_id"`), 1)},
		{name: "trailing whitespace", raw: append(append([]byte(nil), valid...), ' ')},
		{name: "trailing JSON", raw: append(append([]byte(nil), valid...), []byte(`{}`)...)},
		{name: "alternate slash escape", raw: bytes.Replace(valid, []byte(`"account_id":"1-2"`), []byte(`"account_id":"1\u002d2"`), 1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseReceiptBytes(tt.raw); err == nil {
				t.Fatal("ParseReceiptBytes() accepted non-canonical JSON")
			}
		})
	}
	if _, err := ParseReceiptBytes(valid); err != nil {
		t.Fatalf("ParseReceiptBytes() rejected canonical fixture: %v", err)
	}
}

func TestP256DERSignatureRejectsMalformedEncodings(t *testing.T) {
	order := "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
	tests := []struct {
		name string
		hex  string
	}{
		{name: "empty", hex: ""},
		{name: "truncated", hex: "30060201010201"},
		{name: "trailing byte", hex: "300602010102010200"},
		{name: "zero r", hex: "3006020100020101"},
		{name: "zero s", hex: "3006020101020100"},
		{name: "negative r", hex: "3006020180020101"},
		{name: "redundant leading zero", hex: "300702020001020101"},
		{name: "r equals curve order", hex: "3026022100" + order + "020101"},
		{name: "s equals curve order", hex: "3026020101022100" + order},
		{name: "high-S twin", hex: "3026020101022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f"},
		{name: "oversized", hex: strings.Repeat("00", maxP256DERSignatureBytes+1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateP256DERSignature(mustDecodeHex(t, []byte(tt.hex))); err == nil {
				t.Fatal("ValidateP256DERSignature() accepted malformed signature")
			}
		})
	}

	valid := string(sharedGate1AFixture(t, "signature.base64url"))
	for _, encoded := range []string{"", valid + "=", "MAYCAQECAQI+", strings.Repeat("A", 98)} {
		if _, err := DecodeP256DERSignature(encoded); err == nil {
			t.Fatalf("DecodeP256DERSignature(%q) accepted invalid base64url", encoded)
		}
	}
}

func TestP256PublicKeyCodecRejectsTampering(t *testing.T) {
	x963 := mustDecodeHex(t, sharedGate1AFixture(t, "public-key.x963.hex"))
	spki := mustDecodeHex(t, sharedGate1AFixture(t, "public-key.spki.hex"))
	tests := []struct {
		name string
		x963 []byte
	}{
		{name: "empty", x963: nil},
		{name: "compressed marker", x963: append([]byte{0x02}, x963[1:]...)},
		{name: "short", x963: x963[:len(x963)-1]},
		{name: "off curve", x963: append([]byte{0x04}, make([]byte, 64)...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := P256X963ToDERSPKI(tt.x963); err == nil {
				t.Fatal("P256X963ToDERSPKI() accepted invalid point")
			}
		})
	}

	for _, mutated := range [][]byte{
		spki[:len(spki)-1],
		append([]byte{0x31}, spki[1:]...),
		append(append([]byte(nil), spki...), 0),
	} {
		if _, err := P256DERSPKIToX963(mutated); err == nil {
			t.Fatal("P256DERSPKIToX963() accepted tampered SPKI")
		}
		if _, err := P256SPKIFingerprintSHA256(mutated); err == nil {
			t.Fatal("P256SPKIFingerprintSHA256() accepted tampered SPKI")
		}
	}

	x, y := elliptic.P256().ScalarBaseMult([]byte{2})
	alternate := elliptic.Marshal(elliptic.P256(), x, y)
	alternateSPKI, err := P256X963ToDERSPKI(alternate)
	if err != nil {
		t.Fatal(err)
	}
	fixtureFingerprint := string(sharedGate1AFixture(t, "public-key.fingerprint-sha256"))
	alternateFingerprint, err := P256SPKIFingerprintSHA256(alternateSPKI)
	if err != nil {
		t.Fatal(err)
	}
	if alternateFingerprint == fixtureFingerprint {
		t.Fatal("fingerprint did not bind the exact public key")
	}
}

func gate1AReceipt(t *testing.T) Receipt {
	t.Helper()
	receipt, err := ParseReceiptBytes(receiptV3Fixture(t, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func sharedGate1AFixture(t *testing.T, name string) []byte {
	t.Helper()
	return readApprovalFixture(t, "gate1a", name)
}

func receiptV3Fixture(t *testing.T, name string) []byte {
	t.Helper()
	return readApprovalFixture(t, "gate1a-v3", name)
}

func readApprovalFixture(t *testing.T, directory, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", directory, name))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		t.Fatalf("fixture %q must end with one LF", name)
	}
	return append([]byte(nil), raw[:len(raw)-1]...)
}

func mustDecodeHex(t *testing.T, raw []byte) []byte {
	t.Helper()
	decoded := make([]byte, hex.DecodedLen(len(raw)))
	count, err := hex.Decode(decoded, raw)
	if err != nil {
		t.Fatal(err)
	}
	return decoded[:count]
}

func sha256HexForTest(raw []byte) string {
	// Keep the test helper local so production remains the only receipt digest
	// implementation under test.
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
