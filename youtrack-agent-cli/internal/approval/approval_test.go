package approval

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
)

func TestSigningBytesGoldenVector(t *testing.T) {
	receipt := Receipt{
		SchemaVersion: ReceiptSchemaVersion, ReceiptID: "YTAR-AAAQEAYEAUDAOCAJBIFQYDIOB4", Nonce: "YTAN-6DQNBQFQUCIIA4DAKBADAIAQAA",
		ChallengeSHA256:  "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd",
		RegistryRevision: 1, AuthorizationContextSHA256: strings.Repeat("a", 64),
		PlanID: "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA", PlanSHA256: strings.Repeat("1", 64),
		ProfileIdentitySHA256: strings.Repeat("2", 64), AccountID: "1-2", ProjectID: "0-1", ProjectKey: "APP",
		SchemaSHA256: strings.Repeat("3", 64), RequestSHA256: strings.Repeat("4", 64), ExpectedSHA256: strings.Repeat("5", 64),
		IssuedAt:      time.Date(2026, 9, 2, 15, 34, 56, 0, time.UTC),
		ExpiresAt:     time.Date(2026, 9, 2, 15, 39, 56, 0, time.UTC),
		KeyGeneration: "YTAG-00000000000000000001", KeyFingerprintSHA256: strings.Repeat("6", 64), Signature: "MAYCAQECAQI",
	}
	got, err := SigningBytes(receipt)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema_version":3,"receipt_id":"YTAR-AAAQEAYEAUDAOCAJBIFQYDIOB4","nonce":"YTAN-6DQNBQFQUCIIA4DAKBADAIAQAA","challenge_sha256":"630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd","registry_revision":1,"authorization_context_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","plan_id":"YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA","plan_sha256":"1111111111111111111111111111111111111111111111111111111111111111","profile_identity_sha256":"2222222222222222222222222222222222222222222222222222222222222222","account_id":"1-2","project_id":"0-1","project_key":"APP","schema_sha256":"3333333333333333333333333333333333333333333333333333333333333333","request_sha256":"4444444444444444444444444444444444444444444444444444444444444444","expected_sha256":"5555555555555555555555555555555555555555555555555555555555555555","issued_at":"2026-09-02T15:34:56Z","expires_at":"2026-09-02T15:39:56Z","key_generation":"YTAG-00000000000000000001","key_fingerprint_sha256":"6666666666666666666666666666666666666666666666666666666666666666"}`
	if string(got) != want {
		t.Fatalf("signing bytes changed\n got: %s\nwant: %s", got, want)
	}
}

func TestUnsupportedAlwaysFailsClosed(t *testing.T) {
	_, err := (Unsupported{}).Confirm(context.Background(), []byte("immutable"))
	assertPresenceUnavailable(t, err)
}

func assertPresenceUnavailable(t *testing.T, err error) {
	t.Helper()
	var typed *errx.Error
	if !errors.As(err, &typed) || typed.Reason != "USER_PRESENCE_UNAVAILABLE" || typed.Code != errx.CodeConfirm {
		t.Fatalf("error = %#v", err)
	}
}
