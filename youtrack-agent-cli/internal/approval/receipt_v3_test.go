package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/intent"
)

func expectedReceiptBindingForTest(t *testing.T) *ExpectedReceiptBinding {
	t.Helper()
	binding, err := NewExpectedReceiptBinding(1, repeatHex('a'))
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func TestSharedReceiptV3RevisionCorpus(t *testing.T) {
	var cases []struct {
		Name     string `json:"name"`
		Accepted bool   `json:"accepted"`
		Signing  string `json:"signing"`
		Receipt  string `json:"receipt"`
	}
	if err := json.Unmarshal(receiptV3Fixture(t, "revision-boundaries.json"), &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) != 3 {
		t.Fatal("expected three revision boundary vectors")
	}
	for _, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			receipt, err := ParseReceiptBytes([]byte(test.Receipt))
			if (err == nil) != test.Accepted {
				t.Fatalf("receipt accepted=%v, want %v: %v", err == nil, test.Accepted, err)
			}
			if test.Accepted {
				signing, err := SigningBytes(receipt)
				if err != nil || string(signing) != test.Signing {
					t.Fatalf("signing vector mismatch: %v", err)
				}
			} else {
				// Go has no public unsigned parser; decode the literal signing
				// fields into Receipt, then exercise its public signing validator.
				var unsigned Receipt
				if err := json.Unmarshal([]byte(test.Signing), &unsigned); err != nil {
					t.Fatal(err)
				}
				if _, err := SigningBytes(unsigned); err == nil {
					t.Fatal("invalid unsigned vector accepted")
				}
			}
		})
	}
	spki := mustDecodeHex(t, sharedGate1AFixture(t, "public-key.spki.hex"))
	if _, err := NewExpectedSigningKey("YTAG-00000000000000000257", spki, string(sharedGate1AFixture(t, "public-key.fingerprint-sha256"))); err == nil {
		t.Fatal("standalone generation 257 accepted")
	}
}

func TestIPCFailureUnionDoesNotRequireMatchingSigningRevision(t *testing.T) {
	snapshot, key := fixtureSnapshotAndKey(t)
	binding, err := NewExpectedReceiptBinding(2, repeatHex('a'))
	if err != nil {
		t.Fatal(err)
	}
	challenge := ipcChallengeForTest()
	for _, code := range []IPCErrorCode{IPCErrorUserCanceled, IPCErrorRequestInvalid, IPCErrorUserPresenceUnavailable, IPCErrorKeyUnavailable, IPCErrorSigningFailed, IPCErrorInternalFailure} {
		t.Run(strconv.Itoa(int(code)), func(t *testing.T) {
			raw, err := EncodeIPCFailure(IPCFailure{Challenge: challenge, Code: code})
			if err != nil {
				t.Fatal(err)
			}
			response, err := DecodeAndValidateIPCResponse(context.Background(), raw, challenge, snapshot, key, binding, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			failure, ok := response.HelperError()
			if !ok || failure.Code != code {
				t.Fatalf("wrong failure union: %#v", response)
			}
			if _, ok := response.VerifiedReceipt(); ok {
				t.Fatal("failure exposed receipt")
			}
			wrongChallenge := challenge
			wrongChallenge[0] ^= 1
			_, err = DecodeAndValidateIPCResponse(context.Background(), raw, wrongChallenge, snapshot, key, binding, time.Now())
			assertReason(t, err, "APPROVAL_CHALLENGE_MISMATCH")
			unknown := append([]byte(nil), raw...)
			unknown[len(unknown)-1] = 255
			for _, malformed := range [][]byte{raw[:len(raw)-1], append(append([]byte(nil), raw...), 0), unknown} {
				_, err := DecodeAndValidateIPCResponse(context.Background(), malformed, challenge, snapshot, key, binding, time.Now())
				assertReason(t, err, "APPROVAL_RESPONSE_INVALID")
			}
		})
	}
	issued := time.Date(2026, 9, 2, 15, 34, 56, 0, time.UTC)
	raw, signingKey := signedResponseForTest(t, snapshot, challenge, issued, issued.Add(2*time.Minute), nil)
	_, err = DecodeAndValidateIPCResponse(context.Background(), raw, challenge, snapshot, signingKey, binding, issued.Add(time.Minute))
	assertReason(t, err, "APPROVAL_SIGNING_KEY_MISMATCH")
}

func TestReceiptV3RevisionAndAuthorizationContextBoundaries(t *testing.T) {
	for _, revision := range []int{1, 256} {
		t.Run(strconv.Itoa(revision), func(t *testing.T) {
			receipt := gate1AReceipt(t)
			receipt.RegistryRevision = revision
			receipt.KeyGeneration = "YTAG-" + strings.Repeat("0", 20-len(strconv.Itoa(revision))) + strconv.Itoa(revision)
			raw, err := ReceiptBytes(receipt)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseReceiptBytes(raw)
			if err != nil || got.RegistryRevision != revision || got.AuthorizationContextSHA256 != repeatHex('a') {
				t.Fatalf("boundary receipt = %#v, %v", got, err)
			}
			binding, err := NewExpectedReceiptBinding(revision, repeatHex('a'))
			if err != nil || binding.RegistryRevision() != revision || binding.AuthorizationContextSHA256() != repeatHex('a') {
				t.Fatalf("expected binding boundary rejected: %v", err)
			}
			spki := mustDecodeHex(t, sharedGate1AFixture(t, "public-key.spki.hex"))
			if _, err := NewExpectedSigningKey(receipt.KeyGeneration, spki, string(sharedGate1AFixture(t, "public-key.fingerprint-sha256"))); err != nil {
				t.Fatalf("expected signing key boundary rejected: %v", err)
			}
		})
	}
	for _, revision := range []int{0, -1, 257} {
		if _, err := NewExpectedReceiptBinding(revision, repeatHex('a')); err == nil {
			t.Fatalf("invalid revision %d accepted", revision)
		}
	}
	for _, digest := range []string{"", strings.Repeat("a", 63), strings.Repeat("a", 65), repeatHex('A'), repeatHex('g')} {
		if _, err := NewExpectedReceiptBinding(1, digest); err == nil {
			t.Fatal("invalid context accepted")
		}
	}
	valid := receiptV3Fixture(t, "receipt.json")
	for _, value := range []string{"0", "-1", "257", "999999999999999999999999999999", "1.0", "1e0", "null", `"1"`} {
		t.Run("wire revision "+value, func(t *testing.T) {
			raw := bytes.Replace(valid, []byte(`"registry_revision":1`), []byte(`"registry_revision":`+value), 1)
			if !json.Valid(raw) || bytes.Equal(raw, valid) {
				t.Fatal("invalid test mutation")
			}
			if _, err := ParseReceiptBytes(raw); err == nil {
				t.Fatal("noncanonical revision accepted")
			}
		})
	}
	for name, raw := range map[string][]byte{
		"missing revision":    bytes.Replace(valid, []byte(`,"registry_revision":1`), nil, 1),
		"duplicate revision":  bytes.Replace(valid, []byte(`"registry_revision":1`), []byte(`"registry_revision":1,"registry_revision":1`), 1),
		"missing context":     bytes.Replace(valid, []byte(`,"authorization_context_sha256":"`+repeatHex('a')+`"`), nil, 1),
		"duplicate context":   bytes.Replace(valid, []byte(`"authorization_context_sha256":"`+repeatHex('a')+`"`), []byte(`"authorization_context_sha256":"`+repeatHex('a')+`","authorization_context_sha256":"`+repeatHex('a')+`"`), 1),
		"wrong order":         bytes.Replace(valid, []byte(`"registry_revision":1,"authorization_context_sha256":"`+repeatHex('a')+`"`), []byte(`"authorization_context_sha256":"`+repeatHex('a')+`","registry_revision":1`), 1),
		"wrong context shape": bytes.Replace(valid, []byte(`"authorization_context_sha256":"`+repeatHex('a')+`"`), []byte(`"authorization_context_sha256":null`), 1),
		"generation greater":  bytes.Replace(valid, []byte("YTAG-00000000000000000001"), []byte("YTAG-00000000000000000002"), 1),
		"generation less":     bytes.Replace(valid, []byte(`"registry_revision":1`), []byte(`"registry_revision":2`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(raw, valid) || !json.Valid(raw) {
				t.Fatal("invalid test mutation")
			}
			if _, err := ParseReceiptBytes(raw); err == nil {
				t.Fatal("invalid binding accepted")
			}
		})
	}
}

func TestHistoricalReceiptV2RemainsRejected(t *testing.T) {
	for _, name := range []string{"receipt.json", "ipc-success-receipt.json"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "gate1a", name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseReceiptBytes(bytes.TrimSuffix(raw, []byte{'\n'})); err == nil {
			t.Fatalf("legacy %s accepted", name)
		}
	}
}

func TestReceiptV3RedactsDecoderDiagnostics(t *testing.T) {
	valid := receiptV3Fixture(t, "receipt.json")
	for _, marker := range []string{"987654321098765432109876543210987654321", "123456789012345678901234567890123456789"} {
		raw := bytes.Replace(valid, []byte(`"registry_revision":1`), []byte(`"registry_revision":`+marker), 1)
		var control struct {
			Revision int `json:"registry_revision"`
		}
		controlErr := json.Unmarshal(raw, &control)
		var decoderErr *json.UnmarshalTypeError
		if !errors.As(controlErr, &decoderErr) || !strings.Contains(controlErr.Error(), marker) {
			t.Fatal("control did not reach an echoing decoder error")
		}
		_, err := ParseReceiptBytes(raw)
		assertReason(t, err, "RECEIPT_INVALID")
		if strings.Contains(err.Error(), marker) || errors.As(err, &decoderErr) {
			t.Fatal("public receipt parser exposed decoder details")
		}
		if err.Error() != "the signed approval receipt fields are malformed" {
			t.Fatalf("unexpected public diagnostic: %v", err)
		}
	}
	for _, marker := range []string{"UNTRUSTED_SENTINEL_FIRST", "UNTRUSTED_SENTINEL_SECOND"} {
		raw := bytes.Replace(valid, []byte(`"registry_revision":1`), []byte(`"`+marker+`":1`), 1)
		controlErr := decodeExactReceiptObject(raw)
		if controlErr == nil || !strings.Contains(controlErr.Error(), marker) {
			t.Fatal("control did not reach an echoing unknown-field diagnostic")
		}
		_, err := ParseReceiptBytes(raw)
		assertReason(t, err, "RECEIPT_INVALID")
		if strings.Contains(err.Error(), marker) || errors.Unwrap(err) != nil {
			t.Fatal("public receipt parser exposed unknown-field details")
		}
		if err.Error() != "the signed approval receipt JSON is not canonical" {
			t.Fatalf("unexpected public diagnostic: %v", err)
		}
	}
}

func TestIPCPlanSnapshotRedactsDecoderDiagnostics(t *testing.T) {
	valid := sharedGate1AFixture(t, "plan-comment-add.json")
	for _, marker := range []string{"UNTRUSTED_SENTINEL_FIRST", "UNTRUSTED_SENTINEL_SECOND"} {
		raw := bytes.Replace(valid, []byte(`{"schema_version":1`), []byte(`{"`+marker+`":0,"schema_version":1`), 1)
		_, controlErr := intent.ParseApprovalSnapshot(raw, MaxIPCPlanBytes)
		if controlErr == nil || !strings.Contains(controlErr.Error(), marker) {
			t.Fatal("control did not reach an echoing plan decoder diagnostic")
		}
		challenge := ipcChallengeForTest()
		frame := ipcHeaderForTest(IPCFrameRequest, uint32(IPCChallengeSize+len(raw)))
		frame = append(frame, challenge[:]...)
		frame = append(frame, raw...)
		for _, parse := range []func() error{
			func() error { _, err := NewApprovalSnapshot(raw); return err },
			func() error { _, err := DecodeIPCRequest(frame); return err },
		} {
			err := parse()
			assertReason(t, err, "APPROVAL_RESPONSE_INVALID")
			if strings.Contains(err.Error(), marker) || errors.Unwrap(err) != nil {
				t.Fatal("IPC plan boundary exposed decoder details")
			}
			if err.Error() != "the approval plan snapshot is invalid" {
				t.Fatalf("unexpected public diagnostic: %v", err)
			}
		}
	}
}

func TestIPCV3ChecksIndependentExpectedBindingWithValidSignatures(t *testing.T) {
	snapshot, _ := fixtureSnapshotAndKey(t)
	challenge := ipcChallengeForTest()
	issued := time.Date(2026, 9, 2, 15, 34, 56, 0, time.UTC)
	now := issued.Add(time.Minute)
	raw, key := signedResponseForTest(t, snapshot, challenge, issued, issued.Add(2*time.Minute), nil)
	if _, err := DecodeAndValidateIPCResponse(context.Background(), raw, challenge, snapshot, key, expectedReceiptBindingForTest(t), now); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []*ExpectedReceiptBinding{nil, {}} {
		_, err := DecodeAndValidateIPCResponse(context.Background(), raw, challenge, snapshot, key, invalid, now)
		assertReason(t, err, "APPROVAL_RESPONSE_INVALID")
	}
	wrongContext, err := NewExpectedReceiptBinding(1, repeatHex('f'))
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecodeAndValidateIPCResponse(context.Background(), raw, challenge, snapshot, key, wrongContext, now)
	assertReason(t, err, "APPROVAL_RESPONSE_INVALID")
	changedContextRaw, changedContextKey := signedResponseWithMutationForTest(t, snapshot, challenge, issued, issued.Add(2*time.Minute), nil, func(r *Receipt) { r.AuthorizationContextSHA256 = repeatHex('f') }, nil)
	if _, err := DecodeAndValidateIPCResponse(context.Background(), changedContextRaw, challenge, snapshot, changedContextKey, wrongContext, now); err != nil {
		t.Fatalf("signed changed-context control rejected: %v", err)
	}
	_, err = DecodeAndValidateIPCResponse(context.Background(), changedContextRaw, challenge, snapshot, changedContextKey, expectedReceiptBindingForTest(t), now)
	assertReason(t, err, "APPROVAL_RESPONSE_INVALID")

	revisionRaw, originalKey := signedResponseWithMutationForTest(t, snapshot, challenge, issued, issued.Add(2*time.Minute), nil, func(r *Receipt) { r.RegistryRevision = 2; r.KeyGeneration = "YTAG-00000000000000000002" }, nil)
	revisionKey, err := NewExpectedSigningKey("YTAG-00000000000000000002", originalKey.SPKIDER(), originalKey.FingerprintSHA256())
	if err != nil {
		t.Fatal(err)
	}
	revisionBinding, err := NewExpectedReceiptBinding(2, repeatHex('a'))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAndValidateIPCResponse(context.Background(), revisionRaw, challenge, snapshot, revisionKey, revisionBinding, now); err != nil {
		t.Fatalf("signed revision-two control rejected: %v", err)
	}
	_, err = DecodeAndValidateIPCResponse(context.Background(), revisionRaw, challenge, snapshot, revisionKey, expectedReceiptBindingForTest(t), now)
	assertReason(t, err, "APPROVAL_SIGNING_KEY_MISMATCH")

	// Expected values follow the tampered bytes, so only the original signature
	// can reject these syntactically and semantically consistent alterations.
	unsignedContextTamper := bytes.Replace(raw, []byte(repeatHex('a')), []byte(repeatHex('f')), 1)
	_, err = DecodeAndValidateIPCResponse(context.Background(), unsignedContextTamper, challenge, snapshot, key, wrongContext, now)
	assertReason(t, err, "APPROVAL_SIGNATURE_INVALID")
	unsignedRevisionTamper := bytes.Replace(raw, []byte(`"registry_revision":1`), []byte(`"registry_revision":2`), 1)
	unsignedRevisionTamper = bytes.Replace(unsignedRevisionTamper, []byte("YTAG-00000000000000000001"), []byte("YTAG-00000000000000000002"), 1)
	tamperKey, err := NewExpectedSigningKey("YTAG-00000000000000000002", key.SPKIDER(), key.FingerprintSHA256())
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecodeAndValidateIPCResponse(context.Background(), unsignedRevisionTamper, challenge, snapshot, tamperKey, revisionBinding, now)
	assertReason(t, err, "APPROVAL_SIGNATURE_INVALID")
}
