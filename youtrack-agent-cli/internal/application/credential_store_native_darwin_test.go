//go:build darwin && cgo

package application

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/abigotado/agent-clis/core/secretstore"
	"github.com/abigotado/agent-clis/core/secretstore/secretstoretest"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/auth"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/profile"
)

func saveCredential() auth.Credential {
	return auth.Credential{Kind: auth.CredentialPermanentToken, PermanentToken: "token", ProfileIdentity: strings.Repeat("ab", 32),
		Generation: strings.Repeat("A", 43), Capabilities: []profile.Capability{profile.CapabilityRead}}
}

func TestNativeStoreFailuresReachTheEnvelopeCodes(t *testing.T) {
	unusable := &secretstore.Error{Op: "load", Backend: "keychain", Kind: secretstore.KindUnavailable, Status: -50, Reason: secretstore.ReasonKeychainUnusable}
	tests := []struct {
		name   string
		core   error
		reason string
		exit   int
		// writeReason and writeExit override the expectation for save and
		// delete when set.
		writeReason string
		writeExit   int
	}{
		{"unusable keychain", unusable, "CREDENTIAL_STORE_UNAVAILABLE", 8, "", 0},
		{"unavailable", &secretstore.Error{Op: "load", Backend: "keychain", Kind: secretstore.KindUnavailable}, "CREDENTIAL_STORE_UNAVAILABLE", 8, "", 0},
		{"read only", &secretstore.Error{Op: "load", Backend: "keychain", Kind: secretstore.KindReadOnly, Status: 100001}, "CREDENTIAL_STORE_READ_ONLY", 8, "", 0},
		{"read only -61", &secretstore.Error{Op: "load", Backend: "keychain", Kind: secretstore.KindReadOnly, Status: -61}, "CREDENTIAL_STORE_READ_ONLY", 8, "", 0},
		{"read only -25292", &secretstore.Error{Op: "load", Backend: "keychain", Kind: secretstore.KindReadOnly, Status: -25292}, "CREDENTIAL_STORE_READ_ONLY", 8, "", 0},
		{"write refused -25307", &secretstore.Error{Op: "load", Backend: "keychain", Kind: secretstore.KindReadOnly, Status: -25307}, "CREDENTIAL_STORE_UNAVAILABLE", 8, "", 0},
		{"write refused -36", &secretstore.Error{Op: "load", Backend: "keychain", Kind: secretstore.KindReadOnly, Status: -36}, "CREDENTIAL_STORE_UNAVAILABLE", 8, "", 0},
		{"write refused -50", &secretstore.Error{Op: "load", Backend: "keychain", Kind: secretstore.KindReadOnly, Status: -50}, "CREDENTIAL_STORE_UNAVAILABLE", 8, "", 0},
		{"write refused no status", &secretstore.Error{Op: "load", Backend: "keychain", Kind: secretstore.KindReadOnly}, "CREDENTIAL_STORE_UNAVAILABLE", 8, "", 0},
		{"write refused positive", &secretstore.Error{Op: "load", Backend: "keychain", Kind: secretstore.KindReadOnly, Status: 77}, "CREDENTIAL_STORE_UNAVAILABLE", 8, "", 0},
		{"contended", &secretstore.Error{Op: "load", Backend: "keychain", Kind: secretstore.KindContended}, "CREDENTIAL_STORE_CONTENDED", 9, "", 0},
		{"not found", &secretstore.Error{Op: "load", Backend: "keychain", Kind: secretstore.KindNotFound}, "CREDENTIAL_NOT_FOUND", 5, "", 0},
		{"access denied", &secretstore.Error{Op: "load", Backend: "keychain", Kind: secretstore.KindAccessDenied}, "CONFIRMATION_REQUIRED", 7, "", 0},
		{"interaction required", &secretstore.Error{Op: "load", Backend: "keychain", Kind: secretstore.KindInteractionRequired}, "KEYCHAIN_INTERACTION_REQUIRED", 5, "", 0},
		{"canceled", &secretstore.Error{Op: "load", Backend: "keychain", Kind: secretstore.KindCanceled}, "CONFIRMATION_REQUIRED", 7, "", 0},
		{"invalid argument", &secretstore.Error{Op: "load", Backend: "keychain", Kind: secretstore.KindInvalidArgument}, "INTERNAL", 1, "", 0},
		{"other", &secretstore.Error{Op: "load", Backend: "keychain", Kind: secretstore.KindOther, Status: 7}, "INTERNAL", 1, "CREDENTIAL_STORE_UNAVAILABLE", 8},
		{"other -25307", &secretstore.Error{Op: "load", Backend: "keychain", Kind: secretstore.KindOther, Status: -25307}, "INTERNAL", 1, "CREDENTIAL_STORE_UNAVAILABLE", 8},
		{"other -36", &secretstore.Error{Op: "load", Backend: "keychain", Kind: secretstore.KindOther, Status: -36}, "INTERNAL", 1, "CREDENTIAL_STORE_UNAVAILABLE", 8},
		{"other -50", &secretstore.Error{Op: "load", Backend: "keychain", Kind: secretstore.KindOther, Status: -50}, "INTERNAL", 1, "CREDENTIAL_STORE_UNAVAILABLE", 8},
		{"other no status", &secretstore.Error{Op: "load", Backend: "keychain", Kind: secretstore.KindOther}, "INTERNAL", 1, "", 0},
	}
	operations := []struct {
		name  string
		op    secretstoretest.Op
		call  func(*auth.NativeStore) error
		write bool
	}{
		{"exists", secretstoretest.OpExists, func(s *auth.NativeStore) error { _, err := s.Exists(t.Context(), "work"); return err }, false},
		{"load", secretstoretest.OpLoad, func(s *auth.NativeStore) error { _, err := s.Load(t.Context(), "work"); return err }, false},
		{"delete", secretstoretest.OpDelete, func(s *auth.NativeStore) error { return s.Delete(t.Context(), "work") }, true},
		{"save", secretstoretest.OpSave, func(s *auth.NativeStore) error { return s.Save(t.Context(), "work", saveCredential()) }, true},
	}
	for _, test := range tests {
		for _, operation := range operations {
			t.Run(test.name+"/"+operation.name, func(t *testing.T) {
				memory := secretstoretest.NewMemory(secretstore.Options{MaxSecretBytes: 1024})
				memory.SetErr(operation.op, test.core)
				store := auth.NewNativeStore(secretstore.InteractionNever, func(context.Context, secretstore.Options) (secretstore.Store, error) {
					return memory, nil
				})
				var typed *errx.Error
				if !errors.As(TranslateError(operation.call(store), "work"), &typed) {
					t.Fatal("not a typed error")
				}
				wantReason, wantExit := test.reason, test.exit
				if operation.write && test.writeReason != "" {
					wantReason, wantExit = test.writeReason, test.writeExit
				}
				if typed.Reason != wantReason || int(typed.Code) != wantExit {
					t.Fatalf("reason=%q exit=%d, want %q/%d", typed.Reason, typed.Code, wantReason, wantExit)
				}
				if operation.write && test.writeReason == "CREDENTIAL_STORE_UNAVAILABLE" && test.reason != "CREDENTIAL_STORE_UNAVAILABLE" {
					if want := "the credential store refused the write; run youtrack-agent-cli auth status --profile work and report the failure to the operator; do not re-authenticate"; typed.Hint != want {
						t.Fatalf("hint=%q, want the neutral write-refused hint", typed.Hint)
					}
				}
			})
		}
	}
}

func TestNativeStoreCorruptAndTooLargeReachTheEnvelopeCodes(t *testing.T) {
	for _, kind := range []secretstore.Kind{secretstore.KindCorrupt, secretstore.KindTooLarge} {
		for _, operation := range []struct {
			name   string
			op     secretstoretest.Op
			call   func(*auth.NativeStore) error
			reason string
			exit   int
		}{
			// A stored item that cannot be decoded keeps today's invalid-credential code.
			{"load", secretstoretest.OpLoad, func(s *auth.NativeStore) error { _, err := s.Load(t.Context(), "work"); return err }, "USAGE", 2},
			{"exists", secretstoretest.OpExists, func(s *auth.NativeStore) error { _, err := s.Exists(t.Context(), "work"); return err }, "INTERNAL", 1},
			{"save", secretstoretest.OpSave, func(s *auth.NativeStore) error { return s.Save(t.Context(), "work", saveCredential()) }, "INTERNAL", 1},
			{"delete", secretstoretest.OpDelete, func(s *auth.NativeStore) error { return s.Delete(t.Context(), "work") }, "INTERNAL", 1},
		} {
			t.Run(kind.String()+"/"+operation.name, func(t *testing.T) {
				memory := secretstoretest.NewMemory(secretstore.Options{MaxSecretBytes: 1024})
				memory.SetErr(operation.op, &secretstore.Error{Op: operation.name, Backend: "keychain", Kind: kind})
				store := auth.NewNativeStore(secretstore.InteractionNever, func(context.Context, secretstore.Options) (secretstore.Store, error) {
					return memory, nil
				})
				var typed *errx.Error
				if !errors.As(TranslateError(operation.call(store), "work"), &typed) || typed.Reason != operation.reason || int(typed.Code) != operation.exit {
					t.Fatalf("got %v, want %s/%d", typed, operation.reason, operation.exit)
				}
			})
		}
	}
}
