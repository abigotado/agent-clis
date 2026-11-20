//go:build darwin && cgo

package application

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abigotado/agent-clis/core/secretstore"
	"github.com/abigotado/agent-clis/core/secretstore/secretstoretest"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/auth"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/profile"
)

// migrateHarness wires a Service with two lazily opened native stores over
// in-memory fakes, like production, and counts how often each was opened.
type migrateHarness struct {
	service     *Service
	never       *secretstoretest.Memory
	allowed     *secretstoretest.Memory
	neverOpens  int
	allowedOpen int
}

// newMigrateHarness stores one credential under "work" in the allowed fake.
// allowedMode is the interaction mode the allowed fake enforces. Core fixes the
// mode at the first valid Open; a process without a GUI opens Allowed and then
// gets InteractionRequired, which the Never fake stands in for.
func newMigrateHarness(t *testing.T, allowedMode secretstore.Interaction, stored bool) *migrateHarness {
	t.Helper()
	h := &migrateHarness{
		never:   secretstoretest.NewMemory(secretstore.Options{MaxSecretBytes: 110592, Interaction: secretstore.InteractionNever}),
		allowed: secretstoretest.NewMemory(secretstore.Options{MaxSecretBytes: 110592, Interaction: allowedMode}),
	}
	registry := profile.NewRegistry(filepath.Join(t.TempDir(), "config", "profiles.json"))
	if err := registry.Add(t.Context(), oauthApplicationProfile(t, false)); err != nil {
		t.Fatal(err)
	}
	credentials := auth.NewNativeStore(secretstore.InteractionNever, func(context.Context, secretstore.Options) (secretstore.Store, error) {
		h.neverOpens++
		return h.never, nil
	})
	repair := auth.NewNativeStore(secretstore.InteractionAllowed, func(context.Context, secretstore.Options) (secretstore.Store, error) {
		h.allowedOpen++
		return h.allowed, nil
	})
	h.service = &Service{Profiles: registry, Credentials: credentials, RepairCredentials: repair}
	if stored {
		// A separate store over the same fake, so the counted seam stays unopened.
		seed := auth.NewNativeStore(secretstore.InteractionAllowed, func(context.Context, secretstore.Options) (secretstore.Store, error) {
			return h.allowed, nil
		})
		if err := seed.Save(t.Context(), "work", saveCredential()); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func TestServiceMigrateKeychainRepairsThroughOnlyTheAllowedStore(t *testing.T) {
	h := newMigrateHarness(t, secretstore.InteractionAllowed, true)
	if err := h.service.MigrateKeychain(t.Context(), "work"); err != nil {
		t.Fatalf("MigrateKeychain: %v", err)
	}
	if h.neverOpens != 0 || h.allowedOpen != 1 {
		t.Fatalf("opens never=%d allowed=%d, want 0 and 1", h.neverOpens, h.allowedOpen)
	}
}

func TestServiceMigrateKeychainOutcomes(t *testing.T) {
	coreErr := func(kind secretstore.Kind, status int64, reason secretstore.Reason) error {
		return &secretstore.Error{Op: "repair", Backend: "keychain", Kind: kind, Status: status, Reason: reason}
	}
	tests := []struct {
		name   string
		mode   secretstore.Interaction
		stored bool
		op     secretstoretest.Op
		inject error
		reason string
		exit   errx.Code
	}{
		{"no interaction in this session", secretstore.InteractionNever, true, 0, nil, "KEYCHAIN_MIGRATION_BLOCKED", 5},
		{"repair needs interaction", secretstore.InteractionAllowed, true, secretstoretest.OpRepair, coreErr(secretstore.KindInteractionRequired, 0, ""), "KEYCHAIN_MIGRATION_BLOCKED", 5},
		{"exists needs interaction", secretstore.InteractionAllowed, true, secretstoretest.OpExists, coreErr(secretstore.KindInteractionRequired, 0, ""), "KEYCHAIN_MIGRATION_BLOCKED", 5},
		{"repair denied access", secretstore.InteractionAllowed, true, secretstoretest.OpRepair, coreErr(secretstore.KindAccessDenied, 0, ""), "CONFIRMATION_REQUIRED", 7},
		{"canceled dialog", secretstore.InteractionAllowed, true, secretstoretest.OpRepair, coreErr(secretstore.KindCanceled, 0, ""), "CONFIRMATION_REQUIRED", 7},
		{"item missing", secretstore.InteractionAllowed, false, 0, nil, "NOT_FOUND_KEYCHAIN_CREDENTIAL", 3},
		{"item vanishes before repair", secretstore.InteractionAllowed, true, secretstoretest.OpRepair, coreErr(secretstore.KindNotFound, 0, ""), "NOT_FOUND_KEYCHAIN_CREDENTIAL", 3},
		{"keychain unusable on repair", secretstore.InteractionAllowed, true, secretstoretest.OpRepair, coreErr(secretstore.KindUnavailable, -50, secretstore.ReasonKeychainUnusable), "CREDENTIAL_STORE_UNAVAILABLE", 8},
		{"keychain unusable on exists", secretstore.InteractionAllowed, true, secretstoretest.OpExists, coreErr(secretstore.KindUnavailable, -50, secretstore.ReasonKeychainUnusable), "CREDENTIAL_STORE_UNAVAILABLE", 8},
		{"read only", secretstore.InteractionAllowed, true, secretstoretest.OpRepair, coreErr(secretstore.KindReadOnly, 100001, ""), "CREDENTIAL_STORE_READ_ONLY", 8},
		{"write refused", secretstore.InteractionAllowed, true, secretstoretest.OpRepair, coreErr(secretstore.KindReadOnly, -25307, ""), "CREDENTIAL_STORE_UNAVAILABLE", 8},
		{"contended", secretstore.InteractionAllowed, true, secretstoretest.OpRepair, coreErr(secretstore.KindContended, 0, ""), "CREDENTIAL_STORE_CONTENDED", 9},
		{"invalid argument", secretstore.InteractionAllowed, true, secretstoretest.OpRepair, coreErr(secretstore.KindInvalidArgument, 0, ""), "INTERNAL", 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := newMigrateHarness(t, test.mode, test.stored)
			if test.inject != nil {
				h.allowed.SetErr(test.op, test.inject)
			}
			var typed *errx.Error
			if !errors.As(TranslateError(h.service.MigrateKeychain(t.Context(), "work"), "work"), &typed) {
				t.Fatal("not a typed error")
			}
			if typed.Reason != test.reason || typed.Code != test.exit {
				t.Fatalf("reason=%q exit=%d, want %q/%d", typed.Reason, typed.Code, test.reason, test.exit)
			}
			if h.neverOpens != 0 {
				t.Fatalf("migrate opened the never store %d times", h.neverOpens)
			}
		})
	}
}

func TestServiceMigrateKeychainAccessDeniedPointsToRelogin(t *testing.T) {
	h := newMigrateHarness(t, secretstore.InteractionAllowed, true)
	h.allowed.SetErr(secretstoretest.OpRepair, &secretstore.Error{Op: "repair", Backend: "keychain", Kind: secretstore.KindAccessDenied})
	var typed *errx.Error
	if !errors.As(TranslateError(h.service.MigrateKeychain(t.Context(), "work"), "work"), &typed) {
		t.Fatal("not a typed error")
	}
	for _, want := range []string{"auth login --profile work", "auth import-token --profile work --interactive"} {
		if !strings.Contains(typed.Hint, want) {
			t.Fatalf("hint %q lacks %q", typed.Hint, want)
		}
	}
	if strings.Contains(typed.Hint, "migrate-keychain") {
		t.Fatalf("hint %q sends the caller back to migrate", typed.Hint)
	}
}

func TestServiceMigrateKeychainRequiresTheRepairStore(t *testing.T) {
	h := newMigrateHarness(t, secretstore.InteractionAllowed, true)
	h.service.RepairCredentials = nil
	var typed *errx.Error
	if !errors.As(TranslateError(h.service.MigrateKeychain(t.Context(), "work"), "work"), &typed) || typed.Code != errx.CodeInternal {
		t.Fatalf("got %v, want an internal error", typed)
	}
	if h.neverOpens != 0 || h.allowedOpen != 0 {
		t.Fatalf("opens never=%d allowed=%d, want none", h.neverOpens, h.allowedOpen)
	}
}
