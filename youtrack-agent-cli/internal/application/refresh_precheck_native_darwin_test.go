//go:build darwin && cgo

package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/abigotado/agent-clis/core/secretstore"
	"github.com/abigotado/agent-clis/core/secretstore/secretstoretest"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/auth"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
)

func TestRefreshPrecheckThroughNativeStoreStopsBeforeTheTokenEndpoint(t *testing.T) {
	fixture := newRefreshPrecheckFixture(t, time.Unix(1_700_000_000, 0).UTC(), nil)
	memory := secretstoretest.NewMemory(secretstore.Options{MaxSecretBytes: 1 << 16})
	native := auth.NewNativeStore(secretstore.InteractionNever, func(context.Context, secretstore.Options) (secretstore.Store, error) {
		return memory, nil
	})
	if err := native.Save(t.Context(), "work", fixture.store.value); err != nil {
		t.Fatal(err)
	}
	memory.SetErr(secretstoretest.OpSave, &secretstore.Error{Op: "save", Backend: "keychain", Kind: secretstore.KindUnavailable, Status: -50, Reason: secretstore.ReasonKeychainUnusable})
	fixture.service.Credentials = native

	_, err := fixture.service.AuthStatus(t.Context(), "work", true)
	if err == nil {
		t.Fatal("refresh unexpectedly succeeded with an unusable keychain")
	}
	if *fixture.requests != 0 {
		t.Fatalf("token endpoint hits = %d, want 0", *fixture.requests)
	}
	var typed *errx.Error
	if !errors.As(TranslateError(err, "work"), &typed) || typed.Reason != "CREDENTIAL_STORE_UNAVAILABLE" || typed.Code != errx.CodePermission {
		t.Fatalf("recovery=%#v, want CREDENTIAL_STORE_UNAVAILABLE exit 8", typed)
	}
}
