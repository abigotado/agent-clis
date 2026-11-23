//go:build darwin && cgo

package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abigotado/agent-clis/core/secretstore"
	"github.com/abigotado/agent-clis/core/secretstore/secretstoretest"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/profile"
)

const (
	goldenIdentity   = "abababababababababababababababababababababababababababababababab"
	goldenGeneration = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	tokenMarker      = "tok-MARKER-7c1e90b4"
)

// nativeHarness backs a NativeStore with secretstoretest.Memory and records
// how the store was opened.
type nativeHarness struct {
	memory *secretstoretest.Memory
	opens  int
	opts   secretstore.Options
	store  *NativeStore
}

func newNativeHarness(t *testing.T, interaction secretstore.Interaction) *nativeHarness {
	t.Helper()
	h := &nativeHarness{memory: secretstoretest.NewMemory(secretstore.Options{MaxSecretBytes: maxStoredCredentialBytes, Interaction: interaction})}
	h.store = NewNativeStore(interaction, func(_ context.Context, opts secretstore.Options) (secretstore.Store, error) {
		h.opens++
		h.opts = opts
		return h.memory, nil
	})
	return h
}

func goldenCredential() Credential {
	return Credential{Kind: CredentialPermanentToken, PermanentToken: "golden-token", ProfileIdentity: goldenIdentity,
		Generation: goldenGeneration, Capabilities: []profile.Capability{profile.CapabilityRead}}
}

func coreError(kind secretstore.Kind, status int64, reason secretstore.Reason) error {
	return &secretstore.Error{Op: "load", Backend: "keychain", Kind: kind, Status: status, Reason: reason}
}

func TestNativeStoreV2BytesGoldenAndRoundTrip(t *testing.T) {
	h := newNativeHarness(t, secretstore.InteractionNever)
	if err := h.store.Save(t.Context(), "work", goldenCredential()); err != nil {
		t.Fatal(err)
	}
	want := "youtrack-agent-cli:credential:v2\x00" +
		`{"version":2,"kind":"permanent-token","profile_identity":"` + goldenIdentity + `","generation":"` + goldenGeneration +
		`","capabilities":["read"],"permanent_token":"golden-token"}`
	got, err := h.memory.Load(t.Context(), secretstore.Key{Service: "youtrack-agent-cli", Account: "work"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("stored bytes = %q, want %q", got, want)
	}
	loaded, err := h.store.Load(t.Context(), "work")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Kind != CredentialPermanentToken || loaded.PermanentToken != "golden-token" || loaded.ProfileIdentity != goldenIdentity {
		t.Fatal("round trip changed the credential")
	}
	exists, err := h.store.Exists(t.Context(), "work")
	if err != nil || !exists {
		t.Fatalf("Exists = %v, %v", exists, err)
	}
	if err := h.store.Delete(t.Context(), "work"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.Load(t.Context(), "work"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Load after Delete = %v, want ErrNotFound", err)
	}
}

func TestNativeStoreDecodesV1AndKeepsItsBytes(t *testing.T) {
	h := newNativeHarness(t, secretstore.InteractionNever)
	legacy := credentialPayloadPrefixV1 +
		`{"version":1,"kind":"oauth","profile_identity":"` + goldenIdentity + `","generation":"` + goldenGeneration +
		`","capabilities":["read"],"access_token":"access","refresh_token":"refresh","token_type":"Bearer","access_token_expires_at":"2030-01-01T00:00:00Z"}`
	key := secretstore.Key{Service: KeychainService, Account: "work"}
	if err := h.memory.Save(t.Context(), key, []byte(legacy)); err != nil {
		t.Fatal(err)
	}
	loaded, err := h.store.Load(t.Context(), "work")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Kind != CredentialOAuth || loaded.AccessToken != "access" || loaded.OAuthScopes != nil || !loaded.legacyOAuthScopes {
		t.Fatalf("v1 decode = %#v", loaded)
	}
	if err := h.store.Save(t.Context(), "work", loaded); err != nil {
		t.Fatal(err)
	}
	restored, err := h.memory.Load(t.Context(), key)
	if err != nil || string(restored) != legacy {
		t.Fatalf("v1 compensation bytes = %q, %v", restored, err)
	}
}

func TestNativeStoreMapsEveryCoreKind(t *testing.T) {
	status := func(operation string) error { return &StatusError{Operation: operation, Status: 77} }
	tests := []struct {
		name string
		core error
		want error // sentinel for errors.Is, or nil
		op   string
	}{
		{"unusable keychain with -50", coreError(secretstore.KindUnavailable, -50, secretstore.ReasonKeychainUnusable), ErrCredentialStoreUnavailable, "load"},
		{"unavailable other reason", coreError(secretstore.KindUnavailable, 0, secretstore.ReasonNoReply), ErrCredentialStoreUnavailable, "load"},
		{"unavailable no reason", coreError(secretstore.KindUnavailable, 0, ""), ErrCredentialStoreUnavailable, "load"},
		{"reason outranks kind", coreError(secretstore.KindNotFound, -50, secretstore.ReasonKeychainUnusable), ErrCredentialStoreUnavailable, "load"},
		{"reason outranks other", coreError(secretstore.KindOther, -50, secretstore.ReasonKeychainUnusable), ErrCredentialStoreUnavailable, "load"},
		{"read only", coreError(secretstore.KindReadOnly, 100001, ""), ErrCredentialStoreReadOnly, "save"},
		{"contended", coreError(secretstore.KindContended, 0, ""), ErrCredentialStoreContended, "save"},
		{"not found", coreError(secretstore.KindNotFound, 0, ""), ErrNotFound, "load"},
		{"access denied", coreError(secretstore.KindAccessDenied, 0, ""), ErrKeychainMigrationRequired, "load"},
		{"interaction required", coreError(secretstore.KindInteractionRequired, 0, ""), ErrInteractionNotAllowed, "load"},
		{"canceled", coreError(secretstore.KindCanceled, 0, ""), ErrKeychainMigrationCanceled, "load"},
		{"corrupt on load", coreError(secretstore.KindCorrupt, 0, ""), ErrInvalidToken, "load"},
		{"too large on load", coreError(secretstore.KindTooLarge, 0, ""), ErrInvalidToken, "load"},
		{"invalid argument", coreError(secretstore.KindInvalidArgument, 0, ""), ErrCredentialStoreInternal, "load"},
		{"corrupt on save", coreError(secretstore.KindCorrupt, 0, ""), ErrCredentialStoreInternal, "save"},
		{"too large on save", coreError(secretstore.KindTooLarge, 0, ""), ErrCredentialStoreInternal, "save"},
		{"corrupt on exists", coreError(secretstore.KindCorrupt, 0, ""), ErrCredentialStoreInternal, "exists"},
		{"too large on delete", coreError(secretstore.KindTooLarge, 0, ""), ErrCredentialStoreInternal, "delete"},
		{"unclassified failure", errors.New("not a core error"), ErrCredentialStoreInternal, "load"},
		{"other", coreError(secretstore.KindOther, 77, ""), status("load"), "load"},
	}
	sentinels := []error{ErrCredentialStoreUnavailable, ErrCredentialStoreReadOnly, ErrCredentialStoreContended, ErrNotFound,
		ErrKeychainMigrationRequired, ErrInteractionNotAllowed, ErrKeychainMigrationCanceled, ErrInvalidToken, ErrCredentialStoreInternal}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := mapNativeError(test.op, test.core)
			var wantStatus *StatusError
			if errors.As(test.want, &wantStatus) {
				var gotStatus *StatusError
				if !errors.As(got, &gotStatus) || *gotStatus != *wantStatus {
					t.Fatalf("mapped = %v, want %v", got, wantStatus)
				}
				return
			}
			for _, sentinel := range sentinels {
				if errors.Is(got, sentinel) != errors.Is(sentinel, test.want) {
					t.Fatalf("mapped = %v; errors.Is(%v) = %v, want %v", got, sentinel, errors.Is(got, sentinel), errors.Is(sentinel, test.want))
				}
			}
		})
	}
}

func TestNativeStoreMapsKindsThroughMemoryOnEveryOperation(t *testing.T) {
	operations := []struct {
		name string
		op   secretstoretest.Op
		call func(*NativeStore) error
	}{
		{"exists", secretstoretest.OpExists, func(s *NativeStore) error { _, err := s.Exists(t.Context(), "work"); return err }},
		{"load", secretstoretest.OpLoad, func(s *NativeStore) error { _, err := s.Load(t.Context(), "work"); return err }},
		{"save", secretstoretest.OpSave, func(s *NativeStore) error { return s.Save(t.Context(), "work", goldenCredential()) }},
		{"delete", secretstoretest.OpDelete, func(s *NativeStore) error { return s.Delete(t.Context(), "work") }},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			h := newNativeHarness(t, secretstore.InteractionNever)
			h.memory.SetErr(operation.op, coreError(secretstore.KindUnavailable, -50, secretstore.ReasonKeychainUnusable))
			err := operation.call(h.store)
			if !errors.Is(err, ErrCredentialStoreUnavailable) || errors.Is(err, ErrNotFound) {
				t.Fatalf("err = %v, want only ErrCredentialStoreUnavailable", err)
			}
		})
	}
}

func TestNativeStoreInvalidArgumentIsInternalAndOtherIsStatus(t *testing.T) {
	h := newNativeHarness(t, secretstore.InteractionNever)
	h.memory.SetErr(secretstoretest.OpLoad, coreError(secretstore.KindInvalidArgument, 0, ""))
	if _, err := h.store.Load(t.Context(), "work"); !errors.Is(err, ErrCredentialStoreInternal) {
		t.Fatalf("InvalidArgument = %v, want ErrCredentialStoreInternal", err)
	}

	h.memory.SetErr(secretstoretest.OpLoad, coreError(secretstore.KindOther, 123, ""))
	_, err := h.store.Load(t.Context(), "work")
	var status *StatusError
	if !errors.As(err, &status) || status.Operation != "load" || status.Status != 123 {
		t.Fatalf("Other = %v, want *StatusError{load, 123}", err)
	}

	h.memory.SetErr(secretstoretest.OpLoad, errors.New("not a core error"))
	if _, err := h.store.Load(t.Context(), "work"); !errors.Is(err, ErrCredentialStoreInternal) {
		t.Fatalf("unclassified failure = %v, want ErrCredentialStoreInternal", err)
	}
}

func TestNativeStoreCorruptAndTooLargeOutsideLoadAreInternal(t *testing.T) {
	operations := []struct {
		name string
		op   secretstoretest.Op
		call func(*NativeStore) error
	}{
		{"exists", secretstoretest.OpExists, func(s *NativeStore) error { _, err := s.Exists(t.Context(), "work"); return err }},
		{"save", secretstoretest.OpSave, func(s *NativeStore) error { return s.Save(t.Context(), "work", goldenCredential()) }},
		{"delete", secretstoretest.OpDelete, func(s *NativeStore) error { return s.Delete(t.Context(), "work") }},
	}
	for _, operation := range operations {
		for _, kind := range []secretstore.Kind{secretstore.KindCorrupt, secretstore.KindTooLarge} {
			t.Run(operation.name+"/"+kind.String(), func(t *testing.T) {
				h := newNativeHarness(t, secretstore.InteractionNever)
				h.memory.SetErr(operation.op, coreError(kind, 0, ""))
				err := operation.call(h.store)
				if !errors.Is(err, ErrCredentialStoreInternal) || errors.Is(err, ErrInvalidToken) {
					t.Fatalf("err = %v, want only ErrCredentialStoreInternal", err)
				}
			})
		}
	}
}

func TestNativeStorePassesContextErrorsThrough(t *testing.T) {
	h := newNativeHarness(t, secretstore.InteractionNever)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := h.store.Load(ctx, "work"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled load = %v, want context.Canceled", err)
	}
	h.memory.SetErr(secretstoretest.OpSave, context.DeadlineExceeded)
	err := h.store.Save(t.Context(), "work", goldenCredential())
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("deadline save = %v, want context.DeadlineExceeded", err)
	}
}

func TestNativeStoreDoesNotCacheContextErrorsFromOpen(t *testing.T) {
	h := newNativeHarness(t, secretstore.InteractionNever)
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := h.store.Exists(canceled, "work"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Exists = %v, want context.Canceled", err)
	}
	if _, err := h.store.Exists(t.Context(), "work"); err != nil {
		t.Fatalf("Exists with a live context after a canceled one = %v", err)
	}

	// A context error returned by the open function itself is not remembered either.
	calls := 0
	store := NewNativeStore(secretstore.InteractionNever, func(_ context.Context, opts secretstore.Options) (secretstore.Store, error) {
		calls++
		if calls == 1 {
			return nil, context.DeadlineExceeded
		}
		return secretstoretest.NewMemory(opts), nil
	})
	if _, err := store.Exists(t.Context(), "work"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first Exists = %v, want context.DeadlineExceeded", err)
	}
	if _, err := store.Exists(t.Context(), "work"); err != nil || calls != 2 {
		t.Fatalf("second Exists = %v after %d opens, want success after 2", err, calls)
	}
}

func TestNativeStoreOpensLazilyOnceWithTheBound(t *testing.T) {
	for _, interaction := range []secretstore.Interaction{secretstore.InteractionNever, secretstore.InteractionAllowed} {
		h := newNativeHarness(t, interaction)
		if h.opens != 0 {
			t.Fatalf("constructor opened the store %d times", h.opens)
		}
		for range 3 {
			if _, err := h.store.Exists(t.Context(), "work"); err != nil {
				t.Fatal(err)
			}
		}
		if h.opens != 1 {
			t.Fatalf("opens = %d, want 1", h.opens)
		}
		want := secretstore.Options{MaxSecretBytes: maxStoredCredentialBytes, Interaction: interaction}
		if h.opts != want {
			t.Fatalf("options = %+v, want %+v", h.opts, want)
		}
	}
}

func TestNativeStoreOpenFailureIsMappedAndCached(t *testing.T) {
	opens := 0
	store := NewNativeStore(secretstore.InteractionNever, func(context.Context, secretstore.Options) (secretstore.Store, error) {
		opens++
		return nil, coreError(secretstore.KindUnavailable, -50, secretstore.ReasonKeychainUnusable)
	})
	for range 2 {
		if _, err := store.Load(t.Context(), "work"); !errors.Is(err, ErrCredentialStoreUnavailable) {
			t.Fatalf("Load = %v, want ErrCredentialStoreUnavailable", err)
		}
	}
	if opens != 1 {
		t.Fatalf("opens = %d, want 1", opens)
	}
}

func TestNativeStoreRejectsInvalidNamesBeforeOpening(t *testing.T) {
	h := newNativeHarness(t, secretstore.InteractionNever)
	for _, name := range []string{"", "-lead", ".lead", "a#b", "a b", "ü", strings.Repeat("a", 65)} {
		if _, err := h.store.Load(t.Context(), name); !errors.Is(err, profile.ErrInvalidProfile) && !errors.Is(err, profile.ErrProfileRequired) {
			t.Errorf("Load(%q) = %v, want a profile name error", name, err)
		}
		if err := h.store.Save(t.Context(), name, goldenCredential()); err == nil {
			t.Errorf("Save(%q) succeeded", name)
		}
	}
	if h.opens != 0 {
		t.Fatalf("an invalid name opened the store %d times", h.opens)
	}
}

func TestNativeStoreBoundaryProfileNamesAreValidKeys(t *testing.T) {
	h := newNativeHarness(t, secretstore.InteractionNever)
	names := []string{"a", "Z", "0", "a.b", "a-b", "a_b", "A9._-", strings.Repeat("x", 64), "0" + strings.Repeat("-", 63)}
	for _, name := range names {
		if err := profile.ValidateName(name); err != nil {
			t.Fatalf("test name %q is not a valid profile name: %v", name, err)
		}
		if err := h.store.Save(t.Context(), name, goldenCredential()); err != nil {
			t.Fatalf("Save(%q) = %v", name, err)
		}
		if _, err := h.store.Load(t.Context(), name); err != nil {
			t.Fatalf("Load(%q) = %v", name, err)
		}
		if err := h.store.Delete(t.Context(), name); err != nil {
			t.Fatalf("Delete(%q) = %v", name, err)
		}
	}
}

func TestNativeStoreHonoursTheStoredCredentialBound(t *testing.T) {
	t.Run("worst-case credential fits", func(t *testing.T) {
		h := newNativeHarness(t, secretstore.InteractionNever)
		// json escapes '<' as a six-byte sequence, the worst case for the bound.
		token := strings.Repeat("<", MaxTokenBytes)
		credential := Credential{Kind: CredentialOAuth, AccessToken: token, RefreshToken: token, TokenType: "Bearer",
			AccessTokenExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), OAuthScopes: []string{"YouTrack"},
			ProfileIdentity: goldenIdentity, Generation: goldenGeneration, Capabilities: []profile.Capability{profile.CapabilityRead}}
		if err := h.store.Save(t.Context(), "work", credential); err != nil {
			t.Fatal(err)
		}
		raw, err := h.memory.Load(t.Context(), secretstore.Key{Service: KeychainService, Account: "work"})
		if err != nil || len(raw) < 2*6*MaxTokenBytes || len(raw) > maxStoredCredentialBytes {
			t.Fatalf("stored %d bytes, err %v", len(raw), err)
		}
		loaded, err := h.store.Load(t.Context(), "work")
		if err != nil || loaded.AccessToken != token {
			t.Fatalf("Load = %v", err)
		}
	})
	t.Run("the opened bound is the codec bound", func(t *testing.T) {
		h := newNativeHarness(t, secretstore.InteractionNever)
		if _, err := h.store.Exists(t.Context(), "work"); err != nil {
			t.Fatal(err)
		}
		if h.opts.MaxSecretBytes != maxStoredCredentialBytes || h.opts.MaxSecretBytes > secretstore.MaxSecretBytesLimit {
			t.Fatalf("MaxSecretBytes = %d", h.opts.MaxSecretBytes)
		}
		bounded := secretstoretest.NewMemory(h.opts)
		key := secretstore.Key{Service: KeychainService, Account: "work"}
		if err := bounded.Save(t.Context(), key, bytes.Repeat([]byte{'x'}, h.opts.MaxSecretBytes)); err != nil {
			t.Fatalf("a value of exactly the bound: %v", err)
		}
		if err := bounded.Save(t.Context(), key, bytes.Repeat([]byte{'x'}, h.opts.MaxSecretBytes+1)); !errors.Is(err, secretstore.ErrTooLarge) {
			t.Fatalf("a value above the bound: %v", err)
		}
	})
	t.Run("core TooLarge on load is an invalid credential", func(t *testing.T) {
		h := newNativeHarness(t, secretstore.InteractionNever)
		h.memory.SetErr(secretstoretest.OpLoad, coreError(secretstore.KindTooLarge, 0, ""))
		if _, err := h.store.Load(t.Context(), "work"); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("Load = %v, want ErrInvalidToken", err)
		}
	})
	t.Run("a stored item above the bound or empty is invalid", func(t *testing.T) {
		for name, raw := range map[string][]byte{
			"above the bound": bytes.Repeat([]byte{'x'}, maxStoredCredentialBytes+1),
			"empty":           {},
		} {
			store := NewNativeStore(secretstore.InteractionNever, func(context.Context, secretstore.Options) (secretstore.Store, error) {
				return fixedLoadStore{raw: raw}, nil
			})
			if _, err := store.Load(t.Context(), "work"); !errors.Is(err, ErrInvalidToken) {
				t.Errorf("%s: Load = %v, want ErrInvalidToken", name, err)
			}
		}
	})
}

// fixedLoadStore returns raw from Load and fails everything else.
type fixedLoadStore struct {
	secretstore.Store
	raw []byte
}

func (s fixedLoadStore) Load(context.Context, secretstore.Key) ([]byte, error) {
	return bytes.Clone(s.raw), nil
}

// recordingStore keeps the slices that cross the adapter boundary.
type recordingStore struct {
	secretstore.Store
	loaded     []byte
	saved      []byte
	savedAtOps []byte
}

func (s *recordingStore) Load(ctx context.Context, key secretstore.Key) ([]byte, error) {
	raw, err := s.Store.Load(ctx, key)
	s.loaded = raw
	return raw, err
}

func (s *recordingStore) Save(ctx context.Context, key secretstore.Key, secret []byte) error {
	s.saved = secret
	s.savedAtOps = bytes.Clone(secret)
	return s.Store.Save(ctx, key, secret)
}

func TestNativeStoreZeroesTheSlicesItHandles(t *testing.T) {
	recorder := &recordingStore{Store: secretstoretest.NewMemory(secretstore.Options{MaxSecretBytes: maxStoredCredentialBytes})}
	store := NewNativeStore(secretstore.InteractionNever, func(context.Context, secretstore.Options) (secretstore.Store, error) {
		return recorder, nil
	})
	if err := store.Save(t.Context(), "work", goldenCredential()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(recorder.savedAtOps, []byte("golden-token")) {
		t.Fatal("the store was not given the encoded payload")
	}
	if !allZero(recorder.saved) {
		t.Fatal("the encoded payload was not zeroed after Save")
	}
	if _, err := store.Load(t.Context(), "work"); err != nil {
		t.Fatal(err)
	}
	if len(recorder.loaded) == 0 || !allZero(recorder.loaded) {
		t.Fatal("the loaded slice was not zeroed after Load")
	}

	// Zeroed on a decode failure as well.
	garbage := &recordingStore{Store: secretstoretest.NewMemory(secretstore.Options{MaxSecretBytes: maxStoredCredentialBytes})}
	if err := garbage.Store.Save(t.Context(), secretstore.Key{Service: KeychainService, Account: "work"}, []byte("not-a-credential-"+tokenMarker)); err != nil {
		t.Fatal(err)
	}
	failing := NewNativeStore(secretstore.InteractionNever, func(context.Context, secretstore.Options) (secretstore.Store, error) {
		return garbage, nil
	})
	if _, err := failing.Load(t.Context(), "work"); err == nil {
		t.Fatal("garbage decoded")
	}
	if len(garbage.loaded) == 0 || !allZero(garbage.loaded) {
		t.Fatal("the loaded slice was not zeroed after a decode failure")
	}
}

func allZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

func TestNativeStoreNeverLeaksATokenMarker(t *testing.T) {
	marked := goldenCredential()
	marked.PermanentToken = tokenMarker
	var textLog, jsonLog bytes.Buffer
	loggers := []*slog.Logger{slog.New(slog.NewTextHandler(&textLog, nil)), slog.New(slog.NewJSONHandler(&jsonLog, nil))}

	var observed []string
	record := func(err error) {
		if err == nil {
			return
		}
		observed = append(observed, err.Error(), fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err), fmt.Sprintf("%s", err))
		for _, logger := range loggers {
			logger.Error("credential store failure", "err", err, "credential", marked)
		}
	}

	kinds := []secretstore.Kind{secretstore.KindOther, secretstore.KindNotFound, secretstore.KindAccessDenied, secretstore.KindInteractionRequired,
		secretstore.KindUnavailable, secretstore.KindReadOnly, secretstore.KindContended, secretstore.KindTooLarge, secretstore.KindCorrupt,
		secretstore.KindCanceled, secretstore.KindInvalidArgument}
	// The reason outranks the kind in mapNativeError, so each kind is injected
	// once with a reason (the unusable-keychain branch) and once without, which
	// reaches every kind branch with the marked credential stored.
	// Status 5 reaches the write-refused branch of KindReadOnly and, for
	// KindOther, of save and delete; 100001 the read-only one; 0 the plain
	// status error of KindOther.
	for _, status := range []int64{0, 5, 100001} {
		for _, reason := range []secretstore.Reason{secretstore.ReasonKeychainUnusable, ""} {
			for _, kind := range kinds {
				h := newNativeHarness(t, secretstore.InteractionNever)
				if err := h.store.Save(t.Context(), "work", marked); err != nil {
					t.Fatal(err)
				}
				for _, op := range []secretstoretest.Op{secretstoretest.OpExists, secretstoretest.OpLoad, secretstoretest.OpSave, secretstoretest.OpDelete} {
					h.memory.SetErr(op, coreError(kind, status, reason))
				}
				_, loadErr := h.store.Load(t.Context(), "work")
				_, existsErr := h.store.Exists(t.Context(), "work")
				saveErr := h.store.Save(t.Context(), "work", marked)
				deleteErr := h.store.Delete(t.Context(), "work")
				for operation, err := range map[string]error{"load": loadErr, "exists": existsErr, "save": saveErr, "delete": deleteErr} {
					if err == nil {
						t.Fatalf("%s with kind %v and reason %q succeeded, so the error path did not run", operation, kind, reason)
					}
					record(err)
				}
			}
		}
	}

	// Invalid input carrying the marker, and an undecodable stored item.
	invalid := marked
	invalid.PermanentToken = tokenMarker + "\n"
	h := newNativeHarness(t, secretstore.InteractionNever)
	record(h.store.Save(t.Context(), "work", invalid))
	if err := h.memory.Save(t.Context(), secretstore.Key{Service: KeychainService, Account: "work"}, []byte("garbage-"+tokenMarker)); err != nil {
		t.Fatal(err)
	}
	_, err := h.store.Load(t.Context(), "work")
	record(err)
	// An invalid name that carries the marker must fail without echoing it.
	invalidName := tokenMarker + "#"
	for operation, err := range map[string]error{
		"save":   h.store.Save(t.Context(), invalidName, marked),
		"load":   func() error { _, err := h.store.Load(t.Context(), invalidName); return err }(),
		"exists": func() error { _, err := h.store.Exists(t.Context(), invalidName); return err }(),
		"delete": h.store.Delete(t.Context(), invalidName),
	} {
		if err == nil {
			t.Fatalf("%s with an invalid name succeeded, so the error path did not run", operation)
		}
		record(err)
	}

	observed = append(observed, textLog.String(), jsonLog.String(), fmt.Sprintf("%v %+v %#v", marked, marked, marked))
	for index, text := range observed {
		if strings.Contains(text, tokenMarker) {
			t.Fatalf("output %d contains the token marker: %q", index, text)
		}
	}
	if textLog.Len() == 0 || jsonLog.Len() == 0 {
		t.Fatal("nothing was logged, so the check proved nothing")
	}
}

// plainStore hides everything but secretstore.Store, so it has no ACLRepairer.
type plainStore struct{ secretstore.Store }

func TestNativeStoreMigrateKeychainRepairsTheExactItem(t *testing.T) {
	h := newNativeHarness(t, secretstore.InteractionAllowed)
	if err := h.store.Save(t.Context(), "work", goldenCredential()); err != nil {
		t.Fatal(err)
	}
	if err := h.store.MigrateKeychain(t.Context(), "work"); err != nil {
		t.Fatalf("MigrateKeychain = %v", err)
	}
	if h.opens != 1 || h.opts.Interaction != secretstore.InteractionAllowed {
		t.Fatalf("opens=%d interaction=%v, want one allowed open", h.opens, h.opts.Interaction)
	}
	if err := h.store.MigrateKeychain(t.Context(), "other"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("MigrateKeychain(missing item) = %v, want ErrNotFound", err)
	}
}

func TestNativeStoreMigrateKeychainMapsRepairErrors(t *testing.T) {
	tests := []struct {
		name string
		core error
		want error
	}{
		{"unusable keychain", coreError(secretstore.KindUnavailable, -50, secretstore.ReasonKeychainUnusable), ErrCredentialStoreUnavailable},
		{"read only", coreError(secretstore.KindReadOnly, 100001, ""), ErrCredentialStoreReadOnly},
		{"unrecognized write status", coreError(secretstore.KindReadOnly, -25307, ""), ErrCredentialStoreWriteRefused},
		{"contended", coreError(secretstore.KindContended, 0, ""), ErrCredentialStoreContended},
		{"canceled", coreError(secretstore.KindCanceled, 0, ""), ErrKeychainMigrationCanceled},
		{"interaction required", coreError(secretstore.KindInteractionRequired, 0, ""), ErrInteractionNotAllowed},
		{"not found", coreError(secretstore.KindNotFound, 0, ""), ErrNotFound},
		{"invalid argument", coreError(secretstore.KindInvalidArgument, 0, ""), ErrCredentialStoreInternal},
		{"corrupt", coreError(secretstore.KindCorrupt, 0, ""), ErrCredentialStoreInternal},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := newNativeHarness(t, secretstore.InteractionAllowed)
			h.memory.SetErr(secretstoretest.OpRepair, test.core)
			if err := h.store.MigrateKeychain(t.Context(), "work"); !errors.Is(err, test.want) {
				t.Fatalf("MigrateKeychain = %v, want %v", err, test.want)
			}
		})
	}
	h := newNativeHarness(t, secretstore.InteractionAllowed)
	h.memory.SetErr(secretstoretest.OpRepair, coreError(secretstore.KindOther, 77, ""))
	if err := h.store.MigrateKeychain(t.Context(), "work"); !errors.Is(err, ErrCredentialStoreWriteRefused) {
		t.Fatalf("MigrateKeychain(other, 77) = %v, want ErrCredentialStoreWriteRefused", err)
	}
	h.memory.SetErr(secretstoretest.OpRepair, coreError(secretstore.KindOther, 0, ""))
	var status *StatusError
	if err := h.store.MigrateKeychain(t.Context(), "work"); !errors.As(err, &status) || status.Operation != "repair" || status.Status != 0 {
		t.Fatalf("MigrateKeychain(other, 0) = %v, want a repair StatusError", err)
	}
}

// slowRepairer blocks in RepairAccess until the context ends, like a system
// dialog that is answered too late, and then reports the context error.
type slowRepairer struct{ secretstore.Store }

func (r *slowRepairer) RepairAccess(ctx context.Context, _ secretstore.Key) error {
	<-ctx.Done()
	return fmt.Errorf("repair: %w", ctx.Err())
}

func TestNativeStoreMigrateKeychainContextExpiringDuringRepairLeavesTheItem(t *testing.T) {
	memory := secretstoretest.NewMemory(secretstore.Options{MaxSecretBytes: maxStoredCredentialBytes, Interaction: secretstore.InteractionAllowed})
	store := NewNativeStore(secretstore.InteractionAllowed, func(context.Context, secretstore.Options) (secretstore.Store, error) {
		return &slowRepairer{Store: memory}, nil
	})
	if err := store.Save(t.Context(), "work", goldenCredential()); err != nil {
		t.Fatal(err)
	}
	key := secretstore.Key{Service: KeychainService, Account: "work"}
	before, err := memory.Load(t.Context(), key)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	migrateErr := store.MigrateKeychain(ctx, "work")
	if !errors.Is(migrateErr, context.DeadlineExceeded) {
		t.Fatalf("MigrateKeychain = %v, want the context error", migrateErr)
	}
	for _, sentinel := range []error{ErrKeychainMigrationCanceled, ErrCredentialStoreInternal, ErrKeychainMigrationUnavailable} {
		if errors.Is(migrateErr, sentinel) {
			t.Fatalf("a context expiry was reported as %v", sentinel)
		}
	}
	after, err := memory.Load(t.Context(), key)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("item changed during an expired repair: %v", err)
	}
	if got := translateMigrationStoreError(migrateErr); got != migrateErr {
		t.Fatalf("translate changed %v into %v", migrateErr, got)
	}
}

func TestNativeStoreMigrateKeychainRefusesWithoutInteraction(t *testing.T) {
	h := newNativeHarness(t, secretstore.InteractionNever)
	if err := h.store.Save(t.Context(), "work", goldenCredential()); err != nil {
		t.Fatal(err)
	}
	if err := h.store.MigrateKeychain(t.Context(), "work"); !errors.Is(err, ErrInteractionNotAllowed) {
		t.Fatalf("MigrateKeychain = %v, want ErrInteractionNotAllowed", err)
	}
}

func TestNativeStoreMigrateKeychainWithoutRepairerIsUnavailable(t *testing.T) {
	memory := secretstoretest.NewMemory(secretstore.Options{MaxSecretBytes: maxStoredCredentialBytes, Interaction: secretstore.InteractionAllowed})
	store := NewNativeStore(secretstore.InteractionAllowed, func(context.Context, secretstore.Options) (secretstore.Store, error) {
		return plainStore{memory}, nil
	})
	if err := store.MigrateKeychain(t.Context(), "work"); !errors.Is(err, ErrKeychainMigrationUnavailable) {
		t.Fatalf("MigrateKeychain = %v, want ErrKeychainMigrationUnavailable", err)
	}
}

func TestNativeStoreMigrateKeychainValidatesBeforeOpening(t *testing.T) {
	h := newNativeHarness(t, secretstore.InteractionAllowed)
	if err := h.store.MigrateKeychain(t.Context(), "-bad"); !errors.Is(err, profile.ErrInvalidProfile) {
		t.Fatalf("MigrateKeychain(invalid name) = %v", err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := h.store.MigrateKeychain(canceled, "work"); !errors.Is(err, context.Canceled) {
		t.Fatalf("MigrateKeychain(canceled) = %v", err)
	}
	if h.opens != 0 {
		t.Fatalf("invalid input opened the store %d times", h.opens)
	}
}

func TestDefaultNativeStoresOpenNothingUntilUsed(t *testing.T) {
	// Like secretstore.Open: the first mode is fixed for the process and a
	// different mode afterwards is an invalid argument.
	var opens []secretstore.Interaction
	var fixed *secretstore.Interaction
	open := func(_ context.Context, opts secretstore.Options) (secretstore.Store, error) {
		opens = append(opens, opts.Interaction)
		if fixed == nil {
			mode := opts.Interaction
			fixed = &mode
		}
		if *fixed != opts.Interaction {
			return nil, &secretstore.Error{Op: "open", Backend: "none", Kind: secretstore.KindInvalidArgument}
		}
		return secretstoretest.NewMemory(opts), nil
	}
	credentials, repair := newDefaultNativeStores(open)
	if credentials == repair || len(opens) != 0 {
		t.Fatalf("constructed %d opens, same store = %v", len(opens), credentials == repair)
	}
	if _, err := credentials.Exists(t.Context(), "work"); err != nil {
		t.Fatal(err)
	}
	if len(opens) != 1 || opens[0] != secretstore.InteractionNever {
		t.Fatalf("opens after first use = %v, want [never]", opens)
	}
	if _, err := repair.Exists(t.Context(), "work"); !errors.Is(err, ErrCredentialStoreInternal) {
		t.Fatalf("second mode in one process = %v, want ErrCredentialStoreInternal", err)
	}
	if len(opens) != 2 || opens[1] != secretstore.InteractionAllowed {
		t.Fatalf("opens = %v, want [never allowed]", opens)
	}

	// The migrate process opens only the Allowed store, which then works.
	fixed, opens = nil, nil
	_, repairOnly := newDefaultNativeStores(open)
	if _, err := repairOnly.Exists(t.Context(), "work"); err != nil || len(opens) != 1 {
		t.Fatalf("repair-only Exists = %v after %v opens", err, opens)
	}
}

// checkpointContext lets a test observe the caller between the store's first
// context check and its wait for the lock, and cancel the caller from that
// point on. The store calls Err first, so the first call closes checked.
type checkpointContext struct {
	context.Context
	checked  chan struct{}
	once     sync.Once
	canceled atomic.Bool
}

func newCheckpointContext(parent context.Context) *checkpointContext {
	return &checkpointContext{Context: parent, checked: make(chan struct{})}
}

func (c *checkpointContext) Err() error {
	c.once.Do(func() { close(c.checked) })
	if c.canceled.Load() {
		return context.Canceled
	}
	return nil
}

// gatedOpen counts opens and the most that ran at once. Every open waits for
// release, so callers that are not serialized pile up inside it.
type gatedOpen struct {
	opens    atomic.Int32
	inFlight atomic.Int32
	maxSeen  atomic.Int32
	release  chan struct{}
}

func (g *gatedOpen) open(_ context.Context, opts secretstore.Options) (secretstore.Store, error) {
	g.opens.Add(1)
	now := g.inFlight.Add(1)
	defer g.inFlight.Add(-1)
	for {
		seen := g.maxSeen.Load()
		if now <= seen || g.maxSeen.CompareAndSwap(seen, now) {
			break
		}
	}
	<-g.release
	return secretstoretest.NewMemory(opts), nil
}

func TestNativeStoreBackendOpensExactlyOnceUnderConcurrency(t *testing.T) {
	const callers = 32
	gate := &gatedOpen{release: make(chan struct{})}
	store := NewNativeStore(secretstore.InteractionNever, gate.open)

	var wg sync.WaitGroup
	errs := make(chan error, callers)
	contexts := make([]*checkpointContext, callers)
	for index := range contexts {
		contexts[index] = newCheckpointContext(t.Context())
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.Exists(contexts[index], "work")
			errs <- err
		}()
	}
	// Every caller is past its first check, so each is inside the open or
	// waiting for the lock; none can finish before the release.
	for _, ctx := range contexts {
		<-ctx.checked
	}
	close(gate.release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("Exists = %v", err)
		}
	}
	if got := gate.opens.Load(); got != 1 {
		t.Errorf("opens = %d, want exactly 1", got)
	}
	if got := gate.maxSeen.Load(); got != 1 {
		t.Errorf("concurrent opens = %d, want 1", got)
	}
}

func TestNativeStoreBackendCanceledCallerDoesNotBlockALiveOne(t *testing.T) {
	var calls, inFlight, maxSeen atomic.Int32
	entered := make(chan struct{})
	store := NewNativeStore(secretstore.InteractionNever, func(ctx context.Context, opts secretstore.Options) (secretstore.Store, error) {
		call := calls.Add(1)
		now := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			seen := maxSeen.Load()
			if now <= seen || maxSeen.CompareAndSwap(seen, now) {
				break
			}
		}
		if call == 1 {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return secretstoretest.NewMemory(opts), nil
	})

	canceledCtx, cancel := context.WithCancel(t.Context())
	defer cancel()
	canceledResult := make(chan error, 1)
	go func() {
		_, err := store.Exists(canceledCtx, "work")
		canceledResult <- err
	}()
	<-entered

	liveCtx := newCheckpointContext(t.Context())
	liveResult := make(chan error, 1)
	go func() {
		_, err := store.Exists(liveCtx, "work")
		liveResult <- err
	}()
	// With the mutex the live caller waits behind the first open, so a second
	// concurrent open never appears. It is past its first check here.
	<-liveCtx.checked
	cancel()

	if err := <-canceledResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled caller = %v, want context.Canceled", err)
	}
	if err := <-liveResult; err != nil {
		t.Fatalf("live caller = %v, want a successful open", err)
	}
	if got := maxSeen.Load(); got != 1 {
		t.Errorf("concurrent opens = %d, want the live caller to wait for the canceled one", got)
	}
	if _, err := store.Exists(t.Context(), "work"); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("opens = %d, want the canceled attempt plus exactly one successful open", got)
	}
}

// A caller canceled while another goroutine holds the lock for the open must
// get the context error, never the cached open failure the opener produced.
func TestNativeStoreBackendRechecksContextAfterWaitingForTheOpener(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	store := NewNativeStore(secretstore.InteractionNever, func(context.Context, secretstore.Options) (secretstore.Store, error) {
		close(entered)
		<-release
		return nil, coreError(secretstore.KindUnavailable, 0, secretstore.ReasonNoReply)
	})

	openerResult := make(chan error, 1)
	go func() {
		_, err := store.Exists(t.Context(), "work")
		openerResult <- err
	}()
	<-entered

	waiterCtx := newCheckpointContext(t.Context())
	waiterResult := make(chan error, 1)
	go func() {
		_, err := store.Exists(waiterCtx, "work")
		waiterResult <- err
	}()
	// The waiter passed its first check, so it is at or behind the lock held by
	// the opener; canceling now and then releasing the opener orders the
	// cancellation before the waiter can read the cached failure.
	<-waiterCtx.checked
	waiterCtx.canceled.Store(true)
	close(release)

	if err := <-openerResult; !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("opener = %v, want ErrCredentialStoreUnavailable", err)
	}
	err := <-waiterResult
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("canceled waiter = %v, want context.Canceled and not the cached open failure", err)
	}
	if _, err := store.Exists(t.Context(), "work"); !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("later live caller = %v, want the cached open failure", err)
	}
}

func TestMapNativeErrorSplitsReadOnlyByStatus(t *testing.T) {
	tests := []struct {
		name         string
		status       int64
		wantReadOnly bool
	}{
		{"sandbox-exec file-write denial", 100001, true},
		{"errSecWrPerm", -61, true},
		{"errSecReadOnly", -25292, true},
		{"missing default keychain", -25307, false},
		{"i/o error", -36, false},
		{"errSecNotAvailable-style -50", -50, false},
		{"no status", 0, false},
		{"arbitrary positive status", 77, false},
	}
	for _, test := range tests {
		for _, operation := range []string{"save", "delete", "repair"} {
			t.Run(test.name+"/"+operation, func(t *testing.T) {
				got := mapNativeError(operation, coreError(secretstore.KindReadOnly, test.status, ""))
				if errors.Is(got, ErrCredentialStoreReadOnly) != test.wantReadOnly {
					t.Fatalf("mapped = %v; read-only = %v, want %v", got, !test.wantReadOnly, test.wantReadOnly)
				}
				if errors.Is(got, ErrCredentialStoreWriteRefused) == test.wantReadOnly {
					t.Fatalf("mapped = %v; write-refused = %v, want %v", got, test.wantReadOnly, !test.wantReadOnly)
				}
				if !errors.Is(got, ErrCredentialStoreUnavailable) && !test.wantReadOnly {
					t.Fatalf("mapped = %v, want it to satisfy ErrCredentialStoreUnavailable", got)
				}
				if errors.Is(got, ErrNotFound) || errors.Is(got, ErrCredentialStoreInternal) {
					t.Fatalf("mapped = %v, must not read as missing or internal", got)
				}
			})
		}
	}
	if strings.Contains(ErrCredentialStoreWriteRefused.Error(), "read-only") {
		t.Fatalf("sentinel text %q must not say read-only", ErrCredentialStoreWriteRefused)
	}
}

// Core v0.1.1 reports an unrecognized write status as KindOther with the
// status kept; the outward result must match what v0.1.0's KindReadOnly gave.
func TestMapNativeErrorRefusesUnrecognizedKindOtherWrites(t *testing.T) {
	tests := []struct {
		name        string
		operation   string
		status      int64
		wantRefused bool
	}{}
	for _, operation := range []string{"save", "delete", "repair"} {
		for _, status := range []int64{-25307, -36, -50, 7} {
			tests = append(tests, struct {
				name        string
				operation   string
				status      int64
				wantRefused bool
			}{fmt.Sprintf("%s/%d", operation, status), operation, status, true})
		}
		tests = append(tests, struct {
			name        string
			operation   string
			status      int64
			wantRefused bool
		}{operation + "/status 0", operation, 0, false})
	}
	for _, operation := range []string{"load", "exists", "open"} {
		tests = append(tests, struct {
			name        string
			operation   string
			status      int64
			wantRefused bool
		}{operation + "/-25307", operation, -25307, false})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := mapNativeError(test.operation, coreError(secretstore.KindOther, test.status, ""))
			if errors.Is(got, ErrCredentialStoreWriteRefused) != test.wantRefused {
				t.Fatalf("mapped = %v; write-refused = %v, want %v", got, !test.wantRefused, test.wantRefused)
			}
			if test.wantRefused {
				if !errors.Is(got, ErrCredentialStoreUnavailable) || errors.Is(got, ErrCredentialStoreReadOnly) || errors.Is(got, ErrCredentialStoreInternal) {
					t.Fatalf("mapped = %v, want unavailable and neither read-only nor internal", got)
				}
				return
			}
			var status *StatusError
			if !errors.As(got, &status) || status.Operation != test.operation || status.Status != test.status {
				t.Fatalf("mapped = %v, want the unchanged StatusError", got)
			}
		})
	}
}
