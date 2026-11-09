package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/profile"
)

type memoryCredentialStore struct {
	values       map[string]Credential
	migrateCalls int
	saveCalls    int
	encodeSave   bool
}

type logoutCredentialStore struct {
	credential  Credential
	loadErr     error
	deleteErr   error
	saveErr     error
	loadCalls   int
	deleteCalls int
	saveCalls   int
	saveCtxErr  error
	encodeSave  bool
}

func (*logoutCredentialStore) Exists(context.Context, string) (bool, error) { return true, nil }

func (s *logoutCredentialStore) Load(context.Context, string) (Credential, error) {
	s.loadCalls++
	return s.credential, s.loadErr
}

func (s *logoutCredentialStore) Save(ctx context.Context, _ string, value Credential) error {
	s.saveCalls++
	s.saveCtxErr = ctx.Err()
	s.credential = value
	if s.encodeSave {
		_, err := encodeCredentialValue(value)
		return err
	}
	return s.saveErr
}

func (s *logoutCredentialStore) Delete(context.Context, string) error {
	s.deleteCalls++
	return s.deleteErr
}

type logoutRegistry struct {
	removeErr   error
	lockCalls   int
	removeCalls int
}

type failingPutRegistry struct {
	ProfileRegistry
	err error
}

func (r failingPutRegistry) Put(context.Context, profile.Profile) error { return r.err }

func (r *logoutRegistry) WithProfileLock(_ context.Context, _ string, fn func() error) error {
	r.lockCalls++
	return fn()
}

func (*logoutRegistry) Get(context.Context, string) (profile.Profile, error) {
	return profile.Profile{}, profile.ErrNotFound
}

func (*logoutRegistry) Add(context.Context, profile.Profile) error { return nil }
func (*logoutRegistry) Put(context.Context, profile.Profile) error { return nil }

func (r *logoutRegistry) Remove(context.Context, string) error {
	r.removeCalls++
	return r.removeErr
}

func (s *memoryCredentialStore) Exists(_ context.Context, name string) (bool, error) {
	_, ok := s.values[name]
	return ok, nil
}

func (s *memoryCredentialStore) Load(_ context.Context, name string) (Credential, error) {
	value, ok := s.values[name]
	if !ok {
		return Credential{}, ErrNotFound
	}
	return value, nil
}

func (s *memoryCredentialStore) Save(_ context.Context, name string, value Credential) error {
	s.saveCalls++
	if s.encodeSave {
		if _, err := encodeCredentialValue(value); err != nil {
			return err
		}
	}
	s.values[name] = value
	return nil
}

func (s *memoryCredentialStore) Delete(_ context.Context, name string) error {
	delete(s.values, name)
	return nil
}

func (s *memoryCredentialStore) MigrateKeychain(context.Context, string) error {
	s.migrateCalls++
	return nil
}

func TestLoginInitialBindingAndReplacementConfirmation(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	registry := profile.NewRegistry(filepath.Join(directory, "profiles.json"))
	intent, err := authTestProfile(t).LoginIntent()
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Add(ctx, intent); err != nil {
		t.Fatal(err)
	}
	store := &memoryCredentialStore{values: map[string]Credential{}}
	credential := Credential{Kind: CredentialPermanentToken, PermanentToken: "sentinel"}
	if _, err := Login(ctx, store, registry, intent, credential, false); err != nil {
		t.Fatalf("initial binding required confirmation: %v", err)
	}
	rotated, err := registry.Get(ctx, intent.Name)
	if err != nil {
		t.Fatal(err)
	}
	nextIntent, err := rotated.LoginIntent()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Login(ctx, store, registry, nextIntent, credential, false); !errors.Is(err, ErrOverwriteConfirmationRequired) {
		t.Fatalf("replacement error=%v, want confirmation", err)
	}
	if _, err := Login(ctx, store, registry, nextIntent, credential, true); err != nil {
		t.Fatalf("confirmed replacement failed: %v", err)
	}
	if store.migrateCalls != 0 {
		t.Fatalf("ordinary login implicitly migrated Keychain ACL %d times", store.migrateCalls)
	}
}

func TestLoginRejectsProfileTopologyDrift(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	registry := profile.NewRegistry(filepath.Join(directory, "profiles.json"))
	original, err := authTestProfile(t).LoginIntent()
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Add(ctx, original); err != nil {
		t.Fatal(err)
	}
	changed := original
	changed.ExpectedLogin = "bob"
	if err := registry.Put(ctx, changed); err != nil {
		t.Fatal(err)
	}
	store := &memoryCredentialStore{values: map[string]Credential{}}
	credential := Credential{Kind: CredentialPermanentToken, PermanentToken: "sentinel"}
	if _, err := Login(ctx, store, registry, original, credential, true); !errors.Is(err, ErrProfileChangedDuringLogin) {
		t.Fatalf("drift error=%v, want ErrProfileChangedDuringLogin", err)
	}
	if len(store.values) != 0 {
		t.Fatal("credential was stored after topology drift")
	}
}

func TestLoginRejectsProfileDeletedDuringVerification(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	registry := profile.NewRegistry(filepath.Join(directory, "profiles.json"))
	loginIntent, err := authTestProfile(t).LoginIntent()
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryCredentialStore{values: map[string]Credential{}}
	credential := Credential{Kind: CredentialPermanentToken, PermanentToken: "sentinel"}
	if _, err := Login(ctx, store, registry, loginIntent, credential, true); !errors.Is(err, ErrProfileChangedDuringLogin) {
		t.Fatalf("deleted profile error=%v, want ErrProfileChangedDuringLogin", err)
	}
	if len(store.values) != 0 {
		t.Fatal("credential was stored after profile deletion")
	}
}

func TestLogoutDeletesAcrossAllCredentialSnapshotStates(t *testing.T) {
	for _, test := range []struct {
		name    string
		loadErr error
	}{
		{name: "snapshot available"},
		{name: "credential absent", loadErr: ErrNotFound},
		{name: "snapshot unavailable", loadErr: ErrInteractionNotAllowed},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &logoutCredentialStore{
				credential: Credential{Kind: CredentialPermanentToken, PermanentToken: "sentinel"},
				loadErr:    test.loadErr,
			}
			registry := &logoutRegistry{}
			if err := Logout(t.Context(), store, registry, "work"); err != nil {
				t.Fatal(err)
			}
			if store.loadCalls != 1 || store.deleteCalls != 1 || store.saveCalls != 0 || registry.removeCalls != 1 {
				t.Fatalf("calls load=%d delete=%d save=%d remove=%d", store.loadCalls, store.deleteCalls, store.saveCalls, registry.removeCalls)
			}
		})
	}
}

func TestLogoutRollbackDependsOnSnapshotState(t *testing.T) {
	removeErr := errors.New("registry unavailable")
	restoreErr := errors.New("credential restore unavailable")
	for _, test := range []struct {
		name           string
		loadErr        error
		saveErr        error
		wantSave       int
		wantIncomplete bool
	}{
		{name: "snapshot restores credential", wantSave: 1},
		{name: "snapshot restore fails", saveErr: restoreErr, wantSave: 1, wantIncomplete: true},
		{name: "absent needs no restore", loadErr: ErrNotFound},
		{name: "unreadable cannot restore", loadErr: ErrInteractionNotAllowed, wantIncomplete: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent, cancel := context.WithCancel(context.Background())
			cancel()
			store := &logoutCredentialStore{
				credential: Credential{Kind: CredentialPermanentToken, PermanentToken: "sentinel"},
				loadErr:    test.loadErr,
				saveErr:    test.saveErr,
			}
			registry := &logoutRegistry{removeErr: removeErr}
			err := Logout(parent, store, registry, "work")
			if !errors.Is(err, removeErr) || errors.Is(err, ErrLogoutIncomplete) != test.wantIncomplete {
				t.Fatalf("error = %v", err)
			}
			if test.saveErr != nil && !errors.Is(err, test.saveErr) {
				t.Fatalf("restore error was lost: %v", err)
			}
			if store.saveCalls != test.wantSave {
				t.Fatalf("save calls = %d, want %d", store.saveCalls, test.wantSave)
			}
			if store.saveCtxErr != nil {
				t.Fatalf("compensation inherited canceled context: %v", store.saveCtxErr)
			}
		})
	}
}

func TestLogoutCancellationNeverFallsThroughToDeletion(t *testing.T) {
	for _, cancellation := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(cancellation.Error(), func(t *testing.T) {
			store := &logoutCredentialStore{loadErr: cancellation}
			registry := &logoutRegistry{}
			err := Logout(t.Context(), store, registry, "work")
			if !errors.Is(err, cancellation) {
				t.Fatalf("error = %v", err)
			}
			if store.deleteCalls != 0 || registry.removeCalls != 0 {
				t.Fatalf("canceled load continued: delete=%d remove=%d", store.deleteCalls, registry.removeCalls)
			}
		})
	}
}

func TestLogoutDeleteCancellationPreservesMetadata(t *testing.T) {
	store := &logoutCredentialStore{deleteErr: context.Canceled}
	registry := &logoutRegistry{}
	err := Logout(t.Context(), store, registry, "work")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	if registry.removeCalls != 0 || store.saveCalls != 0 {
		t.Fatalf("delete failure changed later state: remove=%d save=%d", registry.removeCalls, store.saveCalls)
	}
}

func TestLogoutCanRestoreDecodedV1OAuthCredential(t *testing.T) {
	selected := authTestProfile(t)
	legacyPayload := fmt.Sprintf(
		`{"version":1,"kind":"oauth","profile_identity":%q,"generation":%q,"capabilities":["read","issue-update"],"access_token":"access","refresh_token":"refresh","token_type":"Bearer","access_token_expires_at":"2030-01-01T00:00:00Z"}`,
		profile.CredentialIdentity(selected),
		selected.CredentialGeneration,
	)
	legacy, err := decodeCredentialValue(append([]byte(credentialPayloadPrefixV1), legacyPayload...))
	if err != nil {
		t.Fatal(err)
	}
	removeErr := errors.New("registry unavailable")
	store := &logoutCredentialStore{credential: legacy, encodeSave: true}
	registry := &logoutRegistry{removeErr: removeErr}
	err = Logout(t.Context(), store, registry, selected.Name)
	if !errors.Is(err, removeErr) || errors.Is(err, ErrLogoutIncomplete) {
		t.Fatalf("error = %v", err)
	}
	if store.saveCalls != 1 {
		t.Fatalf("save calls = %d", store.saveCalls)
	}
}

func TestLoginCanRestoreDecodedV1OAuthCredential(t *testing.T) {
	ctx := t.Context()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	registry := profile.NewRegistry(filepath.Join(directory, "profiles.json"))
	selected := authTestProfile(t)
	if err := registry.Add(ctx, selected); err != nil {
		t.Fatal(err)
	}
	loginIntent, err := selected.LoginIntent()
	if err != nil {
		t.Fatal(err)
	}
	legacyPayload := fmt.Sprintf(
		`{"version":1,"kind":"oauth","profile_identity":%q,"generation":%q,"capabilities":["read","issue-update"],"access_token":"old-access","refresh_token":"old-refresh","token_type":"Bearer","access_token_expires_at":"2030-01-01T00:00:00Z"}`,
		profile.CredentialIdentity(selected),
		selected.CredentialGeneration,
	)
	legacy, err := decodeCredentialValue(append([]byte(credentialPayloadPrefixV1), legacyPayload...))
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryCredentialStore{values: map[string]Credential{selected.Name: legacy}, encodeSave: true}
	putErr := errors.New("registry unavailable")
	newCredential := Credential{
		Kind: CredentialOAuth, AccessToken: "new-access", RefreshToken: "new-refresh",
		TokenType: "Bearer", AccessTokenExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		OAuthScopes: []string{"YouTrack"},
	}
	_, err = Login(ctx, store, failingPutRegistry{ProfileRegistry: registry, err: putErr}, loginIntent, newCredential, true)
	if !errors.Is(err, putErr) {
		t.Fatalf("error = %v", err)
	}
	if store.saveCalls != 2 || store.values[selected.Name].AccessToken != legacy.AccessToken {
		t.Fatalf("legacy credential was not restored: saves=%d credential=%#v", store.saveCalls, store.values[selected.Name])
	}
}
