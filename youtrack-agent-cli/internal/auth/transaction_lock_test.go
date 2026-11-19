package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/profile"
)

// lockRegistry is a ProfileRegistry that counts how deep the exclusive profile
// lock is held. A real lock file cannot be re-entered from the same process, so
// a second nested WithProfileLock is recorded as a violation too.
type lockRegistry struct {
	existing   profile.Profile
	addErr     error
	putErr     error
	removeErr  error
	depth      int
	locks      int
	violations []string
}

func (r *lockRegistry) WithProfileLock(_ context.Context, _ string, fn func() error) error {
	r.depth++
	r.locks++
	if r.depth > 1 {
		r.violations = append(r.violations, "nested profile lock")
	}
	defer func() { r.depth-- }()
	return fn()
}

func (r *lockRegistry) requireLocked(operation string) {
	if r.depth == 0 {
		r.violations = append(r.violations, "registry "+operation+" outside the lock")
	}
}

func (r *lockRegistry) Get(context.Context, string) (profile.Profile, error) {
	r.requireLocked("get")
	return r.existing, nil
}

func (r *lockRegistry) Add(context.Context, profile.Profile) error {
	r.requireLocked("add")
	return r.addErr
}

func (r *lockRegistry) Put(context.Context, profile.Profile) error {
	r.requireLocked("put")
	return r.putErr
}

func (r *lockRegistry) Remove(context.Context, string) error {
	r.requireLocked("remove")
	return r.removeErr
}

// guardStore fails any Save, Delete or migration made outside the exclusive
// profile lock, and records what happened.
type guardStore struct {
	registry *lockRegistry
	exists   bool
	loadErr  error
	existing Credential
	deleted  int
	migrated int
	saved    []Credential
	deleteEr error
	loads    int
	// saveErr fails the first Save only; any later Save would be recorded.
	saveErr     error
	failedSaves int
}

func (s *guardStore) guard(operation string) {
	if s.registry.depth == 0 {
		s.registry.violations = append(s.registry.violations, "store "+operation+" outside the exclusive lock")
	}
}

func (s *guardStore) Exists(context.Context, string) (bool, error) { return s.exists, nil }

func (s *guardStore) Load(context.Context, string) (Credential, error) {
	s.loads++
	if s.loadErr != nil {
		return Credential{}, s.loadErr
	}
	return s.existing, nil
}

func (s *guardStore) Save(_ context.Context, _ string, value Credential) error {
	s.guard("save")
	if s.saveErr != nil && s.failedSaves == 0 {
		s.failedSaves++
		return s.saveErr
	}
	s.saved = append(s.saved, value)
	return nil
}

func (s *guardStore) Delete(context.Context, string) error {
	s.guard("delete")
	s.deleted++
	return s.deleteEr
}

func (s *guardStore) MigrateKeychain(context.Context, string) error {
	s.guard("migrate")
	s.migrated++
	return nil
}

func lockTestCredential(kind CredentialKind, marker string) Credential {
	if kind == CredentialOAuth {
		return Credential{
			Kind: CredentialOAuth, AccessToken: marker + "-access", RefreshToken: marker + "-refresh", TokenType: "Bearer",
			AccessTokenExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), OAuthScopes: []string{"YouTrack"},
		}
	}
	return Credential{Kind: CredentialPermanentToken, PermanentToken: marker + "-permanent"}
}

// From outside the store a failed Save over an existing item cannot be told
// apart from one that never reached its destructive step, so login makes no
// further mutation: no restore, no delete, and the original error class stays.
func TestLoginSaveFailureOverExistingCredentialMutatesNothingMore(t *testing.T) {
	failures := map[string]error{
		"contended": fmt.Errorf("credential store save: %w", ErrCredentialStoreContended),
		"canceled":  fmt.Errorf("credential store save: %w", context.Canceled),
		"generic":   errors.New("save failed"),
	}
	existing := map[string]func(*guardStore){
		"readable item": func(store *guardStore) {
			store.exists, store.existing = true, lockTestCredential(CredentialPermanentToken, "old")
		},
		"unreadable item": func(store *guardStore) { store.exists, store.loadErr = true, ErrKeychainMigrationRequired },
	}
	for failureName, saveErr := range failures {
		for itemName, arrange := range existing {
			t.Run(failureName+"/"+itemName, func(t *testing.T) {
				registry, store, intent := newLockFixture(t)
				store.saveErr = saveErr
				arrange(store)
				_, err := Login(t.Context(), store, registry, intent, lockTestCredential(CredentialOAuth, "new"), true)
				if !errors.Is(err, saveErr) || errors.Is(err, ErrLoginIncomplete) {
					t.Fatalf("error = %v, want only the save error", err)
				}
				if store.failedSaves != 1 || len(store.saved) != 0 || store.deleted != 0 {
					t.Errorf("failed saves=%d restoring saves=%d deletes=%d, want one failed save and nothing else", store.failedSaves, len(store.saved), store.deleted)
				}
				requireNoLockViolations(t, registry)
			})
		}
	}
}

func newLockFixture(t *testing.T) (*lockRegistry, *guardStore, profile.Profile) {
	t.Helper()
	selected := authTestProfile(t)
	intent, err := selected.LoginIntent()
	if err != nil {
		t.Fatal(err)
	}
	registry := &lockRegistry{existing: selected}
	return registry, &guardStore{registry: registry}, intent
}

func requireNoLockViolations(t *testing.T, registry *lockRegistry) {
	t.Helper()
	if len(registry.violations) != 0 {
		t.Errorf("lock violations: %v", registry.violations)
	}
	if registry.depth != 0 {
		t.Errorf("lock depth after the call = %d", registry.depth)
	}
}

// Every Save and Delete of a credential runs under the one exclusive profile
// lock, so the native store needs no lock of its own.
func TestCredentialWritesRunUnderTheExclusiveProfileLock(t *testing.T) {
	metadataErr := errors.New("registry unavailable")
	tests := []struct {
		name        string
		run         func(t *testing.T, registry *lockRegistry, store *guardStore, intent profile.Profile) error
		wantSaves   int
		wantDeletes int
		wantMigrate int
		wantErr     error
	}{
		{
			name: "oauth login",
			run: func(t *testing.T, registry *lockRegistry, store *guardStore, intent profile.Profile) error {
				_, err := Login(t.Context(), store, registry, intent, lockTestCredential(CredentialOAuth, "new"), false)
				return err
			},
			wantSaves: 1,
		},
		{
			name: "import-token login",
			run: func(t *testing.T, registry *lockRegistry, store *guardStore, intent profile.Profile) error {
				_, err := Login(t.Context(), store, registry, intent, lockTestCredential(CredentialPermanentToken, "new"), false)
				return err
			},
			wantSaves: 1,
		},
		{
			name: "login overwrite",
			run: func(t *testing.T, registry *lockRegistry, store *guardStore, intent profile.Profile) error {
				store.exists, store.existing = true, lockTestCredential(CredentialPermanentToken, "old")
				_, err := Login(t.Context(), store, registry, intent, lockTestCredential(CredentialOAuth, "new"), true)
				return err
			},
			wantSaves: 1,
		},
		{
			name: "login rollback restores the snapshot",
			run: func(t *testing.T, registry *lockRegistry, store *guardStore, intent profile.Profile) error {
				store.exists, store.existing = true, lockTestCredential(CredentialPermanentToken, "old")
				registry.putErr = metadataErr
				_, err := Login(t.Context(), store, registry, intent, lockTestCredential(CredentialOAuth, "new"), true)
				return err
			},
			wantSaves: 2, wantErr: metadataErr,
		},
		{
			name: "login rollback deletes the new item",
			run: func(t *testing.T, registry *lockRegistry, store *guardStore, intent profile.Profile) error {
				registry.putErr = metadataErr
				store.exists, store.loadErr = true, ErrKeychainMigrationRequired
				_, err := Login(t.Context(), store, registry, intent, lockTestCredential(CredentialOAuth, "new"), true)
				return err
			},
			wantSaves: 1, wantDeletes: 1, wantErr: metadataErr,
		},
		{
			name: "logout restore after a metadata failure",
			run: func(t *testing.T, registry *lockRegistry, store *guardStore, _ profile.Profile) error {
				store.exists, store.existing = true, lockTestCredential(CredentialOAuth, "old")
				registry.removeErr = metadataErr
				return Logout(t.Context(), store, registry, "work")
			},
			wantSaves: 1, wantDeletes: 1, wantErr: metadataErr,
		},
		{
			name: "migrate keychain",
			run: func(t *testing.T, registry *lockRegistry, store *guardStore, _ profile.Profile) error {
				store.exists = true
				return MigrateKeychain(t.Context(), store, registry, "work")
			},
			wantMigrate: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registry, store, intent := newLockFixture(t)
			err := test.run(t, registry, store, intent)
			if test.wantErr == nil && err != nil {
				t.Fatalf("error = %v", err)
			}
			if test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
			if len(store.saved) != test.wantSaves || store.deleted != test.wantDeletes || store.migrated != test.wantMigrate {
				t.Errorf("saves=%d deletes=%d migrations=%d, want %d %d %d", len(store.saved), store.deleted, store.migrated, test.wantSaves, test.wantDeletes, test.wantMigrate)
			}
			if registry.locks != 1 {
				t.Errorf("lock acquisitions = %d, want 1", registry.locks)
			}
			requireNoLockViolations(t, registry)
		})
	}
}

// R8: a confirmed overwrite proceeds without a snapshot only when the old item
// is unreadable by policy (AccessDenied) or reported present but not loadable.
func TestLoginOverUnreadableCredential(t *testing.T) {
	metadataErr := errors.New("registry unavailable")
	const oldMarker = "old"
	unreadable := map[string]error{
		"access denied":                  fmt.Errorf("credential store load: %w: access denied", ErrKeychainMigrationRequired),
		"exists true but load not found": fmt.Errorf("credential store load: %w: not found", ErrNotFound),
	}
	for name, loadErr := range unreadable {
		t.Run(name+" with --yes saves without a snapshot", func(t *testing.T) {
			registry, store, intent := newLockFixture(t)
			store.exists, store.loadErr = true, loadErr
			if _, err := Login(t.Context(), store, registry, intent, lockTestCredential(CredentialOAuth, "new"), true); err != nil {
				t.Fatalf("error = %v", err)
			}
			if len(store.saved) != 1 || store.deleted != 0 || store.loads != 1 {
				t.Errorf("saves=%d deletes=%d loads=%d", len(store.saved), store.deleted, store.loads)
			}
			requireNoLockViolations(t, registry)
		})
		t.Run(name+" with --yes and a metadata failure deletes the new item", func(t *testing.T) {
			registry, store, intent := newLockFixture(t)
			registry.putErr = metadataErr
			store.exists, store.loadErr = true, loadErr
			_, err := Login(t.Context(), store, registry, intent, lockTestCredential(CredentialOAuth, "new"), true)
			if !errors.Is(err, ErrLoginIncomplete) || !errors.Is(err, metadataErr) {
				t.Fatalf("error = %v, want ErrLoginIncomplete joined with the metadata error", err)
			}
			if len(store.saved) != 1 || store.deleted != 1 {
				t.Errorf("saves=%d deletes=%d, want the new item saved then deleted", len(store.saved), store.deleted)
			}
			requireNoLockViolations(t, registry)
		})
		deleteFailures := map[string]error{
			"plain":              errors.New("delete failed"),
			"status error":       &StatusError{Operation: "delete", Status: -1},
			"migration required": fmt.Errorf("delete: %w", ErrKeychainMigrationRequired),
			"contended":          fmt.Errorf("delete: %w", ErrCredentialStoreContended),
			"not found":          fmt.Errorf("delete: %w", ErrNotFound),
			"already exists":     fmt.Errorf("delete: %w", profile.ErrAlreadyExists),
		}
		for failureName, deleteErr := range deleteFailures {
			t.Run(name+" with a failing rollback delete ("+failureName+") still reports the replaced credential", func(t *testing.T) {
				registry, store, intent := newLockFixture(t)
				registry.putErr, store.deleteEr = metadataErr, deleteErr
				store.exists, store.loadErr = true, loadErr
				_, err := Login(t.Context(), store, registry, intent, lockTestCredential(CredentialOAuth, "new"), true)
				if !errors.Is(err, ErrLoginIncomplete) || !errors.Is(err, metadataErr) || !errors.Is(err, deleteErr) {
					t.Fatalf("error = %v, want ErrLoginIncomplete with the metadata and delete errors", err)
				}
				requireNoLockViolations(t, registry)
			})
		}
		t.Run(name+" without --yes still requires confirmation", func(t *testing.T) {
			registry, store, intent := newLockFixture(t)
			store.exists, store.loadErr = true, loadErr
			_, err := Login(t.Context(), store, registry, intent, lockTestCredential(CredentialOAuth, "new"), false)
			if !errors.Is(err, ErrOverwriteConfirmationRequired) {
				t.Fatalf("error = %v, want ErrOverwriteConfirmationRequired", err)
			}
			if store.loads != 0 || len(store.saved) != 0 || store.deleted != 0 {
				t.Errorf("loads=%d saves=%d deletes=%d, want none before confirmation", store.loads, len(store.saved), store.deleted)
			}
			requireNoLockViolations(t, registry)
		})
	}

	abort := map[string]error{
		"unavailable":          fmt.Errorf("load: %w", ErrCredentialStoreUnavailable),
		"read only":            fmt.Errorf("load: %w", ErrCredentialStoreReadOnly),
		"interaction required": fmt.Errorf("load: %w", ErrInteractionNotAllowed),
		"corrupt or too large": fmt.Errorf("stored credential is invalid: %w", ErrInvalidToken),
		"internal":             fmt.Errorf("load: %w", ErrCredentialStoreInternal),
		"contended":            fmt.Errorf("load: %w", ErrCredentialStoreContended),
		"canceled":             fmt.Errorf("load: %w", context.Canceled),
		"deadline":             fmt.Errorf("load: %w", context.DeadlineExceeded),
		"status error":         &StatusError{Operation: "load", Status: -1},
	}
	for name, loadErr := range abort {
		t.Run(name+" aborts before any write", func(t *testing.T) {
			registry, store, intent := newLockFixture(t)
			store.exists, store.loadErr = true, loadErr
			_, err := Login(t.Context(), store, registry, intent, lockTestCredential(CredentialOAuth, "new"), true)
			if !errors.Is(err, loadErr) || errors.Is(err, ErrLoginIncomplete) {
				t.Fatalf("error = %v, want %v", err, loadErr)
			}
			if len(store.saved) != 0 || store.deleted != 0 {
				t.Errorf("saves=%d deletes=%d, want none", len(store.saved), store.deleted)
			}
			requireNoLockViolations(t, registry)
		})
	}

	t.Run("readable item with --yes is restored on a metadata failure", func(t *testing.T) {
		registry, store, intent := newLockFixture(t)
		registry.putErr = metadataErr
		store.exists, store.existing = true, lockTestCredential(CredentialPermanentToken, oldMarker)
		_, err := Login(t.Context(), store, registry, intent, lockTestCredential(CredentialOAuth, "new"), true)
		if !errors.Is(err, metadataErr) || errors.Is(err, ErrLoginIncomplete) {
			t.Fatalf("error = %v, want only the metadata error", err)
		}
		if len(store.saved) != 2 || store.deleted != 0 {
			t.Fatalf("saves=%d deletes=%d, want new then restored snapshot", len(store.saved), store.deleted)
		}
		if got := store.saved[1].PermanentToken; got != oldMarker+"-permanent" {
			t.Errorf("restored credential kind=%q token present=%v, want the previous permanent token", store.saved[1].Kind, got != "")
		}
		requireNoLockViolations(t, registry)
	})
	t.Run("readable item without --yes requires confirmation", func(t *testing.T) {
		registry, store, intent := newLockFixture(t)
		store.exists, store.existing = true, lockTestCredential(CredentialPermanentToken, oldMarker)
		_, err := Login(t.Context(), store, registry, intent, lockTestCredential(CredentialOAuth, "new"), false)
		if !errors.Is(err, ErrOverwriteConfirmationRequired) || store.loads != 0 || len(store.saved) != 0 {
			t.Fatalf("error=%v loads=%d saves=%d", err, store.loads, len(store.saved))
		}
	})
	t.Run("no existing item deletes the new one on a metadata failure", func(t *testing.T) {
		registry, store, intent := newLockFixture(t)
		registry.putErr = metadataErr
		_, err := Login(t.Context(), store, registry, intent, lockTestCredential(CredentialOAuth, "new"), false)
		if !errors.Is(err, metadataErr) || errors.Is(err, ErrLoginIncomplete) {
			t.Fatalf("error = %v, want only the metadata error", err)
		}
		if len(store.saved) != 1 || store.deleted != 1 || store.loads != 0 {
			t.Errorf("saves=%d deletes=%d loads=%d", len(store.saved), store.deleted, store.loads)
		}
	})
	t.Run("the incomplete-login error names re-login and leaks no token", func(t *testing.T) {
		registry, store, intent := newLockFixture(t)
		registry.putErr = metadataErr
		store.exists, store.loadErr = true, ErrKeychainMigrationRequired
		_, err := Login(t.Context(), store, registry, intent, lockTestCredential(CredentialOAuth, "secret-marker"), true)
		if !errors.Is(err, ErrLoginIncomplete) {
			t.Fatalf("error = %v", err)
		}
		if strings.Contains(err.Error(), "secret-marker") {
			t.Errorf("error leaks a token: %v", err)
		}
		if !strings.Contains(ErrLoginIncomplete.Error(), "unreadable credential") {
			t.Errorf("sentinel text = %q", ErrLoginIncomplete)
		}
	})
}
