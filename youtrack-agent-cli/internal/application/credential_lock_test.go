package application

import (
	"context"
	"sync"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/auth"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/profile"
)

// lockProbeStore fails any Save or Delete made without the exclusive profile
// lock. It proves exclusivity with the real registry: while another descriptor
// holds the lock exclusively, a shared acquisition cannot succeed and times
// out; if it succeeds, the caller was not holding the exclusive lock.
type lockProbeStore struct {
	auth.CredentialAccessStore
	registry *profile.Registry

	mu         sync.Mutex
	saves      int
	deletes    int
	violations []string
}

func (s *lockProbeStore) requireExclusive(ctx context.Context, name, operation string) {
	err := s.registry.WithExistingProfileLock(ctx, name, func() error { return nil })
	s.mu.Lock()
	defer s.mu.Unlock()
	if !profile.IsLockTimeout(err) {
		s.violations = append(s.violations, operation+" outside the exclusive profile lock")
	}
}

func (s *lockProbeStore) Save(ctx context.Context, name string, value auth.Credential) error {
	s.requireExclusive(ctx, name, "save")
	s.mu.Lock()
	s.saves++
	s.mu.Unlock()
	return s.CredentialAccessStore.Save(ctx, name, value)
}

func (s *lockProbeStore) Delete(ctx context.Context, name string) error {
	s.requireExclusive(ctx, name, "delete")
	s.mu.Lock()
	s.deletes++
	s.mu.Unlock()
	return s.CredentialAccessStore.Delete(ctx, name)
}

func (s *lockProbeStore) requireClean(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.violations) != 0 {
		t.Errorf("lock violations: %v", s.violations)
	}
}

func TestCredentialSavesRunUnderTheExclusiveLockThroughTheService(t *testing.T) {
	t.Run("probe detects a save without the lock", func(t *testing.T) {
		t.Parallel()
		fixture := newReadLockFixture(t, true)
		fixture.writeLock(t, 0o600)
		probe := &lockProbeStore{CredentialAccessStore: &fixture.store.oauthCredentialStore, registry: fixture.service.Profiles}
		if err := probe.Save(t.Context(), "work", fixture.store.sequence[0]); err != nil {
			t.Fatal(err)
		}
		if len(probe.violations) != 1 {
			t.Fatalf("violations = %v, want the unlocked save to be reported", probe.violations)
		}
	})
	t.Run("oauth login", func(t *testing.T) {
		t.Parallel()
		selected := oauthApplicationProfile(t, false)
		store := &oauthCredentialStore{}
		service := oauthApplicationService(t, selected, store, &oauthFlowTransport{scopeField: `,"scope":"beta"`})
		probe := &lockProbeStore{CredentialAccessStore: store, registry: service.Profiles}
		service.Credentials = probe
		if _, err := service.LoginOAuth(t.Context(), selected.Name, false, callbackBrowser{}); err != nil {
			t.Fatal(err)
		}
		if probe.saves != 1 {
			t.Errorf("saves = %d, want 1", probe.saves)
		}
		probe.requireClean(t)
	})
	t.Run("import-token", func(t *testing.T) {
		t.Parallel()
		selected := oauthApplicationProfile(t, false)
		store := &oauthCredentialStore{}
		service := oauthApplicationService(t, selected, store, &readLockTransport{})
		probe := &lockProbeStore{CredentialAccessStore: store, registry: service.Profiles}
		service.Credentials = probe
		credential := auth.Credential{Kind: auth.CredentialPermanentToken, PermanentToken: "perm-sentinel"}
		if _, err := service.ImportPermanentToken(t.Context(), selected.Name, credential, false); err != nil {
			t.Fatal(err)
		}
		if probe.saves != 1 {
			t.Errorf("saves = %d, want 1", probe.saves)
		}
		probe.requireClean(t)
	})
	t.Run("refresh saves under the writable lock", func(t *testing.T) {
		t.Parallel()
		fixture := newReadLockFixture(t, true)
		fixture.writeLock(t, 0o600)
		fixture.store.sequence = []auth.Credential{readLockCredential(t, fixture.selected, "expired-access", readLockNow.Add(-1))}
		probe := &lockProbeStore{CredentialAccessStore: fixture.store, registry: fixture.service.Profiles}
		fixture.service.Credentials = probe
		if _, _, err := fixture.service.InspectIssue(t.Context(), "work", "APP-1"); err != nil {
			t.Fatal(err)
		}
		if probe.saves != 2 || fixture.transport.tokenRequests != 1 {
			t.Errorf("saves=%d token requests=%d, want 2 and 1", probe.saves, fixture.transport.tokenRequests)
		}
		probe.requireClean(t)
	})
	t.Run("readClient never writes", func(t *testing.T) {
		t.Parallel()
		fixture := newReadLockFixture(t, true)
		fixture.writeLock(t, 0o600)
		probe := &lockProbeStore{CredentialAccessStore: fixture.store, registry: fixture.service.Profiles}
		fixture.service.Credentials = probe
		if _, _, err := fixture.service.readClient(t.Context(), "work"); err != nil {
			t.Fatal(err)
		}
		if probe.saves != 0 || probe.deletes != 0 || fixture.store.saveCalls != 0 {
			t.Errorf("readClient wrote: saves=%d deletes=%d", probe.saves, probe.deletes)
		}
		probe.requireClean(t)
	})
}
