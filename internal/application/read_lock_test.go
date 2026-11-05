package application

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/auth"
	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/lockfile"
	"github.com/abigotado/youtrack-agent-cli/internal/profile"
)

var readLockNow = time.Unix(1_700_000_000, 0).UTC()

// sequenceStore returns its credentials in order, repeating the last one, so a
// test can change what another process would have stored between two loads.
type sequenceStore struct {
	oauthCredentialStore
	sequence []auth.Credential
	loadErr  error
	loads    int
}

func (s *sequenceStore) Load(context.Context, string) (auth.Credential, error) {
	s.loads++
	if s.loadErr != nil {
		return auth.Credential{}, s.loadErr
	}
	return s.sequence[min(s.loads, len(s.sequence))-1], nil
}

type readLockTransport struct {
	tokenRequests int
	bearers       []string
}

func (transport *readLockTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	var body string
	switch path := request.URL.Path; {
	case request.URL.Host == "hub.example.test":
		transport.tokenRequests++
		body = `{"access_token":"refreshed-access","refresh_token":"refreshed-refresh","token_type":"Bearer","expires_in":3600}`
	case request.URL.Host != "tracker.example.test":
		return nil, fmt.Errorf("unexpected origin %s", request.URL.Host)
	case strings.HasSuffix(path, "/users/me"):
		transport.bearers = append(transport.bearers, request.Header.Get("Authorization"))
		body = `{"id":"1-42","login":"alice"}`
	case strings.HasSuffix(path, "/issues"), strings.HasSuffix(path, "/comments"), strings.HasSuffix(path, "/customFields"):
		body = `[]`
	case strings.Contains(path, "/admin/projects/"):
		body = `{"id":"0-1","shortName":"APP"}`
	default:
		body = `{"id":"2-1","idReadable":"APP-1","summary":"s","project":{"id":"0-1","shortName":"APP"}}`
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: request}, nil
}

func readLockCredential(t *testing.T, selected profile.Profile, access string, expires time.Time) auth.Credential {
	t.Helper()
	bound, err := auth.BindCredential(auth.Credential{
		Kind: auth.CredentialOAuth, AccessToken: access, RefreshToken: "stored-refresh", TokenType: "Bearer",
		AccessTokenExpiresAt: expires, OAuthScopes: []string{"beta"},
	}, selected)
	if err != nil {
		t.Fatal(err)
	}
	return bound
}

type readLockFixture struct {
	service   *Service
	store     *sequenceStore
	transport *readLockTransport
	selected  profile.Profile
	directory string
	lock      string
}

func newReadLockFixture(t *testing.T, register bool) *readLockFixture {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	registryPath := filepath.Join(directory, "profiles.json")
	registry := profile.NewRegistry(registryPath)
	selected := oauthApplicationProfile(t, true)
	if register {
		if err := registry.Add(t.Context(), selected); err != nil {
			t.Fatal(err)
		}
	}
	store := &sequenceStore{sequence: []auth.Credential{readLockCredential(t, selected, "stored-access", readLockNow.Add(time.Hour))}}
	transport := &readLockTransport{}
	service := &Service{Profiles: registry, Credentials: store, HTTP: transport, Now: func() time.Time { return readLockNow }}
	return &readLockFixture{service: service, store: store, transport: transport, selected: selected, directory: directory, lock: registryPath + ".profile-work.lock"}
}

func (fixture *readLockFixture) writeLock(t *testing.T, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(fixture.lock, nil, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.lock, mode); err != nil {
		t.Fatal(err)
	}
}

func directoryNames(t *testing.T, directory string) []string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func inspectReads() map[string]func(context.Context, *Service) error {
	return map[string]func(context.Context, *Service) error{
		"issue": func(ctx context.Context, service *Service) error {
			_, _, err := service.InspectIssue(ctx, "work", "APP-1")
			return err
		},
		"issues": func(ctx context.Context, service *Service) error {
			_, _, _, err := service.InspectIssues(ctx, "work", "project: APP", 10, 0)
			return err
		},
		"comments": func(ctx context.Context, service *Service) error {
			_, _, _, err := service.InspectComments(ctx, "work", "APP-1", 10, 0)
			return err
		},
		"project": func(ctx context.Context, service *Service) error {
			_, _, err := service.InspectProject(ctx, "work", "0-1")
			return err
		},
		"schema": func(ctx context.Context, service *Service) error {
			_, _, _, err := service.InspectSchema(ctx, "work", "0-1", 10, 0)
			return err
		},
	}
}

func requireTypedRecovery(t *testing.T, err error, reason string, code errx.Code) *errx.Error {
	t.Helper()
	var typed *errx.Error
	if !errors.As(TranslateError(err, "work"), &typed) {
		t.Fatalf("untyped result for %v", err)
	}
	if typed.Reason != reason || typed.Code != code {
		t.Fatalf("reason=%q code=%d, want %q %d (%v)", typed.Reason, typed.Code, reason, code, err)
	}
	return typed
}

func TestReadWithExistingLockChangesNoLocalState(t *testing.T) {
	fixture := newReadLockFixture(t, true)
	fixture.writeLock(t, 0o600)
	before := directoryNames(t, fixture.directory)

	if _, _, err := fixture.service.InspectIssue(t.Context(), "work", "APP-1"); err != nil {
		t.Fatal(err)
	}

	if after := directoryNames(t, fixture.directory); !slices.Equal(before, after) {
		t.Errorf("directory changed: %v -> %v", before, after)
	}
	if fixture.store.loads != 1 || fixture.store.saveCalls != 0 || fixture.transport.tokenRequests != 0 {
		t.Errorf("loads=%d saves=%d token requests=%d", fixture.store.loads, fixture.store.saveCalls, fixture.transport.tokenRequests)
	}
}

// The read-only descriptor must keep real exclusion, or a read could load a
// credential in the middle of another process's login or refresh.
func TestReadWaitsForTheWritableLockHolder(t *testing.T) {
	fixture := newReadLockFixture(t, true)
	fixture.writeLock(t, 0o600)

	err := fixture.service.Profiles.WithProfileLock(t.Context(), "work", func() error {
		_, _, readErr := fixture.service.InspectIssue(t.Context(), "work", "APP-1")
		return readErr
	})

	var timedOut *lockfile.TimeoutError
	if !errors.As(err, &timedOut) {
		t.Fatalf("err=%v, want a lock timeout", err)
	}
	if fixture.store.loads != 0 {
		t.Errorf("credential loaded %d times while the lock was held", fixture.store.loads)
	}
}

func TestDueReadReloadsTheCredentialUnderTheWritableLock(t *testing.T) {
	fixture := newReadLockFixture(t, true)
	fixture.writeLock(t, 0o600)
	fixture.store.sequence = []auth.Credential{
		readLockCredential(t, fixture.selected, "expired-access", readLockNow.Add(-time.Minute)),
		readLockCredential(t, fixture.selected, "renewed-elsewhere", readLockNow.Add(time.Hour)),
	}

	if _, _, err := fixture.service.InspectIssue(t.Context(), "work", "APP-1"); err != nil {
		t.Fatal(err)
	}

	if fixture.transport.tokenRequests != 0 || fixture.store.saveCalls != 0 {
		t.Errorf("spent a stale refresh token: token requests=%d saves=%d", fixture.transport.tokenRequests, fixture.store.saveCalls)
	}
	if want := []string{"Bearer renewed-elsewhere"}; !slices.Equal(fixture.transport.bearers, want) {
		t.Errorf("bearers=%v, want %v", fixture.transport.bearers, want)
	}
}

func TestReadRefreshesExactlyWhenTheSkewIsReached(t *testing.T) {
	tests := []struct {
		name    string
		expires time.Duration
		refresh bool
	}{
		{"expired", -time.Minute, true},
		{"inside skew", refreshSkew - time.Second, true},
		{"at skew", refreshSkew, true},
		{"past skew", refreshSkew + time.Second, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newReadLockFixture(t, true)
			fixture.writeLock(t, 0o600)
			fixture.store.sequence = []auth.Credential{readLockCredential(t, fixture.selected, "stored-access", readLockNow.Add(test.expires))}

			if _, _, err := fixture.service.InspectIssue(t.Context(), "work", "APP-1"); err != nil {
				t.Fatal(err)
			}

			wantRequests, wantSaves, wantBearer := 0, 0, "Bearer stored-access"
			if test.refresh {
				wantRequests, wantSaves, wantBearer = 1, 1, "Bearer refreshed-access"
			}
			if fixture.transport.tokenRequests != wantRequests || fixture.store.saveCalls != wantSaves {
				t.Errorf("token requests=%d saves=%d", fixture.transport.tokenRequests, fixture.store.saveCalls)
			}
			if !slices.Equal(fixture.transport.bearers, []string{wantBearer}) {
				t.Errorf("bearers=%v, want %s", fixture.transport.bearers, wantBearer)
			}
		})
	}
}

func TestMissingLockIsCreatedOnlyForARegisteredProfile(t *testing.T) {
	t.Run("registered", func(t *testing.T) {
		fixture := newReadLockFixture(t, true)
		if _, _, err := fixture.service.InspectIssue(t.Context(), "work", "APP-1"); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(fixture.lock); err != nil {
			t.Errorf("lock was not created: %v", err)
		}
	})
	t.Run("unknown profile", func(t *testing.T) {
		fixture := newReadLockFixture(t, false)
		before := directoryNames(t, fixture.directory)
		_, _, err := fixture.service.InspectIssue(t.Context(), "work", "APP-1")
		if !errors.Is(err, profile.ErrNotFound) {
			t.Fatalf("err=%v", err)
		}
		if after := directoryNames(t, fixture.directory); !slices.Equal(before, after) {
			t.Errorf("directory changed: %v -> %v", before, after)
		}
	})
	t.Run("missing state directory", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "state")
		service := &Service{Profiles: profile.NewRegistry(filepath.Join(directory, "profiles.json")), Credentials: &trapCredentials{}}
		if _, _, err := service.InspectIssue(t.Context(), "work", "APP-1"); !errors.Is(err, profile.ErrNotFound) {
			t.Fatalf("err=%v", err)
		}
		if _, err := os.Lstat(directory); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("a read created the state directory: %v", err)
		}
	})
}

func TestUnusableLockKeepsAnswersTheRegistryCanGive(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the file mode that denies the lock")
	}
	t.Run("unknown profile keeps not found", func(t *testing.T) {
		fixture := newReadLockFixture(t, false)
		fixture.writeLock(t, 0o000)
		if _, _, err := fixture.service.InspectIssue(t.Context(), "work", "APP-1"); !errors.Is(err, profile.ErrNotFound) {
			t.Fatalf("err=%v", err)
		}
	})
	for name, mode := range map[string]os.FileMode{"denied": 0o000, "read-only mode": 0o400} {
		t.Run(name+" lock reports the denial", func(t *testing.T) {
			fixture := newReadLockFixture(t, true)
			fixture.writeLock(t, mode)
			_, _, err := fixture.service.InspectIssue(t.Context(), "work", "APP-1")
			typed := requireTypedRecovery(t, err, localStateAccessDenied, errx.CodePermission)
			if strings.Contains(typed.Hint, "auth status") {
				t.Errorf("a renewal cannot repair this lock: %q", typed.Hint)
			}
			if fixture.store.loads != 0 {
				t.Errorf("credential loaded %d times", fixture.store.loads)
			}
		})
	}
	t.Run("removed saved default stays stale", func(t *testing.T) {
		fixture := newReadLockFixture(t, false)
		ctx := context.WithValue(t.Context(), selectionGuardKey{}, selectionGuard{name: "work", identity: profile.SelectionIdentity(fixture.selected)})
		_, _, err := fixture.service.InspectIssue(ctx, "work", "APP-1")
		requireTypedRecovery(t, err, "PROFILE_DEFAULT_STALE", errx.CodeConflict)
	})
	t.Run("replaced saved default stays stale", func(t *testing.T) {
		fixture := newReadLockFixture(t, true)
		fixture.writeLock(t, 0o000)
		ctx := context.WithValue(t.Context(), selectionGuardKey{}, selectionGuard{name: "work", identity: "another-identity"})
		_, _, err := fixture.service.InspectIssue(ctx, "work", "APP-1")
		requireTypedRecovery(t, err, "PROFILE_DEFAULT_STALE", errx.CodeConflict)
		if fixture.store.loads != 0 {
			t.Errorf("credential loaded %d times", fixture.store.loads)
		}
	})
	t.Run("unreadable state directory reports the denial", func(t *testing.T) {
		parent := t.TempDir()
		directory := filepath.Join(parent, "state")
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		service := &Service{Profiles: profile.NewRegistry(filepath.Join(directory, "profiles.json")), Credentials: &trapCredentials{}}
		if err := os.Chmod(parent, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.Chmod(parent, 0o700); err != nil {
				t.Error(err)
			}
		})
		_, _, err := service.InspectIssue(t.Context(), "work", "APP-1")
		requireTypedRecovery(t, err, localStateAccessDenied, errx.CodePermission)
	})
}

// Everything past the lock has a recovery of its own and must not be retried
// through the writable lock, which in a sandbox would hide it behind a denial.
func TestErrorsUnderTheReadLockKeepTheirRecovery(t *testing.T) {
	denied := fmt.Errorf("load: %w", fs.ErrPermission)
	tests := []struct {
		name   string
		err    error
		reason string
		code   errx.Code
	}{
		{"missing credential", auth.ErrNotFound, "CREDENTIAL_NOT_FOUND", errx.CodeAuth},
		{"typed", errx.Conflict("TYPED_RECOVERY", "keeps its recovery"), "TYPED_RECOVERY", errx.CodeConflict},
		{"untyped denial", denied, localStateAccessDenied, errx.CodePermission},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newReadLockFixture(t, true)
			fixture.writeLock(t, 0o600)
			fixture.store.loadErr = test.err
			_, _, err := fixture.service.InspectIssue(t.Context(), "work", "APP-1")
			requireTypedRecovery(t, err, test.reason, test.code)
			if fixture.store.loads != 1 {
				t.Errorf("loads=%d, want one attempt", fixture.store.loads)
			}
		})
	}
	t.Run("binding mismatch", func(t *testing.T) {
		fixture := newReadLockFixture(t, true)
		fixture.writeLock(t, 0o600)
		other := fixture.selected
		other.ExpectedLogin = "mallory"
		fixture.store.sequence = []auth.Credential{readLockCredential(t, other, "other-access", readLockNow.Add(time.Hour))}
		_, _, err := fixture.service.InspectIssue(t.Context(), "work", "APP-1")
		if !errors.Is(err, auth.ErrCredentialBindingMismatch) {
			t.Fatalf("err=%v", err)
		}
		if fixture.store.loads != 1 || len(fixture.transport.bearers) != 0 {
			t.Errorf("loads=%d bearers=%v", fixture.store.loads, fixture.transport.bearers)
		}
	})
}
