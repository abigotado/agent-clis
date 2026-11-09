//go:build darwin

package application

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/auth"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
)

// freezeState stands in for an agent sandbox: the immutable flag keeps every
// file and the directory at their usual modes, while creating a file or opening
// one for writing fails with EPERM. It models neither per-process policy nor
// Keychain and network access, which only a real sandbox run can show.
func freezeState(t *testing.T, directory string) {
	t.Helper()
	paths := []string{directory}
	for _, name := range directoryNames(t, directory) {
		paths = append(paths, filepath.Join(directory, name))
	}
	for _, path := range paths {
		if err := unix.Chflags(path, unix.UF_IMMUTABLE); err != nil {
			t.Skipf("the file system refuses the immutable flag: %v", err)
		}
		t.Cleanup(func() {
			if err := unix.Chflags(path, 0); err != nil {
				t.Errorf("clear immutable flag: %v", err)
			}
		})
	}
	if file, err := os.OpenFile(filepath.Join(directory, "probe"), os.O_CREATE|os.O_WRONLY, 0o600); !errors.Is(err, os.ErrPermission) {
		if err == nil {
			_ = file.Close()
		}
		t.Fatalf("stand-in allowed a create: %v", err)
	}
}

func requireFrozenLock(t *testing.T, lock string) {
	t.Helper()
	if file, err := os.OpenFile(lock, os.O_RDWR, 0); !errors.Is(err, os.ErrPermission) {
		if err == nil {
			_ = file.Close()
		}
		t.Fatalf("stand-in allowed a writable lock open: %v", err)
	}
	file, err := os.Open(lock)
	if err != nil {
		t.Fatalf("stand-in refused a read-only lock open: %v", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := unix.Flock(int(file.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		t.Fatalf("stand-in refused flock on a read-only descriptor: %v", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
}

func TestInspectReadsWorkWhereTheStateDirectoryIsNotWritable(t *testing.T) {
	for name, read := range inspectReads() {
		t.Run(name, func(t *testing.T) {
			fixture := newReadLockFixture(t, true)
			fixture.writeLock(t, 0o600)
			freezeState(t, fixture.directory)
			requireFrozenLock(t, fixture.lock)
			before := directoryNames(t, fixture.directory)

			if err := read(t.Context(), fixture.service); err != nil {
				t.Fatal(err)
			}

			if !slices.Equal(fixture.transport.bearers, []string{"Bearer stored-access"}) {
				t.Errorf("bearers=%v", fixture.transport.bearers)
			}
			if after := directoryNames(t, fixture.directory); !slices.Equal(before, after) {
				t.Errorf("directory changed: %v -> %v", before, after)
			}
		})
	}
}

func TestNonWritableStateDirectoryAsksForARenewalWithoutSpendingATokenRefresh(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, *readLockFixture)
		loads int
	}{
		{
			name: "refresh due",
			setup: func(t *testing.T, fixture *readLockFixture) {
				fixture.writeLock(t, 0o600)
				fixture.store.sequence = []auth.Credential{readLockCredential(t, fixture.selected, "expired-access", readLockNow.Add(-time.Minute))}
			},
			loads: 1,
		},
		{
			name:  "lock not created yet",
			setup: func(*testing.T, *readLockFixture) {},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newReadLockFixture(t, true)
			test.setup(t, fixture)
			freezeState(t, fixture.directory)

			_, _, err := fixture.service.InspectIssue(t.Context(), "work", "APP-1")

			typed := requireTypedRecovery(t, err, localStateAccessDenied, errx.CodePermission)
			if !strings.Contains(typed.Hint, "auth status --profile work --check") {
				t.Errorf("hint=%q", typed.Hint)
			}
			if fixture.store.loads != test.loads || fixture.store.saveCalls != 0 || fixture.transport.tokenRequests != 0 {
				t.Errorf("loads=%d saves=%d token requests=%d", fixture.store.loads, fixture.store.saveCalls, fixture.transport.tokenRequests)
			}
		})
	}
}

func TestUnknownProfileStaysNotFoundWhereTheStateDirectoryIsNotWritable(t *testing.T) {
	fixture := newReadLockFixture(t, false)
	freezeState(t, fixture.directory)

	_, _, err := fixture.service.InspectIssue(t.Context(), "work", "APP-1")

	requireTypedRecovery(t, err, "NOT_FOUND_PROFILE", errx.CodeNotFound)
}

// auth status --check is how an operator renews a token, so it keeps the
// writable lock rather than reporting success without being able to refresh.
func TestAuthStatusCheckStillNeedsTheWritableLock(t *testing.T) {
	fixture := newReadLockFixture(t, true)
	fixture.writeLock(t, 0o600)
	freezeState(t, fixture.directory)

	_, err := fixture.service.AuthStatus(t.Context(), "work", true)

	requireTypedRecovery(t, err, localStateAccessDenied, errx.CodePermission)
	if fixture.store.loads != 0 {
		t.Errorf("credential loaded %d times", fixture.store.loads)
	}
}

// A snapshot belongs to the write path, whose local state must stay writable.
func TestOperatorSnapshotStillNeedsTheWritableLock(t *testing.T) {
	fixture := newOperatorFixture(t)
	enableCommentDelete(t, fixture)
	lock := fixture.service.Profiles.Path() + ".profile-work.lock"
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	freezeState(t, filepath.Dir(lock))
	requireFrozenLock(t, lock)
	credentials, network := &trapCredentials{}, &trapTransport{}
	fixture.service.Credentials, fixture.service.HTTP = credentials, network

	_, err := fixture.service.SnapshotOperatorWrite(t.Context(), OperatorSnapshotInput{Profile: "work", Kind: "comment.delete", IssueID: "APP-12", CommentID: "4-1"})

	requireTypedRecovery(t, err, localStateAccessDenied, errx.CodePermission)
	if credentials.calls != 0 || network.calls != 0 {
		t.Errorf("credentials=%d network=%d", credentials.calls, network.calls)
	}
}
