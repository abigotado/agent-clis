// Package lock serializes sign-release runs for one repository and tag. A run
// holds an exclusive advisory lock for its whole length, so a second run of the
// same release refuses at once instead of racing the first on the draft.
//
// The lock is a file in a private directory of the operator's cache, named from
// the account's home directory and never from $HOME or $XDG_CACHE_HOME. It guards
// against a second run by the same operator, not against another process of the
// same account that chooses to ignore it.
package lock

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
)

// ErrLocked reports that another run holds the lock.
var ErrLocked = errors.New("another sign-release run holds the lock")

// ErrUnsupported reports a platform without advisory file locks.
var ErrUnsupported = errors.New("file locks are not supported on this platform")

// Lock is a held lock. Release gives it up; it is also given up when the
// process ends.
type Lock struct {
	release func() error
}

// Release unlocks and closes the lock file. The file stays, so the next run
// reuses it.
func (l *Lock) Release() error {
	if l == nil || l.release == nil {
		return nil
	}
	release := l.release
	l.release = nil
	return release()
}

// fileName names the lock file of a repository and tag. It is a hash, so the
// slashes of a repository and a tag never reach the file system.
func fileName(repo, tag string) string {
	sum := sha256.Sum256([]byte(repo + "\x00" + tag))
	return hex.EncodeToString(sum[:]) + ".lock"
}

// Acquire takes the exclusive lock for repo and tag, keeping its file in dir,
// which is created with mode 0700 when it does not exist. It never waits: a
// lock that is held is an error wrapping ErrLocked.
func Acquire(dir, repo, tag string) (*Lock, error) {
	if repo == "" || tag == "" {
		return nil, fmt.Errorf("lock: repository %q and tag %q must not be empty", repo, tag)
	}
	l, err := acquire(dir, fileName(repo, tag))
	if err != nil {
		if errors.Is(err, ErrLocked) {
			return nil, fmt.Errorf("%w for %s %s; wait for it to finish, or, if no other run is active, run again", err, repo, tag)
		}
		return nil, fmt.Errorf("lock %s %s: %w", repo, tag, err)
	}
	return l, nil
}

// Dir is the lock directory under an account home: the macOS user cache. It
// reads no environment variable, so a parent environment cannot move the lock.
func Dir(home string) string {
	return filepath.Join(home, "Library", "Caches", "sign-release")
}

// AcquireForHome takes the lock for repo and tag in Dir(home).
func AcquireForHome(home, repo, tag string) (*Lock, error) {
	return Acquire(Dir(home), repo, tag)
}
