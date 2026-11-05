// Package lockfile serializes read-modify-write cycles between concurrent
// youtrack-agent-cli processes using an OS advisory lock. The small lock file persists;
// the kernel releases ownership automatically when a process exits.
package lockfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	defaultTimeout = 2 * time.Second
	retryInterval  = 5 * time.Millisecond
)

// TimeoutError reports that a live process held a lock for the whole wait
// budget. The protected operation is not run without the lock.
type TimeoutError struct {
	Path    string
	Timeout time.Duration
}

func (e *TimeoutError) Error() string {
	return fmt.Sprintf("acquire lock %s: timed out after %s", e.Path, e.Timeout)
}

// With runs fn while holding an exclusive advisory lock beside path, creating
// the lock file when it is missing.
func With(path string, fn func() error) error {
	return withOpened(path, openLockNoFollow, false, fn)
}

// WithExisting holds a shared lock on the same file through a read-only
// descriptor. It never creates the lock file, so a caller allowed to read but
// not to write beside path still excludes every With holder. Shared because
// NFS emulation of flock grants an exclusive lock only to a writable descriptor.
func WithExisting(path string, fn func() error) error {
	return withOpened(path, openExistingLockNoFollow, true, fn)
}

func withOpened(path string, open func(directory, name string) (*os.File, error), shared bool, fn func() error) (err error) {
	if fn == nil {
		return errors.New("lockfile: nil callback")
	}
	lock := path + ".lock"
	file, err := open(filepath.Dir(lock), filepath.Base(lock))
	if err != nil {
		return fmt.Errorf("open lock %s: %w", lock, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close lock %s: %w", lock, closeErr))
		}
	}()
	if err := acquire(file, lock, shared, defaultTimeout); err != nil {
		return err
	}
	defer func() {
		if unlockErr := unlockAdvisory(file); unlockErr != nil {
			err = errors.Join(err, fmt.Errorf("release lock %s: %w", lock, unlockErr))
		}
	}()
	return fn()
}

func acquire(file *os.File, path string, shared bool, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		acquired, err := tryAdvisoryLock(file, shared)
		if err == nil && acquired {
			return nil
		}
		if err != nil {
			return fmt.Errorf("acquire lock %s: %w", path, err)
		}
		if !time.Now().Before(deadline) {
			return &TimeoutError{Path: path, Timeout: timeout}
		}
		time.Sleep(retryInterval)
	}
}
