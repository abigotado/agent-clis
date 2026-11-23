//go:build unix

package lock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func acquire(dir, name string) (*Lock, error) {
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("lock directory %q is not absolute", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create lock directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("stat lock directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("lock directory %s must be a real directory that only its owner can use", dir)
	}
	// O_NOFOLLOW refuses a symbolic link in the file's place; the directory is
	// private, so nobody else can plant one.
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		closeQuietly(f)
		return nil, fmt.Errorf("lock file %s is not a regular file", name)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		closeQuietly(f)
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("flock: %w", err)
	}
	return &Lock{release: func() error {
		// Closing the descriptor drops the flock; unlock first so a failure is
		// reported.
		unlockErr := syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		closeErr := f.Close()
		if unlockErr != nil {
			return fmt.Errorf("unlock: %w", unlockErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close lock file: %w", closeErr)
		}
		return nil
	}}, nil
}

func closeQuietly(f *os.File) {
	_ = f.Close() // the caller is already returning a different error
}
