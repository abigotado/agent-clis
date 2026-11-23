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
	if err := ensurePrivateDir(dir); err != nil {
		return nil, err
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

// ensurePrivateDir creates dir with mode 0700 when it is missing, then requires
// that Lstat shows a real directory (not a symbolic link) owned by the current
// user with mode exactly 0700.
func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("stat directory %s: %w", dir, err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode().Perm() != 0o700 || !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("directory %s must be a real directory, owned by the current user, with mode 0700", dir)
	}
	return nil
}

// MkWorkDir creates a new 0700 work directory inside WorkRoot(home), after
// validating that parent. The temp directory and TMPDIR play no part.
func MkWorkDir(home string) (string, error) {
	root := WorkRoot(home)
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("work root %q is not absolute", root)
	}
	if err := ensurePrivateDir(root); err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(root, "sign-release-")
	if err != nil {
		return "", fmt.Errorf("create work directory: %w", err)
	}
	return dir, nil
}

func closeQuietly(f *os.File) {
	_ = f.Close() // the caller is already returning a different error
}
