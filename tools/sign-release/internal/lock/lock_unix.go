//go:build unix

package lock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// ensurePrivateDir creates dir with mode 0700 when it is missing, then walks
// every component from the root down with Lstat. An ancestor must be a real
// directory (not a symbolic link), owned by root or the current user, and not
// writable by group or others (a root-owned sticky directory excepted), so no
// other user can swap a component. The leaf
// must be owned by the current user with mode exactly 0700. dir must be
// absolute and already resolved: a path that EvalSymlinks changes is refused.
func ensurePrivateDir(dir string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return fmt.Errorf("directory %q must be an absolute, clean path", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return fmt.Errorf("resolve directory %s: %w", dir, err)
	}
	if resolved != dir {
		return fmt.Errorf("directory %s resolves to %s through a symbolic link; use the resolved path", dir, resolved)
	}
	uid := uint32(os.Getuid())
	current := string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(dir, current), current)
	for i := -1; i < len(parts); i++ {
		if i >= 0 {
			current = filepath.Join(current, parts[i])
		}
		leaf := i == len(parts)-1
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("stat directory %s: %w", current, err)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() {
			return fmt.Errorf("%s must be a real directory, not a symbolic link", current)
		}
		if leaf {
			if info.Mode().Perm() != 0o700 || st.Uid != uid {
				return fmt.Errorf("directory %s must be owned by the current user with mode 0700", current)
			}
			continue
		}
		// A root-owned sticky directory (/tmp, /private/tmp) is accepted even
		// though others can write it: in a sticky directory another user can
		// neither rename nor delete an entry it does not own, and a name it
		// pre-creates is owned by that user, so the owner checks on the next
		// component refuse it. Any other ancestor must not be writable by
		// group or others.
		if st.Uid == 0 && info.Mode()&os.ModeSticky != 0 {
			continue
		}
		if (st.Uid != 0 && st.Uid != uid) || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("directory %s, an ancestor of %s, must be owned by root or the current user and not writable by group or others", current, dir)
		}
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
