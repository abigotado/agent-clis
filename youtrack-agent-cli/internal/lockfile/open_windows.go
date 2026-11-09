//go:build windows

package lockfile

import (
	"errors"
	"os"
	"path/filepath"
)

func openLockNoFollow(directory, name string) (*os.File, error) {
	return openVerifiedLock(filepath.Join(directory, name), os.O_CREATE|os.O_RDWR, 0o600)
}

func openExistingLockNoFollow(directory, name string) (*os.File, error) {
	return openVerifiedLock(filepath.Join(directory, name), os.O_RDONLY, 0)
}

func openVerifiedLock(path string, flags int, mode os.FileMode) (*os.File, error) {
	before, statErr := os.Lstat(path)
	if statErr == nil && before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("lock path is a symlink")
	}
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return nil, statErr
	}
	file, err := os.OpenFile(path, flags, mode)
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*os.File, error) {
		_ = file.Close()
		return nil, cause
	}
	opened, err := file.Stat()
	if err != nil {
		return fail(err)
	}
	linked, err := os.Lstat(path)
	if err != nil || !opened.Mode().IsRegular() || linked.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, linked) {
		return fail(errors.New("lock path is not the opened regular file"))
	}
	return file, nil
}
