//go:build !windows

package lockfile

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestWithExistingRefusesWhatWithRefuses(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(t *testing.T, lock string)
		denied bool
	}{
		{name: "symlink", setup: func(t *testing.T, lock string) {
			outside := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(outside, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, lock); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "wider mode", setup: func(t *testing.T, lock string) {
			if err := os.WriteFile(lock, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(lock, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "fifo does not block", setup: func(t *testing.T, lock string) {
			if err := syscall.Mkfifo(lock, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "denied", denied: true, setup: func(t *testing.T, lock string) {
			if os.Geteuid() == 0 {
				t.Skip("root ignores the file mode that denies the lock")
			}
			if err := os.WriteFile(lock, nil, 0o000); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "registry.json")
			test.setup(t, path+".lock")

			err := WithExisting(path, func() error {
				t.Error("callback ran")
				return nil
			})

			if err == nil {
				t.Fatal("WithExisting accepted the lock path")
			}
			if denied := errors.Is(err, os.ErrPermission); denied != test.denied {
				t.Errorf("err=%v, denied=%t", err, denied)
			}
		})
	}
}
