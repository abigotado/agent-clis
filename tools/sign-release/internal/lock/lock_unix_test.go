//go:build unix

package lock

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAcquireIsExclusivePerRepositoryAndTag(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sign-release")
	first, err := Acquire(dir, "owner/repo", "cli/v1.0.0")
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}

	tests := []struct {
		name, repo, tag string
		wantLocked      bool
	}{
		{"same repository and tag", "owner/repo", "cli/v1.0.0", true},
		{"other tag", "owner/repo", "cli/v1.0.1", false},
		{"other repository", "owner/other", "cli/v1.0.0", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, err := Acquire(dir, tt.repo, tt.tag)
			if tt.wantLocked {
				if !errors.Is(err, ErrLocked) || !strings.Contains(err.Error(), tt.repo) || !strings.Contains(err.Error(), tt.tag) {
					t.Fatalf("Acquire() error = %v, want ErrLocked naming the repository and tag", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Acquire() error = %v", err)
			}
			if err := l.Release(); err != nil {
				t.Fatalf("Release() error = %v", err)
			}
		})
	}

	if err := first.Release(); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
	if err := first.Release(); err != nil {
		t.Fatalf("second Release() error = %v, want nil", err)
	}
	again, err := Acquire(dir, "owner/repo", "cli/v1.0.0")
	if err != nil {
		t.Fatalf("Acquire() after Release error = %v", err)
	}
	if err := again.Release(); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
}

func TestAcquireUsesPrivateFilesAndRefusesALink(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sign-release")
	l, err := Acquire(dir, "owner/repo", "cli/v1.0.0")
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode = %v (err %v), want 0700", info.Mode().Perm(), err)
	}
	path := filepath.Join(dir, fileName("owner/repo", "cli/v1.0.0"))
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("lock file mode = %v (err %v), want 0600", info.Mode().Perm(), err)
	}

	// A symbolic link in the file's place is refused, not followed.
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove lock file: %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if l, err := Acquire(dir, "owner/repo", "cli/v1.0.0"); err == nil {
		_ = l.Release() // test cleanup after the assertion below fails
		t.Fatal("Acquire() followed a symbolic link")
	}
}

func TestAcquireRefusesAnOpenDirectoryAndEmptyKeys(t *testing.T) {
	open := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := Acquire(open, "owner/repo", "cli/v1.0.0"); err == nil {
		t.Fatal("Acquire() accepted a group- or world-accessible directory")
	}
	if _, err := Acquire(t.TempDir(), "", "tag"); err == nil {
		t.Fatal("Acquire() accepted an empty repository")
	}
	if _, err := Acquire("relative/dir", "owner/repo", "tag"); err == nil {
		t.Fatal("Acquire() accepted a relative directory")
	}
}

func TestAcquireForHomeIgnoresTheParentEnvironment(t *testing.T) {
	home := t.TempDir()
	envHome := t.TempDir()
	envCache := t.TempDir()
	t.Setenv("HOME", envHome)
	t.Setenv("XDG_CACHE_HOME", envCache)

	want := filepath.Join(home, "Library", "Caches", "sign-release")
	if got := Dir(home); got != want {
		t.Fatalf("Dir() = %q, want %q", got, want)
	}
	l, err := AcquireForHome(home, "owner/repo", "cli/v1.0.0")
	if err != nil {
		t.Fatalf("AcquireForHome() error = %v", err)
	}
	defer func() {
		if err := l.Release(); err != nil {
			t.Errorf("Release() error = %v", err)
		}
	}()
	if _, err := os.Stat(filepath.Join(want, fileName("owner/repo", "cli/v1.0.0"))); err != nil {
		t.Fatalf("lock file not under the injected home: %v", err)
	}
	for _, other := range []string{envHome, envCache} {
		entries, err := os.ReadDir(other)
		if err != nil || len(entries) != 0 {
			t.Fatalf("%s holds %d entries (err %v), want an untouched directory", other, len(entries), err)
		}
	}
}

func TestMkWorkDirIgnoresTMPDIRAndHOME(t *testing.T) {
	home := t.TempDir()
	envTmp, envHome := t.TempDir(), t.TempDir()
	t.Setenv("TMPDIR", envTmp)
	t.Setenv("HOME", envHome)

	dir, err := MkWorkDir(home)
	if err != nil {
		t.Fatalf("MkWorkDir() error = %v", err)
	}
	if filepath.Dir(dir) != WorkRoot(home) || !strings.HasPrefix(filepath.Base(dir), "sign-release-") {
		t.Fatalf("work dir = %q, want a sign-release-* child of %q", dir, WorkRoot(home))
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("work dir mode = %v (err %v), want 0700", info.Mode().Perm(), err)
	}
	for _, other := range []string{envTmp, envHome} {
		if entries, err := os.ReadDir(other); err != nil || len(entries) != 0 {
			t.Fatalf("%s holds %d entries (err %v), want it untouched", other, len(entries), err)
		}
	}
}

func TestMkWorkDirRefusesAnUnsafeParent(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, root string)
	}{
		{"symlink", func(t *testing.T, root string) {
			// The target is itself private and ours, so only the link is wrong.
			target := filepath.Join(t.TempDir(), "target")
			if err := os.Mkdir(target, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, root); err != nil {
				t.Fatal(err)
			}
		}},
		{"wrong mode", func(t *testing.T, root string) {
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(root, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			if err := os.MkdirAll(Dir(home), 0o700); err != nil {
				t.Fatal(err)
			}
			tt.setup(t, WorkRoot(home))
			if dir, err := MkWorkDir(home); err == nil {
				t.Fatalf("MkWorkDir() = %q, want an error", dir)
			}
		})
	}
}
