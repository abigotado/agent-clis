//go:build unix

package lock

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestAcquireIsExclusivePerRepositoryAndTag(t *testing.T) {
	dir := filepath.Join(tempDir(t), "sign-release")
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
	dir := filepath.Join(tempDir(t), "sign-release")
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
	target := filepath.Join(tempDir(t), "elsewhere")
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
	open := filepath.Join(tempDir(t), "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := Acquire(open, "owner/repo", "cli/v1.0.0"); err == nil {
		t.Fatal("Acquire() accepted a group- or world-accessible directory")
	}
	if _, err := Acquire(tempDir(t), "", "tag"); err == nil {
		t.Fatal("Acquire() accepted an empty repository")
	}
	if _, err := Acquire("relative/dir", "owner/repo", "tag"); err == nil {
		t.Fatal("Acquire() accepted a relative directory")
	}
}

func TestAcquireForHomeIgnoresTheParentEnvironment(t *testing.T) {
	home := tempDir(t)
	envHome := tempDir(t)
	envCache := tempDir(t)
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
	home := tempDir(t)
	envTmp, envHome := tempDir(t), tempDir(t)
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
			target := filepath.Join(tempDir(t), "target")
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
			home := tempDir(t)
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

// tempDir is t.TempDir with its symbolic links resolved: on macOS the temp tree
// sits under /var, a link to /private/var, which the production rule refuses.
func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestEnsurePrivateDirRefusesUnsafeAncestors(t *testing.T) {
	// Each case adds one hostile component under a clean base that must pass
	// first, so a refusal is about that component alone.
	tests := []struct {
		name  string
		build func(t *testing.T, base string) string
	}{
		{"symlinked ancestor", func(t *testing.T, base string) string {
			real := filepath.Join(base, "real")
			if err := os.Mkdir(real, 0o755); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(base, "link")
			if err := os.Symlink(real, link); err != nil {
				t.Fatal(err)
			}
			return link
		}},
		{"group-writable ancestor", func(t *testing.T, base string) string {
			return chmodedDir(t, base, "shared", 0o775)
		}},
		{"non-sticky world-writable ancestor", func(t *testing.T, base string) string {
			return chmodedDir(t, base, "open", 0o777)
		}},
		{"sticky ancestor owned by the current user", func(t *testing.T, base string) string {
			if os.Getuid() == 0 {
				t.Skip("the current user is root, so a sticky directory it owns is accepted")
			}
			return chmodedDir(t, base, "mine", 0o777|os.ModeSticky)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := filepath.Join(tempDir(t), "base")
			if err := ensurePrivateDir(filepath.Join(base, "sign-release")); err != nil {
				t.Fatalf("clean base: ensurePrivateDir() error = %v", err)
			}
			hostile := tt.build(t, base)
			if err := ensurePrivateDir(filepath.Join(hostile, "sign-release")); err == nil {
				t.Fatal("ensurePrivateDir() = nil, want a refusal")
			}
		})
	}
}

func chmodedDir(t *testing.T, base, name string, mode os.FileMode) string {
	t.Helper()
	dir := filepath.Join(base, name)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestEnsurePrivateDirAcceptsARootOwnedStickyAncestor(t *testing.T) {
	base, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		t.Skipf("no /tmp: %v", err)
	}
	info, err := os.Lstat(base)
	if err != nil {
		t.Skipf("cannot stat %s: %v", base, err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || info.Mode()&os.ModeSticky == 0 || !info.IsDir() {
		t.Skipf("%s is not a root-owned sticky directory", base)
	}
	work, err := os.MkdirTemp(base, "sign-release-lock-test-")
	if err != nil {
		t.Skipf("cannot create a directory in %s: %v", base, err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(work); err != nil {
			t.Errorf("remove %s: %v", work, err)
		}
	})
	if err := ensurePrivateDir(filepath.Join(work, "clean")); err != nil {
		t.Fatalf("clean directory below a sticky ancestor: ensurePrivateDir() error = %v", err)
	}
	// The sticky directory itself is an ancestor of the leaf here.
	leaf, err := os.MkdirTemp(base, "sign-release-lock-leaf-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(leaf); err != nil {
			t.Errorf("remove %s: %v", leaf, err)
		}
	})
	if err := ensurePrivateDir(leaf); err != nil {
		t.Fatalf("ensurePrivateDir(%s) error = %v", leaf, err)
	}
}

func TestEnsurePrivateDirAcceptsASafeTree(t *testing.T) {
	if err := ensurePrivateDir(filepath.Join(tempDir(t), "a", "b")); err != nil {
		t.Fatalf("ensurePrivateDir() error = %v", err)
	}
}
