//go:build unix

package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abigotado/agent-clis/tools/sign-release/internal/lock"
)

func TestHomeSeamsUseTheInjectedHomeNotTheEnvironment(t *testing.T) {
	resolve := func() string {
		dir, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		return dir
	}
	home, envHome, envCache, envTmp := resolve(), resolve(), resolve(), resolve()
	t.Setenv("HOME", envHome)
	t.Setenv("XDG_CACHE_HOME", envCache)
	t.Setenv("TMPDIR", envTmp)

	seams := NewHomeSeams(func() (string, error) { return home, nil })

	if got, err := seams.HomeDir(); err != nil || got != home {
		t.Fatalf("HomeDir() = %q, %v, want %q", got, err, home)
	}
	release, err := seams.Lock("owner/repo", "cli/v1.0.0")
	if err != nil {
		t.Fatalf("Lock() error = %v", err)
	}
	if _, err := seams.Lock("owner/repo", "cli/v1.0.0"); err == nil {
		t.Fatal("second Lock() = nil error, want the lock to be held")
	}
	if err := release(); err != nil {
		t.Fatalf("release() error = %v", err)
	}
	dir, err := seams.MkWorkDir()
	if err != nil {
		t.Fatalf("MkWorkDir() error = %v", err)
	}
	if filepath.Dir(dir) != lock.WorkRoot(home) || !strings.HasPrefix(filepath.Base(dir), "sign-release-") {
		t.Fatalf("work dir = %q, want a child of %q", dir, lock.WorkRoot(home))
	}
	if entries, err := os.ReadDir(lock.Dir(home)); err != nil || len(entries) < 2 {
		t.Fatalf("injected home holds %d lock-dir entries (err %v), want the lock file and work root", len(entries), err)
	}
	for _, other := range []string{envHome, envCache, envTmp} {
		if entries, err := os.ReadDir(other); err != nil || len(entries) != 0 {
			t.Fatalf("%s holds %d entries (err %v), want it untouched", other, len(entries), err)
		}
	}
}
