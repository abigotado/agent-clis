//go:build darwin && cgo && !portable_readonly && !macos_identity_readonly

package skills

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallChecksDarwinACLWritePermissions(t *testing.T) {
	tests := []struct {
		name       string
		homeACL    []string
		rootACL    []string
		wantReason string
	}{
		{name: "no ACL allows install"},
		{
			name:    "deny-only ACL on home allows install",
			homeACL: []string{"everyone deny delete"},
		},
		{
			name:       "deny then allow write on home is refused",
			homeACL:    []string{"everyone deny delete", "everyone allow add_file"},
			wantReason: "DEST_SHARED_WRITABLE",
		},
		{
			name:       "allow write on home ancestor is refused",
			homeACL:    []string{"everyone allow add_file"},
			wantReason: "DEST_SHARED_WRITABLE",
		},
		{
			name:       "allow write on skills destination is refused",
			rootACL:    []string{"everyone allow add_file"},
			wantReason: "DEST_SHARED_WRITABLE",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			home := temporaryDarwinHome(t)
			root := filepath.Join(home, ".claude", "skills")
			if err := os.MkdirAll(root, 0o755); err != nil {
				t.Fatalf("create temporary skills root: %v", err)
			}
			addDarwinACL(t, home, test.homeACL...)
			addDarwinACL(t, root, test.rootACL...)
			if len(test.homeACL) == 2 {
				assertDarwinACLOrder(t, home, "deny delete", "allow add_file")
			}

			_, err := Install(context.Background(), Options{
				Provider: ProviderClaude, Scope: ScopeUser, HomeDir: fixedHome(home), Confirmed: true,
			})
			skillFile := filepath.Join(root, SkillName, "SKILL.md")
			if test.wantReason != "" {
				assertReason(t, err, test.wantReason)
				if _, statErr := os.Stat(filepath.Join(root, SkillName)); !os.IsNotExist(statErr) {
					t.Fatalf("install created a skill after ACL refusal: %v", statErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("install with safe ACL: %v", err)
			}
			if _, err := os.Stat(skillFile); err != nil {
				t.Fatalf("installed skill is missing: %v", err)
			}
		})
	}
}

func TestUninstallRefusesDarwinACLWritePermission(t *testing.T) {
	home := temporaryDarwinHome(t)
	opts := Options{Provider: ProviderClaude, Scope: ScopeUser, HomeDir: fixedHome(home), Confirmed: true}
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("seed installed skill: %v", err)
	}
	root := filepath.Join(home, ".claude", "skills")
	addDarwinACL(t, root, "everyone allow add_file")
	_, err := Uninstall(context.Background(), opts)
	assertReason(t, err, "DEST_SHARED_WRITABLE")
	if _, err := os.Stat(filepath.Join(root, SkillName, "SKILL.md")); err != nil {
		t.Fatalf("uninstall changed the skill after ACL refusal: %v", err)
	}
}

func temporaryDarwinHome(t *testing.T) string {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatalf("create temporary home: %v", err)
	}
	return home
}

func TestInstallChecksAncestorSymlinkTarget(t *testing.T) {
	tests := []struct {
		name       string
		permission os.FileMode
		wantReason string
	}{
		{name: "private target allows install", permission: 0o755},
		{name: "non-sticky shared-writable target is refused", permission: 0o777, wantReason: "DEST_SHARED_WRITABLE"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			base := t.TempDir()
			shared := filepath.Join(base, "parent")
			resolvedHome := filepath.Join(shared, "private", "home")
			root := filepath.Join(resolvedHome, ".claude", "skills")
			if err := os.MkdirAll(root, 0o755); err != nil {
				t.Fatalf("create temporary skills root: %v", err)
			}
			alias := filepath.Join(base, "alias")
			if err := os.Symlink(filepath.Join(shared, "private"), alias); err != nil {
				t.Fatalf("create ancestor symlink: %v", err)
			}
			if err := os.Chmod(shared, test.permission); err != nil {
				t.Fatalf("set resolved ancestor permissions: %v", err)
			}
			t.Cleanup(func() {
				if err := os.Chmod(shared, 0o755); err != nil {
					t.Errorf("restore temporary ancestor permissions: %v", err)
				}
			})

			_, err := Install(context.Background(), Options{
				Provider: ProviderClaude, Scope: ScopeUser,
				HomeDir: fixedHome(filepath.Join(alias, "home")), Confirmed: true,
			})
			if test.wantReason != "" {
				assertReason(t, err, test.wantReason)
				if _, statErr := os.Stat(filepath.Join(root, SkillName)); !os.IsNotExist(statErr) {
					t.Fatalf("install created a skill below shared-writable symlink target: %v", statErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("install below private symlink target: %v", err)
			}
			if _, err := os.Stat(filepath.Join(root, SkillName, "SKILL.md")); err != nil {
				t.Fatalf("installed skill is missing below private symlink target: %v", err)
			}
		})
	}
}

func TestDarwinACLInspectionFailsClosedForMissingPath(t *testing.T) {
	root := t.TempDir()
	info, err := os.Lstat(root)
	if err != nil {
		t.Fatalf("stat temporary directory: %v", err)
	}
	if !isSharedWritable(filepath.Join(root, "missing"), info) {
		t.Fatal("missing ACL inspection target was treated as private")
	}
}

func addDarwinACL(t *testing.T, target string, entries ...string) {
	t.Helper()
	if len(entries) == 0 {
		return
	}
	t.Cleanup(func() {
		command := exec.Command("/bin/chmod", "-N", target)
		if output, err := command.CombinedOutput(); err != nil {
			t.Errorf("remove ACL from temporary directory: %v (%s)", err, output)
		}
	})
	for _, entry := range entries {
		command := exec.Command("/bin/chmod", "+a", entry, target)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("add ACL %q to temporary directory: %v (%s)", entry, err, output)
		}
	}
}

func assertDarwinACLOrder(t *testing.T, target, first, second string) {
	t.Helper()
	output, err := exec.Command("/bin/ls", "-lde", target).CombinedOutput()
	if err != nil {
		t.Fatalf("inspect temporary ACL entry order: %v (%s)", err, output)
	}
	firstIndex := strings.Index(string(output), first)
	secondIndex := strings.Index(string(output), second)
	if firstIndex < 0 || secondIndex < 0 || firstIndex >= secondIndex {
		t.Fatalf("temporary ACL entries are not in DENY then ALLOW order: %s", output)
	}
}
