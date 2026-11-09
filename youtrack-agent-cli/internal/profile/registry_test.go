package profile

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/endpoint"
)

func TestRegistryRoundTripAndPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "config")
	registry := NewRegistry(filepath.Join(dir, "profiles.json"))
	if err := registry.Add(context.Background(), testProfile("zeta")); err != nil {
		t.Fatal(err)
	}
	if err := registry.Add(context.Background(), testProfile("alpha")); err != nil {
		t.Fatal(err)
	}
	profiles, err := registry.List(context.Background())
	if err != nil || len(profiles) != 2 || profiles[0].Name != "alpha" {
		t.Fatalf("profiles=%#v err=%v", profiles, err)
	}
	for path, mode := range map[string]os.FileMode{dir: 0o700, registry.Path(): 0o600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != mode {
			t.Fatalf("%s mode=%v", path, info.Mode().Perm())
		}
	}
}

func TestRegistryReadsLegacyApprovalIncompatibleProfile(t *testing.T) {
	profile := testProfile("work")
	profile.ServiceURL = "https://tracker.example.test:443/youtrack"
	profile.RESTBaseURL = profile.ServiceURL + endpoint.RESTPath
	var err error
	profile.MCPURL, err = endpoint.CanonicalMCPURL(profile.ServiceURL)
	if err != nil {
		t.Fatal(err)
	}
	profile.OAuth.IssuerURL = "https://hub.example.test:443/hub"
	profile.OAuth.AuthorizationURL = profile.OAuth.IssuerURL + endpoint.OAuthAuthorizationPath
	profile.OAuth.TokenURL = profile.OAuth.IssuerURL + endpoint.OAuthTokenPath
	if err := profile.Validate(); err != nil {
		t.Fatalf("legacy profile no longer passes durable validation: %v", err)
	}
	raw, err := json.Marshal([]Profile{profile})
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "config")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "profiles.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := NewRegistry(path).Get(context.Background(), "work")
	if err != nil {
		t.Fatalf("read legacy profile: %v", err)
	}
	if loaded.ServiceURL != profile.ServiceURL || loaded.OAuth.IssuerURL != profile.OAuth.IssuerURL {
		t.Fatalf("loaded profile changed legacy endpoints: %#v", loaded)
	}
}

func TestRegistryFailsClosed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "config")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "profiles.json")
	for _, input := range []string{`[{"name":"work"}]`, `[] {}`, `null`} {
		if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewRegistry(path).List(context.Background()); !errors.Is(err, ErrCorruptRegistry) {
			t.Fatalf("List() error=%v", err)
		}
	}
}

func TestProfileLockRejectsSymlinkedRegistryDirectoryBeforeOutsideWrite(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "config")
	if err := os.Symlink(outside, config); err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry(filepath.Join(config, "profiles.json"))
	called := false
	if err := registry.WithProfileLock(context.Background(), "work", func() error { called = true; return nil }); err == nil {
		t.Fatal("symlinked registry directory was accepted")
	}
	if called {
		t.Fatal("profile transaction ran through symlinked directory")
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("outside directory gained entries: %v", entries)
	}
}

func TestRegistryConcurrentAdds(t *testing.T) {
	registry := NewRegistry(filepath.Join(t.TempDir(), "config", "profiles.json"))
	var wait sync.WaitGroup
	errCh := make(chan error, 8)
	for index := 0; index < 8; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			errCh <- registry.Add(context.Background(), testProfile("p"+string(rune('a'+index))))
		}(index)
	}
	wait.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	profiles, err := registry.List(context.Background())
	if err != nil || len(profiles) != 8 {
		t.Fatalf("count=%d err=%v", len(profiles), err)
	}
}
