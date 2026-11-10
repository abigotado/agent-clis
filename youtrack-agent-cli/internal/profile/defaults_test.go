package profile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func defaultSlot(name string) *DefaultSlot {
	return &DefaultSlot{ProfileName: name, ProfileIdentitySHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
}

func defaultsRegistry(t *testing.T) *Registry {
	t.Helper()
	return NewRegistry(filepath.Join(t.TempDir(), "config", "profiles.json"))
}

func TestDefaultsMissingFileIsEmptyAndDoesNotCreateArtifacts(t *testing.T) {
	registry := defaultsRegistry(t)
	value, err := registry.GetDefaults(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if value.Version != defaultsVersion || value.Read != nil || value.Write != nil {
		t.Fatalf("defaults=%#v", value)
	}
	if _, err := os.Stat(registry.DefaultsPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("defaults file stat error=%v, want not exist", err)
	}
	if _, err := os.Stat(filepath.Dir(registry.DefaultsPath())); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("defaults directory stat error=%v, want not exist", err)
	}
}

func TestDefaultsRejectStrictOrUnsafeDocuments(t *testing.T) {
	registry := defaultsRegistry(t)
	directory := filepath.Dir(registry.DefaultsPath())
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	validDigest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for _, test := range []struct {
		name string
		raw  string
	}{
		{name: "null", raw: `null`},
		{name: "unknown field", raw: `{"version":1,"unknown":true}`},
		{name: "duplicate field", raw: `{"version":1,"version":1}`},
		{name: "trailing JSON", raw: `{"version":1}{}`},
		{name: "wrong version", raw: `{"version":2}`},
		{name: "null slot", raw: `{"version":1,"read":null}`},
		{name: "unknown slot field", raw: `{"version":1,"read":{"profile_name":"read","profile_identity_sha256":"` + validDigest + `","unknown":true}}`},
		{name: "bad digest", raw: `{"version":1,"read":{"profile_name":"read","profile_identity_sha256":"bad"}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(registry.DefaultsPath(), []byte(test.raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := registry.GetDefaults(context.Background()); !errors.Is(err, ErrCorruptRegistry) {
				t.Fatalf("GetDefaults() error=%v, want corrupt registry", err)
			}
		})
	}
}

func TestDefaultsWritePermissionsAndPartialUpdate(t *testing.T) {
	registry := defaultsRegistry(t)
	first, err := registry.UpdateDefaults(context.Background(), func(Defaults) (Defaults, error) {
		return Defaults{Version: defaultsVersion, Read: defaultSlot("reader")}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Read == nil || first.Write != nil {
		t.Fatalf("first=%#v", first)
	}
	updated, err := registry.UpdateDefaults(context.Background(), func(current Defaults) (Defaults, error) {
		current.Write = defaultSlot("writer")
		return current, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Read == nil || updated.Read.ProfileName != "reader" || updated.Write == nil || updated.Write.ProfileName != "writer" {
		t.Fatalf("updated=%#v", updated)
	}
	for path, want := range map[string]os.FileMode{filepath.Dir(registry.DefaultsPath()): 0o700, registry.DefaultsPath(): 0o600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s mode=%#o, want %#o", path, info.Mode().Perm(), want)
		}
	}
}

func TestDefaultsClearLeavesVersionOnlyDocument(t *testing.T) {
	registry := defaultsRegistry(t)
	if _, err := registry.UpdateDefaults(context.Background(), func(Defaults) (Defaults, error) {
		return Defaults{Version: defaultsVersion, Read: defaultSlot("reader"), Write: defaultSlot("writer")}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.ClearDefaults(context.Background(), true, false); err != nil {
		t.Fatal(err)
	}
	value, err := registry.ClearDefaults(context.Background(), false, true)
	if err != nil {
		t.Fatal(err)
	}
	if value.Version != defaultsVersion || value.Read != nil || value.Write != nil {
		t.Fatalf("cleared=%#v", value)
	}
	raw, err := os.ReadFile(registry.DefaultsPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "{\n  \"version\": 1\n}\n" {
		t.Fatalf("defaults document=%q", raw)
	}
}

func TestDefaultsRejectSymlinkBeforeOutsideRead(t *testing.T) {
	registry := defaultsRegistry(t)
	directory := filepath.Dir(registry.DefaultsPath())
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside-defaults.json")
	if err := os.WriteFile(outside, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, registry.DefaultsPath()); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.GetDefaults(context.Background()); !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("GetDefaults() error=%v, want insecure permissions", err)
	}
}

func TestDefaultsConcurrentPartialUpdatesPreserveBothSlots(t *testing.T) {
	registry := defaultsRegistry(t)
	var wait sync.WaitGroup
	errs := make(chan error, 2)
	for _, update := range []func(*Defaults){
		func(value *Defaults) { value.Read = defaultSlot("reader") },
		func(value *Defaults) { value.Write = defaultSlot("writer") },
	} {
		wait.Add(1)
		go func(update func(*Defaults)) {
			defer wait.Done()
			_, err := registry.UpdateDefaults(context.Background(), func(value Defaults) (Defaults, error) {
				update(&value)
				return value, nil
			})
			errs <- err
		}(update)
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	value, err := registry.GetDefaults(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if value.Read == nil || value.Write == nil || value.Read.ProfileName != "reader" || value.Write.ProfileName != "writer" {
		t.Fatalf("defaults=%#v", value)
	}
}
