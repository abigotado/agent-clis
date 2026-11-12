//go:build windows && credmanintegration

package secretstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// These tests run against the real Credential Manager of the account running
// them, under random secretstore-test-<hex> services, and delete everything
// they create. CI runs them on a disposable runner; run them locally only on a
// machine whose credentials you do not mind a test touching.

func realCredman(t *testing.T) *credman {
	t.Helper()
	c := newCredman()
	probe := "secretstore-test-" + randomService(t) + "/probe"
	t.Cleanup(func() { removeTarget(t, c, probe) })
	if err := c.write(t.Context(), probe, "probe", []byte("x")); err != nil {
		if os.Getenv("SECRETSTORE_REQUIRE_CREDMAN") == "1" {
			t.Fatalf("Credential Manager is required but unusable: %v", err)
		}
		t.Skipf("Credential Manager is unusable: %v", err)
	}
	return c
}

func randomService(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("read random bytes: %v", err)
	}
	return hex.EncodeToString(b)
}

func removeTarget(t *testing.T, c *credman, target string) {
	t.Helper()
	// WithoutCancel: cleanup must run after the test context is canceled.
	err := c.delete(context.WithoutCancel(t.Context()), target)
	if err != nil && !isCredNotFound(err) {
		t.Errorf("cleanup: delete a test credential: %v", err)
	}
}

// ownKey returns a key under a fresh service and removes everything stored
// under its prefix when the test ends, including names written by hand.
func ownKey(t *testing.T, c *credman, account string) Key {
	t.Helper()
	key := Key{Service: "secretstore-test-" + randomService(t), Account: account}
	t.Cleanup(func() {
		ctx := context.WithoutCancel(t.Context())
		prefix := manifestTarget(key)
		removeTarget(t, c, prefix)
		names, err := c.enumerate(ctx, prefix+"#*")
		if err != nil {
			t.Errorf("cleanup: enumerate: %v", err)
		}
		for _, name := range names {
			removeTarget(t, c, name)
		}
	})
	return key
}

func TestCredmanChunkBoundaries(t *testing.T) {
	c := realCredman(t)
	for _, size := range []int{1, chunkSize - 1, chunkSize, chunkSize + 1, MaxSecretBytesLimit} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			store := newChunkedStore(c, MaxSecretBytesLimit)
			key := ownKey(t, c, "profile")
			secret := patterned(size, 3)
			if err := store.Save(t.Context(), key, secret); err != nil {
				t.Fatalf("Save: %v", err)
			}
			got, err := store.Load(t.Context(), key)
			if err != nil || !bytes.Equal(got, secret) {
				t.Fatalf("Load = %d bytes, %v, want the secret", len(got), err)
			}
			names, err := c.enumerate(t.Context(), chunkFilter(manifestTarget(key)))
			if err != nil {
				t.Fatalf("enumerate: %v", err)
			}
			if want := (size + chunkSize - 1) / chunkSize; len(names) != want {
				t.Fatalf("%d chunks stored, want %d", len(names), want)
			}
			for _, name := range names {
				blob, err := c.read(t.Context(), name, chunkSize)
				if err != nil || len(blob) == 0 || len(blob) > chunkSize {
					t.Fatalf("chunk read = %d bytes, %v", len(blob), err)
				}
			}
			if err := store.Delete(t.Context(), key); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if names, err := c.enumerate(t.Context(), chunkFilter(manifestTarget(key))); err != nil || len(names) != 0 {
				t.Fatalf("Delete left %q, %v", names, err)
			}
		})
	}
}

// TestCredmanMatchingAssumptions checks the two behaviours of the real service
// that the target encoding and the fake in the unit tests are built on.
func TestCredmanMatchingAssumptions(t *testing.T) {
	c := realCredman(t)
	key := ownKey(t, c, "profile")
	target := manifestTarget(key) + "#" + genN(7) + ".0"
	if err := c.write(t.Context(), target, key.Account, []byte("v")); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Run("lookup is case-insensitive", func(t *testing.T) {
		got, err := c.read(t.Context(), strings.ToUpper(target), chunkSize)
		if err != nil || string(got) != "v" {
			t.Fatalf("read of the upper-cased target = %q, %v", got, err)
		}
	})
	t.Run("filter is case-insensitive and * is a wildcard", func(t *testing.T) {
		names, err := c.enumerate(t.Context(), strings.ToUpper(manifestTarget(key))+"#*")
		if err != nil || !slices.Contains(names, target) {
			t.Fatalf("enumerate = %q, %v, want it to contain %q", names, err, target)
		}
	})
	t.Run("no match is empty", func(t *testing.T) {
		names, err := c.enumerate(t.Context(), "secretstore-test-"+randomService(t)+"/none#*")
		if err != nil || len(names) != 0 {
			t.Fatalf("enumerate = %q, %v, want nothing", names, err)
		}
	})
	t.Run("a missing credential is ERROR_NOT_FOUND", func(t *testing.T) {
		_, err := c.read(t.Context(), target+"9", chunkSize)
		var we *win32Error
		if !errors.As(err, &we) || we.code != win32NotFound {
			t.Fatalf("read of a missing target = %v, want ERROR_NOT_FOUND", err)
		}
		err = c.delete(t.Context(), target+"9")
		if !errors.As(err, &we) || we.code != win32NotFound {
			t.Fatalf("delete of a missing target = %v, want ERROR_NOT_FOUND", err)
		}
	})
}

func TestCredmanStoredAttributes(t *testing.T) {
	c := realCredman(t)
	store := newChunkedStore(c, 4096)
	key := ownKey(t, c, "Pro file/é")
	if err := store.Save(t.Context(), key, []byte("secret")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	prefix := manifestTarget(key)
	names, err := c.enumerate(t.Context(), chunkFilter(prefix))
	if err != nil || len(names) != 1 {
		t.Fatalf("enumerate = %q, %v", names, err)
	}
	for _, target := range []string{prefix, names[0]} {
		err := c.readCredential(t.Context(), target, func(cred *credential) error {
			user := ""
			if cred.UserName != nil {
				user = windows.UTF16PtrToString(cred.UserName)
			}
			switch {
			case cred.Type != credTypeGeneric:
				t.Errorf("%q: Type = %d, want generic", target, cred.Type)
			case cred.Persist != credPersistLocalHost:
				t.Errorf("%q: Persist = %d, want local machine", target, cred.Persist)
			case user != key.Account:
				t.Errorf("%q: UserName = %q, want the account", target, user)
			case cred.Comment != nil && windows.UTF16PtrToString(cred.Comment) != "":
				t.Errorf("%q: Comment is set", target)
			case cred.TargetAlias != nil && windows.UTF16PtrToString(cred.TargetAlias) != "":
				t.Errorf("%q: TargetAlias is set", target)
			case cred.AttributeCount != 0:
				t.Errorf("%q: AttributeCount = %d, want 0", target, cred.AttributeCount)
			case cred.Flags != 0:
				t.Errorf("%q: Flags = %d, want 0", target, cred.Flags)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("readCredential %q: %v", target, err)
		}
	}
}

func TestCredmanSweepLeavesOtherNamesAlone(t *testing.T) {
	c := realCredman(t)
	store := newChunkedStore(c, MaxSecretBytesLimit)
	accounts := []string{"acct", "ACCT", "ac*", "ac?", "ac%"}
	secrets := make(map[Key][]byte)
	// One service for every account, so one account's sweep could reach
	// another's names if the encoding allowed it.
	service := "secretstore-test-" + randomService(t)
	keys := make([]Key, 0, len(accounts))
	for i, account := range accounts {
		key := Key{Service: service, Account: account}
		keys = append(keys, key)
		secret := patterned(chunkSize+1+i, byte(i))
		secrets[key] = secret
		t.Cleanup(func() {
			if err := store.Delete(context.WithoutCancel(t.Context()), key); err != nil {
				t.Errorf("cleanup: %v", err)
			}
		})
		if err := store.Save(t.Context(), key, secret); err != nil {
			t.Fatalf("Save %q: %v", account, err)
		}
	}

	target := keys[0]
	prefix := manifestTarget(target)
	orphan := chunkTarget(prefix, genN(40), 0)
	foreign := prefix + "#not-a-chunk"
	for _, name := range []string{orphan, foreign} {
		if err := c.write(t.Context(), name, target.Account, []byte("x")); err != nil {
			t.Fatalf("write %q: %v", name, err)
		}
		t.Cleanup(func() { removeTarget(t, c, name) })
	}
	if err := store.Save(t.Context(), target, []byte("replacement")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := c.read(t.Context(), orphan, chunkSize); err == nil {
		t.Fatal("the orphan generation was not swept")
	}
	if _, err := c.read(t.Context(), foreign, chunkSize); err != nil {
		t.Fatalf("a name that is not a chunk was removed: %v", err)
	}
	if err := store.Delete(t.Context(), target); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	for _, key := range keys[1:] {
		got, err := store.Load(t.Context(), key)
		if err != nil || !bytes.Equal(got, secrets[key]) {
			t.Fatalf("Load %q = %d bytes, %v; another account's value changed", key.Account, len(got), err)
		}
	}
	if _, err := c.read(t.Context(), foreign, chunkSize); err != nil {
		t.Fatalf("Delete removed a name that is not a chunk: %v", err)
	}
}

func TestCredmanRefusesAnOversizedBlob(t *testing.T) {
	c := realCredman(t)
	err := c.write(t.Context(), "secretstore-test-"+randomService(t)+"/big", "x", make([]byte, chunkSize+1))
	var we *win32Error
	if !errors.As(err, &we) {
		t.Fatalf("write of an oversized blob = %v, want a win32Error", err)
	}
}

func TestCredmanZeroLengthBlobAndSizeBound(t *testing.T) {
	c := realCredman(t)
	target := "secretstore-test-" + randomService(t) + "/blob"
	t.Cleanup(func() { removeTarget(t, c, target) })
	if err := c.write(t.Context(), target, "u", bytes.Repeat([]byte{7}, 100)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := c.read(t.Context(), target, 99); !errors.Is(err, errBlobTooLarge) {
		t.Fatalf("read with a bound below the size = %v, want errBlobTooLarge", err)
	}
	got, err := c.read(t.Context(), target, 100)
	if err != nil || len(got) != 100 {
		t.Fatalf("read = %d bytes, %v", len(got), err)
	}
}
