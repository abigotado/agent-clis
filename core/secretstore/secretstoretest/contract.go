package secretstoretest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/abigotado/agent-clis/core/secretstore"
)

// minContractBound is the smallest bound Contract accepts: its all-byte-values
// row stores 256 bytes.
const minContractBound = 256

// Contract runs the behaviour suite against s, which must have been opened
// with MaxSecretBytes equal to maxSecretBytes (at least 256). It stores only
// under a random service named secretstore-test-<random> and deletes everything
// it created when t finishes, so it is safe against a real store, though the
// real-backend tests of a later change run it in disposable environments.
//
// The rows are: missing keys, round trip and copy isolation, overwrite,
// idempotent delete, isolation between keys, the size bound (a value of exactly
// the bound, and one byte more leaving the previous value intact), empty
// secrets, all 256 byte values, non-ASCII accounts, accounts that differ only by
// case, accounts with wildcard characters, invalid keys on every operation,
// pre-canceled contexts, and a redaction check: a random marker secret, account
// and service never appear in provoked errors formatted with %v, %+v, %#v and
// %s, nor in slog text and JSON output.
func Contract(t *testing.T, s secretstore.Store, maxSecretBytes int) {
	t.Helper()
	if maxSecretBytes < minContractBound || maxSecretBytes > secretstore.MaxSecretBytesLimit {
		t.Fatalf("Contract: maxSecretBytes = %d, want %d..%d", maxSecretBytes, minContractBound, secretstore.MaxSecretBytesLimit)
	}
	c := &contract{s: s, max: maxSecretBytes, service: "secretstore-test-" + randomHex(t, 8), used: map[secretstore.Key]struct{}{}}
	cleanupCtx := context.WithoutCancel(t.Context())
	t.Cleanup(func() {
		for key := range c.used {
			if err := s.Delete(cleanupCtx, key); err != nil {
				t.Errorf("cleanup: delete a test item: %v", err)
			}
		}
	})

	t.Run("missing key", c.missing)
	t.Run("round trip and copy isolation", c.roundTrip)
	t.Run("overwrite", c.overwrite)
	t.Run("idempotent delete", c.idempotentDelete)
	t.Run("key isolation", c.isolation)
	t.Run("size bound", c.sizeBound)
	t.Run("empty secret", c.emptySecret)
	t.Run("every byte value", c.allBytes)
	t.Run("non-ASCII accounts", c.nonASCII)
	t.Run("accounts differing only by case", c.caseDistinct)
	t.Run("wildcard characters in accounts", c.wildcards)
	t.Run("invalid keys on every operation", c.invalidKeys)
	t.Run("pre-canceled context", c.canceled)
	t.Run("redaction", c.redaction)
}

type contract struct {
	s       secretstore.Store
	max     int
	service string
	used    map[secretstore.Key]struct{}
}

// key returns a key under the random service and registers it for cleanup.
func (c *contract) key(account string) secretstore.Key {
	return c.keyIn(c.service, account)
}

func (c *contract) keyIn(service, account string) secretstore.Key {
	k := secretstore.Key{Service: service, Account: account}
	c.used[k] = struct{}{}
	return k
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("read random bytes: %v", err)
	}
	return hex.EncodeToString(b)
}

func (c *contract) mustSave(t *testing.T, key secretstore.Key, secret []byte) {
	t.Helper()
	if err := c.s.Save(t.Context(), key, secret); err != nil {
		t.Fatalf("Save: %v", err)
	}
}

func (c *contract) wantLoad(t *testing.T, key secretstore.Key, want []byte) {
	t.Helper()
	got, err := c.s.Load(t.Context(), key)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Load returned %d bytes, want %d different bytes", len(got), len(want))
	}
}

func (c *contract) wantExists(t *testing.T, key secretstore.Key, want bool) {
	t.Helper()
	got, err := c.s.Exists(t.Context(), key)
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if got != want {
		t.Fatalf("Exists = %v, want %v", got, want)
	}
}

func wantKind(t *testing.T, what string, err, sentinel error) {
	t.Helper()
	if !errors.Is(err, sentinel) {
		t.Fatalf("%s: err = %v, want %v", what, err, sentinel)
	}
	var se *secretstore.Error
	if !errors.As(err, &se) {
		t.Fatalf("%s: err = %v is not a *secretstore.Error", what, err)
	}
}

func (c *contract) missing(t *testing.T) {
	key := c.key("missing")
	c.wantExists(t, key, false)
	_, err := c.s.Load(t.Context(), key)
	wantKind(t, "Load of a missing key", err, secretstore.ErrNotFound)
	if err := c.s.Delete(t.Context(), key); err != nil {
		t.Fatalf("Delete of a missing key: %v", err)
	}
}

func (c *contract) roundTrip(t *testing.T) {
	key := c.key("round-trip")
	secret := []byte("s3cret-value")
	c.mustSave(t, key, secret)
	secret[0] = 'X' // the store must have copied the input
	c.wantExists(t, key, true)
	want := []byte("s3cret-value")
	got, err := c.s.Load(t.Context(), key)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("Load = %q, %v; want the original bytes", got, err)
	}
	got[0] = 'Y' // the store must hand out a copy
	c.wantLoad(t, key, want)
}

func (c *contract) overwrite(t *testing.T) {
	key := c.key("overwrite")
	long := bytes.Repeat([]byte("long-"), 40)
	c.mustSave(t, key, long)
	c.wantLoad(t, key, long)
	c.mustSave(t, key, []byte("short"))
	c.wantLoad(t, key, []byte("short"))
	c.mustSave(t, key, long)
	c.wantLoad(t, key, long)
}

func (c *contract) idempotentDelete(t *testing.T) {
	key := c.key("delete")
	c.mustSave(t, key, []byte("v"))
	for i := range 2 {
		if err := c.s.Delete(t.Context(), key); err != nil {
			t.Fatalf("Delete #%d: %v", i+1, err)
		}
		c.wantExists(t, key, false)
		_, err := c.s.Load(t.Context(), key)
		wantKind(t, "Load after Delete", err, secretstore.ErrNotFound)
	}
}

func (c *contract) isolation(t *testing.T) {
	otherService := c.service + "-other"
	tests := []struct {
		name string
		a, b secretstore.Key
	}{
		{"accounts of one service", c.key("iso-a"), c.key("iso-b")},
		{"one account in two services", c.key("iso-same"), c.keyIn(otherService, "iso-same")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c.mustSave(t, tt.a, []byte("value-a"))
			c.wantExists(t, tt.b, false)
			c.mustSave(t, tt.b, []byte("value-b"))
			c.wantLoad(t, tt.a, []byte("value-a"))
			c.wantLoad(t, tt.b, []byte("value-b"))
			if err := c.s.Delete(t.Context(), tt.a); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			c.wantExists(t, tt.a, false)
			c.wantLoad(t, tt.b, []byte("value-b"))
		})
	}
}

func (c *contract) sizeBound(t *testing.T) {
	key := c.key("bound")
	atBound := bytes.Repeat([]byte{0xAB}, c.max)
	c.mustSave(t, key, atBound)
	c.wantLoad(t, key, atBound)

	err := c.s.Save(t.Context(), key, bytes.Repeat([]byte{0xCD}, c.max+1))
	wantKind(t, "Save above the bound", err, secretstore.ErrTooLarge)
	c.wantLoad(t, key, atBound) // the previous value survives the refusal

	fresh := c.key("bound-fresh")
	err = c.s.Save(t.Context(), fresh, bytes.Repeat([]byte{0xCD}, c.max+1))
	wantKind(t, "Save above the bound to a new key", err, secretstore.ErrTooLarge)
	c.wantExists(t, fresh, false)
}

func (c *contract) emptySecret(t *testing.T) {
	key := c.key("empty")
	c.mustSave(t, key, []byte("keep"))
	for name, secret := range map[string][]byte{"nil": nil, "zero length": {}} {
		t.Run(name, func(t *testing.T) {
			err := c.s.Save(t.Context(), key, secret)
			wantKind(t, "Save of an empty secret", err, secretstore.ErrInvalidArgument)
			c.wantLoad(t, key, []byte("keep"))
		})
	}
	fresh := c.key("empty-fresh")
	err := c.s.Save(t.Context(), fresh, nil)
	wantKind(t, "Save of an empty secret to a new key", err, secretstore.ErrInvalidArgument)
	c.wantExists(t, fresh, false)
}

func (c *contract) allBytes(t *testing.T) {
	key := c.key("all-bytes")
	secret := make([]byte, 256)
	for i := range secret {
		secret[i] = byte(i)
	}
	c.mustSave(t, key, secret)
	c.wantLoad(t, key, secret)
}

func (c *contract) nonASCII(t *testing.T) {
	accounts := []string{"пользователь", "日本語-profile", "café", "emoji-\U0001F511"}
	for _, account := range accounts {
		t.Run(account, func(t *testing.T) {
			key := c.key(account)
			secret := []byte("value-for-" + account)
			c.mustSave(t, key, secret)
			c.wantLoad(t, key, secret)
			if err := c.s.Delete(t.Context(), key); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			c.wantExists(t, key, false)
		})
	}
}

// distinct saves a different value under every account and checks that each
// reads back its own value, that none disturbs another, and that deleting one
// leaves the others.
func (c *contract) distinct(t *testing.T, accounts []string) {
	t.Helper()
	for i, account := range accounts {
		c.wantExists(t, c.key(account), false)
		c.mustSave(t, c.key(account), []byte(fmt.Sprintf("value-%d", i)))
	}
	for i, account := range accounts {
		c.wantLoad(t, c.key(account), []byte(fmt.Sprintf("value-%d", i)))
	}
	if err := c.s.Delete(t.Context(), c.key(accounts[0])); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	c.wantExists(t, c.key(accounts[0]), false)
	for i, account := range accounts[1:] {
		c.wantLoad(t, c.key(account), []byte(fmt.Sprintf("value-%d", i+1)))
	}
}

func (c *contract) caseDistinct(t *testing.T) {
	c.distinct(t, []string{"case-account", "Case-Account", "CASE-ACCOUNT"})
}

func (c *contract) wildcards(t *testing.T) {
	t.Run("prefixes of a wildcard account do not exist", func(t *testing.T) {
		c.mustSave(t, c.key("wild*"), []byte("w"))
		for _, account := range []string{"wild", "wild?", "wild%", "wil", "*", "%"} {
			c.wantExists(t, c.key(account), false)
		}
		if err := c.s.Delete(t.Context(), c.key("wild*")); err != nil {
			t.Fatalf("Delete: %v", err)
		}
	})
	t.Run("accounts stay distinct", func(t *testing.T) {
		c.distinct(t, []string{"*", "?", "%", "a*", "a?", "a%", "a", "ab"})
	})
}

func (c *contract) invalidKeys(t *testing.T) {
	long := strings.Repeat("a", 129)
	keys := map[string]secretstore.Key{
		"empty service":          {Service: "", Account: "a"},
		"empty account":          {Service: c.service, Account: ""},
		"service with slash":     {Service: c.service + "/x", Account: "a"},
		"service too long":       {Service: "a" + strings.Repeat("b", 64), Account: "a"},
		"account too long":       {Service: c.service, Account: long},
		"account control char":   {Service: c.service, Account: "a\x00b"},
		"account separator rune": {Service: c.service, Account: "a␟b"},
		"account hash":           {Service: c.service, Account: "a#b"},
		"account invalid UTF-8":  {Service: c.service, Account: "a\xffb"},
	}
	for name, key := range keys {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			_, err := c.s.Exists(ctx, key)
			wantKind(t, "Exists", err, secretstore.ErrInvalidArgument)
			_, err = c.s.Load(ctx, key)
			wantKind(t, "Load", err, secretstore.ErrInvalidArgument)
			wantKind(t, "Save", c.s.Save(ctx, key, []byte("v")), secretstore.ErrInvalidArgument)
			wantKind(t, "Delete", c.s.Delete(ctx, key), secretstore.ErrInvalidArgument)
		})
	}
}

func (c *contract) canceled(t *testing.T) {
	key := c.key("canceled")
	c.mustSave(t, key, []byte("kept"))
	missing := c.key("canceled-missing")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := c.s.Exists(ctx, key)
	wantContextCanceled(t, "Exists", err)
	_, err = c.s.Load(ctx, key)
	wantContextCanceled(t, "Load", err)
	wantContextCanceled(t, "Save", c.s.Save(ctx, missing, []byte("never-written")))
	wantContextCanceled(t, "Delete", c.s.Delete(ctx, key))

	c.wantExists(t, missing, false)    // a canceled Save writes nothing
	c.wantLoad(t, key, []byte("kept")) // a canceled Delete removes nothing
}

func wantContextCanceled(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("%s with a canceled context: err = %v, want context.Canceled", what, err)
	}
}

func (c *contract) redaction(t *testing.T) {
	for _, finding := range c.redactionFindings(t) {
		t.Error(finding)
	}
}

// redactionFindings provokes errors from the store and returns one line per
// leaked marker. The Contract's own random service is a marker too: it appears
// in errors only if a backend echoes key.Service.
func (c *contract) redactionFindings(t *testing.T) []string {
	secretMarker := "secret-marker-" + randomHex(t, 8)
	accountMarker := "acct-marker-" + randomHex(t, 8)
	serviceMarker := "svc-marker-" + randomHex(t, 8)
	markers := []string{secretMarker, accountMarker, serviceMarker, c.service}

	stored := c.key(accountMarker)
	c.mustSave(t, stored, []byte(secretMarker))
	missing := c.key(accountMarker + "-missing")
	badService := secretstore.Key{Service: serviceMarker + "/x", Account: accountMarker}
	badAccount := secretstore.Key{Service: c.service, Account: accountMarker + "#"}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()

	var provoked []error
	add := func(err error) {
		if err != nil {
			provoked = append(provoked, err)
		}
	}
	_, err := c.s.Load(t.Context(), missing)
	add(err)
	add(c.s.Save(t.Context(), stored, append([]byte(secretMarker), make([]byte, c.max)...)))
	add(c.s.Save(t.Context(), missing, nil))
	for _, key := range []secretstore.Key{badService, badAccount} {
		_, err = c.s.Exists(t.Context(), key)
		add(err)
		_, err = c.s.Load(t.Context(), key)
		add(err)
		add(c.s.Save(t.Context(), key, []byte(secretMarker)))
		add(c.s.Delete(t.Context(), key))
	}
	_, err = c.s.Load(canceled, stored)
	add(err)
	add(c.s.Save(canceled, stored, []byte(secretMarker)))
	if len(provoked) < 10 {
		t.Fatalf("provoked only %d errors; the store accepted inputs it must refuse", len(provoked))
	}
	var findings []string
	for i, err := range provoked {
		if found := leaks(err, markers...); len(found) > 0 {
			findings = append(findings, fmt.Sprintf("error %d leaks: %s", i, strings.Join(found, "; ")))
		}
	}
	return findings
}

// leaks formats err every way a caller or logger might and returns a
// description of each marker found in the output. It holds no secret itself:
// descriptions name the verb and the marker's position, never its text.
func leaks(err error, markers ...string) []string {
	outputs := map[string]string{
		"%v":  fmt.Sprintf("%v", err),
		"%+v": fmt.Sprintf("%+v", err),
		"%#v": fmt.Sprintf("%#v", err),
		"%s":  fmt.Sprintf("%s", err),
	}
	var text, jsonOut bytes.Buffer
	slog.New(slog.NewTextHandler(&text, nil)).Error("provoked", "err", err)
	slog.New(slog.NewJSONHandler(&jsonOut, nil)).Error("provoked", slog.Any("err", err))
	outputs["slog text"] = text.String()
	outputs["slog json"] = jsonOut.String()

	var found []string
	for where, out := range outputs {
		for i, marker := range markers {
			if strings.Contains(out, marker) {
				found = append(found, fmt.Sprintf("%s contains marker #%d", where, i))
			}
		}
	}
	return found
}
