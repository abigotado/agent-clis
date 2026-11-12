package secretstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

var chunkedKey = Key{Service: "svc.test", Account: "profile"}

func newChunked(t *testing.T, max int) (*fakeCredMan, *chunkedStore) {
	t.Helper()
	f := newFakeCredMan()
	s := newChunkedStore(f, max)
	s.random = &countReader{}
	return f, s
}

// patterned returns n bytes that differ from chunk to chunk, so a chunk stored
// in the wrong place changes the digest.
func patterned(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7+i/chunkSize*13) + seed
	}
	return b
}

func wantCredError(t *testing.T, err error, op string, kind Kind, status int64) {
	t.Helper()
	var se *Error
	if !errors.As(err, &se) {
		t.Fatalf("err = %v, want an *Error", err)
	}
	if se.Op != op || se.Kind != kind || se.Status != status || se.Backend != "credman" {
		t.Fatalf("err = {op %q backend %q kind %v status %d}, want {op %q backend credman kind %v status %d}",
			se.Op, se.Backend, se.Kind, se.Status, op, kind, status)
	}
	text := err.Error()
	for _, leak := range []string{chunkedKey.Service, chunkedKey.Account, manifestTarget(chunkedKey)} {
		if strings.Contains(text, leak) {
			t.Fatalf("error text %q contains %q", text, leak)
		}
	}
}

func chunkedLoad(t *testing.T, s Store, want []byte) {
	t.Helper()
	got, err := s.Load(t.Context(), chunkedKey)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Load returned %d bytes, want %d different bytes", len(got), len(want))
	}
}

func chunkedSave(t *testing.T, s Store, secret []byte) {
	t.Helper()
	if err := s.Save(t.Context(), chunkedKey, secret); err != nil {
		t.Fatalf("Save: %v", err)
	}
}

// wantTargets asserts the store holds exactly the manifest and the chunks
// of the given generations, each with the stated number of chunks.
func wantTargets(t *testing.T, f *fakeCredMan, key Key, gens map[string]int) {
	t.Helper()
	prefix := manifestTarget(key)
	want := []string{prefix}
	for gen, n := range gens {
		for i := 0; i < n; i++ {
			want = append(want, chunkTarget(prefix, gen, i))
		}
	}
	slices.Sort(want)
	if got := f.targets(); !slices.Equal(got, want) {
		t.Fatalf("stored targets:\n%q\nwant:\n%q", got, want)
	}
}

func TestChunkedEncodeTarget(t *testing.T) {
	for _, tt := range []struct {
		in, want string
	}{
		{"svc.test", "svc.test"},
		{"Svc.test", "%53vc.test"},
		{"a-b_c.d9", "a-b_c.d9"},
		{"Al ice/é*?%", "%41l%20ice%2F%C3%A9%2A%3F%25"},
		{"a#b", "a%23b"},
		{"\x00\xff", "%00%FF"},
		{"ACCT", "%41%43%43%54"},
	} {
		t.Run(tt.in, func(t *testing.T) {
			if got := encodeTarget(tt.in); got != tt.want {
				t.Fatalf("encodeTarget(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}

	t.Run("literal set is exactly lower-case letters, digits and . _ -", func(t *testing.T) {
		for c := 0; c < 256; c++ {
			got := encodeTarget(string([]byte{byte(c)}))
			literal := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-'
			want := fmt.Sprintf("%%%02X", c)
			if literal {
				want = string([]byte{byte(c)})
			}
			if got != want {
				t.Fatalf("byte %#02x encodes to %q, want %q", c, got, want)
			}
			if strings.ContainsAny(got, "*?#/") {
				t.Fatalf("byte %#02x encodes to %q, which holds a wildcard or separator", c, got)
			}
		}
	})

	t.Run("injective under case-insensitive comparison", func(t *testing.T) {
		seen := make(map[string]string)
		for a := 0; a < 256; a++ {
			for b := -1; b < 256; b++ {
				in := string([]byte{byte(a)})
				if b >= 0 {
					in += string([]byte{byte(b)})
				}
				folded := strings.ToLower(encodeTarget(in))
				if prev, dup := seen[folded]; dup {
					t.Fatalf("%q and %q both encode to %q (case-folded)", prev, in, folded)
				}
				seen[folded] = in
			}
		}
	})
}

func TestChunkedOnStoreGolden(t *testing.T) {
	f, s := newChunked(t, 4096)
	key := Key{Service: "Svc.test", Account: "Al ice/é*?%"}
	if err := s.Save(t.Context(), key, []byte("secret")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	const manifestName = "%53vc.test/%41l%20ice%2F%C3%A9%2A%3F%25"
	gen := genN(1)
	chunkName := manifestName + "#" + gen + ".0"
	if got, want := f.targets(), []string{manifestName, chunkName}; !slices.Equal(got, want) {
		t.Fatalf("targets = %q, want %q", got, want)
	}
	const wantManifest = `{"v":1,"gen":"01010101010101010101010101010101","n":1,"sha256":"2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b"}`
	blob, _, _ := f.get(manifestName)
	if string(blob) != wantManifest {
		t.Fatalf("manifest = %s, want %s", blob, wantManifest)
	}
	blob, _, _ = f.get(chunkName)
	if string(blob) != "secret" {
		t.Fatalf("chunk = %q, want the secret", blob)
	}
	for _, target := range []string{manifestName, chunkName} {
		f.mu.Lock()
		user := f.items[strings.ToLower(target)].user
		f.mu.Unlock()
		if user != key.Account {
			t.Fatalf("UserName of %q = %q, want the account", target, user)
		}
	}
}

func TestChunkedBoundaries(t *testing.T) {
	for _, tt := range []struct {
		size   int
		chunks int
	}{
		{1, 1}, {chunkSize - 1, 1}, {chunkSize, 1}, {chunkSize + 1, 2},
		{2 * chunkSize, 2}, {2*chunkSize + 1, 3}, {MaxSecretBytesLimit - 1, 52}, {MaxSecretBytesLimit, 52},
	} {
		t.Run(strconv.Itoa(tt.size), func(t *testing.T) {
			f, s := newChunked(t, MaxSecretBytesLimit)
			secret := patterned(tt.size, 1)
			chunkedSave(t, s, secret)
			wantTargets(t, f, chunkedKey, map[string]int{genN(1): tt.chunks})
			for i := 0; i < tt.chunks; i++ {
				blob, _, _ := f.get(chunkTarget(manifestTarget(chunkedKey), genN(1), i))
				want := chunkSize
				if i == tt.chunks-1 {
					want = tt.size - i*chunkSize
				}
				if len(blob) != want {
					t.Fatalf("chunk %d holds %d bytes, want %d", i, len(blob), want)
				}
			}
			chunkedLoad(t, s, secret)
			if ok, err := s.Exists(t.Context(), chunkedKey); err != nil || !ok {
				t.Fatalf("Exists = %v, %v, want true", ok, err)
			}
		})
	}

	t.Run("one byte over the hard cap", func(t *testing.T) {
		f, s := newChunked(t, MaxSecretBytesLimit)
		err := s.Save(t.Context(), chunkedKey, make([]byte, MaxSecretBytesLimit+1))
		wantCredError(t, err, "save", KindTooLarge, 0)
		if calls := f.calls(); len(calls) != 0 {
			t.Fatalf("an oversized Save touched the store: %v", calls)
		}
	})
	t.Run("a bound above the hard cap is clamped", func(t *testing.T) {
		_, s := newChunked(t, 1<<30)
		if s.max != MaxSecretBytesLimit {
			t.Fatalf("max = %d, want %d", s.max, MaxSecretBytesLimit)
		}
	})
	t.Run("empty secret", func(t *testing.T) {
		f, s := newChunked(t, 4096)
		wantCredError(t, s.Save(t.Context(), chunkedKey, nil), "save", KindInvalidArgument, 0)
		if len(f.calls()) != 0 {
			t.Fatal("an empty Save touched the store")
		}
	})
}

func TestChunkedLoadBound(t *testing.T) {
	t.Run("a value above the bound is too large without reading chunks", func(t *testing.T) {
		f, big := newChunked(t, MaxSecretBytesLimit)
		chunkedSave(t, big, patterned(3*chunkSize, 1))
		small := newChunkedStore(f, 2*chunkSize)
		f.resetCalls()
		_, err := small.Load(t.Context(), chunkedKey)
		wantCredError(t, err, "load", KindTooLarge, 0)
		for _, call := range f.calls() {
			if call.kind() == "read chunk" {
				t.Fatalf("Load read a chunk of a value it cannot return: %v", call)
			}
		}
	})
	t.Run("a value above the bound within the chunk count is too large", func(t *testing.T) {
		f, big := newChunked(t, MaxSecretBytesLimit)
		chunkedSave(t, big, patterned(chunkSize+500, 1))
		small := newChunkedStore(f, chunkSize+100)
		_, err := small.Load(t.Context(), chunkedKey)
		wantCredError(t, err, "load", KindTooLarge, 0)
	})
	t.Run("a value at the bound loads", func(t *testing.T) {
		f, big := newChunked(t, MaxSecretBytesLimit)
		secret := patterned(chunkSize+500, 1)
		chunkedSave(t, big, secret)
		chunkedLoad(t, newChunkedStore(f, len(secret)), secret)
	})
}

func validManifest(gen string, n int, secret []byte) string {
	sum := sha256.Sum256(secret)
	return fmt.Sprintf(`{"v":1,"gen":%q,"n":%d,"sha256":%q}`, gen, n, hex.EncodeToString(sum[:]))
}

func TestChunkedMalformedManifest(t *testing.T) {
	gen := genN(9)
	good := validManifest(gen, 1, []byte("x"))
	sum := hex.EncodeToString(func() []byte { s := sha256.Sum256([]byte("x")); return s[:] }())
	for _, tt := range []struct {
		name string
		blob string
	}{
		{"empty", ""},
		{"not json", "not json"},
		{"empty object", "{}"},
		{"null", "null"},
		{"future version", strings.Replace(good, `"v":1`, `"v":2`, 1)},
		{"version zero", strings.Replace(good, `"v":1`, `"v":0`, 1)},
		{"version as string", strings.Replace(good, `"v":1`, `"v":"1"`, 1)},
		{"n zero", validManifest(gen, 0, []byte("x"))},
		{"n above the cap", validManifest(gen, 53, []byte("x"))},
		{"n negative", validManifest(gen, -1, []byte("x"))},
		{"n huge", validManifest(gen, 1<<30, []byte("x"))},
		{"n beyond int range", strings.Replace(good, `"n":1`, `"n":1e30`, 1)},
		{"n fractional", strings.Replace(good, `"n":1`, `"n":1.5`, 1)},
		{"gen upper case", strings.Replace(good, gen, strings.ToUpper(strings.Repeat("ab", 16)), 1)},
		{"gen short", strings.Replace(good, gen, gen[:30], 1)},
		{"gen long", strings.Replace(good, gen, gen+"09", 1)},
		{"gen not hex", strings.Replace(good, gen, strings.Repeat("zz", 16), 1)},
		{"sha short", strings.Replace(good, sum, sum[:62], 1)},
		{"sha upper case", strings.Replace(good, sum, strings.ToUpper(sum), 1)},
		{"unknown field", strings.Replace(good, `}`, `,"extra":1}`, 1)},
		{"trailing data", good + " x"},
		{"two objects", good + good},
		{"trailing NUL", good + "\x00"},
		{"over the manifest bound", good + strings.Repeat(" ", manifestMaxBytes)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f, s := newChunked(t, MaxSecretBytesLimit)
			prefix := manifestTarget(chunkedKey)
			f.put(prefix, []byte(tt.blob))
			f.put(chunkTarget(prefix, gen, 0), []byte("x"))
			f.resetCalls()
			_, err := s.Load(t.Context(), chunkedKey)
			wantCredError(t, err, "load", KindCorrupt, 0)
			if ok, err := s.Exists(t.Context(), chunkedKey); err != nil || !ok {
				t.Fatalf("Exists = %v, %v, want true for a present manifest", ok, err)
			}
			// Nothing is allocated or read for a manifest that is not valid.
			for _, call := range f.calls() {
				if call.kind() == "read chunk" {
					t.Fatalf("Load read a chunk for an invalid manifest: %v", call)
				}
			}
			// A Save replaces it and a Delete removes it.
			chunkedSave(t, s, []byte("fresh"))
			chunkedLoad(t, s, []byte("fresh"))
			if err := s.Delete(t.Context(), chunkedKey); err != nil {
				t.Fatalf("Delete: %v", err)
			}
		})
	}

	t.Run("valid manifest parses", func(t *testing.T) {
		m, err := parseManifest([]byte(good))
		if err != nil || m.V != 1 || m.Gen != gen || m.N != 1 || m.SHA256 != sum {
			t.Fatalf("parseManifest = %+v, %v", m, err)
		}
		if _, err := parseManifest([]byte(good + "\n")); err != nil {
			t.Fatalf("trailing newline: %v", err)
		}
	})
}

func TestChunkedDamagedValue(t *testing.T) {
	secret := patterned(2*chunkSize+100, 5)
	prefix := manifestTarget(chunkedKey)
	chunk := func(i int) string { return chunkTarget(prefix, genN(1), i) }
	for _, tt := range []struct {
		name   string
		damage func(f *fakeCredMan)
	}{
		{"first chunk missing", func(f *fakeCredMan) { f.remove(chunk(0)) }},
		{"middle chunk missing", func(f *fakeCredMan) { f.remove(chunk(1)) }},
		{"last chunk missing", func(f *fakeCredMan) { f.remove(chunk(2)) }},
		{"non-last chunk short", func(f *fakeCredMan) { f.put(chunk(0), make([]byte, chunkSize-1)) }},
		{"last chunk empty", func(f *fakeCredMan) { f.put(chunk(2), nil) }},
		{"chunk over the size limit", func(f *fakeCredMan) { f.put(chunk(1), make([]byte, chunkSize+1)) }},
		{"flipped byte", func(f *fakeCredMan) {
			blob, _, _ := f.get(chunk(1))
			blob[7] ^= 1
			f.put(chunk(1), blob)
		}},
		{"swapped chunks", func(f *fakeCredMan) {
			a, _, _ := f.get(chunk(0))
			b, _, _ := f.get(chunk(1))
			f.put(chunk(0), b)
			f.put(chunk(1), a)
		}},
		{"last chunk grown", func(f *fakeCredMan) {
			blob, _, _ := f.get(chunk(2))
			f.put(chunk(2), append(blob, 0))
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f, s := newChunked(t, MaxSecretBytesLimit)
			chunkedSave(t, s, secret)
			tt.damage(f)
			f.resetCalls()
			_, err := s.Load(t.Context(), chunkedKey)
			wantCredError(t, err, "load", KindCorrupt, 0)
			manifestReads := 0
			chunkReads := make(map[string]int)
			for _, call := range f.calls() {
				switch call.kind() {
				case "read manifest":
					manifestReads++
				case "read chunk":
					if chunkReads[call.target]++; chunkReads[call.target] > 1 {
						t.Fatalf("chunk %q was read twice for the same generation", call.target)
					}
				}
			}
			if manifestReads != 2 {
				t.Fatalf("manifest was read %d times, want 2 (once, then once to check for a newer generation)", manifestReads)
			}
			if ok, err := s.Exists(t.Context(), chunkedKey); err != nil || !ok {
				t.Fatalf("Exists = %v, %v, want true", ok, err)
			}
		})
	}
}

func TestChunkedSaveOverwritesAndSweeps(t *testing.T) {
	f, s := newChunked(t, MaxSecretBytesLimit)
	chunkedSave(t, s, patterned(3*chunkSize, 1))
	wantTargets(t, f, chunkedKey, map[string]int{genN(1): 3})
	second := patterned(chunkSize+1, 2)
	chunkedSave(t, s, second)
	wantTargets(t, f, chunkedKey, map[string]int{genN(2): 2})
	chunkedLoad(t, s, second)
	third := []byte("short")
	chunkedSave(t, s, third)
	wantTargets(t, f, chunkedKey, map[string]int{genN(3): 1})
	chunkedLoad(t, s, third)

	if err := s.Delete(t.Context(), chunkedKey); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got := f.targets(); len(got) != 0 {
		t.Fatalf("Delete left %q", got)
	}
	if err := s.Delete(t.Context(), chunkedKey); err != nil {
		t.Fatalf("second Delete: %v", err)
	}
	_, err := s.Load(t.Context(), chunkedKey)
	wantCredError(t, err, "load", KindNotFound, win32NotFound)
	if ok, err := s.Exists(t.Context(), chunkedKey); err != nil || ok {
		t.Fatalf("Exists = %v, %v, want false", ok, err)
	}
}

func TestChunkedOrphanGenerationsAreSwept(t *testing.T) {
	prefix := manifestTarget(chunkedKey)
	orphans := []string{
		chunkTarget(prefix, genN(40), 0),
		chunkTarget(prefix, genN(40), 51),
		chunkTarget(prefix, genN(41), 7),
	}
	t.Run("Save", func(t *testing.T) {
		f, s := newChunked(t, MaxSecretBytesLimit)
		for _, o := range orphans {
			f.put(o, []byte("orphan"))
		}
		chunkedSave(t, s, []byte("value"))
		wantTargets(t, f, chunkedKey, map[string]int{genN(1): 1})
	})
	t.Run("Delete without a manifest", func(t *testing.T) {
		f, s := newChunked(t, MaxSecretBytesLimit)
		for _, o := range orphans {
			f.put(o, []byte("orphan"))
		}
		if err := s.Delete(t.Context(), chunkedKey); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if got := f.targets(); len(got) != 0 {
			t.Fatalf("Delete left %q", got)
		}
	})
}

func TestChunkedLeavesForeignNamesAlone(t *testing.T) {
	prefix := manifestTarget(chunkedKey)
	gen := genN(40)
	foreign := []string{
		prefix + "#",
		prefix + "#x",
		prefix + "#" + gen,
		prefix + "#" + gen + ".",
		prefix + "#" + strings.ToUpper(strings.Repeat("ab", 16)) + ".0",
		prefix + "#" + gen[:31] + ".0",
		prefix + "#" + gen + "0.0",
		prefix + "#" + gen + ".52",
		prefix + "#" + gen + ".100",
		prefix + "#" + gen + ".01",
		prefix + "#" + gen + ".00",
		prefix + "#" + gen + ".5a",
		prefix + "#" + gen + ".-1",
		prefix + "#" + gen + ".+1",
		prefix + "#" + gen + ".0.1",
		prefix + "#" + gen + ".0#",
		prefix + "#" + gen + ".٣",
		prefix + "##" + gen + ".0",
		strings.ToUpper(prefix) + "#" + gen + ".0",
	}
	for _, name := range foreign {
		if gen, ok := ownChunk(prefix, name); ok {
			t.Fatalf("ownChunk accepted the foreign name %q (gen %s)", name, gen)
		}
	}
	for _, name := range []string{
		prefix + "#" + gen + ".0", prefix + "#" + gen + ".9", prefix + "#" + gen + ".10", prefix + "#" + gen + ".51",
	} {
		if got, ok := ownChunk(prefix, name); !ok || got != gen {
			t.Fatalf("ownChunk rejected the own name %q", name)
		}
	}

	f, s := newChunked(t, MaxSecretBytesLimit)
	for _, name := range foreign {
		f.put(name, []byte("foreign"))
	}
	before := snapshotCreds(f)
	chunkedSave(t, s, patterned(chunkSize+1, 3))
	chunkedSave(t, s, []byte("second"))
	if err := s.Delete(t.Context(), chunkedKey); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	after := snapshotCreds(f)
	if !maps.EqualFunc(before, after, bytes.Equal) {
		t.Fatalf("foreign names changed:\nbefore %q\nafter  %q", slices.Sorted(maps.Keys(before)), slices.Sorted(maps.Keys(after)))
	}
}

func snapshotCreds(f *fakeCredMan) map[string][]byte {
	out := make(map[string][]byte)
	for _, target := range f.targets() {
		blob, _, _ := f.get(target)
		out[target] = blob
	}
	return out
}

// belongsTo reports whether target is the manifest or a chunk name of the
// account whose manifest name is prefix, using exact case-sensitive prefixes.
func belongsTo(target, prefix string) bool {
	return target == prefix || strings.HasPrefix(target, prefix+"#")
}

func TestChunkedNeverTouchesAnotherAccount(t *testing.T) {
	keys := []Key{
		{Service: "svc.test", Account: "acct"},
		{Service: "svc.test", Account: "ACCT"},
		{Service: "svc.test", Account: "Acct"},
		{Service: "svc.test", Account: "ac*"},
		{Service: "svc.test", Account: "ac?"},
		{Service: "svc.test", Account: "ac%"},
		{Service: "svc.test", Account: "ac%2A"},
		{Service: "svc.test", Account: "acct2"},
		{Service: "svc.test", Account: "ac"},
		{Service: "svc.test", Account: "a/b"},
		{Service: "svc.test", Account: "a"},
		{Service: "Svc.test", Account: "acct"},
		{Service: "SVC.TEST", Account: "acct"},
		{Service: "svc.test2", Account: "acct"},
	}
	for _, target := range keys {
		t.Run(target.Service+"/"+target.Account, func(t *testing.T) {
			f, s := newChunked(t, MaxSecretBytesLimit)
			secrets := make(map[Key][]byte)
			for i, key := range keys {
				secrets[key] = patterned(chunkSize*(i%3)+10+i, byte(i))
				if err := s.Save(t.Context(), key, secrets[key]); err != nil {
					t.Fatalf("Save %v: %v", key, err)
				}
			}
			prefix := manifestTarget(target)
			others := func() map[string][]byte {
				out := make(map[string][]byte)
				for name, blob := range snapshotCreds(f) {
					if !belongsTo(name, prefix) {
						out[name] = blob
					}
				}
				return out
			}
			before := others()
			f.resetCalls()

			if err := s.Save(t.Context(), target, []byte("replacement")); err != nil {
				t.Fatalf("Save: %v", err)
			}
			if err := s.Delete(t.Context(), target); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if after := others(); !maps.EqualFunc(before, after, bytes.Equal) {
				t.Fatalf("another account's items changed")
			}
			for _, call := range f.calls() {
				switch call.op {
				case "enumerate":
					if !strings.HasSuffix(call.target, "#*") || strings.Count(call.target, "*") != 1 ||
						strings.ContainsAny(call.target, "?") || !strings.HasPrefix(call.target, prefix+"#") {
						t.Fatalf("enumerate filter %q is not this account's own prefix", call.target)
					}
				case "delete", "write":
					if !belongsTo(call.target, prefix) {
						t.Fatalf("%s of %q touches another account", call.op, call.target)
					}
				}
			}
			for _, key := range keys {
				if key == target {
					continue
				}
				got, err := s.Load(t.Context(), key)
				if err != nil || !bytes.Equal(got, secrets[key]) {
					t.Fatalf("Load %v = %d bytes, %v; another account's value changed", key, len(got), err)
				}
			}
		})
	}
}

// crashRun runs fn, which must die with crashed, and clears the hooks so the
// "restarted" process behaves normally.
func crashRun(t *testing.T, f *fakeCredMan, fn func()) {
	t.Helper()
	defer func() {
		f.setHooks(nil, nil)
		switch r := recover().(type) {
		case nil:
			t.Fatal("expected the simulated crash, but the operation returned")
		case crashed:
		default:
			panic(r)
		}
	}()
	fn()
}

// countMutations runs fn and returns how many writes and deletes it made.
func countMutations(f *fakeCredMan, fn func()) int {
	f.resetCalls()
	fn()
	n := 0
	for _, call := range f.calls() {
		if isMutationCall(call) {
			n++
		}
	}
	return n
}

func TestChunkedTornSave(t *testing.T) {
	oldValue := patterned(2*chunkSize+1, 1)
	newValue := patterned(3*chunkSize+5, 2)
	// The new Save writes 4 chunks (mutations 1..4), the manifest (5), then
	// sweeps the 3 old chunks (6..8) when there was an old value.
	const manifestStep = 5

	for _, withOld := range []bool{true, false} {
		name := "first save"
		total := manifestStep
		if withOld {
			name, total = "over an old value", manifestStep+3
		}
		t.Run(name, func(t *testing.T) {
			setup := func(t *testing.T) (*fakeCredMan, *chunkedStore) {
				f, s := newChunked(t, MaxSecretBytesLimit)
				if withOld {
					chunkedSave(t, s, oldValue)
				}
				return f, s
			}
			f, s := setup(t)
			if got := countMutations(f, func() { chunkedSave(t, s, newValue) }); got != total {
				t.Fatalf("a Save makes %d mutations, want %d", got, total)
			}

			for k := 1; k <= total; k++ {
				t.Run("crash after mutation "+strconv.Itoa(k), func(t *testing.T) {
					f, s := setup(t)
					f.crashAfterMutations(k)
					crashRun(t, f, func() { _ = s.Save(t.Context(), chunkedKey, newValue) })

					restarted := newChunkedStore(f, MaxSecretBytesLimit)
					restarted.random = &countReader{n: 100}
					got, err := restarted.Load(t.Context(), chunkedKey)
					switch {
					case k >= manifestStep:
						if err != nil || !bytes.Equal(got, newValue) {
							t.Fatalf("after the manifest write Load = %d bytes, %v, want the new value", len(got), err)
						}
					case withOld:
						if err != nil || !bytes.Equal(got, oldValue) {
							t.Fatalf("before the manifest write Load = %d bytes, %v, want the old value", len(got), err)
						}
					default:
						wantCredError(t, err, "load", KindNotFound, win32NotFound)
					}
					// A later Save leaves exactly one generation.
					third := []byte("after the crash")
					if err := restarted.Save(t.Context(), chunkedKey, third); err != nil {
						t.Fatalf("Save after the crash: %v", err)
					}
					wantTargets(t, f, chunkedKey, map[string]int{genN(101): 1})
					chunkedLoad(t, restarted, third)
				})

				t.Run("failure of mutation "+strconv.Itoa(k), func(t *testing.T) {
					f, s := setup(t)
					before := f.targets()
					f.failMutation(k, &win32Error{code: 5})
					err := s.Save(t.Context(), chunkedKey, newValue)
					if k > manifestStep {
						// The manifest is written, so the Save succeeded; only the
						// best-effort sweep of an old chunk failed.
						if err != nil {
							t.Fatalf("Save = %v, want success once the manifest is written", err)
						}
						f.setHooks(nil, nil)
						chunkedLoad(t, s, newValue)
						// The chunk the sweep could not remove is garbage that the
						// next Save removes.
						next := []byte("the next value")
						if err := s.Save(t.Context(), chunkedKey, next); err != nil {
							t.Fatalf("next Save: %v", err)
						}
						chunkedLoad(t, s, next)
						if got := len(f.targets()); got != 2 {
							t.Fatalf("after the next Save %d credentials are stored (%q), want the manifest and one chunk", got, f.targets())
						}
						// So does a Delete, when no Save follows.
						f, s := setup(t)
						f.failMutation(k, &win32Error{code: 5})
						if err := s.Save(t.Context(), chunkedKey, newValue); err != nil {
							t.Fatalf("Save: %v", err)
						}
						f.setHooks(nil, nil)
						if err := s.Delete(t.Context(), chunkedKey); err != nil {
							t.Fatalf("Delete: %v", err)
						}
						if got := f.targets(); len(got) != 0 {
							t.Fatalf("after Delete %q remain, want nothing", got)
						}
						return
					}
					wantCredError(t, err, "save", KindOther, 5)
					got, loadErr := s.Load(t.Context(), chunkedKey)
					switch {
					case withOld:
						if loadErr != nil || !bytes.Equal(got, oldValue) {
							t.Fatalf("Load = %d bytes, %v, want the old value", len(got), loadErr)
						}
					default:
						wantCredError(t, loadErr, "load", KindNotFound, win32NotFound)
					}
					if !slices.Equal(f.targets(), before) {
						t.Fatalf("a failed Save left %q, want %q", f.targets(), before)
					}
				})
			}
		})
	}
}

func TestChunkedTornDelete(t *testing.T) {
	value := patterned(2*chunkSize+1, 1)
	// A Delete removes the manifest (1) and then 3 chunks (2..4).
	for k := 1; k <= 4; k++ {
		t.Run("crash after mutation "+strconv.Itoa(k), func(t *testing.T) {
			f, s := newChunked(t, MaxSecretBytesLimit)
			chunkedSave(t, s, value)
			f.crashAfterMutations(k)
			crashRun(t, f, func() { _ = s.Delete(t.Context(), chunkedKey) })

			restarted := newChunkedStore(f, MaxSecretBytesLimit)
			restarted.random = &countReader{n: 100}
			_, err := restarted.Load(t.Context(), chunkedKey)
			wantCredError(t, err, "load", KindNotFound, win32NotFound)
			if ok, err := restarted.Exists(t.Context(), chunkedKey); err != nil || ok {
				t.Fatalf("Exists = %v, %v, want false", ok, err)
			}
			if err := restarted.Delete(t.Context(), chunkedKey); err != nil {
				t.Fatalf("Delete after the crash: %v", err)
			}
			if got := f.targets(); len(got) != 0 {
				t.Fatalf("Delete after the crash left %q", got)
			}
		})
	}

	t.Run("a manifest that cannot be removed leaves the value", func(t *testing.T) {
		f, s := newChunked(t, MaxSecretBytesLimit)
		chunkedSave(t, s, value)
		f.failMutation(1, &win32Error{code: 5})
		wantCredError(t, s.Delete(t.Context(), chunkedKey), "delete", KindOther, 5)
		chunkedLoad(t, s, value)
	})
	t.Run("a chunk that cannot be removed is reported and the rest are removed", func(t *testing.T) {
		f, s := newChunked(t, MaxSecretBytesLimit)
		chunkedSave(t, s, value)
		f.failMutation(2, &win32Error{code: 5})
		wantCredError(t, s.Delete(t.Context(), chunkedKey), "delete", KindOther, 5)
		if got := f.targets(); len(got) != 1 {
			t.Fatalf("left %q, want the single chunk that failed", got)
		}
	})
}

func TestChunkedConcurrentInterleavings(t *testing.T) {
	first := patterned(3*chunkSize, 1)
	second := patterned(2*chunkSize+9, 2)
	third := patterned(chunkSize+1, 3)

	t.Run("a Save between the manifest read and the chunk reads is retried", func(t *testing.T) {
		f, s := newChunked(t, MaxSecretBytesLimit)
		chunkedSave(t, s, first)
		var once sync.Once
		f.setHooks(nil, func(c credCall) {
			if c.kind() == "read manifest" {
				once.Do(func() {
					if err := s.Save(context.Background(), chunkedKey, second); err != nil {
						t.Errorf("interleaved Save: %v", err)
					}
				})
			}
		})
		chunkedLoad(t, s, second)
	})

	t.Run("a second change during the retry is corrupt", func(t *testing.T) {
		f, s := newChunked(t, MaxSecretBytesLimit)
		chunkedSave(t, s, first)
		manifestReads := 0
		f.setHooks(nil, func(c credCall) {
			if c.kind() != "read manifest" {
				return
			}
			manifestReads++
			next := map[int][]byte{1: second, 2: third}[manifestReads]
			if next == nil {
				return
			}
			if err := s.Save(context.Background(), chunkedKey, next); err != nil {
				t.Errorf("interleaved Save: %v", err)
			}
		})
		_, err := s.Load(t.Context(), chunkedKey)
		wantCredError(t, err, "load", KindCorrupt, 0)
		if manifestReads != 2 {
			t.Fatalf("manifest read %d times, want 2", manifestReads)
		}
	})

	t.Run("a Delete between the manifest read and the chunk reads is not found", func(t *testing.T) {
		f, s := newChunked(t, MaxSecretBytesLimit)
		chunkedSave(t, s, first)
		var once sync.Once
		f.setHooks(nil, func(c credCall) {
			if c.kind() == "read manifest" {
				once.Do(func() {
					if err := s.Delete(context.Background(), chunkedKey); err != nil {
						t.Errorf("interleaved Delete: %v", err)
					}
				})
			}
		})
		_, err := s.Load(t.Context(), chunkedKey)
		wantCredError(t, err, "load", KindNotFound, win32NotFound)
	})

	t.Run("a Save part way through the chunk reads is retried", func(t *testing.T) {
		f, s := newChunked(t, MaxSecretBytesLimit)
		chunkedSave(t, s, first)
		chunkReads := 0
		f.setHooks(nil, func(c credCall) {
			if c.kind() != "read chunk" {
				return
			}
			chunkReads++
			if chunkReads == 2 {
				if err := s.Save(context.Background(), chunkedKey, second); err != nil {
					t.Errorf("interleaved Save: %v", err)
				}
			}
		})
		chunkedLoad(t, s, second)
	})

	t.Run("loads racing a writer return a whole value or corrupt", func(t *testing.T) {
		_, s := newChunked(t, MaxSecretBytesLimit)
		values := [][]byte{first, second}
		chunkedSave(t, s, values[0])
		const saves = 150
		var wg sync.WaitGroup
		done := make(chan struct{})
		wg.Go(func() {
			defer close(done)
			for i := 0; i < saves; i++ {
				if err := s.Save(context.Background(), chunkedKey, values[(i+1)%2]); err != nil {
					t.Errorf("Save: %v", err)
					return
				}
			}
		})
		var mu sync.Mutex
		loaded := 0
		for r := 0; r < 4; r++ {
			wg.Go(func() {
				for {
					got, err := s.Load(context.Background(), chunkedKey)
					switch {
					case err == nil:
						if !bytes.Equal(got, values[0]) && !bytes.Equal(got, values[1]) {
							t.Errorf("Load returned %d bytes that are neither value", len(got))
							return
						}
						mu.Lock()
						loaded++
						mu.Unlock()
					case !errors.Is(err, ErrCorrupt):
						t.Errorf("Load: %v, want a value or ErrCorrupt", err)
						return
					}
					select {
					case <-done:
						return
					default:
					}
				}
			})
		}
		wg.Wait()
		if loaded == 0 {
			t.Fatal("no Load succeeded while the writer ran")
		}
	})
}

func TestChunkedErrorMapping(t *testing.T) {
	ops := []struct {
		name string
		run  func(s *chunkedStore) error
	}{
		{"exists", func(s *chunkedStore) error { _, err := s.Exists(context.Background(), chunkedKey); return err }},
		{"load", func(s *chunkedStore) error { _, err := s.Load(context.Background(), chunkedKey); return err }},
		{"save", func(s *chunkedStore) error { return s.Save(context.Background(), chunkedKey, []byte("v")) }},
		{"delete", func(s *chunkedStore) error { return s.Delete(context.Background(), chunkedKey) }},
	}
	for _, tt := range []struct {
		name   string
		err    error
		kind   Kind
		status int64
	}{
		{"not found", &win32Error{code: 1168}, KindNotFound, 1168},
		{"no such logon session", &win32Error{code: 1312}, KindUnavailable, 1312},
		{"access denied", &win32Error{code: 5}, KindOther, 5},
		{"busy", &win32Error{code: 170}, KindOther, 170},
		{"wrapped", fmt.Errorf("syscall: %w", &win32Error{code: 5}), KindOther, 5},
		{"not a win32 error", errors.New("boom svc.test profile"), KindOther, 0},
	} {
		for _, op := range ops {
			t.Run(tt.name+" in "+op.name, func(t *testing.T) {
				// Every call fails, so each operation fails at its first call.
				// Exists, Delete and Save treat not-found as ordinary, and
				// are checked only for the other kinds.
				f, s := newChunked(t, MaxSecretBytesLimit)
				f.setHooks(func(credCall) error { return tt.err }, nil)
				err := op.run(s)
				if tt.kind == KindNotFound && op.name != "load" {
					switch op.name {
					case "exists":
						if err != nil {
							t.Fatalf("Exists with a not-found manifest: %v", err)
						}
					case "delete":
						// The enumeration that follows fails the same way.
						if err != nil {
							t.Fatalf("Delete of a missing value: %v", err)
						}
					case "save":
						// A write creates the credential, so a not-found from it is
						// an unexpected failure, never "the value is absent".
						wantCredError(t, err, "save", KindOther, 1168)
						if errors.Is(err, ErrNotFound) {
							t.Fatalf("Save = %v, must not match ErrNotFound", err)
						}
					}
					return
				}
				wantCredError(t, err, op.name, tt.kind, tt.status)
			})
		}
	}

	t.Run("context errors keep their cause", func(t *testing.T) {
		f, s := newChunked(t, MaxSecretBytesLimit)
		f.setHooks(func(credCall) error { return context.DeadlineExceeded }, nil)
		_, err := s.Load(context.Background(), chunkedKey)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Load = %v, want the deadline error", err)
		}
	})
}

// TestChunkedWriteNotFoundIsNotAbsence: a not-found from the chunk write or from
// the manifest write is KindOther, and the Save cleans up after itself.
func TestChunkedWriteNotFoundIsNotAbsence(t *testing.T) {
	value := patterned(2*chunkSize+1, 1)
	// Three chunks (1..3), then the manifest (4).
	for _, k := range []int{1, 3, 4} {
		t.Run("mutation "+strconv.Itoa(k), func(t *testing.T) {
			f, s := newChunked(t, MaxSecretBytesLimit)
			f.failMutation(k, &win32Error{code: win32NotFound})
			err := s.Save(t.Context(), chunkedKey, value)
			wantCredError(t, err, "save", KindOther, win32NotFound)
			if errors.Is(err, ErrNotFound) {
				t.Fatalf("Save = %v, must not match ErrNotFound", err)
			}
			if got := f.targets(); len(got) != 0 {
				t.Fatalf("a failed Save left %q", got)
			}
		})
	}
}

func TestChunkedContext(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	f, s := newChunked(t, MaxSecretBytesLimit)
	if _, err := s.Exists(canceled, chunkedKey); !errors.Is(err, context.Canceled) {
		t.Fatalf("Exists = %v", err)
	}
	if _, err := s.Load(canceled, chunkedKey); !errors.Is(err, context.Canceled) {
		t.Fatalf("Load = %v", err)
	}
	if err := s.Save(canceled, chunkedKey, []byte("v")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Save = %v", err)
	}
	if err := s.Delete(canceled, chunkedKey); !errors.Is(err, context.Canceled) {
		t.Fatalf("Delete = %v", err)
	}
	if calls := f.calls(); len(calls) != 0 {
		t.Fatalf("a canceled context reached the store: %v", calls)
	}

	t.Run("canceled before the manifest keeps the old value and removes the new chunks", func(t *testing.T) {
		f, s := newChunked(t, MaxSecretBytesLimit)
		old := patterned(chunkSize+1, 1)
		chunkedSave(t, s, old)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		writes := 0
		f.setHooks(nil, func(c credCall) {
			if c.kind() == "write chunk" {
				if writes++; writes == 2 {
					cancel()
				}
			}
		})
		err := s.Save(ctx, chunkedKey, patterned(4*chunkSize, 2))
		f.setHooks(nil, nil)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Save = %v, want context.Canceled", err)
		}
		chunkedLoad(t, s, old)
		wantTargets(t, f, chunkedKey, map[string]int{genN(1): 2})
	})

	t.Run("canceled after the manifest still finishes the sweep", func(t *testing.T) {
		f, s := newChunked(t, MaxSecretBytesLimit)
		chunkedSave(t, s, patterned(3*chunkSize, 1))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		f.setHooks(nil, func(c credCall) {
			if c.kind() == "write manifest" {
				cancel()
			}
		})
		next := patterned(chunkSize+1, 2)
		if err := s.Save(ctx, chunkedKey, next); err != nil {
			t.Fatalf("Save: %v", err)
		}
		f.setHooks(nil, nil)
		wantTargets(t, f, chunkedKey, map[string]int{genN(2): 2})
		chunkedLoad(t, s, next)
	})
}

func TestChunkedInvalidKey(t *testing.T) {
	f, s := newChunked(t, MaxSecretBytesLimit)
	bad := Key{Service: "bad service", Account: "x"}
	if _, err := s.Exists(t.Context(), bad); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Exists = %v", err)
	}
	if _, err := s.Load(t.Context(), bad); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Load = %v", err)
	}
	if err := s.Save(t.Context(), bad, []byte("v")); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Save = %v", err)
	}
	if err := s.Delete(t.Context(), bad); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Delete = %v", err)
	}
	if calls := f.calls(); len(calls) != 0 {
		t.Fatalf("an invalid key reached the store: %v", calls)
	}
}

func TestChunkedZeroesWhatItReads(t *testing.T) {
	f, s := newChunked(t, MaxSecretBytesLimit)
	secret := patterned(3*chunkSize, 1)
	chunkedSave(t, s, secret)
	chunkedLoad(t, s, secret)
	if _, err := s.Exists(t.Context(), chunkedKey); err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if n := f.unzeroedReads(); n != 0 {
		t.Fatalf("%d blobs returned by the store were not zeroed", n)
	}
	// A damaged value releases what it read too.
	prefix := manifestTarget(chunkedKey)
	f.put(chunkTarget(prefix, genN(1), 2), []byte("short"))
	if _, err := s.Load(t.Context(), chunkedKey); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Load = %v, want ErrCorrupt", err)
	}
	if n := f.unzeroedReads(); n != 0 {
		t.Fatalf("%d blobs were not zeroed after a failed Load", n)
	}
}
