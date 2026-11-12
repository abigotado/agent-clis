package secretstore

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
)

// fakeCredMan is a credAPI over a map that behaves like Credential Manager in
// the two ways the format depends on: target names match case-insensitively,
// and '*' in an enumerate filter matches any run of characters. It also
// refuses what the real service refuses (a blob over 2560 bytes, an empty
// target). Hooks run around every primitive without the lock held, so a test
// can fail a call, simulate a crash with a panic, or run another operation at
// exactly that point.
type fakeCredMan struct {
	mu    sync.Mutex
	items map[string]*fakeCred // keyed by the lower-cased target
	log   []credCall
	// before may return an error, which the primitive then returns without
	// touching the store.
	before func(call credCall) error
	// after runs once a primitive has taken effect.
	after func(call credCall)
	// issued holds every blob returned by read, to check they are zeroed.
	issued [][]byte
}

type fakeCred struct {
	target string
	user   string
	blob   []byte
}

// credCall describes one primitive call.
type credCall struct {
	op     string // read, write, delete or enumerate
	target string // the target, or the filter for enumerate
}

// kind labels the call as manifest or chunk for readable hook conditions.
func (c credCall) kind() string {
	if c.op == "enumerate" {
		return "enumerate"
	}
	if strings.Contains(c.target, "#") {
		return c.op + " chunk"
	}
	return c.op + " manifest"
}

func newFakeCredMan() *fakeCredMan {
	return &fakeCredMan{items: make(map[string]*fakeCred)}
}

func (f *fakeCredMan) enter(ctx context.Context, op, target string) (credCall, error) {
	call := credCall{op: op, target: target}
	f.mu.Lock()
	f.log = append(f.log, call)
	before := f.before
	f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return call, err
	}
	if before != nil {
		return call, before(call)
	}
	return call, nil
}

func (f *fakeCredMan) leave(call credCall) {
	f.mu.Lock()
	after := f.after
	f.mu.Unlock()
	if after != nil {
		after(call)
	}
}

func (f *fakeCredMan) read(ctx context.Context, target string, limit int) ([]byte, error) {
	call, err := f.enter(ctx, "read", target)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	item, ok := f.items[strings.ToLower(target)]
	var out []byte
	if ok && len(item.blob) <= limit {
		out = bytes.Clone(item.blob)
		f.issued = append(f.issued, out)
	}
	f.mu.Unlock()
	f.leave(call)
	switch {
	case !ok:
		return nil, &win32Error{code: win32NotFound}
	case out == nil:
		return nil, errBlobTooLarge
	}
	return out, nil
}

func (f *fakeCredMan) write(ctx context.Context, target, user string, blob []byte) error {
	call, err := f.enter(ctx, "write", target)
	if err != nil {
		return err
	}
	if target == "" || len(target) > 32767 || len(blob) > chunkSize {
		return &win32Error{code: 87}
	}
	f.mu.Lock()
	f.items[strings.ToLower(target)] = &fakeCred{target: target, user: user, blob: bytes.Clone(blob)}
	f.mu.Unlock()
	f.leave(call)
	return nil
}

func (f *fakeCredMan) delete(ctx context.Context, target string) error {
	call, err := f.enter(ctx, "delete", target)
	if err != nil {
		return err
	}
	f.mu.Lock()
	_, ok := f.items[strings.ToLower(target)]
	delete(f.items, strings.ToLower(target))
	f.mu.Unlock()
	f.leave(call)
	if !ok {
		return &win32Error{code: win32NotFound}
	}
	return nil
}

func (f *fakeCredMan) enumerate(ctx context.Context, filter string) ([]string, error) {
	call, err := f.enter(ctx, "enumerate", filter)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	var out []string
	for _, item := range f.items {
		if globMatch(strings.ToLower(filter), strings.ToLower(item.target)) {
			out = append(out, item.target)
		}
	}
	f.mu.Unlock()
	slices.Sort(out)
	f.leave(call)
	return out, nil
}

// globMatch reports whether name matches pattern, where '*' matches any run
// of characters, including none, and every other character is literal.
func globMatch(pattern, name string) bool {
	star := strings.IndexByte(pattern, '*')
	if star < 0 {
		return pattern == name
	}
	head := pattern[:star]
	if !strings.HasPrefix(name, head) {
		return false
	}
	rest := pattern[star+1:]
	name = name[len(head):]
	for i := 0; i <= len(name); i++ {
		if globMatch(rest, name[i:]) {
			return true
		}
	}
	return false
}

// put stores a credential directly, as another program or an older run would.
func (f *fakeCredMan) put(target string, blob []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items[strings.ToLower(target)] = &fakeCred{target: target, user: "foreign", blob: bytes.Clone(blob)}
}

// remove deletes a credential directly, as another program would.
func (f *fakeCredMan) remove(target string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.items, strings.ToLower(target))
}

// get returns the stored blob and the exact target spelling it was written under.
func (f *fakeCredMan) get(target string) (blob []byte, spelled string, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	item, ok := f.items[strings.ToLower(target)]
	if !ok {
		return nil, "", false
	}
	return bytes.Clone(item.blob), item.target, true
}

// targets returns every stored target name, sorted.
func (f *fakeCredMan) targets() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.items))
	for _, item := range f.items {
		out = append(out, item.target)
	}
	slices.Sort(out)
	return out
}

func (f *fakeCredMan) calls() []credCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.log)
}

func (f *fakeCredMan) resetCalls() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = nil
}

func (f *fakeCredMan) setHooks(before func(credCall) error, after func(credCall)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.before, f.after = before, after
}

// unzeroedReads counts blobs returned by read that still hold data.
func (f *fakeCredMan) unzeroedReads() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, blob := range f.issued {
		if slices.ContainsFunc(blob, func(b byte) bool { return b != 0 }) {
			n++
		}
	}
	return n
}

func isMutationCall(c credCall) bool {
	return c.op == "write" || c.op == "delete"
}

// crashAfterMutations makes the process "die" right after the n-th write or
// delete takes effect.
func (f *fakeCredMan) crashAfterMutations(n int) {
	count := 0
	f.setHooks(nil, func(c credCall) {
		if !isMutationCall(c) {
			return
		}
		count++
		if count == n {
			panic(crashed{})
		}
	})
}

// failMutation makes the n-th write or delete fail without taking effect.
func (f *fakeCredMan) failMutation(n int, err error) {
	count := 0
	f.setHooks(func(c credCall) error {
		if !isMutationCall(c) {
			return nil
		}
		count++
		if count == n {
			return err
		}
		return nil
	}, nil)
}

// countReader is a deterministic generation source: the k-th Read fills the
// buffer with the byte k, so the k-th Save has the generation "0k" repeated.
type countReader struct {
	mu sync.Mutex
	n  byte
}

func (r *countReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.n++
	for i := range p {
		p[i] = r.n
	}
	return len(p), nil
}

// genN is the generation of the n-th Save of a store using a countReader.
func genN(n int) string {
	return strings.Repeat(fmt.Sprintf("%02x", n), genBytes)
}
