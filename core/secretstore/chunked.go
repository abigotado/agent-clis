package secretstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
)

// This file holds the on-store format of the Windows backend. It is untagged
// and talks to Credential Manager only through credAPI, so the format, the
// crash windows and the error mapping are testable on any platform.
//
// Credential Manager limits one blob to 2560 bytes, so a secret is stored as a
// manifest plus numbered chunks, and every value uses that shape, even a
// short one. Target names, with encS and encA the encoded Service and Account:
//
//	manifest  <encS>/<encA>                  JSON, see manifest
//	chunk i   <encS>/<encA>#<gen>.<i>        up to 2560 bytes of the secret
//
// encode keeps bytes in [a-z0-9._-] and writes every other byte as %XX with
// upper-case hex. Credential Manager matches targets case-insensitively and
// treats '*' as a wildcard when enumerating, so the encoding has to produce
// only lower-case literal letters and no wildcard, which makes it injective
// under case-insensitive comparison and leaves a prefix filter that can match
// nothing but one key's own names.
//
// Save writes the chunks of a fresh generation, then the manifest that names
// it, then removes the other generations of that key. Until the manifest is
// written the previous value is untouched, and an interrupted Save leaves only
// unreferenced chunks that the next Save or Delete of that key removes.

const (
	// chunkSize is the largest blob Credential Manager stores
	// (CRED_MAX_CREDENTIAL_BLOB_SIZE).
	chunkSize = 2560
	// maxChunks is the most chunks a value can have: ceil(128 KiB / 2560).
	maxChunks = 52
	// manifestVersion is the only manifest version this code reads or writes.
	manifestVersion = 1
	// manifestMaxBytes bounds the manifest blob read before it is parsed; a
	// real manifest is about 130 bytes.
	manifestMaxBytes = 512
	// genBytes is the random generation identifier size, 128 bits.
	genBytes = 16
)

// maxChunks chunks must hold MaxSecretBytesLimit, and one fewer must not.
var (
	_ [maxChunks*chunkSize - MaxSecretBytesLimit]struct{}
	_ [MaxSecretBytesLimit - (maxChunks-1)*chunkSize - 1]struct{}
)

// The Win32 error codes the mapping below depends on.
const (
	win32NotFound           int64 = 1168 // ERROR_NOT_FOUND
	win32NoSuchLogonSession int64 = 1312 // ERROR_NO_SUCH_LOGON_SESSION
)

const (
	credentialBackend       = "credman"
	manifestTargetSeparator = "/"
	chunkTargetSeparator    = "#"
)

// win32Error is what credAPI returns for a failed Win32 call. It never reaches
// a caller: the store classifies it into an *Error.
type win32Error struct {
	code int64
}

func (e *win32Error) Error() string {
	return "secretstore: win32 error " + strconv.FormatInt(e.code, 10)
}

// errBlobTooLarge is what credAPI.read returns for a blob longer than max,
// before the blob is copied.
var errBlobTooLarge = errors.New("secretstore: stored blob exceeds the bound")

// errTooManyEnumerated is what credAPI.enumerate returns when more credentials
// match than one enumeration may return. A partial list would let a sweep
// report success while chunks remain, so it is an error, never a truncation.
var errTooManyEnumerated = errors.New("secretstore: enumeration exceeds the bound")

// maxEnumerated bounds the credentials one enumeration is read from. A key
// owns at most a few generations of 52 chunks, so only a program filling the
// prefix with junk can exceed it.
const maxEnumerated = 1 << 12

// checkEnumerated returns errTooManyEnumerated when count credentials are more
// than one enumeration may return.
func checkEnumerated(count int) error {
	if count > maxEnumerated {
		return errTooManyEnumerated
	}
	return nil
}

// credAPI is the set of Credential Manager primitives the format needs. A
// target is a generic credential's TargetName and the lookup is
// case-insensitive, as in the real service.
type credAPI interface {
	// read returns a copy of the blob. A missing credential is a win32Error
	// with win32NotFound; a blob longer than max is errBlobTooLarge.
	read(ctx context.Context, target string, max int) ([]byte, error)
	// write creates or replaces the credential. userName is stored in
	// UserName. The blob is at most chunkSize bytes and is not retained.
	write(ctx context.Context, target, userName string, blob []byte) error
	// delete removes the credential. A missing one is a win32Error with
	// win32NotFound.
	delete(ctx context.Context, target string) error
	// enumerate returns the stored target names that match filter, a name
	// prefix followed by one '*'. No match is an empty result, not an error,
	// and more than maxEnumerated matches is errTooManyEnumerated, never a
	// truncated list.
	enumerate(ctx context.Context, filter string) ([]string, error)
}

const upperHex = "0123456789ABCDEF"

// encodeTarget writes s so that it uses only lower-case literals and %XX.
func encodeTarget(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(upperHex[c>>4])
		b.WriteByte(upperHex[c&0x0f])
	}
	return b.String()
}

// manifestTarget is the manifest's target name, which is also the prefix of
// every chunk name of the key.
func manifestTarget(key Key) string {
	return encodeTarget(key.Service) + manifestTargetSeparator + encodeTarget(key.Account)
}

func chunkTarget(prefix, gen string, i int) string {
	return prefix + chunkTargetSeparator + gen + "." + strconv.Itoa(i)
}

func chunkFilter(prefix string) string {
	return prefix + chunkTargetSeparator + "*"
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ownChunk reports whether target is exactly prefix + "#" + 32 lower-case hex
// + "." + a canonical decimal 0..51, and returns the generation. Any other
// name under the prefix is not ours to touch.
func ownChunk(prefix, target string) (gen string, ok bool) {
	rest, found := strings.CutPrefix(target, prefix+chunkTargetSeparator)
	if !found {
		return "", false
	}
	gen, index, found := strings.Cut(rest, ".")
	if !found || len(gen) != 2*genBytes || !isLowerHex(gen) {
		return "", false
	}
	if index == "" || len(index) > 2 || (len(index) == 2 && index[0] == '0') {
		return "", false
	}
	n := 0
	for i := 0; i < len(index); i++ {
		if index[i] < '0' || index[i] > '9' {
			return "", false
		}
		n = n*10 + int(index[i]-'0')
	}
	if n >= maxChunks {
		return "", false
	}
	return gen, true
}

// manifest is the blob stored under the key's own name. Its field order and
// names are the on-store contract.
type manifest struct {
	V      int    `json:"v"`
	Gen    string `json:"gen"`
	N      int    `json:"n"`
	SHA256 string `json:"sha256"`
}

// parseManifest decodes and validates a manifest. Anything unexpected,
// including a future version, an unknown field or trailing data, is an error.
func parseManifest(blob []byte) (manifest, error) {
	var m manifest
	dec := json.NewDecoder(bytes.NewReader(blob))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return manifest{}, errors.New("secretstore: malformed manifest")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return manifest{}, errors.New("secretstore: malformed manifest")
	}
	if m.V != manifestVersion || len(m.Gen) != 2*genBytes || !isLowerHex(m.Gen) ||
		m.N < 1 || m.N > maxChunks || len(m.SHA256) != 2*sha256.Size || !isLowerHex(m.SHA256) {
		return manifest{}, errors.New("secretstore: malformed manifest")
	}
	return m, nil
}

// chunkedStore implements Store over a credAPI.
type chunkedStore struct {
	api credAPI
	max int
	// random is the source of generation identifiers.
	random io.Reader
}

var _ Store = (*chunkedStore)(nil)

func newChunkedStore(api credAPI, maxSecretBytes int) *chunkedStore {
	return &chunkedStore{api: api, max: min(maxSecretBytes, MaxSecretBytesLimit), random: rand.Reader}
}

func (s *chunkedStore) fail(op string, kind Kind, status int64) *Error {
	return &Error{Op: op, Backend: credentialBackend, Kind: kind, Status: status}
}

// failure classifies an error from a credAPI primitive.
func (s *chunkedStore) failure(op string, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return contextError(op, err)
	}
	if errors.Is(err, errTooManyEnumerated) {
		e := s.fail(op, KindOther, 0)
		e.Reason = ReasonTooManyMatches
		return e
	}
	var we *win32Error
	if !errors.As(err, &we) {
		return s.fail(op, KindOther, 0)
	}
	switch we.code {
	case win32NotFound:
		return s.fail(op, KindNotFound, we.code)
	case win32NoSuchLogonSession:
		return s.fail(op, KindUnavailable, we.code)
	default:
		return s.fail(op, KindOther, we.code)
	}
}

// writeFailure classifies an error from a credAPI write. A write creates or
// replaces a credential, so it cannot meaningfully report a missing one; if the
// system does, that is an unexpected failure and not "the value is absent",
// which a caller of Save must never read as ErrNotFound.
func (s *chunkedStore) writeFailure(op string, err error) error {
	if isCredNotFound(err) {
		return s.fail(op, KindOther, win32NotFound)
	}
	return s.failure(op, err)
}

func isCredNotFound(err error) bool {
	var we *win32Error
	return errors.As(err, &we) && we.code == win32NotFound
}

// begin runs the checks every operation performs before the store is touched.
func (s *chunkedStore) begin(ctx context.Context, op string, key Key) error {
	if err := ctx.Err(); err != nil {
		return contextError(op, err)
	}
	return validateKey(op, credentialBackend, key)
}

// readManifest reads and parses the manifest. A missing one is KindNotFound
// and an unreadable one KindCorrupt.
func (s *chunkedStore) readManifest(ctx context.Context, op, prefix string) (manifest, error) {
	blob, err := s.api.read(ctx, prefix, manifestMaxBytes)
	defer clear(blob)
	switch {
	case errors.Is(err, errBlobTooLarge):
		return manifest{}, s.fail(op, KindCorrupt, 0)
	case err != nil:
		return manifest{}, s.failure(op, err)
	}
	m, err := parseManifest(blob)
	if err != nil {
		return manifest{}, s.fail(op, KindCorrupt, 0)
	}
	return m, nil
}

// Exists implements Store. It reads the manifest only, so a value whose chunks
// are damaged still exists.
func (s *chunkedStore) Exists(ctx context.Context, key Key) (bool, error) {
	if err := s.begin(ctx, "exists", key); err != nil {
		return false, err
	}
	blob, err := s.api.read(ctx, manifestTarget(key), manifestMaxBytes)
	clear(blob)
	switch {
	case err == nil, errors.Is(err, errBlobTooLarge):
		return true, nil
	case isCredNotFound(err):
		return false, nil
	default:
		return false, s.failure("exists", err)
	}
}

// Load implements Store. A value that fails its checks is read again once if
// the manifest changed in the meantime, because a concurrent Save replaces the
// chunks a first read was using; a second failure is KindCorrupt.
func (s *chunkedStore) Load(ctx context.Context, key Key) ([]byte, error) {
	if err := s.begin(ctx, "load", key); err != nil {
		return nil, err
	}
	prefix := manifestTarget(key)
	m, err := s.readManifest(ctx, "load", prefix)
	if err != nil {
		return nil, err
	}
	for round := 0; ; round++ {
		// The shortest value with this many chunks is a lower bound that
		// needs no read.
		if (m.N-1)*chunkSize+1 > s.max {
			return nil, s.fail("load", KindTooLarge, 0)
		}
		secret, ok, err := s.readChunks(ctx, prefix, m)
		if err != nil {
			return nil, err
		}
		if ok {
			if len(secret) > s.max {
				clear(secret)
				return nil, s.fail("load", KindTooLarge, 0)
			}
			return secret, nil
		}
		if round == 1 {
			return nil, s.fail("load", KindCorrupt, 0)
		}
		next, err := s.readManifest(ctx, "load", prefix)
		if err != nil {
			return nil, err
		}
		if next.Gen == m.Gen {
			return nil, s.fail("load", KindCorrupt, 0)
		}
		m = next
	}
}

// readChunks reads the chunks m names and checks their sizes and digest. ok is
// false, with a nil error, when the stored data does not match the manifest.
func (s *chunkedStore) readChunks(ctx context.Context, prefix string, m manifest) (secret []byte, ok bool, err error) {
	// m.N is 1..maxChunks, so this allocation is bounded.
	buf := make([]byte, 0, m.N*chunkSize)
	for i := 0; i < m.N; i++ {
		if err := ctx.Err(); err != nil {
			clear(buf)
			return nil, false, contextError("load", err)
		}
		blob, err := s.api.read(ctx, chunkTarget(prefix, m.Gen, i), chunkSize)
		if err != nil {
			clear(blob)
			clear(buf)
			if isCredNotFound(err) || errors.Is(err, errBlobTooLarge) {
				return nil, false, nil
			}
			return nil, false, s.failure("load", err)
		}
		last := i == m.N-1
		full := len(blob) == chunkSize
		if !full && !(last && len(blob) > 0) {
			clear(blob)
			clear(buf)
			return nil, false, nil
		}
		buf = append(buf, blob...)
		clear(blob)
	}
	sum := sha256.Sum256(buf)
	defer clear(sum[:])
	want, decodeErr := hex.DecodeString(m.SHA256)
	if decodeErr != nil || subtle.ConstantTimeCompare(sum[:], want) != 1 {
		clear(buf)
		return nil, false, nil
	}
	return buf, true, nil
}

// ownChunks lists the chunk names of the key that parse exactly, with their
// generations. Everything else the filter matches is left out.
func (s *chunkedStore) ownChunks(ctx context.Context, op, prefix string) (names, gens []string, err error) {
	found, err := s.api.enumerate(ctx, chunkFilter(prefix))
	if err != nil {
		if isCredNotFound(err) {
			return nil, nil, nil
		}
		return nil, nil, s.failure(op, err)
	}
	for _, name := range found {
		if gen, ok := ownChunk(prefix, name); ok {
			names = append(names, name)
			gens = append(gens, gen)
		}
	}
	return names, gens, nil
}

// sweep deletes every own chunk whose generation is not keep; an empty keep
// deletes all of them. A chunk that is already gone is not a failure.
func (s *chunkedStore) sweep(ctx context.Context, op, prefix, keep string) error {
	names, gens, err := s.ownChunks(ctx, op, prefix)
	if err != nil {
		return err
	}
	var first error
	for i, name := range names {
		if keep != "" && gens[i] == keep {
			continue
		}
		if err := s.api.delete(ctx, name); err != nil && !isCredNotFound(err) && first == nil {
			first = s.failure(op, err)
		}
	}
	return first
}

// Delete implements Store. It removes the manifest first, so a delete that
// stops halfway leaves no value, only unreferenced chunks, and it removes the
// chunks also when the manifest is already gone. A manifest that cannot be
// removed leaves everything in place.
func (s *chunkedStore) Delete(ctx context.Context, key Key) error {
	if err := s.begin(ctx, "delete", key); err != nil {
		return err
	}
	prefix := manifestTarget(key)
	if err := s.api.delete(ctx, prefix); err != nil && !isCredNotFound(err) {
		return s.failure("delete", err)
	}
	// The value is gone; what remains is cleanup, which runs to its end.
	return s.sweep(context.WithoutCancel(ctx), "delete", prefix, "")
}

// Save implements Store with the sequence described at the top of the file.
// The caller serialises Save and Delete of one key: they share the key's chunk
// names and the sweep, so a Delete that overlaps a Save can remove the chunks
// the Save has just written. Once the manifest is written Save has succeeded
// and returns nil; the final sweep of the other generations is best effort,
// and a chunk it cannot remove is removed by the next Save or Delete of the
// key.
func (s *chunkedStore) Save(ctx context.Context, key Key, secret []byte) error {
	if err := s.begin(ctx, "save", key); err != nil {
		return err
	}
	if len(secret) == 0 {
		return s.fail("save", KindInvalidArgument, 0)
	}
	if len(secret) > s.max {
		return s.fail("save", KindTooLarge, 0)
	}
	var genRaw [genBytes]byte
	if _, err := io.ReadFull(s.random, genRaw[:]); err != nil {
		return s.fail("save", KindOther, 0)
	}
	gen := hex.EncodeToString(genRaw[:])
	prefix := manifestTarget(key)

	n := (len(secret) + chunkSize - 1) / chunkSize
	var written []string
	for i := 0; i < n; i++ {
		if err := ctx.Err(); err != nil {
			s.discard(ctx, written)
			return contextError("save", err)
		}
		name := chunkTarget(prefix, gen, i)
		if err := s.api.write(ctx, name, key.Account, secret[i*chunkSize:min((i+1)*chunkSize, len(secret))]); err != nil {
			s.discard(ctx, written)
			return s.writeFailure("save", err)
		}
		written = append(written, name)
	}
	if err := ctx.Err(); err != nil {
		s.discard(ctx, written)
		return contextError("save", err)
	}

	sum := sha256.Sum256(secret)
	blob, err := json.Marshal(manifest{V: manifestVersion, Gen: gen, N: n, SHA256: hex.EncodeToString(sum[:])})
	clear(sum[:])
	if err != nil {
		s.discard(ctx, written)
		return s.fail("save", KindOther, 0)
	}
	if err := s.api.write(ctx, prefix, key.Account, blob); err != nil {
		s.discard(ctx, written)
		return s.writeFailure("save", err)
	}

	// The manifest names the new generation, so the new value is stored and the
	// old chunks are garbage. The sweep runs to its end, but its failure is not
	// the Save's: reporting it would tell the caller to retry a Save that
	// worked, and an unreferenced chunk is harmless until the next Save or
	// Delete of the key removes it.
	//
	// Best effort: the error is deliberately dropped for the reason above.
	_ = s.sweep(context.WithoutCancel(ctx), "save", prefix, gen)
	return nil
}

// discard removes chunks of a Save that did not reach its manifest.
func (s *chunkedStore) discard(ctx context.Context, names []string) {
	ctx = context.WithoutCancel(ctx)
	for _, name := range names {
		// Best effort: an unreferenced chunk that stays is removed by the next
		// Save or Delete of the key, and the failure that led here is what
		// the caller needs to see.
		_ = s.api.delete(ctx, name)
	}
}
