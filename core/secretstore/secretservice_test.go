package secretstore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/big"
	"slices"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
)

var ssKey = Key{Service: "svc.test", Account: "alice"}

const ssMax = 1024

func newSSStore(f *fakeSS, mode Interaction) *secretServiceStore {
	return newSecretServiceStore(f.dialer(), Options{MaxSecretBytes: ssMax, Interaction: mode})
}

// wantSSError checks the kind and reason of err and that no provider text
// reached it.
func wantSSError(t *testing.T, err error, kind Kind, reason Reason) {
	t.Helper()
	var se *Error
	if !errors.As(err, &se) {
		t.Fatalf("err = %v, want a *Error of kind %v", err, kind)
	}
	if se.Kind != kind || se.Reason != reason || se.Backend != "secretservice" {
		t.Fatalf("err = %#v, want kind %v reason %q on the secretservice backend", se, kind, reason)
	}
	for _, text := range []string{err.Error(), se.GoString()} {
		if strings.Contains(text, "provider text") || strings.Contains(text, ssKey.Service) || strings.Contains(text, ssKey.Account) {
			t.Fatalf("error text %q leaks provider text or the key", text)
		}
	}
}

func TestParseBusAddress(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want []busEndpoint
	}{
		{"path", "unix:path=/run/user/1000/bus", []busEndpoint{{name: "/run/user/1000/bus"}}},
		{"path with guid", "unix:path=/run/user/1000/bus,guid=0123abcd", []busEndpoint{{name: "/run/user/1000/bus"}}},
		{"abstract", "unix:abstract=/tmp/dbus-x", []busEndpoint{{abstract: true, name: "/tmp/dbus-x"}}},
		{"escaped path", "unix:path=/tmp/a%20b", []busEndpoint{{name: "/tmp/a b"}}},
		{"list of unix addresses", "unix:path=/a;unix:abstract=b", []busEndpoint{{name: "/a"}, {abstract: true, name: "b"}}},
		{"empty", "", nil},
		{"tcp", "tcp:host=localhost,port=1234", nil},
		{"nonce-tcp", "nonce-tcp:host=localhost,port=1234,noncefile=/tmp/n", nil},
		{"unixexec", "unixexec:path=/bin/sh,argv1=-c", nil},
		{"autolaunch", "autolaunch:", nil},
		{"launchd", "launchd:env=DBUS_LAUNCHD_SESSION_BUS_SOCKET", nil},
		{"systemd", "systemd:", nil},
		{"no transport", "path=/run/bus", nil},
		{"unix without a socket", "unix:", nil},
		{"unix with a guid only", "unix:guid=abc", nil},
		{"unix runtime", "unix:runtime=yes", nil},
		{"unix tmpdir", "unix:tmpdir=/tmp", nil},
		{"unix dir", "unix:dir=/tmp", nil},
		{"path and abstract", "unix:path=/a,abstract=b", nil},
		{"relative path", "unix:path=bus", nil},
		{"empty path", "unix:path=", nil},
		{"bad escape", "unix:path=/a%zz", nil},
		{"NUL in path", "unix:path=/a%00b", nil},
		{"key without value", "unix:path", nil},
		{"unix then tcp", "unix:path=/a;tcp:host=h,port=1", nil},
		{"tcp then unix", "tcp:host=h,port=1;unix:path=/a", nil},
		{"trailing separator", "unix:path=/a;", nil},
		{"upper-case transport", "UNIX:path=/a", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseBusAddress(tt.addr)
			if tt.want == nil {
				if !errors.Is(err, errBusAddress) || got != nil {
					t.Fatalf("parseBusAddress(%q) = %v, %v; want errBusAddress", tt.addr, got, err)
				}
				return
			}
			if err != nil || !slices.Equal(got, tt.want) {
				t.Fatalf("parseBusAddress(%q) = %v, %v; want %v", tt.addr, got, err, tt.want)
			}
		})
	}
}

func TestOpenSecretService(t *testing.T) {
	refused := []string{
		"", "tcp:host=localhost,port=1", "unixexec:path=/bin/sh", "autolaunch:",
		"launchd:env=X", "unix:path=relative", "unix:runtime=yes", "unix:path=/a;tcp:host=h,port=1",
	}
	for _, addr := range refused {
		t.Run("refuses "+addr, func(t *testing.T) {
			dialed := false
			_, err := openSecretService(t.Context(), Options{MaxSecretBytes: ssMax}, addr,
				func(context.Context, []busEndpoint) (ssBus, error) {
					dialed = true
					return nil, errors.New("must not be reached")
				})
			var se *Error
			if !errors.Is(err, ErrUnavailable) || !errors.As(err, &se) || se.Op != "open" || se.Backend != "secretservice" {
				t.Fatalf("err = %v, want an open ErrUnavailable on the secretservice backend", err)
			}
			if dialed {
				t.Fatal("a refused address was dialed")
			}
			if addr != "" && strings.Contains(err.Error(), addr) {
				t.Fatalf("error text %q echoes the address", err.Error())
			}
		})
	}

	t.Run("probes the service before returning", func(t *testing.T) {
		f := newFakeSS()
		var got []busEndpoint
		s, err := openSecretService(t.Context(), Options{MaxSecretBytes: ssMax}, "unix:path=/run/user/1000/bus",
			func(ctx context.Context, endpoints []busEndpoint) (ssBus, error) {
				got = endpoints
				return f.dialer()(ctx)
			})
		if err != nil || s == nil {
			t.Fatalf("openSecretService = %v, %v", s, err)
		}
		if !slices.Equal(got, []busEndpoint{{name: "/run/user/1000/bus"}}) {
			t.Fatalf("dialed %v", got)
		}
		if f.dials != 1 || f.closes != 1 || len(f.calls("ReadAlias")) != 1 {
			t.Fatalf("probe made %d dials, %d closes, %d ReadAlias calls", f.dials, f.closes, len(f.calls("ReadAlias")))
		}
	})

	probeFailures := []struct {
		name   string
		setup  func(*fakeSS)
		kind   Kind
		reason Reason
	}{
		{"no service owner", func(f *fakeSS) { f.errs["ReadAlias"] = dbusError(errNameNoOwner) }, KindUnavailable, ReasonNameHasNoOwner},
		{"service unknown", func(f *fakeSS) { f.errs["ReadAlias"] = dbusError(errNameServiceUnknown) }, KindUnavailable, ReasonServiceUnknown},
		{"no default collection", func(f *fakeSS) { f.collection = noObject }, KindUnavailable, ReasonNoSuchObject},
		{"bus unreachable", func(f *fakeSS) { f.dialErr = errors.New("connect: no such file") }, KindUnavailable, ""},
	}
	for _, tt := range probeFailures {
		t.Run("probe fails: "+tt.name, func(t *testing.T) {
			f := newFakeSS()
			tt.setup(f)
			_, err := openSecretService(t.Context(), Options{MaxSecretBytes: ssMax}, "unix:path=/x",
				func(ctx context.Context, _ []busEndpoint) (ssBus, error) { return f.dialer()(ctx) })
			wantSSError(t, err, tt.kind, tt.reason)
			var se *Error
			if errors.As(err, &se) && se.Op != "open" {
				t.Fatalf("Op = %q, want open", se.Op)
			}
			if f.closes != f.dials-btoi(f.dialErr != nil) {
				t.Fatalf("%d dials but %d closes", f.dials, f.closes)
			}
		})
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// sessionModes runs a test under the DH session and under the plain one.
func sessionModes(t *testing.T, run func(t *testing.T, f *fakeSS, s *secretServiceStore, algorithm string)) {
	t.Helper()
	for _, mode := range []struct {
		name      string
		plainOnly bool
		want      string
	}{{"dh", false, dhAlgorithm}, {"plain", true, "plain"}} {
		t.Run(mode.name, func(t *testing.T) {
			f := newFakeSS()
			s := newSSStore(f, InteractionNever)
			s.plainOnly = mode.plainOnly
			run(t, f, s, mode.want)
		})
	}
}

func TestSecretServiceSaveLoad(t *testing.T) {
	sessionModes(t, func(t *testing.T, f *fakeSS, s *secretServiceStore, algorithm string) {
		var seen []string
		s.onSession = func(a string) { seen = append(seen, a) }
		secret := []byte("tok\x00en-\xff")
		if err := s.Save(t.Context(), ssKey, secret); err != nil {
			t.Fatalf("Save: %v", err)
		}
		if len(f.created) != 1 {
			t.Fatalf("CreateItem called %d times, want 1", len(f.created))
		}
		created := f.created[0]
		if !created.replace {
			t.Error("CreateItem was called with replace=false")
		}
		if created.contentTyp != "application/octet-stream" {
			t.Errorf("content type = %q", created.contentTyp)
		}
		gotAttrs := created.properties["org.freedesktop.Secret.Item.Attributes"].Value()
		wantAttrs := map[string]string{"xdg:schema": "dev.abigotado.secretstore", "service": "svc.test", "account": "alice"}
		if !mapsEqual(gotAttrs, wantAttrs) {
			t.Errorf("attributes = %v, want exactly %v", gotAttrs, wantAttrs)
		}
		if label := created.properties["org.freedesktop.Secret.Item.Label"].Value(); label != "svc.test (alice)" {
			t.Errorf("label = %v", label)
		}
		if !bytes.Equal(f.items[0].value, secret) {
			t.Error("the provider stored different bytes than were saved")
		}

		got, err := s.Load(t.Context(), ssKey)
		if err != nil || !bytes.Equal(got, secret) {
			t.Fatalf("Load = %q, %v; want %q", got, err, secret)
		}
		if !slices.Equal(seen, []string{algorithm, algorithm}) {
			t.Fatalf("session algorithms = %v, want two %q", seen, algorithm)
		}
		if f.dials != f.closes || f.dials != 2 {
			t.Fatalf("dials = %d, closes = %d, want 2 each", f.dials, f.closes)
		}
		if algorithm == dhAlgorithm && !allZero(f.lastValue) {
			t.Error("the ciphertext buffer of the reply was not zeroed")
		}
	})
}

func mapsEqual(got any, want map[string]string) bool {
	m, ok := got.(map[string]string)
	if !ok || len(m) != len(want) {
		return false
	}
	for k, v := range want {
		if m[k] != v {
			return false
		}
	}
	return true
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func TestSecretServiceExistsAndDelete(t *testing.T) {
	f := newFakeSS()
	s := newSSStore(f, InteractionNever)
	ctx := t.Context()
	if ok, err := s.Exists(ctx, ssKey); err != nil || ok {
		t.Fatalf("Exists before Save = %v, %v", ok, err)
	}
	if err := s.Delete(ctx, ssKey); err != nil {
		t.Fatalf("Delete of a missing item: %v", err)
	}
	if err := s.Save(ctx, ssKey, []byte("v")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	other := Key{Service: ssKey.Service, Account: "Alice"}
	if ok, err := s.Exists(ctx, other); err != nil || ok {
		t.Fatalf("Exists of a key differing by case = %v, %v", ok, err)
	}
	if ok, err := s.Exists(ctx, ssKey); err != nil || !ok {
		t.Fatalf("Exists after Save = %v, %v", ok, err)
	}
	// Two matching items, which the module never writes: Delete removes both.
	f.addItem(storeAttrs(ssKey), []byte("second"))
	if err := s.Delete(ctx, ssKey); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(f.items) != 0 {
		t.Fatalf("%d items left after Delete", len(f.items))
	}
}

func TestSecretServiceSaveReplacesAndRemovesDuplicates(t *testing.T) {
	for _, keep := range []bool{false, true} {
		name := "provider honours replace"
		if keep {
			name = "provider ignores replace"
		}
		t.Run(name, func(t *testing.T) {
			f := newFakeSS()
			f.keepOnCreate = keep
			s := newSSStore(f, InteractionNever)
			f.addItem(storeAttrs(ssKey), []byte("old"))
			f.addItem(storeAttrs(ssKey), []byte("older"))
			bystander := f.addItem(storeAttrs(Key{Service: ssKey.Service, Account: "bob"}), []byte("bob"))
			if err := s.Save(t.Context(), ssKey, []byte("new")); err != nil {
				t.Fatalf("Save: %v", err)
			}
			got, err := s.Load(t.Context(), ssKey)
			if err != nil || string(got) != "new" {
				t.Fatalf("Load = %q, %v; want the new value from a single item", got, err)
			}
			if len(f.items) != 2 || f.item(bystander.path) == nil {
				t.Fatalf("%d items left, want the new one and the other account's", len(f.items))
			}
		})
	}
}

func TestSecretServiceLoadErrors(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(f *fakeSS)
		kind   Kind
		reason Reason
	}{
		{"missing", func(f *fakeSS) {}, KindNotFound, ""},
		{"two matching items", func(f *fakeSS) {
			f.addItem(storeAttrs(ssKey), []byte("a"))
			f.addItem(storeAttrs(ssKey), []byte("b"))
		}, KindCorrupt, ""},
		{"empty stored value", func(f *fakeSS) { f.addItem(storeAttrs(ssKey), nil) }, KindCorrupt, ""},
		{"item vanishes before it is read", func(f *fakeSS) {
			f.addItem(storeAttrs(ssKey), []byte("a"))
			f.errs["GetSecret"] = dbusError(errNameNoSuchObject)
		}, KindNotFound, ReasonNoSuchObject},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionModes(t, func(t *testing.T, f *fakeSS, s *secretServiceStore, _ string) {
				tt.setup(f)
				got, err := s.Load(t.Context(), ssKey)
				if got != nil {
					t.Fatalf("Load returned %q with an error", got)
				}
				wantSSError(t, err, tt.kind, tt.reason)
			})
		})
	}
}

func TestSecretServiceLimits(t *testing.T) {
	t.Run("save refuses before touching the bus", func(t *testing.T) {
		tests := []struct {
			name   string
			key    Key
			secret []byte
			kind   Kind
		}{
			{"empty", ssKey, nil, KindInvalidArgument},
			{"zero length", ssKey, []byte{}, KindInvalidArgument},
			{"above the bound", ssKey, make([]byte, ssMax+1), KindTooLarge},
			{"invalid key", Key{Service: "bad/service", Account: "a"}, []byte("v"), KindInvalidArgument},
			{"invalid account", Key{Service: "svc", Account: "a#b"}, []byte("v"), KindInvalidArgument},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newFakeSS()
				err := newSSStore(f, InteractionNever).Save(t.Context(), tt.key, tt.secret)
				var se *Error
				if !errors.As(err, &se) || se.Kind != tt.kind {
					t.Fatalf("Save = %v, want kind %v", err, tt.kind)
				}
				if f.dials != 0 {
					t.Fatal("the bus was dialed before the refusal")
				}
			})
		}
	})

	t.Run("exact bound round-trips", func(t *testing.T) {
		sessionModes(t, func(t *testing.T, f *fakeSS, s *secretServiceStore, _ string) {
			secret := bytes.Repeat([]byte{0xAB}, ssMax)
			if err := s.Save(t.Context(), ssKey, secret); err != nil {
				t.Fatalf("Save at the bound: %v", err)
			}
			got, err := s.Load(t.Context(), ssKey)
			if err != nil || !bytes.Equal(got, secret) {
				t.Fatalf("Load at the bound = %d bytes, %v", len(got), err)
			}
		})
	})

	t.Run("a stored value above the bound is too large", func(t *testing.T) {
		sessionModes(t, func(t *testing.T, f *fakeSS, s *secretServiceStore, _ string) {
			f.addItem(storeAttrs(ssKey), bytes.Repeat([]byte{1}, ssMax+1))
			_, err := s.Load(t.Context(), ssKey)
			wantSSError(t, err, KindTooLarge, "")
			if !allZero(f.lastValue) && s.plainOnly {
				t.Error("the rejected value was not zeroed")
			}
		})
	})

	t.Run("ciphertext is bounded before it is decrypted", func(t *testing.T) {
		f := newFakeSS()
		s := newSSStore(f, InteractionNever)
		f.addItem(storeAttrs(ssKey), []byte("x"))
		// Garbage of a block-multiple length longer than any legal ciphertext:
		// a decrypt would report corruption, so TooLarge proves the order.
		f.tamper = func(sec *ssSecret) { sec.Value = bytes.Repeat([]byte{7}, ssMax+aesBlock+16) }
		_, err := s.Load(t.Context(), ssKey)
		wantSSError(t, err, KindTooLarge, "")
	})

	t.Run("a ciphertext of bound plus one block is accepted", func(t *testing.T) {
		f := newFakeSS()
		s := newSSStore(f, InteractionNever)
		f.addItem(storeAttrs(ssKey), bytes.Repeat([]byte{9}, ssMax-ssMax%16))
		if _, err := s.Load(t.Context(), ssKey); err != nil {
			t.Fatalf("Load: %v", err)
		}
	})
}

const aesBlock = 16

func TestSecretServiceCorruptSessions(t *testing.T) {
	p := dhPrime()
	be := func(n *big.Int) []byte { return n.FillBytes(make([]byte, dhValueBytes)) }
	peers := []struct {
		name string
		peer any
	}{
		{"zero", be(big.NewInt(0))},
		{"one", be(big.NewInt(1))},
		{"p minus one", be(new(big.Int).Sub(p, big.NewInt(1)))},
		{"p", be(p)},
		{"too long", append([]byte{1}, make([]byte, dhValueBytes)...)},
		{"empty", []byte{}},
		{"not bytes", "a string"},
		{"wrong element type", []uint32{1, 2}},
	}
	for _, tt := range peers {
		t.Run("server value: "+tt.name, func(t *testing.T) {
			f := newFakeSS()
			f.peerValue = tt.peer
			f.addItem(storeAttrs(ssKey), []byte("v"))
			s := newSSStore(f, InteractionNever)
			_, err := s.Load(t.Context(), ssKey)
			wantSSError(t, err, KindCorrupt, "")
			if err := s.Save(t.Context(), ssKey, []byte("v")); err == nil {
				t.Fatal("Save succeeded over a corrupt session")
			} else {
				wantSSError(t, err, KindCorrupt, "")
			}
			if slices.Contains(f.algorithms, "plain") {
				t.Fatal("a corrupt DH session fell back to plain")
			}
			if len(f.created) != 0 {
				t.Fatal("a secret was sent over a corrupt session")
			}
		})
	}

	t.Run("session path is the empty object", func(t *testing.T) {
		f := newFakeSS()
		f.badPath = true
		f.addItem(storeAttrs(ssKey), []byte("v"))
		_, err := newSSStore(f, InteractionNever).Load(t.Context(), ssKey)
		wantSSError(t, err, KindCorrupt, "")
	})

	t.Run("reply tampering", func(t *testing.T) {
		tests := []struct {
			name   string
			tamper func(*ssSecret)
		}{
			{"flipped padding byte", func(s *ssSecret) { s.Value[len(s.Value)-1] ^= 0xff }},
			{"short IV", func(s *ssSecret) { s.Parameters = s.Parameters[:8] }},
			{"missing IV", func(s *ssSecret) { s.Parameters = nil }},
			{"truncated ciphertext", func(s *ssSecret) { s.Value = s.Value[:len(s.Value)-1] }},
			{"empty ciphertext", func(s *ssSecret) { s.Value = nil }},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newFakeSS()
				f.addItem(storeAttrs(ssKey), []byte("a secret"))
				f.tamper = tt.tamper
				_, err := newSSStore(f, InteractionNever).Load(t.Context(), ssKey)
				wantSSError(t, err, KindCorrupt, "")
			})
		}
	})

	t.Run("malformed replies", func(t *testing.T) {
		f := newFakeSS()
		f.addItem(storeAttrs(ssKey), []byte("a secret"))
		s := newSSStore(f, InteractionNever)
		bus := &malformedBus{inner: &fakeBus{f: f}, replace: map[string][]any{"GetSecret": {"not a secret"}}}
		s.dial = func(context.Context) (ssBus, error) { return bus, nil }
		_, err := s.Load(t.Context(), ssKey)
		wantSSError(t, err, KindOther, ReasonOther)
	})
}

// malformedBus replaces the body of selected replies.
type malformedBus struct {
	inner   *fakeBus
	replace map[string][]any
}

func (b *malformedBus) call(ctx context.Context, path dbus.ObjectPath, method string, args ...any) ([]any, error) {
	body, err := b.inner.call(ctx, path, method, args...)
	if r, ok := b.replace[method[strings.LastIndex(method, ".")+1:]]; ok && err == nil {
		return r, nil
	}
	return body, err
}

func (b *malformedBus) watchCompleted(ctx context.Context, p dbus.ObjectPath) (ssWatch, error) {
	return b.inner.watchCompleted(ctx, p)
}
func (b *malformedBus) close() { b.inner.close() }

func TestSecretServicePlainFallback(t *testing.T) {
	t.Run("only NotSupported falls back", func(t *testing.T) {
		f := newFakeSS()
		f.refuseDH = true
		s := newSSStore(f, InteractionNever)
		if err := s.Save(t.Context(), ssKey, []byte("v")); err != nil {
			t.Fatalf("Save: %v", err)
		}
		if !slices.Equal(f.algorithms, []string{"dh", "plain"}) {
			t.Fatalf("algorithms = %v, want dh then plain", f.algorithms)
		}
		got, err := s.Load(t.Context(), ssKey)
		if err != nil || string(got) != "v" {
			t.Fatalf("Load = %q, %v", got, err)
		}
	})

	others := []struct {
		name string
		err  error
		kind Kind
		why  Reason
	}{
		{"access denied", dbusError(errNameAccessDenied), KindAccessDenied, ReasonAccessDenied},
		{"unknown error", dbusError("org.example.Error.Weird"), KindOther, ReasonOther},
		{"no reply", dbusError(errNameNoReply), KindUnavailable, ReasonNoReply},
		{"connection error", io.ErrUnexpectedEOF, KindUnavailable, ""},
	}
	for _, tt := range others {
		t.Run("no fallback on "+tt.name, func(t *testing.T) {
			f := newFakeSS()
			f.errs["OpenSession"] = tt.err
			s := newSSStore(f, InteractionNever)
			err := s.Save(t.Context(), ssKey, []byte("v"))
			wantSSError(t, err, tt.kind, tt.why)
			if len(f.algorithms) != 0 && slices.Contains(f.algorithms, "plain") {
				t.Fatal("fell back to plain")
			}
			if len(f.calls("OpenSession")) != 1 {
				t.Fatalf("OpenSession called %d times, want 1", len(f.calls("OpenSession")))
			}
		})
	}

	t.Run("plain refused too is not supported", func(t *testing.T) {
		f := newFakeSS()
		f.errs["OpenSession"] = dbusError(errNameNotSupported)
		err := newSSStore(f, InteractionNever).Save(t.Context(), ssKey, []byte("v"))
		wantSSError(t, err, KindOther, ReasonNotSupported)
		if len(f.calls("OpenSession")) != 2 {
			t.Fatalf("OpenSession called %d times, want dh then plain", len(f.calls("OpenSession")))
		}
	})
}

func TestSecretServiceInteraction(t *testing.T) {
	const prompt = dbus.ObjectPath("/org/freedesktop/secrets/prompt/p1")

	t.Run("never refuses a locked store without asking the provider", func(t *testing.T) {
		ops := []struct {
			name string
			run  func(*secretServiceStore, context.Context) error
		}{
			{"save", func(s *secretServiceStore, ctx context.Context) error { return s.Save(ctx, ssKey, []byte("v")) }},
			{"load", func(s *secretServiceStore, ctx context.Context) error { _, err := s.Load(ctx, ssKey); return err }},
			{"delete", func(s *secretServiceStore, ctx context.Context) error { return s.Delete(ctx, ssKey) }},
		}
		for _, op := range ops {
			t.Run(op.name, func(t *testing.T) {
				f := newFakeSS()
				f.addItem(storeAttrs(ssKey), []byte("v"))
				f.lockAll()
				f.unlockPrompt = prompt
				err := op.run(newSSStore(f, InteractionNever), t.Context())
				wantSSError(t, err, KindInteractionRequired, ReasonIsLocked)
				for _, forbidden := range []string{"Unlock", "Prompt", "AddMatch", "CreateItem", "GetSecret", "Delete", "OpenSession"} {
					if got := f.calls(forbidden); len(got) != 0 {
						t.Fatalf("under InteractionNever the store called %v", got)
					}
				}
				if !f.collLocked || !f.items[0].locked {
					t.Fatal("the store was unlocked")
				}
			})
		}
	})

	t.Run("exists needs no unlock", func(t *testing.T) {
		f := newFakeSS()
		f.addItem(storeAttrs(ssKey), []byte("v"))
		f.lockAll()
		ok, err := newSSStore(f, InteractionNever).Exists(t.Context(), ssKey)
		if err != nil || !ok {
			t.Fatalf("Exists = %v, %v", ok, err)
		}
	})

	t.Run("allowed unlocks through the prompt, subscribed first", func(t *testing.T) {
		f := newFakeSS()
		f.addItem(storeAttrs(ssKey), []byte("v"))
		f.lockAll()
		f.unlockPrompt = prompt
		got, err := newSSStore(f, InteractionAllowed).Load(t.Context(), ssKey)
		if err != nil || string(got) != "v" {
			t.Fatalf("Load = %q, %v", got, err)
		}
		match, run := f.indexOf("AddMatch:"+string(prompt)), f.indexOf("Prompt:"+string(prompt))
		if match < 0 || run < 0 || match > run {
			t.Fatalf("AddMatch at %d and Prompt at %d in %v; the subscription must come first", match, run, f.log)
		}
		if len(f.calls("Dismiss")) != 0 {
			t.Fatal("a completed prompt was dismissed")
		}
		if len(f.calls("RemoveMatch")) != 1 {
			t.Fatal("the subscription was not removed")
		}
	})

	t.Run("allowed unlocks without a prompt when the provider needs none", func(t *testing.T) {
		f := newFakeSS()
		f.lockAll()
		if err := newSSStore(f, InteractionAllowed).Save(t.Context(), ssKey, []byte("v")); err != nil {
			t.Fatalf("Save: %v", err)
		}
		if len(f.calls("Prompt")) != 0 || len(f.calls("Unlock")) != 1 {
			t.Fatalf("calls = %v", f.log)
		}
	})

	t.Run("a dismissed prompt is canceled", func(t *testing.T) {
		f := newFakeSS()
		f.lockAll()
		f.unlockPrompt = prompt
		f.promptMode = "dismissed"
		err := newSSStore(f, InteractionAllowed).Save(t.Context(), ssKey, []byte("v"))
		wantSSError(t, err, KindCanceled, "")
		if !errors.Is(err, ErrCanceled) {
			t.Fatal("not ErrCanceled")
		}
		if len(f.calls("CreateItem")) != 0 {
			t.Fatal("Save went on after the prompt was dismissed")
		}
	})

	t.Run("a prompt that completes without unlocking is still locked", func(t *testing.T) {
		f := newFakeSS()
		f.lockAll()
		f.unlockPrompt = prompt
		f.stayLocked = true
		err := newSSStore(f, InteractionAllowed).Save(t.Context(), ssKey, []byte("v"))
		wantSSError(t, err, KindInteractionRequired, ReasonIsLocked)
	})

	t.Run("a canceled context dismisses the prompt", func(t *testing.T) {
		f := newFakeSS()
		f.lockAll()
		f.unlockPrompt = prompt
		f.promptMode = "block"
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		f.onPrompt = cancel
		err := newSSStore(f, InteractionAllowed).Save(ctx, ssKey, []byte("v"))
		if !errors.Is(err, context.Canceled) || errors.Is(err, ErrCanceled) {
			t.Fatalf("err = %v, want context.Canceled and not ErrCanceled", err)
		}
		if got := f.calls("Dismiss:" + string(prompt)); len(got) != 1 {
			t.Fatalf("Dismiss calls = %v, want one", got)
		}
		if d := f.dismissCtx[0]; d.ctxErr != nil || !d.hasDeadline {
			t.Fatalf("Dismiss ran on a context with err %v and deadline %v; it must outlive the cancellation and be bounded", d.ctxErr, d.hasDeadline)
		}
		if len(f.calls("CreateItem")) != 0 {
			t.Fatal("Save went on after the context ended")
		}
		if f.dials != f.closes {
			t.Fatal("the connection was not closed")
		}
	})

	t.Run("a failing Prompt call dismisses it", func(t *testing.T) {
		f := newFakeSS()
		f.lockAll()
		f.unlockPrompt = prompt
		f.errs["Prompt"] = dbusError(errNameNoReply)
		err := newSSStore(f, InteractionAllowed).Save(t.Context(), ssKey, []byte("v"))
		wantSSError(t, err, KindUnavailable, ReasonNoReply)
		if len(f.calls("Dismiss")) != 1 {
			t.Fatalf("Dismiss calls = %v", f.calls("Dismiss"))
		}
	})

	t.Run("a failing subscription never starts the prompt", func(t *testing.T) {
		f := newFakeSS()
		f.lockAll()
		f.unlockPrompt = prompt
		f.errs["AddMatch"] = dbusError(errNameAccessDenied)
		err := newSSStore(f, InteractionAllowed).Save(t.Context(), ssKey, []byte("v"))
		wantSSError(t, err, KindAccessDenied, ReasonAccessDenied)
		if len(f.calls("Prompt")) != 0 {
			t.Fatal("Prompt was called without a subscription")
		}
	})

	t.Run("a connection lost while waiting is unavailable", func(t *testing.T) {
		f := newFakeSS()
		f.lockAll()
		f.unlockPrompt = prompt
		f.promptMode = "fail"
		err := newSSStore(f, InteractionAllowed).Save(t.Context(), ssKey, []byte("v"))
		wantSSError(t, err, KindUnavailable, "")
	})

	t.Run("a prompt from CreateItem under never is dismissed unseen", func(t *testing.T) {
		f := newFakeSS()
		f.createPrompt = prompt
		err := newSSStore(f, InteractionNever).Save(t.Context(), ssKey, []byte("v"))
		wantSSError(t, err, KindInteractionRequired, "")
		if len(f.calls("Prompt")) != 0 || len(f.calls("Dismiss:"+string(prompt))) != 1 {
			t.Fatalf("calls = %v", f.log)
		}
	})

	t.Run("a prompt from CreateItem under allowed is run", func(t *testing.T) {
		f := newFakeSS()
		f.createPrompt = prompt
		f.addItem(storeAttrs(ssKey), []byte("old"))
		if err := newSSStore(f, InteractionAllowed).Save(t.Context(), ssKey, []byte("new")); err != nil {
			t.Fatalf("Save: %v", err)
		}
		if len(f.items) != 1 || string(f.items[0].value) != "new" {
			t.Fatalf("items after Save = %d, want only the new one", len(f.items))
		}
	})

	t.Run("a prompt from Delete under never is refused", func(t *testing.T) {
		f := newFakeSS()
		f.deletePrompt = prompt
		f.addItem(storeAttrs(ssKey), []byte("v"))
		err := newSSStore(f, InteractionNever).Delete(t.Context(), ssKey)
		wantSSError(t, err, KindInteractionRequired, "")
		if len(f.calls("Dismiss")) != 1 || len(f.calls("Prompt")) != 0 {
			t.Fatalf("calls = %v", f.log)
		}
	})
}

func TestSecretServiceFailureMapping(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		kind   Kind
		reason Reason
	}{
		{"service unknown", dbusError(errNameServiceUnknown), KindUnavailable, ReasonServiceUnknown},
		{"name has no owner", dbusError(errNameNoOwner), KindUnavailable, ReasonNameHasNoOwner},
		{"no reply", dbusError(errNameNoReply), KindUnavailable, ReasonNoReply},
		{"timeout", dbusError(errNameTimeout), KindUnavailable, ReasonNoReply},
		{"timed out", dbusError(errNameTimedOut), KindUnavailable, ReasonNoReply},
		{"disconnected", dbusError(errNameDisconnected), KindUnavailable, ""},
		{"is locked", dbusError(errNameIsLocked), KindInteractionRequired, ReasonIsLocked},
		{"no session", dbusError(errNameNoSession), KindOther, ReasonNoSession},
		{"no such object", dbusError(errNameNoSuchObject), KindNotFound, ReasonNoSuchObject},
		{"access denied", dbusError(errNameAccessDenied), KindAccessDenied, ReasonAccessDenied},
		{"auth failed", dbusError(errNameAuthFailed), KindAccessDenied, ReasonAccessDenied},
		{"pointer error", dbus.NewError(errNameIsLocked, []any{"provider text"}), KindInteractionRequired, ReasonIsLocked},
		{"wrapped error", wrapErr(dbusError(errNameNoOwner)), KindUnavailable, ReasonNameHasNoOwner},
		{"unknown name", dbusError("org.example.Weird"), KindOther, ReasonOther},
		{"empty name", dbusError(""), KindUnavailable, ""},
		{"closed connection", dbus.ErrClosed, KindUnavailable, ""},
		{"plain error", errors.New("provider text that must never surface"), KindUnavailable, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeSS()
			f.errs["SearchItems"] = tt.err
			s := newSSStore(f, InteractionNever)
			_, err := s.Exists(t.Context(), ssKey)
			wantSSError(t, err, tt.kind, tt.reason)
			var se *Error
			if !errors.As(err, &se) || se.Op != "exists" {
				t.Fatalf("Op = %v, want exists", se)
			}
		})
	}

	t.Run("context errors pass through", func(t *testing.T) {
		for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
			f := newFakeSS()
			f.errs["SearchItems"] = cause
			_, err := newSSStore(f, InteractionNever).Exists(t.Context(), ssKey)
			if !errors.Is(err, cause) {
				t.Fatalf("err = %v, want %v", err, cause)
			}
			var se *Error
			if errors.As(err, &se) {
				t.Fatalf("a context error became %#v", se)
			}
		}
	})

	t.Run("the dial error is classified and nothing leaks", func(t *testing.T) {
		f := newFakeSS()
		f.dialErr = errors.New("dial unix /run/user/1000/bus: connect: provider text")
		_, err := newSSStore(f, InteractionNever).Load(t.Context(), ssKey)
		wantSSError(t, err, KindUnavailable, "")
	})

	t.Run("a pre-canceled context does not dial", func(t *testing.T) {
		f := newFakeSS()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		s := newSSStore(f, InteractionNever)
		_, err := s.Exists(ctx, ssKey)
		if !errors.Is(err, context.Canceled) || f.dials != 0 {
			t.Fatalf("Exists = %v with %d dials", err, f.dials)
		}
		if err := s.Save(ctx, ssKey, []byte("v")); !errors.Is(err, context.Canceled) || f.dials != 0 {
			t.Fatalf("Save = %v with %d dials", err, f.dials)
		}
	})

	t.Run("every operation closes its connection", func(t *testing.T) {
		f := newFakeSS()
		s := newSSStore(f, InteractionNever)
		_ = s.Save(t.Context(), ssKey, []byte("v"))
		_, _ = s.Load(t.Context(), ssKey)
		_, _ = s.Exists(t.Context(), ssKey)
		_ = s.Delete(t.Context(), ssKey)
		f.errs["SearchItems"] = dbusError("org.example.Weird")
		_, _ = s.Load(t.Context(), ssKey)
		_ = s.Delete(t.Context(), ssKey)
		if f.dials != 6 || f.closes != 6 {
			t.Fatalf("dials = %d, closes = %d, want 6 each", f.dials, f.closes)
		}
	})
}

func wrapErr(err error) error { return &wrapped{err} }

type wrapped struct{ err error }

func (w *wrapped) Error() string { return "wrapped" }
func (w *wrapped) Unwrap() error { return w.err }

func TestSecretServiceDeleteIsIdempotentUnderRaces(t *testing.T) {
	tests := []struct {
		name string
		hook func(f *fakeSS)
	}{
		{"item vanishes before the lock check", func(f *fakeSS) { f.vanishOn = "Get" }},
		{"item vanishes before Delete", func(f *fakeSS) { f.vanishOn = "Delete" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeSS()
			f.addItem(storeAttrs(ssKey), []byte("v"))
			tt.hook(f)
			if err := newSSStore(f, InteractionNever).Delete(t.Context(), ssKey); err != nil {
				t.Fatalf("Delete of an item that vanished: %v", err)
			}
		})
	}
}

func TestSecretServiceCollectionMissing(t *testing.T) {
	f := newFakeSS()
	f.collection = noObject
	s := newSSStore(f, InteractionNever)
	_, err := s.Exists(t.Context(), ssKey)
	wantSSError(t, err, KindUnavailable, ReasonNoSuchObject)
	if _, err := s.Load(t.Context(), ssKey); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Load = %v", err)
	}
	if err := s.Save(t.Context(), ssKey, []byte("v")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Save = %v", err)
	}
}

// addMatches adds n items for key, which the module never writes.
func addMatches(f *fakeSS, key Key, n int) {
	for range n {
		f.addItem(storeAttrs(key), []byte("v"))
	}
}

func countMatches(f *fakeSS, key Key) int {
	return len(f.search(storeAttrs(key)))
}

// TestSecretServiceRemovalIsNotCutAtOneSearch covers a key with more items than
// one search reads. Delete and Save's duplicate removal must go on until none
// are left, and report it when some are left after the bound.
func TestSecretServiceRemovalIsNotCutAtOneSearch(t *testing.T) {
	// One round removes maxSearchResults items and there are maxRemoveRounds of
	// them, so this many are removable and one more is not.
	removable := maxSearchResults * maxRemoveRounds
	tests := []struct {
		name    string
		matches int
		wantErr bool
	}{
		{"one", 1, false},
		{"exactly one search", maxSearchResults, false},
		{"one more than one search", maxSearchResults + 1, false},
		{"several searches", 3*maxSearchResults + 5, false},
		{"exactly the bound", removable, false},
		{"one more than the bound", removable + 1, true},
	}
	for _, tt := range tests {
		t.Run("delete: "+tt.name, func(t *testing.T) {
			f := newFakeSS()
			s := newSSStore(f, InteractionNever)
			addMatches(f, ssKey, tt.matches)
			bystander := f.addItem(storeAttrs(Key{Service: ssKey.Service, Account: "bob"}), []byte("bob"))
			err := s.Delete(t.Context(), ssKey)
			if tt.wantErr {
				wantSSError(t, err, KindOther, ReasonTooManyMatches)
				if got := countMatches(f, ssKey); got != 1 {
					t.Fatalf("%d matches left, want the one beyond the bound", got)
				}
			} else {
				if err != nil {
					t.Fatalf("Delete: %v", err)
				}
				ok, err := s.Exists(t.Context(), ssKey)
				if err != nil || ok {
					t.Fatalf("Exists after Delete = %v, %v; want false", ok, err)
				}
			}
			if f.item(bystander.path) == nil {
				t.Fatal("Delete removed another account's item")
			}
		})
		t.Run("save: "+tt.name, func(t *testing.T) {
			f := newFakeSS()
			f.keepOnCreate = true
			s := newSSStore(f, InteractionNever)
			addMatches(f, ssKey, tt.matches)
			err := s.Save(t.Context(), ssKey, []byte("new"))
			if tt.wantErr {
				// The new item is one of the matches: the others are removable
				// up to the bound, and one more than that is not.
				wantSSError(t, err, KindOther, ReasonTooManyMatches)
				return
			}
			if err != nil {
				t.Fatalf("Save: %v", err)
			}
			got, err := s.Load(t.Context(), ssKey)
			if err != nil || string(got) != "new" {
				t.Fatalf("Load = %q, %v; want the new value from a single item", got, err)
			}
		})
	}
}

func TestSecretServiceRemovalGivesUpOnItemsThatComeBack(t *testing.T) {
	for _, op := range []string{"delete", "save"} {
		t.Run(op, func(t *testing.T) {
			f := newFakeSS()
			f.readdOnDelete = true
			f.keepOnCreate = true
			s := newSSStore(f, InteractionNever)
			f.addItem(storeAttrs(ssKey), []byte("old"))
			var err error
			if op == "delete" {
				err = s.Delete(t.Context(), ssKey)
			} else {
				err = s.Save(t.Context(), ssKey, []byte("new"))
			}
			wantSSError(t, err, KindOther, ReasonTooManyMatches)
			var se *Error
			if errors.As(err, &se) && se.Op != op {
				t.Fatalf("Op = %q, want %q", se.Op, op)
			}
			// A round per search, then the search that finds what is left.
			if got := len(f.calls("SearchItems")); got != maxRemoveRounds+1 {
				t.Fatalf("%d searches, want %d: the loop must stop at its bound", got, maxRemoveRounds+1)
			}
		})
	}
}

// TestSecretServiceReadsOfAnOverfullKey checks that a search cut at its limit
// is never read as a single item.
func TestSecretServiceReadsOfAnOverfullKey(t *testing.T) {
	f := newFakeSS()
	s := newSSStore(f, InteractionNever)
	addMatches(f, ssKey, maxSearchResults+1)
	if ok, err := s.Exists(t.Context(), ssKey); err != nil || !ok {
		t.Fatalf("Exists = %v, %v; want true", ok, err)
	}
	_, err := s.Load(t.Context(), ssKey)
	wantSSError(t, err, KindCorrupt, "")
	if len(f.calls("GetSecret")) != 0 {
		t.Fatal("Load read a secret from one of many items")
	}
}

func TestCompletedSignal(t *testing.T) {
	const (
		owner  = ":1.42"
		prompt = dbus.ObjectPath("/org/freedesktop/secrets/prompt/p1")
		name   = "org.freedesktop.Secret.Prompt.Completed"
	)
	result := dbus.MakeVariant(dbus.ObjectPath("/item"))
	good := func() *dbus.Signal {
		return &dbus.Signal{Sender: owner, Path: prompt, Name: name, Body: []any{false, result}}
	}
	tests := []struct {
		name         string
		sig          func() *dbus.Signal
		owner        string
		wantRelevant bool
		wantErr      error
		wantDismiss  bool
	}{
		{"from the service", good, owner, true, nil, false},
		{"dismissed", func() *dbus.Signal {
			sig := good()
			sig.Body[0] = true
			return sig
		}, owner, true, nil, true},
		{"another sender with the prompt's path", func() *dbus.Signal {
			sig := good()
			sig.Sender = ":1.666"
			return sig
		}, owner, false, nil, false},
		{"another sender with a malformed body", func() *dbus.Signal {
			sig := good()
			sig.Sender = ":1.666"
			sig.Body = []any{"junk"}
			return sig
		}, owner, false, nil, false},
		{"no sender", func() *dbus.Signal {
			sig := good()
			sig.Sender = ""
			return sig
		}, owner, false, nil, false},
		{"owner unknown", good, "", false, nil, false},
		{"another prompt", func() *dbus.Signal {
			sig := good()
			sig.Path = "/org/freedesktop/secrets/prompt/p2"
			return sig
		}, owner, false, nil, false},
		{"another signal", func() *dbus.Signal {
			sig := good()
			sig.Name = "org.freedesktop.Secret.Prompt.Other"
			return sig
		}, owner, false, nil, false},
		{"body of the wrong length", func() *dbus.Signal {
			sig := good()
			sig.Body = []any{false}
			return sig
		}, owner, true, errMalformedSignal, false},
		{"body of the wrong types", func() *dbus.Signal {
			sig := good()
			sig.Body = []any{"no", result}
			return sig
		}, owner, true, errMalformedSignal, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, relevant, err := completedSignal(tt.sig(), prompt, tt.owner)
			if relevant != tt.wantRelevant || !errors.Is(err, tt.wantErr) || (err == nil) != (tt.wantErr == nil) {
				t.Fatalf("completedSignal = relevant %v, err %v; want relevant %v, err %v", relevant, err, tt.wantRelevant, tt.wantErr)
			}
			if tt.wantRelevant && tt.wantErr == nil {
				if got.dismissed != tt.wantDismiss || got.result.Value() != result.Value() {
					t.Fatalf("completion = %+v, want dismissed %v and the signal's result", got, tt.wantDismiss)
				}
			}
		})
	}
}
