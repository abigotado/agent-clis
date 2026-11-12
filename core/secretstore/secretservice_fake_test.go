package secretstore

import (
	"context"
	"crypto/rand"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/godbus/dbus/v5"
)

// fakeSS is an in-memory Secret Service behind ssBus. It speaks the real wire
// types (object paths, variants, the secret structure) and runs the real DH
// exchange on its side, so the store's session handling is exercised end to
// end; hooks let a test refuse, tamper with or block any step.
type fakeSS struct {
	collection dbus.ObjectPath // the alias target; noObject for none

	collLocked bool
	items      []*fakeSSItem
	sessions   map[dbus.ObjectPath]*fakeSSSession
	nextID     int

	// Behaviour switches.
	refuseDH     bool // OpenSession(dh) answers NotSupported
	keepOnCreate bool // CreateItem ignores replace and keeps duplicates
	// readdOnDelete makes every Delete of an item add a new item with the same
	// attributes, like a writer that keeps recreating it.
	readdOnDelete bool
	// unlockPrompt, when set, is the prompt Unlock returns; the objects are
	// unlocked when it completes.
	unlockPrompt dbus.ObjectPath
	createPrompt dbus.ObjectPath // CreateItem returns this prompt and no item
	deletePrompt dbus.ObjectPath // Delete returns this prompt
	promptMode   string          // complete, dismissed, block or fail
	pending      []dbus.ObjectPath
	pendingNew   *fakeSSItem // an item CreateItem made once its prompt completes
	// stayLocked makes a completed unlock prompt leave the objects locked.
	stayLocked bool

	// vanishOn names a method (Get or Delete) on which the item it is called on
	// is removed by someone else first, so the call answers NoSuchObject and
	// later searches no longer find the item.
	vanishOn string

	// Hooks and errors.
	errs      map[string]error // method name -> error to return
	onPrompt  func()           // runs when Prompt is called
	peer      []byte           // server DH value to return instead of the real one
	peerValue any              // OpenSession output to return instead of bytes
	badPath   bool             // OpenSession returns the "/" session path
	tamper    func(*ssSecret)  // edits a GetSecret reply before it is returned

	// Records.
	log        []string
	dials      int
	closes     int
	dialErr    error
	algorithms []string
	lastValue  []byte // the ciphertext (or plain value) of the last GetSecret
	created    []createdItem
	dismissCtx []dismissCall
}

type dismissCall struct {
	ctxErr      error
	hasDeadline bool
}

type createdItem struct {
	properties map[string]dbus.Variant
	contentTyp string
	replace    bool
}

type fakeSSItem struct {
	path   dbus.ObjectPath
	attrs  map[string]string
	value  []byte
	locked bool
}

type fakeSSSession struct {
	key []byte // nil for plain
}

func newFakeSS() *fakeSS {
	return &fakeSS{
		collection: "/org/freedesktop/secrets/collection/login",
		sessions:   map[dbus.ObjectPath]*fakeSSSession{},
		errs:       map[string]error{},
		promptMode: "complete",
	}
}

func dbusError(name string) error {
	return dbus.Error{Name: name, Body: []any{"provider text that must never surface"}}
}

func (f *fakeSS) dialer() ssDialer {
	return func(ctx context.Context) (ssBus, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		f.dials++
		if f.dialErr != nil {
			return nil, f.dialErr
		}
		return &fakeBus{f: f}, nil
	}
}

func (f *fakeSS) record(format string, args ...any) {
	f.log = append(f.log, fmt.Sprintf(format, args...))
}

// calls returns the log entries that start with prefix.
func (f *fakeSS) calls(prefix string) []string {
	var out []string
	for _, entry := range f.log {
		if strings.HasPrefix(entry, prefix) {
			out = append(out, entry)
		}
	}
	return out
}

func (f *fakeSS) indexOf(prefix string) int {
	return slices.IndexFunc(f.log, func(entry string) bool { return strings.HasPrefix(entry, prefix) })
}

func (f *fakeSS) item(path dbus.ObjectPath) *fakeSSItem {
	for _, it := range f.items {
		if it.path == path {
			return it
		}
	}
	return nil
}

func (f *fakeSS) addItem(attrs map[string]string, value []byte) *fakeSSItem {
	f.nextID++
	it := &fakeSSItem{
		path:   dbus.ObjectPath(fmt.Sprintf("%s/%d", f.collection, f.nextID)),
		attrs:  maps.Clone(attrs),
		value:  slices.Clone(value),
		locked: f.collLocked,
	}
	f.items = append(f.items, it)
	return it
}

func (f *fakeSS) removeItem(path dbus.ObjectPath) {
	f.items = slices.DeleteFunc(f.items, func(it *fakeSSItem) bool { return it.path == path })
}

// storeAttrs returns the attributes of a key, as the store should write them.
func storeAttrs(key Key) map[string]string {
	return map[string]string{"xdg:schema": "dev.abigotado.secretstore", "service": key.Service, "account": key.Account}
}

func (f *fakeSS) lockAll() {
	f.collLocked = true
	for _, it := range f.items {
		it.locked = true
	}
}

type fakeBus struct {
	f *fakeSS
}

func (b *fakeBus) close() { b.f.closes++ }

func (b *fakeBus) call(ctx context.Context, path dbus.ObjectPath, method string, args ...any) ([]any, error) {
	f := b.f
	short := method[strings.LastIndex(method, ".")+1:]
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch short {
	case "Dismiss":
		f.dismissCtx = append(f.dismissCtx, dismissCall{ctxErr: ctx.Err(), hasDeadline: hasDeadline(ctx)})
		f.record("Dismiss:%s", path)
	case "Prompt":
		f.record("Prompt:%s", path)
	case "Get":
		f.record("Get:%s:%v", path, args[1])
	default:
		f.record("%s:%s", short, path)
	}
	if short == f.vanishOn {
		f.removeItem(path)
		return nil, dbusError(errNameNoSuchObject)
	}
	if err, ok := f.errs[short]; ok {
		return nil, err
	}
	switch short {
	case "ReadAlias":
		return []any{f.collection}, nil
	case "OpenSession":
		return f.openSession(args)
	case "Get":
		return f.property(path)
	case "Unlock":
		return f.unlock(args)
	case "SearchItems":
		return []any{f.search(args[0].(map[string]string))}, nil
	case "CreateItem":
		return f.createItem(args)
	case "GetSecret":
		return f.getSecret(path, args[0].(dbus.ObjectPath))
	case "Delete":
		return f.deleteItem(path)
	case "Prompt":
		if f.onPrompt != nil {
			f.onPrompt()
		}
		return nil, nil
	case "Dismiss":
		return nil, nil
	}
	return nil, dbusError("org.freedesktop.DBus.Error.UnknownMethod")
}

func hasDeadline(ctx context.Context) bool {
	_, ok := ctx.Deadline()
	return ok
}

func (f *fakeSS) openSession(args []any) ([]any, error) {
	algorithm := args[0].(string)
	f.nextID++
	path := dbus.ObjectPath(fmt.Sprintf("/org/freedesktop/secrets/session/s%d", f.nextID))
	if f.badPath {
		path = noObject
	}
	switch algorithm {
	case dhAlgorithm:
		f.algorithms = append(f.algorithms, "dh")
		if f.refuseDH {
			return nil, dbusError(errNameNotSupported)
		}
		client := args[1].(dbus.Variant).Value().([]byte)
		server, err := newDHKeyPair(rand.Reader)
		if err != nil {
			return nil, err
		}
		key, err := server.deriveKey(client)
		if err != nil {
			return nil, err
		}
		f.sessions[path] = &fakeSSSession{key: key}
		var output any = server.pub
		if f.peer != nil {
			output = f.peer
		}
		if f.peerValue != nil {
			output = f.peerValue
		}
		return []any{dbus.MakeVariant(output), path}, nil
	case "plain":
		f.algorithms = append(f.algorithms, "plain")
		f.sessions[path] = &fakeSSSession{}
		return []any{dbus.MakeVariant(""), path}, nil
	}
	return nil, dbusError(errNameNotSupported)
}

func (f *fakeSS) property(path dbus.ObjectPath) ([]any, error) {
	if path == f.collection {
		return []any{dbus.MakeVariant(f.collLocked)}, nil
	}
	if it := f.item(path); it != nil {
		return []any{dbus.MakeVariant(it.locked)}, nil
	}
	return nil, dbusError(errNameNoSuchObject)
}

func (f *fakeSS) unlock(args []any) ([]any, error) {
	paths := args[0].([]dbus.ObjectPath)
	if f.unlockPrompt != "" {
		f.pending = paths
		return []any{[]dbus.ObjectPath{}, f.unlockPrompt}, nil
	}
	f.unlockPaths(paths)
	return []any{paths, noObject}, nil
}

func (f *fakeSS) unlockPaths(paths []dbus.ObjectPath) {
	for _, p := range paths {
		if p == f.collection {
			f.collLocked = false
			for _, it := range f.items {
				it.locked = false
			}
		}
		if it := f.item(p); it != nil {
			it.locked = false
		}
	}
}

func (f *fakeSS) search(want map[string]string) []dbus.ObjectPath {
	out := []dbus.ObjectPath{}
	for _, it := range f.items {
		match := true
		for k, v := range want {
			if it.attrs[k] != v {
				match = false
			}
		}
		if match {
			out = append(out, it.path)
		}
	}
	return out
}

func (f *fakeSS) createItem(args []any) ([]any, error) {
	props := args[0].(map[string]dbus.Variant)
	secret := args[1].(ssSecret)
	replace := args[2].(bool)
	if f.collLocked {
		return nil, dbusError(errNameIsLocked)
	}
	f.created = append(f.created, createdItem{properties: props, contentTyp: secret.ContentType, replace: replace})
	sess, ok := f.sessions[secret.Session]
	if !ok {
		return nil, dbusError(errNameNoSession)
	}
	value := slices.Clone(secret.Value)
	if sess.key != nil {
		plain, err := dhDecrypt(sess.key, secret.Parameters, secret.Value)
		if err != nil {
			return nil, dbusError("org.freedesktop.DBus.Error.InvalidArgs")
		}
		value = plain
	}
	attrs := props[propAttributes].Value().(map[string]string)
	if replace && !f.keepOnCreate {
		for _, p := range f.search(attrs) {
			f.removeItem(p)
		}
	}
	if f.createPrompt != "" {
		f.pendingNew = &fakeSSItem{attrs: maps.Clone(attrs), value: value}
		return []any{noObject, f.createPrompt}, nil
	}
	it := f.addItem(attrs, value)
	return []any{it.path, noObject}, nil
}

func (f *fakeSS) getSecret(path, session dbus.ObjectPath) ([]any, error) {
	it := f.item(path)
	if it == nil {
		return nil, dbusError(errNameNoSuchObject)
	}
	if it.locked {
		return nil, dbusError(errNameIsLocked)
	}
	sess, ok := f.sessions[session]
	if !ok {
		return nil, dbusError(errNameNoSession)
	}
	out := ssSecret{Session: session, Parameters: []byte{}, Value: slices.Clone(it.value), ContentType: contentType}
	if sess.key != nil {
		iv, ct, err := dhEncrypt(sess.key, it.value, rand.Reader)
		if err != nil {
			return nil, err
		}
		out.Parameters, out.Value = iv, ct
	}
	if f.tamper != nil {
		f.tamper(&out)
	}
	f.lastValue = out.Value
	// A real reply arrives as a slice of interfaces; use the same shape.
	return []any{[]any{out.Session, out.Parameters, out.Value, out.ContentType}}, nil
}

func (f *fakeSS) deleteItem(path dbus.ObjectPath) ([]any, error) {
	it := f.item(path)
	if it == nil {
		return nil, dbusError(errNameNoSuchObject)
	}
	if f.deletePrompt != "" {
		return []any{f.deletePrompt}, nil
	}
	f.removeItem(path)
	if f.readdOnDelete {
		f.addItem(it.attrs, it.value)
	}
	return []any{noObject}, nil
}

func (b *fakeBus) watchCompleted(ctx context.Context, prompt dbus.ObjectPath) (ssWatch, error) {
	b.f.record("AddMatch:%s", prompt)
	if err, ok := b.f.errs["AddMatch"]; ok {
		return nil, err
	}
	return &fakeWatch{f: b.f, prompt: prompt}, nil
}

type fakeWatch struct {
	f      *fakeSS
	prompt dbus.ObjectPath
}

func (w *fakeWatch) stop() { w.f.record("RemoveMatch:%s", w.prompt) }

func (w *fakeWatch) wait(ctx context.Context) (ssCompletion, error) {
	f := w.f
	switch f.promptMode {
	case "dismissed":
		return ssCompletion{dismissed: true, result: dbus.MakeVariant("")}, nil
	case "block":
		<-ctx.Done()
		return ssCompletion{}, ctx.Err()
	case "fail":
		return ssCompletion{}, dbus.ErrClosed
	}
	if !f.stayLocked {
		f.unlockPaths(f.pending)
	}
	if w.prompt == f.createPrompt && f.pendingNew != nil {
		it := f.addItem(f.pendingNew.attrs, f.pendingNew.value)
		f.pendingNew = nil
		return ssCompletion{result: dbus.MakeVariant(it.path)}, nil
	}
	return ssCompletion{result: dbus.MakeVariant(noObject)}, nil
}
