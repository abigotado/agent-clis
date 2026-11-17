package secretstore

import (
	"context"
	"crypto/aes"
	"crypto/rand"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

// This file is the Linux backend's logic. It is untagged and talks to the
// session bus only through ssBus, so the session handling, the unlock and
// prompt flow and the error mapping are testable on any platform;
// secretservice_linux.go binds ssBus to a real bus connection.
//
// Every item is a Secret Service item in the collection behind the alias
// "default", found by these attributes and no others:
//
//	xdg:schema = dev.abigotado.secretstore
//	service    = Key.Service
//	account    = Key.Account
//
// with the label "<service> (<account>)" and content type
// application/octet-stream. Each operation opens its own bus connection and
// closes it when it ends; nothing is cached between operations.

const (
	secretServiceBackend = "secretservice"

	// schemaAttribute and schemaValue mark the items this module owns.
	schemaAttribute = "xdg:schema"
	schemaValue     = "dev.abigotado.secretstore"
	// contentType is stored with every secret; the value is raw bytes.
	contentType = "application/octet-stream"

	// dismissTimeout bounds the Dismiss call made after the context ended, which
	// runs on a context that no longer carries the cancellation.
	dismissTimeout = 2 * time.Second
	// maxSearchResults bounds the item paths one search reply is read for. A
	// longer reply is cut, so more than one item is always seen as more than
	// one: Load reports corruption and Exists reports true.
	maxSearchResults = 64
	// maxRemoveRounds bounds the search-and-delete rounds that remove every item
	// of a key. Each round removes at most maxSearchResults items.
	maxRemoveRounds = 8
)

const (
	serviceDest = "org.freedesktop.secrets"
	servicePath = dbus.ObjectPath("/org/freedesktop/secrets")
	noObject    = dbus.ObjectPath("/")

	ifaceService    = "org.freedesktop.Secret.Service"
	ifaceCollection = "org.freedesktop.Secret.Collection"
	ifaceItem       = "org.freedesktop.Secret.Item"
	ifacePrompt     = "org.freedesktop.Secret.Prompt"
	ifaceProperties = "org.freedesktop.DBus.Properties"

	methodOpenSession = ifaceService + ".OpenSession"
	methodReadAlias   = ifaceService + ".ReadAlias"
	methodUnlock      = ifaceService + ".Unlock"
	methodSearchItems = ifaceCollection + ".SearchItems"
	methodCreateItem  = ifaceCollection + ".CreateItem"
	methodGetSecret   = ifaceItem + ".GetSecret"
	methodDeleteItem  = ifaceItem + ".Delete"
	methodPrompt      = ifacePrompt + ".Prompt"
	methodDismiss     = ifacePrompt + ".Dismiss"
	methodGetProperty = ifaceProperties + ".Get"

	propLabel      = ifaceItem + ".Label"
	propAttributes = ifaceItem + ".Attributes"
	propLocked     = "Locked"

	defaultAlias = "default"
)

// The D-Bus error names the mapping below depends on.
const (
	errNameServiceUnknown = "org.freedesktop.DBus.Error.ServiceUnknown"
	errNameNoOwner        = "org.freedesktop.DBus.Error.NameHasNoOwner"
	errNameNoReply        = "org.freedesktop.DBus.Error.NoReply"
	errNameTimeout        = "org.freedesktop.DBus.Error.Timeout"
	errNameTimedOut       = "org.freedesktop.DBus.Error.TimedOut"
	errNameDisconnected   = "org.freedesktop.DBus.Error.Disconnected"
	errNameNotSupported   = "org.freedesktop.DBus.Error.NotSupported"
	errNameAccessDenied   = "org.freedesktop.DBus.Error.AccessDenied"
	errNameAuthFailed     = "org.freedesktop.DBus.Error.AuthFailed"
	errNameIsLocked       = "org.freedesktop.Secret.Error.IsLocked"
	errNameNoSession      = "org.freedesktop.Secret.Error.NoSession"
	errNameNoSuchObject   = "org.freedesktop.Secret.Error.NoSuchObject"
)

// ssBus is the part of a bus connection one operation needs. A real one wraps a
// private connection; tests substitute a fake service.
type ssBus interface {
	// call invokes a method on the Secret Service and returns the reply body.
	// A D-Bus error reply is returned as a dbus.Error.
	call(ctx context.Context, path dbus.ObjectPath, method string, args ...any) ([]any, error)
	// watchCompleted subscribes to the Completed signal of a prompt. The
	// subscription is in force when it returns, so a prompt started afterwards
	// cannot complete unseen.
	watchCompleted(ctx context.Context, prompt dbus.ObjectPath) (ssWatch, error)
	// close ends the connection.
	close()
}

// ssWatch is one prompt subscription.
type ssWatch interface {
	// wait blocks until the prompt completes, the connection fails, or ctx ends.
	wait(ctx context.Context) (ssCompletion, error)
	// stop removes the subscription.
	stop()
}

// ssCompletion is the payload of a prompt's Completed signal.
type ssCompletion struct {
	dismissed bool
	result    dbus.Variant
}

// ssDialer opens a connection with authentication and Hello done.
type ssDialer func(ctx context.Context) (ssBus, error)

// busEndpoint is one address of a bus address list.
type busEndpoint struct {
	abstract bool
	name     string // a filesystem path, or an abstract socket name
}

var errMalformedSignal = errors.New("secretstore: malformed Completed signal")

var errBusAddress = errors.New("secretstore: session bus address is not a usable unix address")

// parseBusAddress accepts only unix: addresses with an absolute path or an
// abstract name. Anything else, including an empty address, unixexec:, tcp:,
// nonce-tcp:, autolaunch: and launchd:, is refused: those either start a
// process or connect over the network on the strength of an environment
// variable.
func parseBusAddress(addr string) ([]busEndpoint, error) {
	if addr == "" {
		return nil, errBusAddress
	}
	var endpoints []busEndpoint
	for entry := range strings.SplitSeq(addr, ";") {
		transport, keys, found := strings.Cut(entry, ":")
		if !found || transport != "unix" {
			return nil, errBusAddress
		}
		var path, abstract string
		var hasPath, hasAbstract bool
		for kv := range strings.SplitSeq(keys, ",") {
			key, raw, found := strings.Cut(kv, "=")
			if !found {
				return nil, errBusAddress
			}
			switch key {
			case "path", "abstract":
				value, err := dbus.UnescapeBusAddressValue(raw)
				if err != nil || value == "" || strings.ContainsRune(value, 0) {
					return nil, errBusAddress
				}
				if key == "path" {
					path, hasPath = value, true
				} else {
					abstract, hasAbstract = value, true
				}
			case "guid":
			default:
				// runtime=, tmpdir=, dir= and the rest name no socket.
				return nil, errBusAddress
			}
		}
		switch {
		case hasPath == hasAbstract:
			return nil, errBusAddress
		case hasPath && !strings.HasPrefix(path, "/"):
			return nil, errBusAddress
		case hasPath:
			endpoints = append(endpoints, busEndpoint{name: path})
		default:
			endpoints = append(endpoints, busEndpoint{abstract: true, name: abstract})
		}
	}
	return endpoints, nil
}

// secretServiceStore implements Store over a Secret Service provider.
type secretServiceStore struct {
	dial        ssDialer
	max         int
	interaction Interaction
	// random is the source of private exponents and IVs.
	random io.Reader
	// plainOnly skips the DH exchange; tests use it to reach the plain session.
	plainOnly bool
	// onSession, if set, is told the algorithm of every session opened.
	onSession func(algorithm string)
}

var _ Store = (*secretServiceStore)(nil)

func newSecretServiceStore(dial ssDialer, opts Options) *secretServiceStore {
	return &secretServiceStore{
		dial:        dial,
		max:         min(opts.MaxSecretBytes, MaxSecretBytesLimit),
		interaction: opts.Interaction,
		random:      rand.Reader,
	}
}

func (s *secretServiceStore) fail(op string, kind Kind, reason Reason) *Error {
	return &Error{Op: op, Backend: secretServiceBackend, Kind: kind, Reason: reason}
}

// dbusErrorName returns the name of a D-Bus error reply inside err, or "".
func dbusErrorName(err error) string {
	var value dbus.Error
	if errors.As(err, &value) {
		return value.Name
	}
	var pointer *dbus.Error
	if errors.As(err, &pointer) && pointer != nil {
		return pointer.Name
	}
	return ""
}

// failure classifies an error from the bus. The error text, which the provider
// controls, is never copied: only a name from a closed set maps to a Reason.
func (s *secretServiceStore) failure(op string, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return contextError(op, err)
	}
	switch dbusErrorName(err) {
	case errNameServiceUnknown:
		return s.fail(op, KindUnavailable, ReasonServiceUnknown)
	case errNameNoOwner:
		return s.fail(op, KindUnavailable, ReasonNameHasNoOwner)
	case errNameNoReply, errNameTimeout, errNameTimedOut:
		return s.fail(op, KindUnavailable, ReasonNoReply)
	case errNameDisconnected:
		return s.fail(op, KindUnavailable, "")
	case errNameNotSupported:
		return s.fail(op, KindOther, ReasonNotSupported)
	case errNameIsLocked:
		return s.fail(op, KindInteractionRequired, ReasonIsLocked)
	case errNameNoSession:
		return s.fail(op, KindOther, ReasonNoSession)
	case errNameNoSuchObject:
		return s.fail(op, KindNotFound, ReasonNoSuchObject)
	case errNameAccessDenied, errNameAuthFailed:
		return s.fail(op, KindAccessDenied, ReasonAccessDenied)
	case "":
		// Not an error reply: the connection broke or a call could not be sent.
		return s.fail(op, KindUnavailable, "")
	default:
		return s.fail(op, KindOther, ReasonOther)
	}
}

func isErrorName(err error, name string) bool {
	return dbusErrorName(err) == name
}

// begin runs the checks every operation performs before the store is touched.
func (s *secretServiceStore) begin(ctx context.Context, op string, key Key) error {
	if err := ctx.Err(); err != nil {
		return contextError(op, err)
	}
	return validateKey(op, secretServiceBackend, key)
}

// connect opens the operation's own bus connection.
func (s *secretServiceStore) connect(ctx context.Context, op string) (ssBus, error) {
	bus, err := s.dial(ctx)
	if err != nil {
		return nil, s.failure(op, err)
	}
	return bus, nil
}

// malformed is a reply that does not have the shape the specification gives.
func (s *secretServiceStore) malformed(op string) error {
	return s.fail(op, KindOther, ReasonOther)
}

// defaultCollection resolves the alias "default". A missing one means there is
// no collection to keep secrets in.
func (s *secretServiceStore) defaultCollection(ctx context.Context, bus ssBus, op string) (dbus.ObjectPath, error) {
	body, err := bus.call(ctx, servicePath, methodReadAlias, defaultAlias)
	if err != nil {
		return "", s.failure(op, err)
	}
	if len(body) != 1 {
		return "", s.malformed(op)
	}
	path, ok := body[0].(dbus.ObjectPath)
	if !ok || !path.IsValid() {
		return "", s.malformed(op)
	}
	if path == noObject {
		return "", s.fail(op, KindUnavailable, ReasonNoSuchObject)
	}
	return path, nil
}

func (s *secretServiceStore) attributes(key Key) map[string]string {
	return map[string]string{
		schemaAttribute: schemaValue,
		"service":       key.Service,
		"account":       key.Account,
	}
}

// search returns the items of the collection that carry key's attributes.
func (s *secretServiceStore) search(ctx context.Context, bus ssBus, op string, collection dbus.ObjectPath, key Key) ([]dbus.ObjectPath, error) {
	body, err := bus.call(ctx, collection, methodSearchItems, s.attributes(key))
	if err != nil {
		return nil, s.failure(op, err)
	}
	if len(body) != 1 {
		return nil, s.malformed(op)
	}
	items, ok := body[0].([]dbus.ObjectPath)
	if !ok {
		return nil, s.malformed(op)
	}
	if len(items) > maxSearchResults {
		items = items[:maxSearchResults]
	}
	return items, nil
}

// isLocked reads the Locked property of a collection or an item.
func (s *secretServiceStore) isLocked(ctx context.Context, bus ssBus, op string, path dbus.ObjectPath, iface string) (bool, error) {
	body, err := bus.call(ctx, path, methodGetProperty, iface, propLocked)
	if err != nil {
		return false, s.failure(op, err)
	}
	if len(body) != 1 {
		return false, s.malformed(op)
	}
	variant, ok := body[0].(dbus.Variant)
	if !ok {
		return false, s.malformed(op)
	}
	locked, ok := variant.Value().(bool)
	if !ok {
		return false, s.malformed(op)
	}
	return locked, nil
}

// ensureUnlocked makes sure path is usable. Under InteractionNever a locked
// object is ErrInteractionRequired and nothing is asked of the provider that
// could show a dialog; under InteractionAllowed it is unlocked, through the
// prompt the provider names if it names one.
func (s *secretServiceStore) ensureUnlocked(ctx context.Context, bus ssBus, op string, path dbus.ObjectPath, iface string) error {
	locked, err := s.isLocked(ctx, bus, op, path, iface)
	if err != nil || !locked {
		return err
	}
	if s.interaction != InteractionAllowed {
		return s.fail(op, KindInteractionRequired, ReasonIsLocked)
	}
	body, err := bus.call(ctx, servicePath, methodUnlock, []dbus.ObjectPath{path})
	if err != nil {
		return s.failure(op, err)
	}
	if len(body) != 2 {
		return s.malformed(op)
	}
	prompt, ok := body[1].(dbus.ObjectPath)
	if !ok || !prompt.IsValid() {
		return s.malformed(op)
	}
	if prompt != noObject {
		if _, err := s.runPrompt(ctx, bus, op, prompt); err != nil {
			return err
		}
	}
	locked, err = s.isLocked(ctx, bus, op, path, iface)
	if err != nil {
		return err
	}
	if locked {
		return s.fail(op, KindInteractionRequired, ReasonIsLocked)
	}
	return nil
}

// runPrompt shows a provider prompt and waits for its Completed signal, which
// is subscribed to before Prompt is called. A dismissed prompt is
// ErrCanceled. When ctx ends first the prompt is dismissed and the context
// error is returned. It returns the payload of Completed.
func (s *secretServiceStore) runPrompt(ctx context.Context, bus ssBus, op string, prompt dbus.ObjectPath) (dbus.Variant, error) {
	watch, err := bus.watchCompleted(ctx, prompt)
	if err != nil {
		return dbus.Variant{}, s.failure(op, err)
	}
	defer watch.stop()
	if _, err := bus.call(ctx, prompt, methodPrompt, ""); err != nil {
		s.dismiss(ctx, bus, prompt)
		return dbus.Variant{}, s.failure(op, err)
	}
	completion, err := watch.wait(ctx)
	if err != nil {
		s.dismiss(ctx, bus, prompt)
		return dbus.Variant{}, s.failure(op, err)
	}
	if completion.dismissed {
		return dbus.Variant{}, s.fail(op, KindCanceled, "")
	}
	return completion.result, nil
}

// completedSignal reads sig as the Completed signal of prompt sent by owner,
// the unique bus name that owns the Secret Service. A signal about another
// prompt or from another sender is not relevant: any bus client can emit a
// signal with a prompt's path, but the bus sets the sender, so only the
// service's own signal may complete a prompt or dismiss it. The sender is
// checked before the body, so another client cannot fail the wait with a
// malformed one.
func completedSignal(sig *dbus.Signal, prompt dbus.ObjectPath, owner string) (completion ssCompletion, relevant bool, err error) {
	if sig.Path != prompt || sig.Name != ifacePrompt+".Completed" {
		return ssCompletion{}, false, nil
	}
	if owner == "" || sig.Sender != owner {
		return ssCompletion{}, false, nil
	}
	if len(sig.Body) != 2 {
		return ssCompletion{}, true, errMalformedSignal
	}
	dismissed, ok1 := sig.Body[0].(bool)
	result, ok2 := sig.Body[1].(dbus.Variant)
	if !ok1 || !ok2 {
		return ssCompletion{}, true, errMalformedSignal
	}
	return ssCompletion{dismissed: dismissed, result: result}, true, nil
}

// dismiss asks the provider to close a prompt this process started or was
// handed. It is best effort and runs on a context that outlives the
// cancellation of ctx, bounded by dismissTimeout.
func (s *secretServiceStore) dismiss(ctx context.Context, bus ssBus, prompt dbus.ObjectPath) {
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dismissTimeout)
	defer cancel()
	// The caller already has the error that matters, and a failed Dismiss only
	// leaves the provider's own timeout to close the dialog.
	_, _ = bus.call(dctx, prompt, methodDismiss)
}

// refusePrompt handles a prompt the provider returned from a call that did not
// need one under InteractionNever: it is dismissed unseen and the call is
// ErrInteractionRequired.
func (s *secretServiceStore) refusePrompt(ctx context.Context, bus ssBus, op string, prompt dbus.ObjectPath) error {
	s.dismiss(ctx, bus, prompt)
	return s.fail(op, KindInteractionRequired, "")
}

// promptOrRefuse runs prompt under InteractionAllowed and refuses it
// otherwise.
func (s *secretServiceStore) promptOrRefuse(ctx context.Context, bus ssBus, op string, prompt dbus.ObjectPath) (dbus.Variant, error) {
	if s.interaction != InteractionAllowed {
		return dbus.Variant{}, s.refusePrompt(ctx, bus, op, prompt)
	}
	return s.runPrompt(ctx, bus, op, prompt)
}

// probe checks that a bus is reachable and a service owns the default
// collection. Open calls it so an environment without a provider fails early.
func (s *secretServiceStore) probe(ctx context.Context) error {
	bus, err := s.connect(ctx, "open")
	if err != nil {
		return err
	}
	defer bus.close()
	_, err = s.defaultCollection(ctx, bus, "open")
	return err
}

// Exists implements Store. It searches the collection by attributes, which
// needs no unlock, and reads no secret.
func (s *secretServiceStore) Exists(ctx context.Context, key Key) (bool, error) {
	if err := s.begin(ctx, "exists", key); err != nil {
		return false, err
	}
	bus, err := s.connect(ctx, "exists")
	if err != nil {
		return false, err
	}
	defer bus.close()
	collection, err := s.defaultCollection(ctx, bus, "exists")
	if err != nil {
		return false, err
	}
	items, err := s.search(ctx, bus, "exists", collection, key)
	if err != nil {
		return false, err
	}
	return len(items) > 0, nil
}

// Delete implements Store. It removes every item with the key's attributes.
func (s *secretServiceStore) Delete(ctx context.Context, key Key) error {
	if err := s.begin(ctx, "delete", key); err != nil {
		return err
	}
	bus, err := s.connect(ctx, "delete")
	if err != nil {
		return err
	}
	defer bus.close()
	collection, err := s.defaultCollection(ctx, bus, "delete")
	if err != nil {
		return err
	}
	return s.removeMatching(ctx, bus, "delete", collection, key, noObject)
}

// removeMatching deletes every item with key's attributes except keep. A search
// is cut at maxSearchResults, so it searches and deletes again until a search
// finds nothing to delete. Matches that survive maxRemoveRounds rounds, because
// the provider keeps them or something keeps adding them, are
// ReasonTooManyMatches and not a success.
func (s *secretServiceStore) removeMatching(ctx context.Context, bus ssBus, op string, collection dbus.ObjectPath, key Key, keep dbus.ObjectPath) error {
	for range maxRemoveRounds {
		removed, err := s.removeRound(ctx, bus, op, collection, key, keep)
		if err != nil {
			return err
		}
		if !removed {
			return nil
		}
	}
	// The last round may have removed the last of them; only a search can tell.
	rest, err := s.searchOthers(ctx, bus, op, collection, key, keep)
	if err != nil {
		return err
	}
	if len(rest) > 0 {
		return s.fail(op, KindOther, ReasonTooManyMatches)
	}
	return nil
}

// searchOthers returns the matches of key other than keep.
func (s *secretServiceStore) searchOthers(ctx context.Context, bus ssBus, op string, collection dbus.ObjectPath, key Key, keep dbus.ObjectPath) ([]dbus.ObjectPath, error) {
	items, err := s.search(ctx, bus, op, collection, key)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(items, func(item dbus.ObjectPath) bool { return item == keep }), nil
}

// removeRound deletes one search's matches other than keep and reports whether
// there were any.
func (s *secretServiceStore) removeRound(ctx context.Context, bus ssBus, op string, collection dbus.ObjectPath, key Key, keep dbus.ObjectPath) (bool, error) {
	items, err := s.searchOthers(ctx, bus, op, collection, key, keep)
	if err != nil {
		return false, err
	}
	for _, item := range items {
		if err := s.deleteItem(ctx, bus, op, item); err != nil {
			return false, err
		}
	}
	return len(items) > 0, nil
}

// deleteItem removes one item. An item that is already gone is a success.
func (s *secretServiceStore) deleteItem(ctx context.Context, bus ssBus, op string, item dbus.ObjectPath) error {
	if err := s.ensureUnlocked(ctx, bus, op, item, ifaceItem); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	body, err := bus.call(ctx, item, methodDeleteItem)
	if err != nil {
		if isErrorName(err, errNameNoSuchObject) {
			return nil
		}
		return s.failure(op, err)
	}
	if len(body) != 1 {
		return s.malformed(op)
	}
	prompt, ok := body[0].(dbus.ObjectPath)
	if !ok || !prompt.IsValid() {
		return s.malformed(op)
	}
	if prompt == noObject {
		return nil
	}
	_, err = s.promptOrRefuse(ctx, bus, op, prompt)
	return err
}

// ssSecret is the Secret Service secret structure (oayays).
type ssSecret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

// parseSecret reads the secret structure of a GetSecret reply.
func parseSecret(v any) (ssSecret, bool) {
	switch fields := v.(type) {
	case ssSecret:
		return fields, true
	case []any:
		if len(fields) != 4 {
			return ssSecret{}, false
		}
		session, ok1 := fields[0].(dbus.ObjectPath)
		params, ok2 := fields[1].([]byte)
		value, ok3 := fields[2].([]byte)
		ctype, ok4 := fields[3].(string)
		if !ok1 || !ok2 || !ok3 || !ok4 {
			return ssSecret{}, false
		}
		return ssSecret{Session: session, Parameters: params, Value: value, ContentType: ctype}, true
	default:
		return ssSecret{}, false
	}
}

// ssSession is an open Secret Service session. aesKey is nil for the plain
// algorithm.
type ssSession struct {
	path   dbus.ObjectPath
	aesKey []byte
}

// wipe zeroes the session key.
func (ss *ssSession) wipe() {
	clear(ss.aesKey)
}

// openSession negotiates the session. DH is preferred; the plain algorithm is
// used only when the provider answers NotSupported to the DH request. Any
// other failure stops the operation, so a provider cannot be talked into
// plain by an unrelated error.
func (s *secretServiceStore) openSession(ctx context.Context, bus ssBus, op string) (*ssSession, error) {
	if !s.plainOnly {
		session, err := s.openDHSession(ctx, bus, op)
		if err == nil {
			s.noteSession(dhAlgorithm)
			return session, nil
		}
		var se *Error
		if !errors.As(err, &se) || se.Reason != ReasonNotSupported {
			return nil, err
		}
	}
	body, err := bus.call(ctx, servicePath, methodOpenSession, "plain", dbus.MakeVariant(""))
	if err != nil {
		return nil, s.failure(op, err)
	}
	path, ok := sessionPath(body)
	if !ok {
		return nil, s.fail(op, KindCorrupt, "")
	}
	s.noteSession("plain")
	return &ssSession{path: path}, nil
}

func (s *secretServiceStore) noteSession(algorithm string) {
	if s.onSession != nil {
		s.onSession(algorithm)
	}
}

// sessionPath returns the session path of an OpenSession reply (output, path).
func sessionPath(body []any) (dbus.ObjectPath, bool) {
	if len(body) != 2 {
		return "", false
	}
	path, ok := body[1].(dbus.ObjectPath)
	if !ok || !path.IsValid() || path == noObject {
		return "", false
	}
	return path, true
}

func (s *secretServiceStore) openDHSession(ctx context.Context, bus ssBus, op string) (*ssSession, error) {
	pair, err := newDHKeyPair(s.random)
	if err != nil {
		return nil, s.fail(op, KindOther, ReasonOther)
	}
	defer pair.wipe()
	body, err := bus.call(ctx, servicePath, methodOpenSession, dhAlgorithm, dbus.MakeVariant(pair.pub))
	if err != nil {
		return nil, s.failure(op, err)
	}
	path, ok := sessionPath(body)
	if !ok {
		return nil, s.fail(op, KindCorrupt, "")
	}
	output, ok := body[0].(dbus.Variant)
	if !ok {
		return nil, s.fail(op, KindCorrupt, "")
	}
	peer, ok := output.Value().([]byte)
	if !ok {
		return nil, s.fail(op, KindCorrupt, "")
	}
	key, err := pair.deriveKey(peer)
	if err != nil {
		return nil, s.fail(op, KindCorrupt, "")
	}
	return &ssSession{path: path, aesKey: key}, nil
}

// Load implements Store. More than one matching item is KindCorrupt: the
// module never writes two, so something else did.
func (s *secretServiceStore) Load(ctx context.Context, key Key) ([]byte, error) {
	if err := s.begin(ctx, "load", key); err != nil {
		return nil, err
	}
	bus, err := s.connect(ctx, "load")
	if err != nil {
		return nil, err
	}
	defer bus.close()
	collection, err := s.defaultCollection(ctx, bus, "load")
	if err != nil {
		return nil, err
	}
	items, err := s.search(ctx, bus, "load", collection, key)
	if err != nil {
		return nil, err
	}
	switch len(items) {
	case 0:
		return nil, s.fail("load", KindNotFound, "")
	case 1:
	default:
		return nil, s.fail("load", KindCorrupt, "")
	}
	if err := s.ensureUnlocked(ctx, bus, "load", items[0], ifaceItem); err != nil {
		return nil, err
	}
	session, err := s.openSession(ctx, bus, "load")
	if err != nil {
		return nil, err
	}
	defer session.wipe()
	body, err := bus.call(ctx, items[0], methodGetSecret, session.path)
	if err != nil {
		return nil, s.failure("load", err)
	}
	if len(body) != 1 {
		return nil, s.malformed("load")
	}
	secret, ok := parseSecret(body[0])
	if !ok {
		return nil, s.malformed("load")
	}
	return s.unseal(session, secret)
}

// unseal turns the secret of a reply into plaintext, checking the bound before
// any decryption. The reply's buffers are wiped.
func (s *secretServiceStore) unseal(session *ssSession, secret ssSecret) ([]byte, error) {
	if session.aesKey == nil {
		if len(secret.Value) > s.max {
			clear(secret.Value)
			return nil, s.fail("load", KindTooLarge, "")
		}
		if len(secret.Value) == 0 {
			return nil, s.fail("load", KindCorrupt, "")
		}
		return secret.Value, nil
	}
	defer clear(secret.Value)
	// The ciphertext is the plaintext plus 1 to 16 padding bytes.
	if len(secret.Value) > s.max+aes.BlockSize {
		return nil, s.fail("load", KindTooLarge, "")
	}
	plain, err := dhDecrypt(session.aesKey, secret.Parameters, secret.Value)
	if err != nil {
		return nil, s.fail("load", KindCorrupt, "")
	}
	if len(plain) > s.max {
		clear(plain)
		return nil, s.fail("load", KindTooLarge, "")
	}
	if len(plain) == 0 {
		return nil, s.fail("load", KindCorrupt, "")
	}
	return plain, nil
}

// seal builds the secret structure for CreateItem. The returned wipe function
// zeroes the buffers the structure holds that are not the caller's.
func (s *secretServiceStore) seal(op string, session *ssSession, secret []byte) (ssSecret, func(), error) {
	if session.aesKey == nil {
		return ssSecret{Session: session.path, Parameters: []byte{}, Value: secret, ContentType: contentType}, func() {}, nil
	}
	iv, ciphertext, err := dhEncrypt(session.aesKey, secret, s.random)
	if err != nil {
		return ssSecret{}, nil, s.fail(op, KindOther, ReasonOther)
	}
	wipe := func() { clear(ciphertext) }
	return ssSecret{Session: session.path, Parameters: iv, Value: ciphertext, ContentType: contentType}, wipe, nil
}

// Save implements Store. CreateItem with replace set swaps an existing item
// with the same attributes; any other item that still matches afterwards is
// removed, so Load never sees two. Save returns nil only with proof that an
// item for the key exists: the path CreateItem or its prompt returned, or a
// search after a prompt that named none.
func (s *secretServiceStore) Save(ctx context.Context, key Key, secret []byte) error {
	if err := s.begin(ctx, "save", key); err != nil {
		return err
	}
	if len(secret) == 0 {
		return s.fail("save", KindInvalidArgument, "")
	}
	if len(secret) > s.max {
		return s.fail("save", KindTooLarge, "")
	}
	bus, err := s.connect(ctx, "save")
	if err != nil {
		return err
	}
	defer bus.close()
	collection, err := s.defaultCollection(ctx, bus, "save")
	if err != nil {
		return err
	}
	if err := s.ensureUnlocked(ctx, bus, "save", collection, ifaceCollection); err != nil {
		return err
	}
	session, err := s.openSession(ctx, bus, "save")
	if err != nil {
		return err
	}
	defer session.wipe()
	sealed, wipe, err := s.seal("save", session, secret)
	if err != nil {
		return err
	}
	properties := map[string]dbus.Variant{
		propLabel:      dbus.MakeVariant(key.Service + " (" + key.Account + ")"),
		propAttributes: dbus.MakeVariant(s.attributes(key)),
	}
	body, err := bus.call(ctx, collection, methodCreateItem, properties, sealed, true)
	wipe()
	if err != nil {
		return s.failure("save", err)
	}
	if len(body) != 2 {
		return s.malformed("save")
	}
	item, ok1 := body[0].(dbus.ObjectPath)
	prompt, ok2 := body[1].(dbus.ObjectPath)
	if !ok1 || !ok2 || !item.IsValid() || !prompt.IsValid() {
		return s.malformed("save")
	}
	if prompt == noObject {
		// No prompt means the item exists, so its path must name it.
		if item == noObject {
			return s.malformed("save")
		}
		return s.removeMatching(ctx, bus, "save", collection, key, item)
	}
	result, err := s.promptOrRefuse(ctx, bus, "save", prompt)
	if err != nil {
		return err
	}
	if created, ok := result.Value().(dbus.ObjectPath); ok && created.IsValid() && created != noObject {
		item = created
	}
	if item == noObject {
		return s.confirmSaved(ctx, bus, collection, key)
	}
	return s.removeMatching(ctx, bus, "save", collection, key, item)
}

// confirmSaved is the end of a Save whose prompt completed without naming the
// item it created. Nothing proves the write, so it searches for the key's
// items: none means the Save did not store anything and fails. Otherwise a
// match is the item just written or one that was there before, and which is
// unknown, so nothing is removed: guessing could delete the item just written.
func (s *secretServiceStore) confirmSaved(ctx context.Context, bus ssBus, collection dbus.ObjectPath, key Key) error {
	items, err := s.search(ctx, bus, "save", collection, key)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return s.malformed("save")
	}
	return nil
}

// openSecretService builds the store over the session bus at addr and checks
// that a provider owns the default collection. connect opens a connection to
// one of the endpoints addr names, in order.
func openSecretService(ctx context.Context, opts Options, addr string, connect func(ctx context.Context, endpoints []busEndpoint) (ssBus, error)) (Store, error) {
	endpoints, err := parseBusAddress(addr)
	if err != nil {
		return nil, &Error{Op: "open", Backend: secretServiceBackend, Kind: KindUnavailable}
	}
	s := newSecretServiceStore(func(ctx context.Context) (ssBus, error) {
		return connect(ctx, endpoints)
	}, opts)
	if err := s.probe(ctx); err != nil {
		return nil, err
	}
	return s, nil
}
