package secretstore

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Kind classifies a failure by the action the caller should take next.
type Kind int

// The kinds an *Error can carry. KindOther is the zero value and has no
// sentinel; its Status or Reason describes the failure.
const (
	// KindOther is a failure no other kind describes.
	KindOther Kind = iota
	// KindNotFound means no item exists for the key.
	KindNotFound
	// KindAccessDenied means the item exists but this code identity may not
	// read it.
	KindAccessDenied
	// KindInteractionRequired means the store needs user interaction, such as
	// unlocking, and the Interaction mode is InteractionNever.
	KindInteractionRequired
	// KindUnavailable means no backend is reachable on this system.
	KindUnavailable
	// KindReadOnly means the store refused a write that reads are allowed.
	KindReadOnly
	// KindContended means the item was replaced while Save was running.
	KindContended
	// KindTooLarge means a secret exceeds the configured or backend bound.
	KindTooLarge
	// KindCorrupt means stored data could not be decoded.
	KindCorrupt
	// KindCanceled means the user dismissed an interactive prompt.
	KindCanceled
	// KindInvalidArgument means a key or option was rejected before any store
	// access, or an Open conflicted with the process-wide mode.
	KindInvalidArgument
)

// String returns a stable lower-case name for the kind.
func (k Kind) String() string {
	switch k {
	case KindOther:
		return "other"
	case KindNotFound:
		return "not-found"
	case KindAccessDenied:
		return "access-denied"
	case KindInteractionRequired:
		return "interaction-required"
	case KindUnavailable:
		return "unavailable"
	case KindReadOnly:
		return "read-only"
	case KindContended:
		return "contended"
	case KindTooLarge:
		return "too-large"
	case KindCorrupt:
		return "corrupt"
	case KindCanceled:
		return "canceled"
	case KindInvalidArgument:
		return "invalid-argument"
	default:
		return "kind(" + strconv.Itoa(int(k)) + ")"
	}
}

// Reason names a provider condition behind an *Error. It is a closed set:
// provider message text never becomes a Reason.
type Reason string

// The closed set of reasons. The empty Reason means none was recorded.
const (
	ReasonServiceUnknown Reason = "service-unknown"
	ReasonNameHasNoOwner Reason = "name-has-no-owner"
	ReasonNoReply        Reason = "no-reply"
	ReasonNotSupported   Reason = "not-supported"
	ReasonIsLocked       Reason = "is-locked"
	ReasonNoSession      Reason = "no-session"
	ReasonNoSuchObject   Reason = "no-such-object"
	ReasonAccessDenied   Reason = "access-denied"
	ReasonOther          Reason = "other"
)

func (r Reason) known() bool {
	switch r {
	case ReasonServiceUnknown, ReasonNameHasNoOwner, ReasonNoReply,
		ReasonNotSupported, ReasonIsLocked, ReasonNoSession,
		ReasonNoSuchObject, ReasonAccessDenied, ReasonOther:
		return true
	default:
		return false
	}
}

// The sentinels errors.Is matches for each Kind except KindOther.
var (
	ErrNotFound            = errors.New("secretstore: not found")
	ErrAccessDenied        = errors.New("secretstore: access denied")
	ErrInteractionRequired = errors.New("secretstore: interaction required")
	ErrUnavailable         = errors.New("secretstore: unavailable")
	ErrReadOnly            = errors.New("secretstore: read-only")
	ErrContended           = errors.New("secretstore: contended")
	ErrTooLarge            = errors.New("secretstore: too large")
	ErrCorrupt             = errors.New("secretstore: corrupt")
	ErrCanceled            = errors.New("secretstore: canceled")
	ErrInvalidArgument     = errors.New("secretstore: invalid argument")
)

// Error is the error every Store method returns for a store failure. Its text
// is built only from the fixed fields below, so it cannot carry a secret, a
// key, or provider text.
type Error struct {
	// Op is the operation: open, exists, load, save, delete, or repair.
	Op string
	// Backend is keychain, credman, secretservice, memory, or none.
	Backend string
	// Kind is the classification errors.Is matches through Unwrap.
	Kind Kind
	// Status is the operating-system status code, or 0 when there is none.
	Status int64
	// Reason is the provider condition, or empty when there is none.
	Reason Reason
}

// knownOp and knownBackend are the closed sets documented on Error. Rendering
// replaces anything else with "other", so a mistaken or hostile field value
// can never reach error text.
func knownOp(op string) string {
	switch op {
	case "open", "exists", "load", "save", "delete", "repair":
		return op
	default:
		return "other"
	}
}

func knownBackend(backend string) string {
	switch backend {
	case "keychain", "credman", "secretservice", "memory", "none":
		return backend
	default:
		return "other"
	}
}

// Error returns "secretstore: <op> (<backend>): <kind>[ status <n>][ <reason>]".
// An Op, Backend or Reason outside its closed set renders as "other".
func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("secretstore: ")
	b.WriteString(knownOp(e.Op))
	b.WriteString(" (")
	b.WriteString(knownBackend(e.Backend))
	b.WriteString("): ")
	b.WriteString(e.Kind.String())
	if e.Status != 0 {
		b.WriteString(" status ")
		b.WriteString(strconv.FormatInt(e.Status, 10))
	}
	if e.Reason != "" {
		reason := e.Reason
		if !reason.known() {
			reason = ReasonOther
		}
		b.WriteByte(' ')
		b.WriteString(string(reason))
	}
	return b.String()
}

// GoString has a value receiver so that %#v of an Error value and of an *Error
// both render the sanitized form, without a leading "&". It renders the error for %#v with the same sanitized fields as Error,
// so the Go-syntax form cannot echo an unknown Reason, Op or Backend.
func (e Error) GoString() string {
	reason := e.Reason
	if reason != "" && !reason.known() {
		reason = ReasonOther
	}
	return fmt.Sprintf("secretstore.Error{Op:%q, Backend:%q, Kind:%q, Status:%d, Reason:%q}",
		knownOp(e.Op), knownBackend(e.Backend), e.Kind.String(), e.Status, string(reason))
}

// Unwrap returns the sentinel for the error's Kind, or nil for KindOther.
func (e *Error) Unwrap() error {
	switch e.Kind {
	case KindNotFound:
		return ErrNotFound
	case KindAccessDenied:
		return ErrAccessDenied
	case KindInteractionRequired:
		return ErrInteractionRequired
	case KindUnavailable:
		return ErrUnavailable
	case KindReadOnly:
		return ErrReadOnly
	case KindContended:
		return ErrContended
	case KindTooLarge:
		return ErrTooLarge
	case KindCorrupt:
		return ErrCorrupt
	case KindCanceled:
		return ErrCanceled
	case KindInvalidArgument:
		return ErrInvalidArgument
	default:
		return nil
	}
}

func newError(op, backend string, kind Kind) *Error {
	return &Error{Op: op, Backend: backend, Kind: kind}
}

// contextError wraps a context failure for op; the context error is kept as
// the cause so errors.Is(err, context.Canceled) works.
func contextError(op string, err error) error {
	return fmt.Errorf("secretstore: %s: %w", op, err)
}
