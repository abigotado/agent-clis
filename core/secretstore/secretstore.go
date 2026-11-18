package secretstore

import (
	"context"
	"errors"
	"syscall"
)

// MaxSecretBytesLimit is the largest MaxSecretBytes an Options value accepts.
const MaxSecretBytesLimit = 128 << 10

// Interaction says whether the store may ask the user for anything.
type Interaction int

const (
	// InteractionNever is the default: the store fails with
	// ErrInteractionRequired instead of prompting. Agents always run here.
	InteractionNever Interaction = iota
	// InteractionAllowed lets the store show unlock and approval prompts. Use
	// it only in explicit interactive flows.
	InteractionAllowed
)

// Key names one secret.
type Key struct {
	// Service identifies the caller, such as "youtrack-agent-cli": 1-64 bytes
	// of ASCII letters, digits, '.', '_' and '-', starting with a letter or
	// digit.
	Service string
	// Account distinguishes secrets of one service, such as a profile name:
	// 1-128 bytes of valid UTF-8 with no control character, no U+241F, and no
	// '#'. Accounts are case-sensitive and wildcard characters are ordinary.
	Account string
}

// Options configure Open.
type Options struct {
	// MaxSecretBytes bounds Save and Load; it must be 1..MaxSecretBytesLimit.
	MaxSecretBytes int
	// Interaction is the process-wide interaction mode.
	Interaction Interaction
}

// Store keeps secrets in the platform credential store. Every method returns
// an *Error for a store failure, a context error for a canceled context, and an
// error matching ErrInvalidArgument for an invalid key.
type Store interface {
	// Exists reports whether an item exists. It returns no secret.
	Exists(ctx context.Context, key Key) (bool, error)
	// Load returns a copy of the secret; the caller zeroes it after use.
	Load(ctx context.Context, key Key) ([]byte, error)
	// Save stores secret, replacing any existing item. An empty secret is
	// ErrInvalidArgument and one above the bound is ErrTooLarge, both before
	// the store is touched.
	Save(ctx context.Context, key Key, secret []byte) error
	// Delete removes the item. Deleting a missing item succeeds.
	Delete(ctx context.Context, key Key) error
}

// ACLRepairer is implemented by the macOS store and the in-memory fake. It
// rewrites an item so the running binary can read it again.
type ACLRepairer interface {
	// RepairAccess needs InteractionAllowed and trusts only the running binary.
	RepairAccess(ctx context.Context, key Key) error
}

// Open returns the native store for this operating system. It never returns a
// file-backed store; where no backend exists it fails with ErrUnavailable.
//
// The first Open with valid options in a process fixes the Interaction mode,
// even if that Open then fails (for example on a canceled context); Open with
// invalid options fixes nothing. A later Open with a different mode fails with
// ErrInvalidArgument.
// Open performs no recovery of interrupted writes.
func Open(ctx context.Context, opts Options) (Store, error) {
	if err := validateOptions(opts); err != nil {
		return nil, err
	}
	if !processMode.fix(opts.Interaction) {
		return nil, newError("open", "none", KindInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return nil, contextError("open", err)
	}
	return openNative(ctx, opts)
}

// DisableCoreDumps sets the soft and hard core-file size limits to zero so a
// crash cannot write secrets to disk. It does nothing on systems without
// RLIMIT_CORE. The limits can only be raised again by a privileged process. A
// failure is an *Error of KindOther whose Status is the errno when there is
// one; it carries no operating-system text.
func DisableCoreDumps() error {
	return disableCoreDumpsWith(disableCoreDumps)
}

func disableCoreDumpsWith(disable func() error) error {
	err := disable()
	if err == nil {
		return nil
	}
	e := &Error{Op: "disable-core-dumps", Backend: "none", Kind: KindOther}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		e.Status = int64(errno)
	}
	return e
}
