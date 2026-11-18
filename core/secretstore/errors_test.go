package secretstore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

var kindCases = []struct {
	kind     Kind
	name     string
	sentinel error
}{
	{KindOther, "other", nil},
	{KindNotFound, "not-found", ErrNotFound},
	{KindAccessDenied, "access-denied", ErrAccessDenied},
	{KindInteractionRequired, "interaction-required", ErrInteractionRequired},
	{KindUnavailable, "unavailable", ErrUnavailable},
	{KindReadOnly, "read-only", ErrReadOnly},
	{KindContended, "contended", ErrContended},
	{KindTooLarge, "too-large", ErrTooLarge},
	{KindCorrupt, "corrupt", ErrCorrupt},
	{KindCanceled, "canceled", ErrCanceled},
	{KindInvalidArgument, "invalid-argument", ErrInvalidArgument},
}

func TestKindString(t *testing.T) {
	for _, tt := range kindCases {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.kind.String(); got != tt.name {
				t.Fatalf("Kind(%d).String() = %q, want %q", int(tt.kind), got, tt.name)
			}
		})
	}
	t.Run("unknown kind", func(t *testing.T) {
		if got := Kind(99).String(); got != "kind(99)" {
			t.Fatalf("Kind(99).String() = %q, want kind(99)", got)
		}
	})
}

func TestErrorMatchesItsKindOnly(t *testing.T) {
	for _, tt := range kindCases {
		t.Run(tt.name, func(t *testing.T) {
			err := error(&Error{Op: "load", Backend: "memory", Kind: tt.kind})
			wrapped := fmt.Errorf("outer: %w", err)
			for _, other := range kindCases {
				if other.sentinel == nil {
					continue
				}
				want := other.kind == tt.kind
				if got := errors.Is(wrapped, other.sentinel); got != want {
					t.Errorf("errors.Is(%v kind, %v) = %v, want %v", tt.name, other.sentinel, got, want)
				}
			}
			var se *Error
			if !errors.As(wrapped, &se) || se.Kind != tt.kind {
				t.Fatalf("errors.As lost the *Error: %v", wrapped)
			}
			if tt.sentinel == nil && errors.Unwrap(err) != nil {
				t.Fatalf("KindOther unwraps to %v, want nil", errors.Unwrap(err))
			}
		})
	}
}

func TestErrorText(t *testing.T) {
	tests := []struct {
		name string
		err  Error
		want string
	}{
		{"kind only", Error{Op: "load", Backend: "memory", Kind: KindNotFound}, "secretstore: load (memory): not-found"},
		{"with status", Error{Op: "save", Backend: "keychain", Kind: KindOther, Status: -25299}, "secretstore: save (keychain): other status -25299"},
		{"with reason", Error{Op: "open", Backend: "secretservice", Kind: KindUnavailable, Reason: ReasonServiceUnknown}, "secretstore: open (secretservice): unavailable service-unknown"},
		{"with status and reason", Error{Op: "delete", Backend: "credman", Kind: KindOther, Status: 5, Reason: ReasonAccessDenied}, "secretstore: delete (credman): other status 5 access-denied"},
		{"keychain unusable", Error{Op: "load", Backend: "keychain", Kind: KindUnavailable, Status: -50, Reason: ReasonKeychainUnusable}, "secretstore: load (keychain): unavailable status -50 keychain-unusable"},
		{"foreign reason text is not echoed", Error{Op: "load", Backend: "secretservice", Kind: KindOther, Reason: "org.example.Error: key=hunter2"}, "secretstore: load (secretservice): other other"},
		{"foreign op and backend are not echoed", Error{Op: "load key=hunter2", Backend: "svc=hunter2", Kind: KindNotFound}, "secretstore: other (other): not-found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Fatalf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReasonSetIsClosed(t *testing.T) {
	want := map[Reason]string{
		ReasonServiceUnknown:   "service-unknown",
		ReasonNameHasNoOwner:   "name-has-no-owner",
		ReasonNoReply:          "no-reply",
		ReasonNotSupported:     "not-supported",
		ReasonIsLocked:         "is-locked",
		ReasonNoSession:        "no-session",
		ReasonNoSuchObject:     "no-such-object",
		ReasonAccessDenied:     "access-denied",
		ReasonTooManyMatches:   "too-many-matches",
		ReasonKeychainUnusable: "keychain-unusable",
		ReasonOther:            "other",
	}
	for reason, text := range want {
		t.Run(text, func(t *testing.T) {
			if string(reason) != text || !reason.known() {
				t.Fatalf("reason %q: known=%v, want %q", reason, reason.known(), text)
			}
		})
	}
	t.Run("unknown reasons are not known", func(t *testing.T) {
		for _, r := range []Reason{"", "bogus", "Other"} {
			if r.known() {
				t.Errorf("Reason(%q).known() = true", r)
			}
		}
	})
}

func TestContextErrorKeepsTheCause(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(cause.Error(), func(t *testing.T) {
			err := contextError("load", cause)
			if !errors.Is(err, cause) {
				t.Fatalf("contextError lost %v: %v", cause, err)
			}
			if errors.Is(err, ErrCanceled) {
				t.Fatalf("a context error must not match ErrCanceled (dialog dismissal only): %v", err)
			}
			if !strings.HasPrefix(err.Error(), "secretstore: load: ") {
				t.Fatalf("contextError text = %q", err)
			}
		})
	}
}

func TestErrorGoStringIsSanitized(t *testing.T) {
	tests := []struct {
		name string
		err  *Error
		want string
	}{
		{"known fields", &Error{Op: "load", Backend: "memory", Kind: KindNotFound, Status: 7, Reason: ReasonIsLocked}, `secretstore.Error{Op:"load", Backend:"memory", Kind:"not-found", Status:7, Reason:"is-locked"}`},
		{"no reason", &Error{Op: "save", Backend: "none", Kind: KindOther}, `secretstore.Error{Op:"save", Backend:"none", Kind:"other", Status:0, Reason:""}`},
		{"unknown reason", &Error{Op: "load", Backend: "memory", Kind: KindOther, Reason: "key=hunter2"}, `secretstore.Error{Op:"load", Backend:"memory", Kind:"other", Status:0, Reason:"other"}`},
		{"unknown op and backend", &Error{Op: "op=hunter2", Backend: "b=hunter2", Kind: KindOther}, `secretstore.Error{Op:"other", Backend:"other", Kind:"other", Status:0, Reason:""}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fmt.Sprintf("%#v", tt.err); got != tt.want {
				t.Fatalf("%%#v = %s, want %s", got, tt.want)
			}
			if got := fmt.Sprintf("%#v", *tt.err); got != tt.want {
				t.Fatalf("%%#v of a value = %s, want %s", got, tt.want)
			}
			if got := fmt.Sprintf("%#v", error(tt.err)); strings.Contains(got, "hunter2") {
				t.Fatalf("%%#v through the error interface leaks: %s", got)
			}
		})
	}
}
