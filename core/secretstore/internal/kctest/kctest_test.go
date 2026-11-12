//go:build darwin && cgo && keychainintegration

package kctest

import (
	"errors"
	"testing"
)

// A closed or deleted keychain holds a NULL reference, which the Security calls
// read as the user's default keychain. Every method must refuse before that.
func TestClosedKeychainRefusesEveryCall(t *testing.T) {
	k := &Keychain{}
	calls := map[string]func() error{
		"Lock":   k.Lock,
		"Unlock": k.Unlock,
		"Unlocked": func() error {
			_, err := k.Unlocked()
			return err
		},
		"ACL": func() error {
			_, err := k.ACL("service", "account")
			return err
		},
		"ImportPEM": func() error { return k.ImportPEM([]byte("x")) },
		"Sign":      func() error { return k.Sign("name", "/nonexistent", "id") },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			if err := call(); !errors.Is(err, errClosed) {
				t.Fatalf("error = %v, want errClosed", err)
			}
		})
	}
}
