//go:build darwin && cgo && !keychainintegration

package secretstore

import (
	"context"
	"fmt"
	"slices"
	"testing"
)

// These scenarios read uiSetterCalls, which the stub in
// keychain_darwin_stub_test.go records, so they exist only without the
// keychainintegration tag. Under that tag the main_test.go helpers that call
// Open reach the real setter in their subprocesses; that is allowed for tagged
// runs.

func init() {
	platformHelpers["keychain-open-never"] = helperKeychainOpenNever
	platformHelpers["keychain-open-allowed"] = helperKeychainOpenAllowed
}

func helperKeychainOpenNever() error {
	uiSetterCalls = nil
	store, err := Open(context.Background(), Options{MaxSecretBytes: 1024, Interaction: InteractionNever})
	if err != nil {
		return fmt.Errorf("Open: %w", err)
	}
	if _, ok := store.(*keychainStore); !ok {
		return fmt.Errorf("Open returned %T, want *keychainStore", store)
	}
	if !slices.Equal(uiSetterCalls, []bool{false}) {
		return fmt.Errorf("setter calls = %v, want [false]", uiSetterCalls)
	}
	_, err = Open(context.Background(), Options{MaxSecretBytes: 1024, Interaction: InteractionAllowed})
	if err := wantInvalidOpen("conflicting Open", err); err != nil {
		return err
	}
	if !slices.Equal(uiSetterCalls, []bool{false}) {
		return fmt.Errorf("a refused Open changed the setting: calls = %v", uiSetterCalls)
	}
	return nil
}

func helperKeychainOpenAllowed() error {
	uiSetterCalls = nil
	if _, err := Open(context.Background(), Options{MaxSecretBytes: 1024, Interaction: InteractionAllowed}); err != nil {
		return fmt.Errorf("Open: %w", err)
	}
	_, err := Open(context.Background(), Options{MaxSecretBytes: 1024, Interaction: InteractionNever})
	if err := wantInvalidOpen("conflicting Open", err); err != nil {
		return err
	}
	if len(uiSetterCalls) != 0 {
		return fmt.Errorf("setter calls = %v, want none", uiSetterCalls)
	}
	return nil
}

func TestOpenSetsTheInteractionModeProcessWide(t *testing.T) {
	t.Run("never", func(t *testing.T) { runHelperProcess(t, "keychain-open-never") })
	t.Run("allowed", func(t *testing.T) { runHelperProcess(t, "keychain-open-allowed") })
}
