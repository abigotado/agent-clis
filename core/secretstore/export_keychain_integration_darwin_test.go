//go:build darwin && cgo && keychainintegration

package secretstore

import (
	"context"
	"errors"
	"fmt"
)

// The helpers below reach the keychain store from the external test package,
// which cannot import unexported identifiers. secretstoretest imports this
// package, so the integration test that runs its contract has to be external.

// NewKeychainStoreForTest returns the macOS store over a scratch keychain,
// without going through Open, which fixes the process-wide interaction mode.
// target is a SecKeychainRef as an integer. A zero target is refused: it would
// mean the default keychain, which a test must never reach.
func NewKeychainStoreForTest(maxSecretBytes int, interaction Interaction, target uintptr) (Store, error) {
	if target == 0 {
		return nil, errors.New("secretstore: the keychain test harness needs a scratch keychain, not the default one")
	}
	return newKeychainStore(Options{MaxSecretBytes: maxSecretBytes, Interaction: interaction}, keychainRef(target)), nil
}

func keychainStoreOf(s Store) (*keychainStore, *keychainItems, error) {
	ks, ok := s.(*keychainStore)
	if !ok {
		return nil, nil, fmt.Errorf("secretstore: store is %T, want *keychainStore", s)
	}
	items, ok := ks.api.(*keychainItems)
	if !ok {
		return nil, nil, fmt.Errorf("secretstore: store backend is %T, want *keychainItems", ks.api)
	}
	return ks, items, nil
}

// KeychainStoreFailsUIForTest reports whether the store's lookups, reads and
// deletes carry kSecUseAuthenticationUIFail, which InteractionNever sets.
func KeychainStoreFailsUIForTest(s Store) (bool, error) {
	_, items, err := keychainStoreOf(s)
	if err != nil {
		return false, err
	}
	return items.uiFail, nil
}

// AddLeftoverStageForTest creates the stage item of key with value, the way an
// interrupted Save leaves it: through the same add primitive, so it carries the
// same access control list.
func AddLeftoverStageForTest(ctx context.Context, s Store, key Key, value []byte) error {
	_, items, err := keychainStoreOf(s)
	if err != nil {
		return err
	}
	return items.add(ctx, itemName{service: key.Service, account: key.Account}.stage(), value)
}

// AddAccountItemForTest creates the account item of key with value through the
// add primitive alone, without the staged sequence: no roll-forward and no
// stage. It is what a competing writer that recreates the item does.
func AddAccountItemForTest(ctx context.Context, s Store, key Key, value []byte) error {
	_, items, err := keychainStoreOf(s)
	if err != nil {
		return err
	}
	return items.add(ctx, itemName{service: key.Service, account: key.Account}, value)
}

// SetAfterStepForTest installs the hook that runs after each completed step of
// Save's own sequence, or removes it with nil.
func SetAfterStepForTest(s Store, hook func(step int)) error {
	ks, _, err := keychainStoreOf(s)
	if err != nil {
		return err
	}
	ks.afterStep = hook
	return nil
}

// StageExistsForTest reports whether the stage item of key exists.
func StageExistsForTest(ctx context.Context, s Store, key Key) (bool, error) {
	_, items, err := keychainStoreOf(s)
	if err != nil {
		return false, err
	}
	return items.exists(ctx, itemName{service: key.Service, account: key.Account}.stage())
}

// StageAccountForTest returns the account name of key's stage item, so a test
// can look it up in the keychain directly.
func StageAccountForTest(key Key) string {
	return itemName{service: key.Service, account: key.Account}.stage().account
}
