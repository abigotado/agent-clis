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

// ReadAccountItemForTest reads the account item of key alone, ignoring its
// stage, which Load would read first.
func ReadAccountItemForTest(ctx context.Context, s Store, key Key) ([]byte, error) {
	ks, items, err := keychainStoreOf(s)
	if err != nil {
		return nil, err
	}
	value, err := items.read(ctx, itemName{service: key.Service, account: key.Account}, ks.max)
	if err != nil {
		return nil, ks.failure("load", err, false)
	}
	return value, nil
}

// KeychainProbe is what one lock probe of the store's keychain reported.
type KeychainProbe struct {
	// Step is the probe call that failed: lookup, copy-keychain, copy-default
	// or get-status, unknown for a status without a step, none when the probe
	// succeeded.
	Step string
	// Status is the OSStatus of the failed call, or 0.
	Status int64
	// Unusable says whether the store's gate reads this probe as
	// keychain-unusable, including the add-target fallback of the item probe.
	Unusable bool
}

func probeStepName(step probeStep) string {
	switch step {
	case probeStepLookup:
		return "lookup"
	case probeStepCopyKeychain:
		return "copy-keychain"
	case probeStepCopyDefault:
		return "copy-default"
	case probeStepGetStatus:
		return "get-status"
	default:
		return "unknown"
	}
}

func reportProbe(unlocked func() (bool, error), gate *Error) KeychainProbe {
	probe := KeychainProbe{Step: "none", Unusable: gate != nil}
	if _, err := unlocked(); err != nil {
		probe.Step = "unknown"
		var se *statusError
		if errors.As(err, &se) {
			probe.Step = probeStepName(se.step)
			probe.Status = se.status
		}
	}
	return probe
}

// ProbeKeychainForTest runs the store's two lock probes for key's account item
// and reports each one's failing step and status, and whether the store's gate
// reads it as unusable: item is the probe taken before a lookup, read or
// delete, add the one taken before an add. It touches no item.
func ProbeKeychainForTest(ctx context.Context, s Store, key Key) (item, add KeychainProbe, err error) {
	ks, items, err := keychainStoreOf(s)
	if err != nil {
		return KeychainProbe{}, KeychainProbe{}, err
	}
	name := itemName{service: key.Service, account: key.Account}
	_, itemGate := ks.beforeProbe(ctx, "load", name, false)
	_, addGate := ks.beforeProbe(ctx, "save", name, true)
	item = reportProbe(func() (bool, error) { return items.keychainUnlocked(ctx, name) }, itemGate)
	add = reportProbe(func() (bool, error) { return items.addKeychainUnlocked(ctx, name) }, addGate)
	return item, add, nil
}
