//go:build darwin && cgo

package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/abigotado/agent-clis/core/secretstore"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/profile"
)

// OpenFunc opens the native secret store. Production passes secretstore.Open;
// tests pass a function that returns an in-memory fake.
type OpenFunc func(context.Context, secretstore.Options) (secretstore.Store, error)

// NativeStore keeps YouTrack credentials in the macOS Keychain through
// core/secretstore. It opens the underlying store on first use, so building it
// reads nothing. The interaction mode is fixed process-wide by the first open.
// A successful open and a classified open failure are remembered; a context
// error is not, so a canceled first call cannot poison later calls.
type NativeStore struct {
	interaction secretstore.Interaction
	open        OpenFunc

	mu     sync.Mutex
	opened bool
	store  secretstore.Store
	err    error
}

var _ CredentialAccessStore = (*NativeStore)(nil)

// NewNativeStore returns a lazily opened store with the given interaction mode.
func NewNativeStore(interaction secretstore.Interaction, open OpenFunc) *NativeStore {
	return &NativeStore{interaction: interaction, open: open}
}

// NewDefaultNativeStores returns the production stores: credentials never
// prompt, and repair may prompt for the one explicit migration flow. Neither
// opens the Keychain until it is used.
func NewDefaultNativeStores() (credentials, repair CredentialAccessStore) {
	return newDefaultNativeStores(secretstore.Open)
}

func newDefaultNativeStores(open OpenFunc) (credentials, repair *NativeStore) {
	return NewNativeStore(secretstore.InteractionNever, open), NewNativeStore(secretstore.InteractionAllowed, open)
}

func (s *NativeStore) backend(ctx context.Context) (secretstore.Store, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("credential store open: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.opened {
		return s.store, s.err
	}
	opened, err := s.open(ctx, secretstore.Options{MaxSecretBytes: maxStoredCredentialBytes, Interaction: s.interaction})
	if err != nil {
		mapped := mapNativeError("open", err)
		if errors.Is(mapped, context.Canceled) || errors.Is(mapped, context.DeadlineExceeded) {
			return nil, mapped
		}
		s.opened, s.err = true, mapped
		return nil, mapped
	}
	s.opened, s.store = true, opened
	return s.store, nil
}

func nativeKey(profileName string) (secretstore.Key, error) {
	if err := profile.ValidateName(profileName); err != nil {
		return secretstore.Key{}, err
	}
	return secretstore.Key{Service: KeychainService, Account: profileName}, nil
}

// Exists reports whether the exact profile account has an item, without
// returning its secret.
func (s *NativeStore) Exists(ctx context.Context, profileName string) (bool, error) {
	key, err := nativeKey(profileName)
	if err != nil {
		return false, err
	}
	store, err := s.backend(ctx)
	if err != nil {
		return false, err
	}
	exists, err := store.Exists(ctx, key)
	if err != nil {
		return false, mapNativeError("exists", err)
	}
	return exists, nil
}

// Load reads and decodes the credential, then zeroes the raw bytes it read.
func (s *NativeStore) Load(ctx context.Context, profileName string) (Credential, error) {
	key, err := nativeKey(profileName)
	if err != nil {
		return Credential{}, err
	}
	store, err := s.backend(ctx)
	if err != nil {
		return Credential{}, err
	}
	raw, err := store.Load(ctx, key)
	// Best effort: only this Go copy is cleared, never the platform's.
	defer clear(raw)
	if err != nil {
		return Credential{}, mapNativeError("load", err)
	}
	if len(raw) == 0 || len(raw) > maxStoredCredentialBytes {
		return Credential{}, fmt.Errorf("stored credential is invalid: %w", ErrInvalidToken)
	}
	return decodeCredentialValue(raw)
}

// Save encodes the credential with the stored-payload codec and writes it.
func (s *NativeStore) Save(ctx context.Context, profileName string, credential Credential) error {
	key, err := nativeKey(profileName)
	if err != nil {
		return err
	}
	encoded, err := encodeCredentialValue(credential)
	if err != nil {
		return err
	}
	defer clear(encoded)
	store, err := s.backend(ctx)
	if err != nil {
		return err
	}
	if err := store.Save(ctx, key, encoded); err != nil {
		return mapNativeError("save", err)
	}
	return nil
}

// Delete removes the item for the exact profile account.
func (s *NativeStore) Delete(ctx context.Context, profileName string) error {
	key, err := nativeKey(profileName)
	if err != nil {
		return err
	}
	store, err := s.backend(ctx)
	if err != nil {
		return err
	}
	if err := store.Delete(ctx, key); err != nil {
		return mapNativeError("delete", err)
	}
	return nil
}

// MigrateKeychain is not implemented yet: until the repair path lands it
// reports the migration as unavailable instead of touching the item.
func (s *NativeStore) MigrateKeychain(ctx context.Context, profileName string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := nativeKey(profileName); err != nil {
		return err
	}
	return ErrKeychainMigrationUnavailable
}

// mapNativeError turns a core/secretstore failure into this package's
// sentinels. The reason is checked before the kind, so a keychain that cannot
// be used from this process is never read as a missing or expired credential.
// The wrapped text comes from core's closed vocabulary and carries no secret,
// key, or operating-system text.
func mapNativeError(operation string, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("credential store %s: %w", operation, err)
	}
	var storeErr *secretstore.Error
	if !errors.As(err, &storeErr) {
		return fmt.Errorf("%w: %s returned an unclassified failure", ErrCredentialStoreInternal, operation)
	}
	if storeErr.Reason == secretstore.ReasonKeychainUnusable {
		return fmt.Errorf("%w: %v", ErrCredentialStoreUnavailable, err)
	}
	switch storeErr.Kind {
	case secretstore.KindUnavailable:
		return fmt.Errorf("%w: %v", ErrCredentialStoreUnavailable, err)
	case secretstore.KindReadOnly:
		return fmt.Errorf("%w: %v", ErrCredentialStoreReadOnly, err)
	case secretstore.KindContended:
		return fmt.Errorf("%w: %v", ErrCredentialStoreContended, err)
	case secretstore.KindNotFound:
		return fmt.Errorf("%w: %v", ErrNotFound, err)
	case secretstore.KindAccessDenied:
		return fmt.Errorf("%w: %v", ErrKeychainMigrationRequired, err)
	case secretstore.KindInteractionRequired:
		return fmt.Errorf("%w: %v", ErrInteractionNotAllowed, err)
	case secretstore.KindCanceled:
		return fmt.Errorf("%w: %v", ErrKeychainMigrationCanceled, err)
	case secretstore.KindCorrupt, secretstore.KindTooLarge:
		if operation == "load" {
			return fmt.Errorf("stored credential is invalid: %w", ErrInvalidToken)
		}
		return fmt.Errorf("%w: %v", ErrCredentialStoreInternal, err)
	case secretstore.KindInvalidArgument:
		return fmt.Errorf("%w: %v", ErrCredentialStoreInternal, err)
	default:
		return &StatusError{Operation: operation, Status: storeErr.Status}
	}
}
