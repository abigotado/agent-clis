package auth

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestTranslateMigrationStoreError(t *testing.T) {
	tests := []struct {
		name string
		in   error
		want error
	}{
		{"not found", fmt.Errorf("repair: %w", ErrNotFound), ErrKeychainEntryNotFound},
		{"interaction", fmt.Errorf("repair: %w", ErrInteractionNotAllowed), ErrKeychainMigrationBlocked},
		{"canceled dialog", fmt.Errorf("repair: %w", ErrKeychainMigrationCanceled), ErrKeychainMigrationCanceled},
		{"unsupported build", fmt.Errorf("repair: %w", ErrUnsupported), ErrKeychainMigrationUnavailable},
		{"store unavailable", fmt.Errorf("repair: %w", ErrCredentialStoreUnavailable), ErrCredentialStoreUnavailable},
		{"store write refused", fmt.Errorf("repair: %w", ErrCredentialStoreWriteRefused), ErrCredentialStoreWriteRefused},
		{"store read only", fmt.Errorf("repair: %w", ErrCredentialStoreReadOnly), ErrCredentialStoreReadOnly},
		{"store contended", fmt.Errorf("repair: %w", ErrCredentialStoreContended), ErrCredentialStoreContended},
		{"store internal", fmt.Errorf("repair: %w", ErrCredentialStoreInternal), ErrCredentialStoreInternal},
		{"context canceled", fmt.Errorf("repair: %w", context.Canceled), context.Canceled},
		{"repair denied access", fmt.Errorf("repair: %w", ErrKeychainMigrationRequired), ErrKeychainRepairDenied},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := translateMigrationStoreError(test.in)
			if !errors.Is(got, test.want) {
				t.Fatalf("translateMigrationStoreError(%v) = %v, want %v", test.in, got, test.want)
			}
			for _, never := range []error{ErrKeychainMigrationUnavailable, ErrKeychainMigrationBlocked} {
				if errors.Is(got, never) && !errors.Is(test.want, never) {
					t.Fatalf("translateMigrationStoreError(%v) became %v", test.in, never)
				}
			}
		})
	}
}
