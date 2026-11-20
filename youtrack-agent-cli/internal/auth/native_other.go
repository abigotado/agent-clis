//go:build !darwin || !cgo

package auth

// NewDefaultNativeStores returns the unsupported store for both the ordinary
// and the repair path: this build has no native credential backend.
func NewDefaultNativeStores() (credentials, repair CredentialAccessStore) {
	return KeychainStore{}, KeychainStore{}
}
