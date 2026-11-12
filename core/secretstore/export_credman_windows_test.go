//go:build windows && credmanintegration

package secretstore

// NewCredmanStoreForTest returns the real Credential Manager store without
// going through Open, which fixes the process-wide interaction mode. The
// external contract test uses it because secretstoretest imports this package.
func NewCredmanStoreForTest(maxSecretBytes int) Store {
	return newChunkedStore(newCredman(), maxSecretBytes)
}
