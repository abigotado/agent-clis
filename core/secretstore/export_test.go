package secretstore

// NewChunkedStoreForTest returns a Store over the chunked Credential Manager
// format backed by an in-memory fake that matches targets case-insensitively
// and treats '*' in enumeration filters as a wildcard, like the real service.
// The external contract test uses it because secretstoretest imports this
// package.
func NewChunkedStoreForTest(maxSecretBytes int) Store {
	return newChunkedStore(newFakeCredMan(), maxSecretBytes)
}
