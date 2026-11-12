package secretstore

// NewChunkedStoreForTest returns a Store over the chunked Credential Manager
// format backed by an in-memory fake that matches targets case-insensitively
// and treats '*' in enumeration filters as a wildcard, like the real service.
// The external contract test uses it because secretstoretest imports this
// package.
func NewChunkedStoreForTest(maxSecretBytes int) Store {
	return newChunkedStore(newFakeCredMan(), maxSecretBytes)
}

// NewFakeSecretServiceStoreForTest returns a Store over the Secret Service
// logic backed by an in-memory provider, with the DH session or the plain one.
// The external contract test uses it because secretstoretest imports this
// package.
func NewFakeSecretServiceStoreForTest(maxSecretBytes int, plainOnly bool) Store {
	s := newSecretServiceStore(newFakeSS().dialer(), Options{MaxSecretBytes: maxSecretBytes})
	s.plainOnly = plainOnly
	return s
}
