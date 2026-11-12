package secretstore

import "context"

// openNative returns the Credential Manager store. It does not probe the
// service or sweep leftovers: a failing call reports itself as ErrUnavailable
// or another kind when it happens.
func openNative(_ context.Context, opts Options) (Store, error) {
	return newChunkedStore(newCredman(), opts.MaxSecretBytes), nil
}
