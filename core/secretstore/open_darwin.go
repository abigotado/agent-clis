//go:build darwin && cgo

package secretstore

import "context"

func openNative(_ context.Context, opts Options) (Store, error) {
	return openKeychain(opts, setUserInteractionAllowed)
}
