//go:build darwin && !cgo

package secretstore

import "context"

// Without cgo the Security.framework calls cannot be made, so there is no
// backend: Open fails with ErrUnavailable instead of reaching for a file.
func openNative(_ context.Context, _ Options) (Store, error) {
	return nil, newError("open", "none", KindUnavailable)
}
