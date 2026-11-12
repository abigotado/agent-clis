package secretstore

import "context"

func openNative(_ context.Context, _ Options) (Store, error) {
	return nil, newError("open", "none", KindUnavailable)
}
