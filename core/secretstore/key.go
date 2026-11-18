package secretstore

import "github.com/abigotado/agent-clis/core/secretstore/internal/rules"

// validateKey rejects a key before any store access. The error carries no part
// of the key.
func validateKey(op, backend string, key Key) error {
	if !rules.ValidService(key.Service) || !rules.ValidAccount(key.Account) {
		return newError(op, backend, KindInvalidArgument)
	}
	return nil
}

// validateOptions rejects options Open cannot honour.
func validateOptions(opts Options) error {
	if opts.MaxSecretBytes < 1 || opts.MaxSecretBytes > MaxSecretBytesLimit {
		return newError("open", "none", KindInvalidArgument)
	}
	if opts.Interaction != InteractionNever && opts.Interaction != InteractionAllowed {
		return newError("open", "none", KindInvalidArgument)
	}
	return nil
}
