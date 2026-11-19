//go:build darwin && cgo && !portable_readonly && !macos_identity_readonly

package main

import (
	"errors"

	"github.com/abigotado/agent-clis/core/secretstore"
)

func disableCoreDumps() error {
	err := secretstore.DisableCoreDumps()
	if err == nil {
		return nil
	}
	var failure *secretstore.Error
	if errors.As(err, &failure) {
		return &hardeningError{status: failure.Status}
	}
	return &hardeningError{}
}
