package application

import (
	"errors"
	"fmt"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/auth"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
)

func TestTranslateErrorCredentialStoreMapping(t *testing.T) {
	const sandboxHint = "stop and ask the operator to run this outside the sandbox; do not change a sandbox policy yourself; do not re-authenticate"
	tests := []struct {
		name   string
		err    error
		reason string
		exit   int
		hint   string
	}{
		{"unavailable", auth.ErrCredentialStoreUnavailable, "CREDENTIAL_STORE_UNAVAILABLE", 8, sandboxHint},
		{"read only", auth.ErrCredentialStoreReadOnly, "CREDENTIAL_STORE_READ_ONLY", 8, sandboxHint},
		{"contended", auth.ErrCredentialStoreContended, "CREDENTIAL_STORE_CONTENDED", 9,
			"another process replaced the stored credential; run youtrack-agent-cli auth status --profile work, then retry"},
		{"migration required", auth.ErrKeychainMigrationRequired, "CONFIRMATION_REQUIRED", 7,
			"ask the operator to run youtrack-agent-cli auth migrate-keychain --profile work --yes in an interactive macOS session, or run auth login again"},
		{"migration canceled unchanged", auth.ErrKeychainMigrationCanceled, "CONFIRMATION_REQUIRED", 7, "obtain trusted human approval before continuing"},
		{"not found unchanged", auth.ErrNotFound, "CREDENTIAL_NOT_FOUND", 5, "run 'youtrack-agent-cli auth login --profile NAME' or rotate the API token"},
		{"interaction unchanged", auth.ErrInteractionNotAllowed, "KEYCHAIN_INTERACTION_REQUIRED", 5, "run 'youtrack-agent-cli auth login --profile NAME' or rotate the API token"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var typed *errx.Error
			if !errors.As(TranslateError(fmt.Errorf("wrapped: %w", test.err), "work"), &typed) {
				t.Fatal("not a typed error")
			}
			if typed.Reason != test.reason || int(typed.Code) != test.exit || typed.Hint != test.hint {
				t.Fatalf("got reason=%q exit=%d hint=%q", typed.Reason, typed.Code, typed.Hint)
			}
		})
	}
}
