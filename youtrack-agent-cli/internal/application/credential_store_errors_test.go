package application

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/auth"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/profile"
)

func TestTranslateErrorCredentialStoreMapping(t *testing.T) {
	const authHint = "run 'youtrack-agent-cli auth login --profile NAME' or rotate the API token"
	const sandboxHint = "stop and ask the operator to run this outside the sandbox; do not change a sandbox policy yourself; do not re-authenticate"
	const refusedHint = "the credential store refused the write; run youtrack-agent-cli auth status --profile work and report the failure to the operator; do not re-authenticate"
	tests := []struct {
		name   string
		err    error
		reason string
		exit   int
		hint   string
	}{
		{"write refused", auth.ErrCredentialStoreWriteRefused, "CREDENTIAL_STORE_UNAVAILABLE", 8, refusedHint},
		{"write refused outranks not found", errors.Join(auth.ErrNotFound, auth.ErrCredentialStoreWriteRefused), "CREDENTIAL_STORE_UNAVAILABLE", 8, refusedHint},
		{"unavailable", auth.ErrCredentialStoreUnavailable, "CREDENTIAL_STORE_UNAVAILABLE", 8, sandboxHint},
		{"read only", auth.ErrCredentialStoreReadOnly, "CREDENTIAL_STORE_READ_ONLY", 8, sandboxHint},
		{"contended", auth.ErrCredentialStoreContended, "CREDENTIAL_STORE_CONTENDED", 9,
			"another process replaced the stored credential; run youtrack-agent-cli auth status --profile work, then retry"},
		{"migration required", auth.ErrKeychainMigrationRequired, "CONFIRMATION_REQUIRED", 7,
			"ask the operator to run youtrack-agent-cli auth migrate-keychain --profile work --yes --timeout 5m in an interactive macOS session, or to run youtrack-agent-cli auth login --profile work --yes"},
		{"repair denied", auth.ErrKeychainRepairDenied, "CONFIRMATION_REQUIRED", 7,
			"the repair was denied access to the stored credential; ask the operator to run youtrack-agent-cli auth login --profile work --yes, or auth import-token --profile work --interactive --yes, in an interactive macOS session"},
		{"login incomplete", auth.ErrLoginIncomplete, "LOGIN_INCOMPLETE", 5,
			"ask the operator to run youtrack-agent-cli auth login --profile work --yes for OAuth, or youtrack-agent-cli auth import-token --profile work --interactive --yes for a permanent token"},
		{"migration canceled unchanged", auth.ErrKeychainMigrationCanceled, "CONFIRMATION_REQUIRED", 7, "obtain trusted human approval before continuing"},
		{"not found unchanged", auth.ErrNotFound, "CREDENTIAL_NOT_FOUND", 5, "run 'youtrack-agent-cli auth login --profile NAME' or rotate the API token"},
		{"interaction unchanged", auth.ErrInteractionNotAllowed, "KEYCHAIN_INTERACTION_REQUIRED", 5, "run 'youtrack-agent-cli auth login --profile NAME' or rotate the API token"},
		{"unsupported unchanged", auth.ErrUnsupported, "KEYCHAIN_UNSUPPORTED", 5, authHint},
		{"invalid token unchanged", auth.ErrInvalidToken, "USAGE", 2, "check the flags against --help"},
		{"migration blocked unchanged", auth.ErrKeychainMigrationBlocked, "KEYCHAIN_MIGRATION_BLOCKED", 5, authHint},
		{"keychain entry not found unchanged", auth.ErrKeychainEntryNotFound, "NOT_FOUND_KEYCHAIN_CREDENTIAL", 3, "verify the keychain_credential key or name and --profile"},
		{"migration unavailable unchanged", auth.ErrKeychainMigrationUnavailable, "KEYCHAIN_MIGRATION_UNAVAILABLE", 5, authHint},
		{"store failure outranks not found", errors.Join(auth.ErrNotFound, auth.ErrCredentialStoreUnavailable), "CREDENTIAL_STORE_UNAVAILABLE", 8, sandboxHint},
		{"read-only outranks not found", errors.Join(auth.ErrNotFound, auth.ErrCredentialStoreReadOnly), "CREDENTIAL_STORE_READ_ONLY", 8, sandboxHint},
		{"contended outranks not found", errors.Join(auth.ErrNotFound, auth.ErrCredentialStoreContended), "CREDENTIAL_STORE_CONTENDED", 9,
			"another process replaced the stored credential; run youtrack-agent-cli auth status --profile work, then retry"},
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
			if test.err == auth.ErrCredentialStoreWriteRefused {
				lower := strings.ToLower(typed.Message + " " + typed.Hint)
				for _, banned := range []string{"sandbox", "read-only", "read only", "login", "re-authenticate "} {
					if strings.Contains(lower, banned) {
						t.Errorf("write-refused text %q contains %q", lower, banned)
					}
				}
			}
		})
	}
}

func TestMapLocalDenialLeavesCredentialStoreFailuresAlone(t *testing.T) {
	for _, sentinel := range []error{auth.ErrCredentialStoreUnavailable, auth.ErrCredentialStoreReadOnly, auth.ErrCredentialStoreContended, auth.ErrNotFound} {
		wrapped := fmt.Errorf("credential store load: %w", sentinel)
		if got := mapLocalDenial(wrapped); got != wrapped {
			t.Errorf("mapLocalDenial(%v) = %v, want the error unchanged", sentinel, got)
		}
	}
}

func TestTranslateErrorKeepsDeliberateCodesOverInternalStoreFailure(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		reason string
		exit   int
	}{
		{"logout incomplete join", errors.Join(auth.ErrLogoutIncomplete, auth.ErrCredentialStoreInternal), "LOGOUT_INCOMPLETE", 9},
		{"logout incomplete wrapped join", fmt.Errorf("logout: %w", errors.Join(auth.ErrLogoutIncomplete, fmt.Errorf("delete: %w", auth.ErrCredentialStoreInternal))), "LOGOUT_INCOMPLETE", 9},
		{"login incomplete join", errors.Join(auth.ErrLoginIncomplete, fmt.Errorf("save profile metadata: %w", profile.ErrAlreadyExists)), "LOGIN_INCOMPLETE", 5},
		{"login incomplete with rollback delete failure", errors.Join(auth.ErrLoginIncomplete, errors.Join(fmt.Errorf("save profile metadata: %w", profile.ErrAlreadyExists), fmt.Errorf("rollback credential: %w", auth.ErrCredentialStoreInternal))), "LOGIN_INCOMPLETE", 5},
		{"login incomplete wrapped store failure", fmt.Errorf("login: %w", errors.Join(auth.ErrLoginIncomplete, auth.ErrCredentialStoreInternal)), "LOGIN_INCOMPLETE", 5},
		{"login rollback join", errors.Join(fmt.Errorf("save profile metadata: %w", profile.ErrAlreadyExists), fmt.Errorf("rollback credential: %w", auth.ErrCredentialStoreInternal)), "CONFIRMATION_REQUIRED", 7},
		{"internal alone", fmt.Errorf("wrapped: %w", auth.ErrCredentialStoreInternal), "INTERNAL", 1},
		{"unavailable outranks internal", errors.Join(auth.ErrCredentialStoreInternal, auth.ErrCredentialStoreUnavailable), "CREDENTIAL_STORE_UNAVAILABLE", 8},
		{"internal outranks not found", errors.Join(auth.ErrNotFound, auth.ErrCredentialStoreInternal), "INTERNAL", 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var typed *errx.Error
			if !errors.As(TranslateError(test.err, "work"), &typed) {
				t.Fatal("not a typed error")
			}
			if typed.Reason != test.reason || int(typed.Code) != test.exit {
				t.Fatalf("got reason=%q exit=%d, want %q/%d", typed.Reason, typed.Code, test.reason, test.exit)
			}
		})
	}
}

func TestLoginIncompleteOutranksEverySentinelTheRollbackCanFailWith(t *testing.T) {
	failures := map[string]error{
		"status error":       &auth.StatusError{Operation: "delete", Status: -1},
		"migration required": auth.ErrKeychainMigrationRequired,
		"contended":          auth.ErrCredentialStoreContended,
		"unavailable":        auth.ErrCredentialStoreUnavailable,
		"read only":          auth.ErrCredentialStoreReadOnly,
		"write refused":      auth.ErrCredentialStoreWriteRefused,
		"internal":           auth.ErrCredentialStoreInternal,
		"not found":          auth.ErrNotFound,
		"interaction":        auth.ErrInteractionNotAllowed,
		"profile exists":     profile.ErrAlreadyExists,
		"profile not found":  profile.ErrNotFound,
		"canceled":           context.Canceled,
	}
	for name, cause := range failures {
		t.Run(name, func(t *testing.T) {
			err := errors.Join(auth.ErrLoginIncomplete,
				fmt.Errorf("save profile metadata: %w", profile.ErrAlreadyExists),
				fmt.Errorf("rollback credential: %w", cause))
			var typed *errx.Error
			if !errors.As(TranslateError(err, "work"), &typed) {
				t.Fatal("not a typed error")
			}
			if typed.Reason != "LOGIN_INCOMPLETE" || int(typed.Code) != 5 {
				t.Fatalf("got reason=%q exit=%d", typed.Reason, typed.Code)
			}
		})
	}
}
