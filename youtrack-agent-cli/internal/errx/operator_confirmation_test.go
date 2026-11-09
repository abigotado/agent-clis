package errx

import (
	"strings"
	"testing"
)

func TestOperatorConfirmationUsesExistingExitWithExplicitIntentRecovery(t *testing.T) {
	err := OperatorConfirmRequired()
	if err.Code != CodeConfirm || ExitCode(err) != 7 || err.Reason != "OPERATOR_CONFIRMATION_REQUIRED" {
		t.Fatalf("operator confirmation error=%#v", err)
	}
	for _, required := range []string{"--confirm-intent", "SHA256", "--yes", "human confirmation"} {
		if !strings.Contains(err.Hint, required) {
			t.Fatalf("confirmation recovery omits %q: %q", required, err.Hint)
		}
	}
	for _, code := range Codes() {
		if code.Code == CodeConfirm && (strings.Contains(code.NextMove, "receipt") || !strings.Contains(code.NextMove, "approval mode")) {
			t.Fatalf("shared exit 7 recovery must permit each operation's mode: %#v", code)
		}
	}
}
