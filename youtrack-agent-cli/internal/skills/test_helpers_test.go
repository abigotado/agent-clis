package skills

import (
	"errors"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
)

func assertReason(t *testing.T, err error, want string) {
	t.Helper()
	var typed *errx.Error
	if !errors.As(err, &typed) || typed.Reason != want {
		t.Fatalf("error = %v, want reason %s", err, want)
	}
}
