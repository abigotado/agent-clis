package application

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"syscall"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
)

func TestTranslateErrorReportsDeniedLocalStateWithoutPath(t *testing.T) {
	const privatePath = "/Users/private-path-sentinel/profiles.json.profile-work.lock"
	tests := []struct {
		name string
		err  error
	}{
		{"sandbox EPERM on a lock file", fmt.Errorf("open lock %s: %w", privatePath, &fs.PathError{Op: "open", Path: privatePath, Err: syscall.EPERM})},
		{"EACCES on a registry", fmt.Errorf("read %s: %w", privatePath, &fs.PathError{Op: "open", Path: privatePath, Err: syscall.EACCES})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var typed *errx.Error
			if !errors.As(TranslateError(test.err, "work"), &typed) {
				t.Fatalf("untyped result for %v", test.err)
			}
			if typed.Reason != "LOCAL_STATE_ACCESS_DENIED" || typed.Code != errx.CodePermission {
				t.Errorf("reason=%q code=%d", typed.Reason, typed.Code)
			}
			if strings.Contains(typed.Message+typed.Hint, "private-path-sentinel") {
				t.Errorf("leaked the local path: %q %q", typed.Message, typed.Hint)
			}
		})
	}
}

func TestTranslateErrorKeepsUnknownFailuresInternal(t *testing.T) {
	var typed *errx.Error
	if !errors.As(TranslateError(errors.New("unknown failure"), "work"), &typed) || typed.Reason != "INTERNAL" {
		t.Fatalf("translated=%#v", typed)
	}
}
