package application

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/auth"
	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/profile"
	"github.com/abigotado/youtrack-agent-cli/internal/writepolicy"
)

func TestReadReportsDeniedProfileLockBeforeCredentialAccess(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the file mode that denies the lock")
	}
	directory := filepath.Join(t.TempDir(), "private-path-sentinel")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	registryPath := filepath.Join(directory, "profiles.json")
	if err := os.WriteFile(registryPath+".profile-work.lock", nil, 0o400); err != nil {
		t.Fatal(err)
	}
	credentials := &trapCredentials{}
	service := &Service{Profiles: profile.NewRegistry(registryPath), Credentials: credentials}

	_, _, err := service.InspectIssue(t.Context(), "work", "APP-1")

	var typed *errx.Error
	if !errors.As(TranslateError(err, "work"), &typed) {
		t.Fatalf("untyped result for %v", err)
	}
	if typed.Reason != "LOCAL_STATE_ACCESS_DENIED" || typed.Code != errx.CodePermission {
		t.Errorf("reason=%q code=%d", typed.Reason, typed.Code)
	}
	if strings.Contains(typed.Message+typed.Hint, "private-path-sentinel") {
		t.Errorf("leaked the local path: %q %q", typed.Message, typed.Hint)
	}
	if credentials.calls != 0 {
		t.Errorf("credential store was called %d times", credentials.calls)
	}
}

type typedFailureStore struct {
	auth.CredentialAccessStore
	err error
}

func (s typedFailureStore) Load(context.Context, string) (auth.Credential, error) {
	return auth.Credential{}, s.err
}

func TestClientKeepsTypedErrorThatWrapsDenial(t *testing.T) {
	service := oauthApplicationService(t, oauthApplicationProfile(t, true), &oauthCredentialStore{}, nil)
	service.Credentials = typedFailureStore{err: errx.Conflict("TYPED_RECOVERY", "keeps its recovery").Wrap(fs.ErrPermission)}

	_, _, err := service.InspectIssue(t.Context(), "work", "APP-1")

	var typed *errx.Error
	if !errors.As(TranslateError(err, "work"), &typed) || typed.Reason != "TYPED_RECOVERY" {
		t.Fatalf("translated=%#v", typed)
	}
}

// A denial after a committed change must not read as a plain access problem:
// the caller has to inspect state rather than simply grant access and repeat.
func TestTranslateErrorDoesNotRelabelDenialAfterCommit(t *testing.T) {
	denied := &fs.PathError{Op: "open", Path: "/private-path-sentinel", Err: syscall.EPERM}
	tests := []struct {
		name string
		err  error
	}{
		{"write policy committed", &writepolicy.CommitError{Err: denied}},
		{"profile committed", fmt.Errorf("profile metadata committed with a durability warning: %w", &profile.CommitError{Err: denied})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var typed *errx.Error
			if !errors.As(TranslateError(test.err, "work"), &typed) || typed.Reason != "INTERNAL" {
				t.Fatalf("translated=%#v", typed)
			}
		})
	}
}
