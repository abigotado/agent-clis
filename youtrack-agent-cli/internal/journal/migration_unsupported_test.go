//go:build !darwin && !linux

package journal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
)

func TestStoreMigrationUnsupportedWithoutCreatingDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent-journal")
	store := New(path)
	_, err := store.MigratePreparedV1(context.Background(), "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA", 1)
	var typed *errx.Error
	if !errors.As(err, &typed) || typed.Reason != "JOURNAL_MIGRATION_UNSUPPORTED" || errx.ExitCode(err) != errx.CodeInternal {
		t.Fatalf("unsupported-platform refusal = %v", err)
	}
	if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("unsupported-platform migration created directory: %v", statErr)
	}
}
