//go:build windows

package journal

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
)

func TestStoreMigratePreparedV1WindowsDoesNotCreateDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent-journal")
	store := New(path)
	_, err := store.MigratePreparedV1(context.Background(), "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA", 1)
	var typed *errx.Error
	if !errors.As(err, &typed) || typed.Reason != "JOURNAL_MIGRATION_UNSUPPORTED" {
		t.Fatalf("Windows migration refusal = %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Windows migration created a directory before refusing: %v", err)
	}
}

func TestStoreMigratePreparedV1WindowsRefusesBeforeWrite(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "journal"))
	if err := os.MkdirAll(store.directory, 0o700); err != nil {
		t.Fatal(err)
	}
	planID := "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA"
	path := filepath.Join(store.directory, planID+".json")
	markerPath := filepath.Join(store.directory, planID+".v1-quarantine.json")
	if err := os.WriteFile(path, []byte(historicalV1Prepared), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MigratePreparedV1(context.Background(), planID, 1); err == nil {
		t.Fatal("Windows migration wrote without an anchored-file implementation")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, []byte(historicalV1Prepared)) {
		t.Fatalf("Windows migration changed v1 source: %v", err)
	}
	if _, err := os.Lstat(markerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Windows migration wrote quarantine marker: %v", err)
	}
}
