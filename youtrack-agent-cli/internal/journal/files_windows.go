//go:build windows

package journal

import (
	"os"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
)

// Windows has no reviewed implementation of the anchored no-follow,
// single-link migration contract. The public method refuses before it
// creates a directory, acquires a lock, or writes a record or marker.
type secureJournalDirectory struct {
	file *os.File
	fd   int
}

func migrationAvailable() bool { return false }

func migrationUnsupported() error {
	refusal := errx.Internal("secure journal migration is not available on Windows")
	refusal.Reason = "JOURNAL_MIGRATION_UNSUPPORTED"
	return refusal.WithHint("retain the journal record; use a reviewed Darwin or Linux migration path")
}

func validJournalDirectoryInfo(info os.FileInfo) bool {
	return info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o077 == 0
}

func openSecureJournalDirectory(string) (*secureJournalDirectory, error) {
	return nil, migrationUnsupported()
}

func (*secureJournalDirectory) close() error                     { return migrationUnsupported() }
func (*secureJournalDirectory) read(string, int) ([]byte, error) { return nil, migrationUnsupported() }
func (*secureJournalDirectory) readIdentified(string, int) ([]byte, journalFileIdentity, error) {
	return nil, journalFileIdentity{}, migrationUnsupported()
}
func (*secureJournalDirectory) createTemp(string, []byte) (string, error) {
	return "", migrationUnsupported()
}
func (*secureJournalDirectory) unlink(string) error { return migrationUnsupported() }
func (*secureJournalDirectory) recoverQuarantineLink(string, func([]byte) bool, func(int, string) error) error {
	return migrationUnsupported()
}
func defaultMigrationRename(int, string, string) error { return migrationUnsupported() }
func defaultMarkerLink(int, string, string) error      { return migrationUnsupported() }
