//go:build !darwin && !linux

package journal

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Unsupported migration platforms keep the historical bounded Store reader.
// They do not use this pathname-based path to migrate or acquire authority.
func readJournalFile(directory, name string, limit int) (raw []byte, err error) {
	path := filepath.Join(directory, name)
	linked, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !linked.Mode().IsRegular() || linked.Mode().Perm() != 0o600 || linked.Size() > int64(limit) {
		return nil, errInvalidJournalWire
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close journal record: %w", closeErr))
		}
	}()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(linked, opened) {
		return nil, errInvalidJournalWire
	}
	raw, err = io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > limit {
		return nil, errInvalidJournalWire
	}
	return raw, nil
}
