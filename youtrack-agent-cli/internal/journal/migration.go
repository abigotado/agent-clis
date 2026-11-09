package journal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/lockfile"
)

type journalFileIdentity struct {
	dev      uint64
	ino      uint64
	size     int64
	modified time.Time
}

func (a journalFileIdentity) same(b journalFileIdentity) bool {
	return a.dev == b.dev && a.ino == b.ino && a.size == b.size && a.modified.Equal(b.modified)
}

// MigratePreparedV1 is an internal, one-shot storage migration. It does not
// grant approval authority or make a v2 record eligible for dispatch. Only a
// canonical pristine v1 record at revision 1 can be replaced. A second call
// with the same expected revision observes an exact migrated v2 and performs
// no write.
func (s Store) MigratePreparedV1(ctx context.Context, planID string, expectedRevision uint64) (PreparedV2Record, error) {
	if err := ctx.Err(); err != nil {
		return PreparedV2Record{}, err
	}
	if !migrationAvailable() {
		return PreparedV2Record{}, migrationUnsupported()
	}
	path, err := s.historicalRecordPath(planID)
	if err != nil {
		return PreparedV2Record{}, err
	}
	if err := s.ensureDirectory(); err != nil {
		return PreparedV2Record{}, err
	}
	var result PreparedV2Record
	err = lockfile.With(path, func() (operationErr error) {
		if err := ctx.Err(); err != nil {
			return err
		}
		directory, err := openSecureJournalDirectory(filepath.Dir(path))
		if err != nil {
			if errors.Is(err, errInvalidJournalWire) {
				return errx.Internal("mutation journal directory is insecure for migration").Wrap(err)
			}
			return errx.Internal("mutation journal directory could not be opened for migration").Wrap(err)
		}
		committed := false
		defer func() {
			if closeErr := directory.close(); closeErr != nil {
				if committed {
					operationErr = &CommitError{Err: errors.Join(operationErr, fmt.Errorf("close migration journal directory: %w", closeErr))}
				} else {
					operationErr = errors.Join(operationErr, fmt.Errorf("close migration journal directory: %w", closeErr))
				}
			}
		}()
		name := filepath.Base(path)
		raw, sourceIdentity, err := directory.readIdentified(name, maxLegacyV1Bytes)
		if errors.Is(err, os.ErrNotExist) {
			return errx.NotFound("mutation_plan", planID, nil)
		}
		if err != nil {
			if errors.Is(err, errInvalidJournalWire) || errors.Is(err, errJournalWireTooLarge) {
				return errx.Internal("mutation journal record is insecure or oversized").Wrap(err)
			}
			return errx.Internal("mutation journal record could not be read for migration").Wrap(err)
		}
		if existing, decodeErr := DecodePreparedV2(raw); decodeErr == nil {
			if existing.Plan.PlanID != planID {
				return errx.Internal("mutation journal filename and embedded plan ID do not match")
			}
			if expectedRevision == 1 && existing.Revision == 2 && existing.LegacyV1RecordSHA256 != nil {
				// A previous directory sync may have failed after the rename.
				// Canonical bytes alone cannot prove the commit is durable.
				syncErr := s.syncMigrationDirectory(directory)
				verified, verifyErr := directory.read(name, maxLegacyV1Bytes)
				verificationErr := verifyErr
				if verificationErr == nil && !bytes.Equal(verified, raw) {
					verificationErr = errInvalidJournalWire
				}
				if syncErr != nil || verificationErr != nil {
					return &CommitError{Err: errx.Internal("existing migrated journal could not be durably verified; do not retry automatically").Wrap(errors.Join(syncErr, verificationErr))}
				}
				committed = true
				result = existing
				return nil
			}
			return migrationRevisionConflict()
		}
		classified, err := ClassifyLegacyV1(raw)
		if err != nil {
			return errx.Internal("mutation journal record is malformed or noncanonical").Wrap(err)
		}
		if classified.Record.Plan.PlanID != planID {
			return errx.Internal("mutation journal filename and embedded plan ID do not match")
		}
		if classified.Disposition == LegacyV1Quarantine {
			// The refusal is unconditional. Marker failure is retained as a
			// private cause, without allowing journal-controlled text into the
			// public message or hint.
			markerErr := s.persistQuarantineMarker(directory, planID, classified)
			refusal := errx.Internal("valid v1 mutation journal state cannot be migrated")
			refusal.Reason = "JOURNAL_V1_AUTHORITY_STATE_QUARANTINED"
			if markerErr != nil {
				return refusal.WithHint("stop; retain the original journal and request operator repair of the quarantine marker; do not retry a mutation").Wrap(markerErr)
			}
			return refusal.WithHint("retain the original journal and resolve this state outside automated migration")
		}
		if expectedRevision != 1 || classified.Record.Revision != expectedRevision {
			return migrationRevisionConflict()
		}
		updatedAt := s.currentTime()
		if updatedAt.Before(classified.Record.CreatedAt) {
			return errx.Internal("migration clock precedes the historical journal creation time")
		}
		digest := classified.SHA256
		candidate := PreparedV2Record{Revision: 2, Plan: classified.Record.Plan,
			LegacyV1RecordSHA256: &digest, CreatedAt: classified.Record.CreatedAt, UpdatedAt: updatedAt}
		encoded, err := EncodePreparedV2(candidate)
		if err != nil {
			return errx.Internal("valid v1 journal cannot be represented by prepared v2").Wrap(err)
		}
		tempName, err := directory.createTemp(".journal-migrate-", encoded)
		if err != nil {
			return errx.Internal("could not create migration journal temporary file").Wrap(err)
		}
		defer func() {
			if removeErr := directory.unlink(tempName); removeErr != nil {
				if committed {
					operationErr = &CommitError{Err: errors.Join(operationErr, removeErr)}
				} else {
					operationErr = errors.Join(operationErr, removeErr)
				}
			}
		}()
		if s.beforeMigrateRename != nil {
			if err := s.beforeMigrateRename(directory.fd, name); err != nil {
				return errx.Internal("migration journal source could not be rechecked before replacement").Wrap(err)
			}
		}
		// Writers that honor the per-plan advisory lock cannot intervene.
		// Recheck exact bytes and identity immediately before the one rename
		// to reject independent same-user changes observed up to this point.
		current, currentIdentity, checkErr := directory.readIdentified(name, maxLegacyV1Bytes)
		if checkErr != nil || !sourceIdentity.same(currentIdentity) || !bytes.Equal(current, raw) {
			if checkErr != nil {
				return errx.Internal("migration journal source changed before replacement").Wrap(checkErr)
			}
			return errx.Internal("migration journal source changed before replacement").Wrap(errInvalidJournalWire)
		}
		rename := s.migrateRename
		if rename == nil {
			rename = defaultMigrationRename
		}
		renameErr := rename(directory.fd, tempName, name)
		observed, readErr := directory.read(name, maxLegacyV1Bytes)
		if readErr == nil && bytes.Equal(observed, encoded) {
			// Even when Renameat reported an error, the exact new record is
			// present. One sync plus an exact reread resolves the outcome.
			if syncErr := s.syncMigrationDirectory(directory); syncErr != nil {
				// This second read diagnoses the on-disk state but cannot turn
				// uncertain directory durability into a claimed success.
				verified, verifyErr := directory.read(name, maxLegacyV1Bytes)
				verificationErr := verifyErr
				if verificationErr == nil && !bytes.Equal(verified, encoded) {
					verificationErr = errInvalidJournalWire
				}
				if verificationErr != nil {
					return &CommitError{Err: errx.Internal("migrated journal changed after failed directory sync").Wrap(errors.Join(renameErr, syncErr, verificationErr))}
				}
				return &CommitError{Err: errx.Internal("migrated journal directory sync failed after replacement; outcome uncertain").Wrap(errors.Join(renameErr, syncErr))}
			}
			verified, verifyErr := directory.read(name, maxLegacyV1Bytes)
			verificationErr := verifyErr
			if verificationErr == nil && !bytes.Equal(verified, encoded) {
				verificationErr = errInvalidJournalWire
			}
			if verificationErr != nil {
				return &CommitError{Err: errx.Internal("migrated journal changed before exact verification").Wrap(errors.Join(renameErr, verificationErr))}
			}
			committed = true
			result = candidate
			return nil
		}
		if renameErr != nil && readErr == nil && bytes.Equal(observed, raw) {
			return errx.Internal("migration journal replacement did not commit").Wrap(renameErr)
		}
		observationErr := readErr
		if observationErr == nil {
			observationErr = errInvalidJournalWire
		}
		return &CommitError{Err: errx.Internal("migration journal replacement outcome is ambiguous; do not retry").Wrap(errors.Join(renameErr, observationErr))}
	})
	return result, err
}

func migrationRevisionConflict() error {
	return journalConflict("JOURNAL_REVISION_CONFLICT", "mutation journal revision is not the expected pristine v1 revision")
}

func preparedRecordProjection(prepared PreparedV2Record) Record {
	return Record{Version: 2, Revision: prepared.Revision, State: StatePrepared, Plan: prepared.Plan,
		CreatedAt: prepared.CreatedAt, UpdatedAt: prepared.UpdatedAt}
}

func (s Store) syncMigrationDirectory(directory *secureJournalDirectory) error {
	syncDirectory := s.migrateDirSync
	if syncDirectory == nil {
		syncDirectory = (*os.File).Sync
	}
	return syncDirectory(directory.file)
}

func (s Store) persistQuarantineMarker(directory *secureJournalDirectory, planID string, classification LegacyV1Classification) error {
	name := planID + ".v1-quarantine.json"
	valid := func(raw []byte) bool {
		marker, err := DecodeQuarantineMarker(raw)
		return err == nil && marker.RecordSHA256 == classification.SHA256 && marker.State == classification.Record.State
	}
	unlink := s.markerUnlink
	if unlink == nil {
		unlink = func(_ int, temporary string) error { return directory.unlink(temporary) }
	}
	if raw, err := directory.read(name, maxQuarantineBytes); err == nil {
		if valid(raw) {
			return nil
		}
		return errx.Internal("existing v1 quarantine marker does not match its source")
	} else if !errors.Is(err, os.ErrNotExist) {
		if recoverErr := directory.recoverQuarantineLink(name, valid, unlink); recoverErr != nil {
			return errx.Internal("existing v1 quarantine marker is insecure or cannot be recovered").Wrap(errors.Join(err, recoverErr))
		}
		if syncErr := s.syncMigrationDirectory(directory); syncErr != nil {
			return errx.Internal("recovered v1 quarantine marker directory sync failed").Wrap(errors.Join(err, syncErr))
		}
		if observed, readErr := directory.read(name, maxQuarantineBytes); readErr != nil || !valid(observed) {
			return errx.Internal("recovered v1 quarantine marker could not be securely verified").Wrap(errors.Join(err, readErr))
		}
		return nil
	}
	marker := QuarantineMarker{RecordSHA256: classification.SHA256,
		State: classification.Record.State, DetectedAt: s.currentTime()}
	encoded, err := EncodeQuarantineMarker(marker)
	if err != nil {
		return errx.Internal("cannot encode v1 quarantine marker").Wrap(err)
	}
	tempName, err := directory.createTemp(".journal-quarantine-", encoded)
	if err != nil {
		return errx.Internal("cannot create v1 quarantine temporary marker").Wrap(err)
	}
	// Linkat gives O_EXCL-like no-clobber semantics for the final marker.
	// The temporary hard link must go before secure reread (nlink must be 1).
	link := s.markerLink
	if link == nil {
		link = defaultMarkerLink
	}
	linkErr := link(directory.fd, tempName, name)
	removeErr := unlink(directory.fd, tempName)
	if removeErr != nil {
		if errors.Is(linkErr, os.ErrExist) {
			return errx.Internal("v1 quarantine temporary marker could not be removed").Wrap(errors.Join(linkErr, removeErr))
		}
		if recoverErr := directory.recoverQuarantineLink(name, valid, unlink); recoverErr != nil {
			return errx.Internal("v1 quarantine temporary link could not be recovered").Wrap(errors.Join(linkErr, removeErr, recoverErr))
		}
		if syncErr := s.syncMigrationDirectory(directory); syncErr != nil {
			return errx.Internal("recovered v1 quarantine marker directory sync failed").Wrap(errors.Join(removeErr, syncErr))
		}
		if observed, readErr := directory.read(name, maxQuarantineBytes); readErr != nil || !valid(observed) {
			return errx.Internal("recovered v1 quarantine marker could not be securely verified").Wrap(errors.Join(removeErr, readErr))
		}
		return nil
	}
	if linkErr != nil && !errors.Is(linkErr, os.ErrExist) {
		// A fault may occur after the link. Resolve only by exact reread.
		observed, readErr := directory.read(name, maxQuarantineBytes)
		if readErr != nil || !bytes.Equal(observed, encoded) {
			return errx.Internal("v1 quarantine marker outcome is uncertain").Wrap(errors.Join(linkErr, readErr))
		}
	}
	if linkErr == nil || !errors.Is(linkErr, os.ErrExist) {
		if err := s.syncMigrationDirectory(directory); err != nil {
			return errx.Internal("v1 quarantine marker directory sync failed").Wrap(errors.Join(linkErr, err))
		}
	}
	observed, err := directory.read(name, maxQuarantineBytes)
	if err != nil {
		return errx.Internal("v1 quarantine marker could not be verified").Wrap(errors.Join(linkErr, err))
	}
	if linkErr != nil && errors.Is(linkErr, os.ErrExist) {
		// Existing matching evidence is immutable, including detected_at.
		if valid(observed) {
			return nil
		}
		return errx.Internal("existing v1 quarantine marker does not match its source").Wrap(linkErr)
	}
	if !bytes.Equal(observed, encoded) {
		return errx.Internal("v1 quarantine marker changed before exact verification")
	}
	return nil
}
