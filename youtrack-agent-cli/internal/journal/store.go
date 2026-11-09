package journal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/intent"
	"github.com/abigotado/youtrack-agent-cli/internal/lockfile"
)

var (
	receiptIDPattern = regexp.MustCompile(`^YTAR-[A-Z2-7]{26}$`)
	noncePattern     = regexp.MustCompile(`^YTAN-[A-Z2-7]{26}$`)
	remoteIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

func journalConflict(reason, format string, args ...any) *errx.Error {
	return errx.Conflict(reason, format, args...).WithHint(
		"inspect the local journal; do not retry a mutation automatically")
}

// Store owns one journal directory. Unrelated records have independent locks.
type Store struct {
	directory string
	now       func() time.Time
	rename    func(string, string) error
	openDir   func(string) (*os.File, error)
	// Migration-only fault boundaries. Nil selects the anchored OS operation.
	migrateRename       func(int, string, string) error
	markerLink          func(int, string, string) error
	markerUnlink        func(int, string) error
	migrateDirSync      func(*os.File) error
	beforeMigrateRename func(int, string) error
}

// CommitError means the atomic rename completed, but directory durability
// could not be confirmed. The new record may already be authoritative.
type CommitError struct{ Err error }

func (e *CommitError) Error() string { return e.Err.Error() }
func (e *CommitError) Unwrap() error { return e.Err }

// WasCommitted identifies a post-rename journal failure.
func WasCommitted(err error) bool {
	var committed *CommitError
	return errors.As(err, &committed)
}

// New returns a journal store rooted at directory.
func New(directory string) Store {
	return Store{directory: directory, now: time.Now}
}

// Create atomically records a valid plan as canonical prepared v2 at revision 1.
func (s Store) Create(ctx context.Context, plan intent.Plan) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	if err := plan.Validate(); err != nil {
		return Record{}, errx.Usage("input failed strict validation").Wrap(err)
	}
	path, err := s.recordPath(plan.PlanID)
	if err != nil {
		return Record{}, err
	}
	now := s.currentTime()
	prepared := PreparedV2Record{
		Revision: 1, Plan: plan, CreatedAt: now, UpdatedAt: now,
	}
	raw, err := EncodePreparedV2(prepared)
	if err != nil {
		return Record{}, errx.Internal("mutation journal plan cannot be encoded as a canonical prepared v2 record").Wrap(err)
	}
	// Project from the canonical bytes, not the caller's in-memory values.
	// This must happen before creating the journal directory or lock file.
	decoded, err := DecodePreparedV2(raw)
	if err != nil {
		return Record{}, errx.Internal("canonical prepared v2 record cannot be decoded").Wrap(err)
	}
	record := preparedRecordProjection(decoded)
	if err := s.ensureDirectory(); err != nil {
		return Record{}, err
	}
	err = lockfile.With(path, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, readErr := os.Lstat(path)
		switch {
		case readErr == nil:
			return journalConflict("JOURNAL_RECORD_EXISTS", "mutation plan %q is already recorded", plan.PlanID)
		case !errors.Is(readErr, os.ErrNotExist):
			return fmt.Errorf("inspect mutation journal record: %w", readErr)
		}
		return s.writeAtomic(path, raw, maxPreparedLineageV2Bytes)
	})
	return record, err
}

// Get returns one strictly decoded record.
func (s Store) Get(ctx context.Context, planID string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	if err := s.ensureDirectory(); err != nil {
		return Record{}, err
	}
	path, err := s.historicalRecordPath(planID)
	if err != nil {
		return Record{}, err
	}
	var record Record
	err = lockfile.With(path, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		loaded, err := readRecord(path, planID)
		if err != nil {
			return err
		}
		record = loaded
		return nil
	})
	return record, err
}

// CompareAndSwap currently has no authority to advance either journal version.
// It still validates the named record so missing or malformed data cannot be
// mistaken for an authorized transition.
func (s Store) CompareAndSwap(ctx context.Context, planID string, _ uint64, _ Transition) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	if err := s.ensureDirectory(); err != nil {
		return Record{}, err
	}
	path, err := s.historicalRecordPath(planID)
	if err != nil {
		return Record{}, err
	}
	err = lockfile.With(path, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := readRecord(path, planID)
		if err != nil {
			return err
		}
		refusal := errx.Internal("journal state transitions are unavailable until native authority verification is implemented")
		refusal.Reason = "JOURNAL_AUTHORITY_UNAVAILABLE"
		return refusal.WithHint("inspect the local journal; do not retry a mutation or transition automatically")
	})
	return Record{}, err
}

func applyTransition(current Record, transition Transition, now time.Time) (Record, error) {
	// Legacy v1 transition logic only. CompareAndSwap does not call this.
	// Never use it to enable v2 transitions without native authority checks.
	if !allowedTransition(current.State, transition.To) {
		return Record{}, journalConflict("INVALID_JOURNAL_TRANSITION", "mutation plan cannot move from %s to %s", current.State, transition.To)
	}
	next := current
	next.Revision++
	next.State = transition.To
	next.UpdatedAt = now
	switch transition.To {
	case StateConfirmed:
		if transition.Receipt == nil {
			return Record{}, journalConflict("RECEIPT_REQUIRED", "confirmation requires a signed receipt binding")
		}
		if err := validateReceiptBinding(current.Plan, *transition.Receipt); err != nil {
			return Record{}, err
		}
		next.Receipt = cloneReceipt(transition.Receipt)
	case StateInFlight:
		if current.Receipt == nil || transition.Receipt != nil || current.MutationAttempts != 0 {
			return Record{}, journalConflict("RECEIPT_REPLAY", "the approval receipt is absent or has already been consumed")
		}
		if !now.Before(current.Receipt.ExpiresAt) {
			return Record{}, journalConflict("RECEIPT_EXPIRED", "the approval receipt expired before durable consumption")
		}
		next.MutationAttempts = 1
	case StateFailedBeforeMutation, StateApplied, StateAmbiguous:
		if transition.Outcome == nil || current.MutationAttempts != 1 {
			return Record{}, journalConflict("OUTCOME_INVALID", "a dispatched mutation requires one bounded outcome")
		}
		if transition.Outcome.Code != string(transition.To) {
			return Record{}, journalConflict("OUTCOME_INVALID", "mutation outcome code does not match state %s", transition.To)
		}
		if err := validateOutcome(*transition.Outcome); err != nil {
			return Record{}, err
		}
		next.Outcome = cloneOutcome(transition.Outcome)
	case StateReconciled, StateOperatorResolutionRequired, StateResolvedApplied, StateResolvedNotApplied:
		if transition.Evidence == nil {
			return Record{}, journalConflict("EVIDENCE_REQUIRED", "this transition requires bounded evidence")
		}
		if err := validateEvidence(*transition.Evidence); err != nil {
			return Record{}, err
		}
		next.Evidence = append(append([]Evidence(nil), current.Evidence...), *transition.Evidence)
	case StateCanceled, StateExpired:
		if transition.Receipt != nil || transition.Outcome != nil || transition.Evidence != nil {
			return Record{}, journalConflict("TRANSITION_DATA_INVALID", "cancel or expiry cannot add receipt, outcome, or evidence")
		}
	}
	if err := validateRecord(next); err != nil {
		return Record{}, err
	}
	return next, nil
}

func allowedTransition(from, to State) bool {
	switch from {
	case StatePrepared:
		return to == StateConfirmed || to == StateCanceled || to == StateExpired
	case StateConfirmed:
		return to == StateInFlight || to == StateCanceled || to == StateExpired
	case StateInFlight:
		return to == StateFailedBeforeMutation || to == StateApplied || to == StateAmbiguous
	case StateApplied:
		return to == StateReconciled || to == StateOperatorResolutionRequired
	case StateAmbiguous:
		return to == StateReconciled || to == StateResolvedNotApplied || to == StateOperatorResolutionRequired
	case StateOperatorResolutionRequired:
		return to == StateResolvedApplied || to == StateResolvedNotApplied
	default:
		return false
	}
}

func validateRecord(record Record) error {
	// Historical v1 validator only. A fresh v2 projection is not valid here;
	// it must be checked by the version-specific codec and authority protocol.
	if record.Version != recordVersion || record.Revision == 0 || record.CreatedAt.IsZero() || record.UpdatedAt.Before(record.CreatedAt) {
		return errx.Internal("mutation journal record metadata is corrupt")
	}
	if err := record.Plan.Validate(); err != nil {
		return errx.Internal("mutation journal contains an invalid plan").Wrap(err)
	}
	if record.MutationAttempts > 1 {
		return errx.Internal("mutation journal records more than one write attempt")
	}
	if record.Receipt != nil {
		if err := validateReceiptBinding(record.Plan, *record.Receipt); err != nil {
			return errx.Internal("mutation journal contains an invalid receipt binding").Wrap(err)
		}
	}
	if record.Outcome != nil {
		if err := validateOutcome(*record.Outcome); err != nil {
			return errx.Internal("mutation journal contains an invalid outcome").Wrap(err)
		}
	}
	if len(record.Evidence) > 16 {
		return errx.Internal("mutation journal contains too many evidence records")
	}
	for _, evidence := range record.Evidence {
		if err := validateEvidence(evidence); err != nil {
			return errx.Internal("mutation journal contains invalid evidence").Wrap(err)
		}
	}
	switch record.State {
	case StatePrepared:
		if record.Receipt != nil || record.MutationAttempts != 0 || record.Outcome != nil || len(record.Evidence) != 0 {
			return errx.Internal("prepared mutation journal record contains later-phase data")
		}
	case StateConfirmed:
		if record.Receipt == nil || record.MutationAttempts != 0 || record.Outcome != nil || len(record.Evidence) != 0 {
			return errx.Internal("confirmed mutation journal record is inconsistent")
		}
	case StateCanceled, StateExpired:
		if record.MutationAttempts != 0 || record.Outcome != nil || len(record.Evidence) != 0 {
			return errx.Internal("canceled or expired mutation journal record is inconsistent")
		}
	case StateInFlight:
		if record.Receipt == nil || record.MutationAttempts != 1 || record.Outcome != nil || len(record.Evidence) != 0 {
			return errx.Internal("in-flight mutation journal record is inconsistent")
		}
	case StateFailedBeforeMutation, StateApplied, StateAmbiguous:
		if record.Receipt == nil || record.MutationAttempts != 1 || record.Outcome == nil || len(record.Evidence) != 0 {
			return errx.Internal("completed dispatch mutation journal record is inconsistent")
		}
		if record.Outcome.Code != string(record.State) {
			return errx.Internal("completed dispatch mutation journal outcome does not match its state")
		}
	case StateReconciled, StateOperatorResolutionRequired, StateResolvedApplied, StateResolvedNotApplied:
		if record.Receipt == nil || record.MutationAttempts != 1 || record.Outcome == nil || len(record.Evidence) == 0 {
			return errx.Internal("resolved mutation journal record is inconsistent")
		}
		if record.Outcome.Code != string(StateApplied) && record.Outcome.Code != string(StateAmbiguous) {
			return errx.Internal("resolved mutation journal record has an impossible dispatch outcome")
		}
	default:
		return errx.Internal("mutation journal record has an unknown state")
	}
	if (record.State == StateConfirmed || record.MutationAttempts == 1) && record.Receipt == nil {
		return errx.Internal("confirmed or dispatched mutation journal record has no receipt")
	}
	return nil
}

func validateOutcome(outcome Outcome) error {
	if outcome.EvidenceSHA256 != "" && !isDigest(outcome.EvidenceSHA256) {
		return journalConflict("OUTCOME_INVALID", "mutation outcome evidence digest is malformed")
	}
	switch outcome.Code {
	case string(StateApplied):
		if !remoteIDPattern.MatchString(outcome.RemoteID) {
			return journalConflict("OUTCOME_INVALID", "applied mutation outcome requires one bounded exact remote ID")
		}
	case string(StateFailedBeforeMutation), string(StateAmbiguous):
		if outcome.RemoteID != "" {
			return journalConflict("OUTCOME_INVALID", "non-applied mutation outcome cannot claim a remote ID")
		}
	default:
		return journalConflict("OUTCOME_INVALID", "mutation outcome code is unsupported")
	}
	return nil
}

func validateReceiptBinding(plan intent.Plan, receipt ReceiptBinding) error {
	if !receiptIDPattern.MatchString(receipt.ReceiptID) || !noncePattern.MatchString(receipt.Nonce) || receipt.PlanSHA256 != plan.IntentSHA256 ||
		receipt.ExpiresAt.IsZero() || strings.TrimSpace(receipt.KeyGeneration) == "" || !isDigest(receipt.ReceiptSHA256) {
		return journalConflict("RECEIPT_BINDING_MISMATCH", "receipt binding does not match mutation plan %q", plan.PlanID)
	}
	return nil
}

func validateEvidence(evidence Evidence) error {
	if !isDigest(evidence.SHA256) || evidence.CollectedAt.IsZero() || evidence.Summary == "" ||
		len(evidence.Summary) > 1024 || strings.ContainsRune(evidence.Summary, '\x00') {
		return journalConflict("EVIDENCE_INVALID", "reconciliation evidence is missing, oversized, or malformed")
	}
	return nil
}

func (s Store) currentTime() time.Time {
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	return now().UTC()
}

func (s Store) ensureDirectory() error {
	if s.directory == "" {
		return errx.Internal("mutation journal directory is empty")
	}
	if err := os.MkdirAll(s.directory, 0o700); err != nil {
		return fmt.Errorf("create mutation journal directory: %w", err)
	}
	info, err := os.Lstat(s.directory)
	if err != nil {
		return fmt.Errorf("inspect mutation journal directory: %w", err)
	}
	if !validJournalDirectoryInfo(info) {
		return errx.Internal("mutation journal directory is not an owned private 0700 or 2700 real directory")
	}
	return nil
}

func (s Store) recordPath(planID string) (string, error) {
	if err := intent.ValidatePlanID(planID); err != nil {
		return "", errx.Usage("plan ID must be a canonical YTAP identifier")
	}
	return filepath.Join(s.directory, planID+".json"), nil
}

func (s Store) historicalRecordPath(planID string) (string, error) {
	// Reads and migration must use the frozen historical grammar. New plan
	// creation may evolve independently with intent.ValidatePlanID.
	if !legacyPlanID(planID) {
		return "", errx.Usage("plan ID must be a canonical historical YTAP identifier")
	}
	return filepath.Join(s.directory, planID+".json"), nil
}

func readRecord(path, expectedPlanID string) (Record, error) {
	raw, err := readJournalFile(filepath.Dir(path), filepath.Base(path), maxLegacyV1Bytes)
	if errors.Is(err, os.ErrNotExist) {
		return Record{}, errx.NotFound("mutation_plan", filepath.Base(path), nil)
	}
	if err != nil {
		if errors.Is(err, errInvalidJournalWire) || errors.Is(err, errJournalWireTooLarge) {
			return Record{}, errx.Internal("mutation journal record is insecure, oversized, or changed while reading").Wrap(err)
		}
		return Record{}, errx.Internal("mutation journal record could not be read").Wrap(err)
	}
	var record Record
	if classified, classifyErr := ClassifyLegacyV1(raw); classifyErr == nil {
		record = classified.Record
	} else if prepared, decodeErr := DecodePreparedV2(raw); decodeErr == nil {
		record = preparedRecordProjection(prepared)
	} else {
		// Decoder diagnostics may contain journal-controlled text. Neither
		// historical nor v2 parser errors cross the Store boundary.
		return Record{}, errx.Internal("mutation journal record is malformed or noncanonical")
	}
	if record.Plan.PlanID != expectedPlanID {
		return Record{}, errx.Internal("mutation journal filename and embedded plan ID do not match")
	}
	return record, nil
}

func (s Store) writeAtomic(path string, raw []byte, maxBytes int) (err error) {
	if len(raw) > maxBytes {
		return errx.Internal("mutation journal record exceeds its size limit")
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".journal-*.tmp")
	if err != nil {
		return fmt.Errorf("create mutation journal temporary file: %w", err)
	}
	tempPath := temp.Name()
	renamed := false
	defer func() {
		if renamed {
			return
		}
		if removeErr := os.Remove(tempPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("remove mutation journal temporary file: %w", removeErr))
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close() // Close cannot improve the preceding failure.
		return fmt.Errorf("protect mutation journal temporary file: %w", err)
	}
	if _, err := temp.Write(raw); err != nil {
		_ = temp.Close() // Close cannot improve the preceding failure.
		return fmt.Errorf("write mutation journal temporary file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close() // Close cannot improve the preceding failure.
		return fmt.Errorf("sync mutation journal temporary file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close mutation journal temporary file: %w", err)
	}
	rename := s.rename
	if rename == nil {
		rename = os.Rename
	}
	if err := rename(tempPath, path); err != nil {
		return fmt.Errorf("commit mutation journal record: %w", err)
	}
	renamed = true
	openDir := s.openDir
	if openDir == nil {
		openDir = os.Open
	}
	directory, err := openDir(filepath.Dir(path))
	if err != nil {
		return &CommitError{Err: fmt.Errorf("open mutation journal directory after commit: %w", err)}
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return &CommitError{Err: errors.Join(wrapJournalError("sync mutation journal directory after commit", syncErr), wrapJournalError("close mutation journal directory after commit", closeErr))}
	}
	return nil
}

func wrapJournalError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func cloneReceipt(value *ReceiptBinding) *ReceiptBinding {
	copy := *value
	return &copy
}

func cloneOutcome(value *Outcome) *Outcome {
	copy := *value
	return &copy
}

func isDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == sha256.Size
}
