package journal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/intent"
)

const (
	maxLegacyV1Bytes          = 1 << 20 // historical maxRecordBytes at the v1 boundary
	maxPreparedLineageV2Bytes = 640 << 10
	maxQuarantineBytes        = 1024
	quarantineReason          = "unsafe_v1_migration_state"
)

var (
	errInvalidJournalWire  = errors.New("invalid canonical mutation journal wire record")
	errJournalWireTooLarge = errors.New("mutation journal wire record exceeds size limit")
)

// Typed errors are allocated at the exported boundary. The package-level
// sentinels are immutable; sharing an *errx.Error would let callers mutate the
// Code, Reason, Message, or wrapped cause observed by later calls.
func typedJournalWireError(cause error) error {
	if cause == nil {
		return nil
	}
	if errors.Is(cause, errJournalWireTooLarge) {
		return errx.Internal("mutation journal wire record exceeds size limit").Wrap(errJournalWireTooLarge)
	}
	return errx.Internal("invalid canonical mutation journal wire record").Wrap(errInvalidJournalWire)
}

// LegacyV1Disposition is a classification, not a grant of authority.
type LegacyV1Disposition string

const (
	LegacyV1Migratable LegacyV1Disposition = "migratable_pristine_prepared"
	LegacyV1Quarantine LegacyV1Disposition = "quarantine_unsafe_authority_state"
)

// LegacyV1Classification describes exact historical bytes. Even a valid
// non-prepared v1 record remains untrusted and must not enter a coordinator.
type LegacyV1Classification struct {
	Disposition LegacyV1Disposition
	Record      Record
	SHA256      string
}

// legacyV1Wire freezes the pre-v2 field order and omission behavior. Never
// decode v1 through Record: adding a field to Record must not silently change
// what historical bytes are considered canonical.
type legacyV1Wire struct {
	Version          int                `json:"version"`
	Revision         uint64             `json:"revision"`
	State            State              `json:"state"`
	Plan             legacyV1Plan       `json:"plan"`
	Receipt          *legacyV1Receipt   `json:"receipt,omitempty"`
	MutationAttempts uint8              `json:"mutation_attempts"`
	Outcome          *legacyV1Outcome   `json:"outcome,omitempty"`
	Evidence         []legacyV1Evidence `json:"evidence,omitempty"`
	CreatedAt        time.Time          `json:"created_at"`
	UpdatedAt        time.Time          `json:"updated_at"`
}

type legacyV1Receipt struct {
	ReceiptID     string    `json:"receipt_id"`
	Nonce         string    `json:"nonce"`
	PlanSHA256    string    `json:"plan_sha256"`
	ExpiresAt     time.Time `json:"expires_at"`
	KeyGeneration string    `json:"key_generation"`
	ReceiptSHA256 string    `json:"receipt_sha256"`
}

type legacyV1Outcome struct {
	Code           string `json:"code"`
	RemoteID       string `json:"remote_id,omitempty"`
	EvidenceSHA256 string `json:"evidence_sha256,omitempty"`
}

type legacyV1Evidence struct {
	SHA256      string    `json:"sha256"`
	Summary     string    `json:"summary"`
	CollectedAt time.Time `json:"collected_at"`
}

// encodePreparedLegacyV1 is deliberately private and prepared-only. The Store
// must never marshal a live Record directly: a future optional field could
// otherwise produce bytes that the frozen historical reader cannot accept.
func encodePreparedLegacyV1(record Record) (encoded []byte, err error) {
	defer func() { err = typedJournalWireError(err) }()
	if !frozenPlanShape(reflect.TypeOf(record), reflect.TypeOf(legacyV1Wire{})) ||
		record.Version != 1 || record.Revision != 1 || record.State != StatePrepared ||
		record.Receipt != nil || record.MutationAttempts != 0 || record.Outcome != nil ||
		len(record.Evidence) != 0 || !record.CreatedAt.Equal(record.UpdatedAt) {
		return nil, errInvalidJournalWire
	}
	plan, err := legacyPlanFromIntent(record.Plan)
	if err != nil {
		return nil, errInvalidJournalWire
	}
	wire := legacyV1Wire{Version: 1, Revision: 1, State: StatePrepared,
		Plan: plan, CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt}
	raw, err := encodeJournalWire(wire)
	if err != nil {
		return nil, errInvalidJournalWire
	}
	if len(raw) > maxLegacyV1Bytes {
		return nil, errJournalWireTooLarge
	}
	classified, err := ClassifyLegacyV1(raw)
	if err != nil || classified.Disposition != LegacyV1Migratable ||
		classified.Record.Plan.PlanID != record.Plan.PlanID {
		return nil, errInvalidJournalWire
	}
	return raw, nil
}

// These types pin the complete v1 plan shape, including all nested operation
// branches. A later addition to intent.Plan or one of its child structs cannot
// change the v1 decoder's byte grammar or silently become a migration field.
type legacyV1Plan struct {
	SchemaVersion  int               `json:"schema_version"`
	PlanID         string            `json:"plan_id"`
	Kind           string            `json:"kind"`
	Profile        legacyV1Profile   `json:"profile"`
	Policy         legacyV1Policy    `json:"policy"`
	Operation      legacyV1Operation `json:"operation"`
	RequestSHA256  string            `json:"request_sha256"`
	ExpectedSHA256 string            `json:"expected_sha256"`
	IntentSHA256   string            `json:"intent_sha256"`
}

type legacyV1Profile struct {
	Name                 string          `json:"name"`
	Instance             string          `json:"instance"`
	RESTBaseURL          string          `json:"rest_base_url"`
	OAuthIssuerURL       string          `json:"oauth_issuer_url"`
	IdentitySHA256       string          `json:"identity_sha256"`
	CredentialGeneration string          `json:"credential_generation"`
	Account              legacyV1Account `json:"account"`
}

type legacyV1Account struct {
	ID    string `json:"id"`
	Login string `json:"login"`
}

type legacyV1Policy struct {
	Project                legacyV1Project `json:"project"`
	PolicyRevision         uint64          `json:"policy_revision"`
	PolicySHA256           string          `json:"policy_sha256"`
	SchemaSHA256           string          `json:"schema_sha256"`
	ExecutorAssurance      string          `json:"executor_assurance"`
	AuthorizedCapability   string          `json:"authorized_capability"`
	NotificationPolicy     string          `json:"notification_policy"`
	ReconciliationStrategy string          `json:"reconciliation_strategy"`
}

type legacyV1Project struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

type legacyV1Operation struct {
	IssueCreate *legacyV1IssueCreate `json:"issue_create,omitempty"`
	IssueUpdate *legacyV1IssueUpdate `json:"issue_update,omitempty"`
	CommentAdd  *legacyV1CommentAdd  `json:"comment_add,omitempty"`
}

type legacyV1IssueCreate struct {
	Request  legacyV1CreateRequest  `json:"request"`
	Expected legacyV1CreateExpected `json:"expected"`
}

type legacyV1CreateRequest struct {
	Summary      string                `json:"summary"`
	Description  string                `json:"description"`
	Visibility   legacyV1Visibility    `json:"visibility"`
	CustomFields []legacyV1CustomField `json:"custom_fields,omitempty"`
	Marker       string                `json:"marker"`
}

type legacyV1CreateExpected struct {
	ProjectStateSHA256 string `json:"project_state_sha256"`
}

type legacyV1IssueUpdate struct {
	Request  legacyV1UpdateRequest  `json:"request"`
	Expected legacyV1UpdateExpected `json:"expected"`
}

type legacyV1UpdateRequest struct {
	IssueID string        `json:"issue_id"`
	Set     legacyV1Patch `json:"set"`
}

type legacyV1Patch struct {
	Summary      *string               `json:"summary,omitempty"`
	Description  *string               `json:"description,omitempty"`
	CustomFields []legacyV1CustomField `json:"custom_fields,omitempty"`
}

type legacyV1UpdateExpected struct {
	IssueID             string `json:"issue_id"`
	IssueStateSHA256    string `json:"issue_state_sha256"`
	TouchedFieldsSHA256 string `json:"touched_fields_sha256"`
}

type legacyV1CommentAdd struct {
	Request  legacyV1CommentRequest  `json:"request"`
	Expected legacyV1CommentExpected `json:"expected"`
}

type legacyV1CommentRequest struct {
	IssueID    string             `json:"issue_id"`
	Text       string             `json:"text"`
	Visibility legacyV1Visibility `json:"visibility"`
	Marker     string             `json:"marker"`
}

type legacyV1CommentExpected struct {
	IssueID          string `json:"issue_id"`
	IssueStateSHA256 string `json:"issue_state_sha256"`
}

type legacyV1Visibility struct {
	Mode     string   `json:"mode"`
	GroupIDs []string `json:"group_ids,omitempty"`
}

type legacyV1CustomField struct {
	FieldID   string  `json:"field_id"`
	FieldType string  `json:"field_type"`
	ValueID   *string `json:"value_id,omitempty"`
	TextValue *string `json:"text_value,omitempty"`
}

// ClassifyLegacyV1 accepts only exact bytes produced by the historical v1
// MarshalIndent-plus-LF encoder. Errors intentionally do not quote input.
func ClassifyLegacyV1(raw []byte) (classification LegacyV1Classification, err error) {
	defer func() { err = typedJournalWireError(err) }()
	if len(raw) > maxLegacyV1Bytes {
		return LegacyV1Classification{}, errJournalWireTooLarge
	}
	if len(raw) == 0 {
		return LegacyV1Classification{}, errInvalidJournalWire
	}
	var wire legacyV1Wire
	if err := decodeExactJournalWire(raw, &wire); err != nil {
		return LegacyV1Classification{}, err
	}
	if wire.Version != 1 {
		return LegacyV1Classification{}, errInvalidJournalWire
	}
	record, err := wire.record()
	if err != nil {
		return LegacyV1Classification{}, errInvalidJournalWire
	}
	if err := validateLegacyV1Record(wire); err != nil {
		return LegacyV1Classification{}, errInvalidJournalWire
	}
	encoded, err := encodeJournalWire(wire)
	if err != nil || !bytes.Equal(raw, encoded) {
		return LegacyV1Classification{}, errInvalidJournalWire
	}
	digest := sha256.Sum256(raw)
	classification = LegacyV1Classification{Record: record, SHA256: hex.EncodeToString(digest[:])}
	if record.State == State("prepared") && record.Revision == 1 && record.MutationAttempts == 0 &&
		record.Receipt == nil && record.Outcome == nil && len(record.Evidence) == 0 &&
		wire.CreatedAt.Format(time.RFC3339Nano) == wire.UpdatedAt.Format(time.RFC3339Nano) &&
		legacyV1MigratableToV2(record) {
		classification.Disposition = LegacyV1Migratable
	} else {
		classification.Disposition = LegacyV1Quarantine
	}
	return classification, nil
}

func (w legacyV1Wire) record() (Record, error) {
	plan := w.Plan.toIntent()
	r := Record{Version: w.Version, Revision: w.Revision, State: w.State, Plan: plan,
		MutationAttempts: w.MutationAttempts, CreatedAt: w.CreatedAt, UpdatedAt: w.UpdatedAt}
	if w.Receipt != nil {
		r.Receipt = &ReceiptBinding{ReceiptID: w.Receipt.ReceiptID, Nonce: w.Receipt.Nonce,
			PlanSHA256: w.Receipt.PlanSHA256, ExpiresAt: w.Receipt.ExpiresAt,
			KeyGeneration: w.Receipt.KeyGeneration, ReceiptSHA256: w.Receipt.ReceiptSHA256}
	}
	if w.Outcome != nil {
		r.Outcome = &Outcome{Code: w.Outcome.Code, RemoteID: w.Outcome.RemoteID,
			EvidenceSHA256: w.Outcome.EvidenceSHA256}
	}
	for _, e := range w.Evidence {
		r.Evidence = append(r.Evidence, Evidence{SHA256: e.SHA256, Summary: e.Summary, CollectedAt: e.CollectedAt})
	}
	return r, nil
}

// PreparedV2Record is the authority-free prepared branch. It contains no
// receipt, coordinator, outcome, or evidence.
type PreparedV2Record struct {
	Revision             uint64
	Plan                 intent.Plan
	LegacyV1RecordSHA256 *string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// preparedLineageV2Wire freezes all 13 fields shared by the prepared and
// claimed prepared-to-canceled branches. An empty struct pointer rejects
// non-null authority-bearing values without json.RawMessage.
type preparedLineageV2Wire struct {
	Version              int          `json:"version"`
	Revision             uint64       `json:"revision"`
	State                State        `json:"state"`
	Plan                 legacyV1Plan `json:"plan"`
	Receipt              *struct{}    `json:"receipt"`
	AuthorityEvidence    *struct{}    `json:"authority_evidence"`
	CoordinatorEvidence  *struct{}    `json:"coordinator_evidence"`
	MutationAttempts     uint8        `json:"mutation_attempts"`
	Outcome              *struct{}    `json:"outcome"`
	Evidence             *struct{}    `json:"evidence"`
	LegacyV1RecordSHA256 *string      `json:"legacy_v1_record_sha256"`
	CreatedAt            string       `json:"created_at"`
	UpdatedAt            string       `json:"updated_at"`
}

type preparedLineageV2Record struct {
	Revision             uint64
	Plan                 intent.Plan
	LegacyV1RecordSHA256 *string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// EncodePreparedV2 returns canonical indented JSON with a single terminal LF.
func EncodePreparedV2(record PreparedV2Record) (encoded []byte, err error) {
	defer func() { err = typedJournalWireError(err) }()
	return encodePreparedLineageV2(preparedLineageV2Record{Revision: record.Revision, Plan: record.Plan,
		LegacyV1RecordSHA256: record.LegacyV1RecordSHA256, CreatedAt: record.CreatedAt,
		UpdatedAt: record.UpdatedAt}, StatePrepared)
}

// DecodePreparedV2 rejects oversized input before JSON decoding and admits
// only the canonical, authority-free prepared branch.
func DecodePreparedV2(raw []byte) (record PreparedV2Record, err error) {
	defer func() { err = typedJournalWireError(err) }()
	decoded, err := decodePreparedLineageV2(raw, StatePrepared)
	if err != nil {
		return PreparedV2Record{}, err
	}
	return PreparedV2Record{Revision: decoded.Revision, Plan: decoded.Plan,
		LegacyV1RecordSHA256: decoded.LegacyV1RecordSHA256, CreatedAt: decoded.CreatedAt,
		UpdatedAt: decoded.UpdatedAt}, nil
}

// PreparedCanceledV2Record is a canonical, authority-free claim that a
// prepared record was canceled. Its bytes alone do not prove the predecessor,
// a valid transition, or any authorization to change the Store.
type PreparedCanceledV2Record struct {
	Revision             uint64
	Plan                 intent.Plan
	LegacyV1RecordSHA256 *string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// EncodePreparedCanceledV2 returns canonical indented JSON with one terminal
// LF for the claimed prepared-to-canceled branch only.
func EncodePreparedCanceledV2(record PreparedCanceledV2Record) (encoded []byte, err error) {
	defer func() { err = typedJournalWireError(err) }()
	return encodePreparedLineageV2(preparedLineageV2Record{Revision: record.Revision, Plan: record.Plan,
		LegacyV1RecordSHA256: record.LegacyV1RecordSHA256, CreatedAt: record.CreatedAt,
		UpdatedAt: record.UpdatedAt}, StateCanceled)
}

// DecodePreparedCanceledV2 rejects oversized input before JSON decoding and
// admits only canonical, authority-free claimed prepared-to-canceled bytes.
func DecodePreparedCanceledV2(raw []byte) (record PreparedCanceledV2Record, err error) {
	defer func() { err = typedJournalWireError(err) }()
	decoded, err := decodePreparedLineageV2(raw, StateCanceled)
	if err != nil {
		return PreparedCanceledV2Record{}, err
	}
	return PreparedCanceledV2Record{Revision: decoded.Revision, Plan: decoded.Plan,
		LegacyV1RecordSHA256: decoded.LegacyV1RecordSHA256, CreatedAt: decoded.CreatedAt,
		UpdatedAt: decoded.UpdatedAt}, nil
}

func encodePreparedLineageV2(record preparedLineageV2Record, state State) ([]byte, error) {
	if err := validatePreparedLineageV2(record, state); err != nil {
		return nil, err
	}
	createdAt, err := canonicalJournalTime(record.CreatedAt)
	if err != nil {
		return nil, errInvalidJournalWire
	}
	updatedAt, err := canonicalJournalTime(record.UpdatedAt)
	if err != nil {
		return nil, errInvalidJournalWire
	}
	planWire, err := legacyPlanFromIntent(record.Plan)
	if err != nil {
		return nil, errInvalidJournalWire
	}
	wire := preparedLineageV2Wire{Version: 2, Revision: record.Revision, State: state,
		Plan: planWire, LegacyV1RecordSHA256: record.LegacyV1RecordSHA256,
		CreatedAt: createdAt, UpdatedAt: updatedAt}
	raw, err := encodeJournalWire(wire)
	if err != nil {
		return nil, errInvalidJournalWire
	}
	if len(raw) > maxPreparedLineageV2Bytes {
		return nil, errJournalWireTooLarge
	}
	return raw, nil
}

func decodePreparedLineageV2(raw []byte, expectedState State) (preparedLineageV2Record, error) {
	if len(raw) > maxPreparedLineageV2Bytes {
		return preparedLineageV2Record{}, errJournalWireTooLarge
	}
	if len(raw) == 0 {
		return preparedLineageV2Record{}, errInvalidJournalWire
	}
	var wire preparedLineageV2Wire
	if err := decodeExactJournalWire(raw, &wire); err != nil {
		return preparedLineageV2Record{}, err
	}
	if wire.Version != 2 || wire.State != expectedState || wire.Receipt != nil ||
		wire.AuthorityEvidence != nil || wire.CoordinatorEvidence != nil ||
		wire.MutationAttempts != 0 || wire.Outcome != nil || wire.Evidence != nil {
		return preparedLineageV2Record{}, errInvalidJournalWire
	}
	created, err := parseCanonicalJournalTime(wire.CreatedAt)
	if err != nil {
		return preparedLineageV2Record{}, errInvalidJournalWire
	}
	updated, err := parseCanonicalJournalTime(wire.UpdatedAt)
	if err != nil {
		return preparedLineageV2Record{}, errInvalidJournalWire
	}
	record := preparedLineageV2Record{Revision: wire.Revision, Plan: wire.Plan.toIntent(),
		LegacyV1RecordSHA256: wire.LegacyV1RecordSHA256, CreatedAt: created, UpdatedAt: updated}
	canonical, err := encodePreparedLineageV2(record, expectedState)
	if err != nil || !bytes.Equal(raw, canonical) {
		return preparedLineageV2Record{}, errInvalidJournalWire
	}
	return record, nil
}

func validatePreparedLineageV2(record preparedLineageV2Record, state State) error {
	// UTC drops monotonic readings; compare the wall times that reach the wire.
	if record.UpdatedAt.UTC().Before(record.CreatedAt.UTC()) {
		return errInvalidJournalWire
	}
	planWire, err := legacyPlanFromIntent(record.Plan)
	if err != nil || validateLegacyPlan(planWire) != nil {
		return errInvalidJournalWire
	}
	switch state {
	case StatePrepared:
		if record.LegacyV1RecordSHA256 == nil {
			// Fresh prepared records preserve the same serialized wall timestamp.
			if record.Revision != 1 || !record.CreatedAt.UTC().Equal(record.UpdatedAt.UTC()) {
				return errInvalidJournalWire
			}
		} else if record.Revision != 2 || !isDigest(*record.LegacyV1RecordSHA256) {
			return errInvalidJournalWire
		}
	case StateCanceled:
		if record.LegacyV1RecordSHA256 == nil {
			if record.Revision != 2 {
				return errInvalidJournalWire
			}
		} else if record.Revision != 3 || !isDigest(*record.LegacyV1RecordSHA256) {
			return errInvalidJournalWire
		}
	default:
		return errInvalidJournalWire
	}
	return nil
}

// QuarantineMarker is non-authoritative evidence that a valid unsafe v1
// record was encountered. It cannot be used to recover or migrate authority.
type QuarantineMarker struct {
	RecordSHA256 string
	State        State
	DetectedAt   time.Time
}

type quarantineMarkerWire struct {
	SchemaVersion int    `json:"schema_version"`
	RecordSHA256  string `json:"record_sha256"`
	State         State  `json:"state"`
	Reason        string `json:"reason"`
	DetectedAt    string `json:"detected_at"`
}

// EncodeQuarantineMarker returns the exact five-field canonical marker.
func EncodeQuarantineMarker(marker QuarantineMarker) (encoded []byte, err error) {
	defer func() { err = typedJournalWireError(err) }()
	if !isDigest(marker.RecordSHA256) || !unsafeLegacyV1State(marker.State) {
		return nil, errInvalidJournalWire
	}
	detectedAt, err := canonicalJournalTime(marker.DetectedAt)
	if err != nil {
		return nil, errInvalidJournalWire
	}
	wire := quarantineMarkerWire{SchemaVersion: 1, RecordSHA256: marker.RecordSHA256,
		State: marker.State, Reason: quarantineReason,
		DetectedAt: detectedAt}
	raw, err := encodeJournalWire(wire)
	if err != nil {
		return nil, errInvalidJournalWire
	}
	if len(raw) > maxQuarantineBytes {
		return nil, errJournalWireTooLarge
	}
	return raw, nil
}

// DecodeQuarantineMarker does not confer authority on the referenced record.
func DecodeQuarantineMarker(raw []byte) (marker QuarantineMarker, err error) {
	defer func() { err = typedJournalWireError(err) }()
	if len(raw) > maxQuarantineBytes {
		return QuarantineMarker{}, errJournalWireTooLarge
	}
	if len(raw) == 0 {
		return QuarantineMarker{}, errInvalidJournalWire
	}
	var wire quarantineMarkerWire
	if err := decodeExactJournalWire(raw, &wire); err != nil {
		return QuarantineMarker{}, err
	}
	if wire.SchemaVersion != 1 || wire.Reason != quarantineReason {
		return QuarantineMarker{}, errInvalidJournalWire
	}
	detected, err := parseCanonicalJournalTime(wire.DetectedAt)
	if err != nil {
		return QuarantineMarker{}, errInvalidJournalWire
	}
	marker = QuarantineMarker{RecordSHA256: wire.RecordSHA256, State: wire.State, DetectedAt: detected}
	canonical, err := EncodeQuarantineMarker(marker)
	if err != nil || !bytes.Equal(raw, canonical) {
		return QuarantineMarker{}, errInvalidJournalWire
	}
	return marker, nil
}

func unsafeLegacyV1State(state State) bool {
	switch state {
	case State("prepared"), State("confirmed"), State("canceled"), State("expired"), State("in_flight"),
		State("failed_before_mutation"), State("applied"), State("ambiguous"), State("reconciled"),
		State("operator_resolution_required"), State("resolved_applied"), State("resolved_not_applied"):
		return true
	default:
		return false
	}
}

func parseCanonicalJournalTime(raw string) (time.Time, error) {
	if !strings.HasSuffix(raw, "Z") {
		return time.Time{}, errInvalidJournalWire
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, errInvalidJournalWire
	}
	canonical, err := canonicalJournalTime(parsed)
	if err != nil || canonical != raw {
		return time.Time{}, errInvalidJournalWire
	}
	return parsed.UTC(), nil
}

func canonicalJournalTime(value time.Time) (string, error) {
	utc := value.UTC()
	if utc.Year() < 1 || utc.Year() > 9999 {
		return "", errInvalidJournalWire
	}
	encoded := utc.Format(time.RFC3339Nano)
	parsed, err := time.Parse(time.RFC3339Nano, encoded)
	if err != nil || !parsed.Equal(utc) || !strings.HasSuffix(encoded, "Z") {
		return "", errInvalidJournalWire
	}
	return encoded, nil
}

func decodeExactJournalWire(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errInvalidJournalWire
	}
	var extra struct{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errInvalidJournalWire
	}
	return nil
}

func encodeJournalWire(value any) ([]byte, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, errInvalidJournalWire
	}
	return append(raw, '\n'), nil
}
