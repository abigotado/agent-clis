// Package intent builds bounded, canonical, offline YouTrack mutation plans.
//
// The package deliberately has no credential, browser, or transport
// dependency. A prepared plan binds the selected profile identity, account,
// exact project policy, schema, expected state, and typed payload.
package intent

import "errors"

const (
	// SchemaVersion is the durable plan schema written to the mutation journal.
	SchemaVersion = 1
	// MaxRequestBytes bounds one operation request before decoding.
	MaxRequestBytes = 64 << 10
	// MaxExpectedBytes bounds one expected-state snapshot before decoding.
	MaxExpectedBytes = 16 << 10
	// MaxCanonicalPlanBytes bounds every produced and validated canonical plan.
	// It covers the accepted request domain after encoding/json HTML escaping
	// plus independently bounded profile, policy, and expected-state metadata.
	MaxCanonicalPlanBytes = 512 << 10
)

var (
	// ErrInvalidPlan means a plan or one of its bindings is malformed.
	ErrInvalidPlan = errors.New("invalid mutation plan")
	// ErrInputTooLarge means bounded input or its canonical plan exceeded a
	// contract limit.
	ErrInputTooLarge = errors.New("mutation input is too large")
)

// Kind identifies one supported Stage A mutation.
type Kind string

const (
	KindIssueCreate Kind = "issue.create"
	KindIssueUpdate Kind = "issue.update"
	KindCommentAdd  Kind = "comment.add"
)

// AccountBinding identifies the authenticated YouTrack account without
// carrying any credential.
type AccountBinding struct {
	ID    string `json:"id"`
	Login string `json:"login"`
}

// ProfileSnapshot binds a plan to one explicit, non-secret profile identity.
// IdentitySHA256 is the digest of the complete canonical profile metadata;
// CredentialGeneration prevents a plan from surviving credential rotation.
type ProfileSnapshot struct {
	Name                 string         `json:"name"`
	Instance             string         `json:"instance"`
	RESTBaseURL          string         `json:"rest_base_url"`
	OAuthIssuerURL       string         `json:"oauth_issuer_url"`
	IdentitySHA256       string         `json:"identity_sha256"`
	CredentialGeneration string         `json:"credential_generation"`
	Account              AccountBinding `json:"account"`
}

// ProjectBinding identifies an exact YouTrack project by immutable ID and
// human-auditable key.
type ProjectBinding struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

// ProjectPolicy binds the project allowlist generation and the exact schema
// used to validate fields and values.
type ProjectPolicy struct {
	Project                ProjectBinding `json:"project"`
	PolicyRevision         uint64         `json:"policy_revision"`
	PolicySHA256           string         `json:"policy_sha256"`
	SchemaSHA256           string         `json:"schema_sha256"`
	ExecutorAssurance      string         `json:"executor_assurance"`
	AuthorizedCapability   string         `json:"authorized_capability"`
	NotificationPolicy     string         `json:"notification_policy"`
	ReconciliationStrategy string         `json:"reconciliation_strategy"`
}

// MarkerPolicy states whether prepare appends a visible audit footer. It is
// explicit because marker-free reconciliation can remain inconclusive.
type MarkerPolicy string

const (
	MarkerNone          MarkerPolicy = "none"
	MarkerVisibleFooter MarkerPolicy = "visible_footer"
)

// Visibility is explicit for issue creation and comments.
type Visibility struct {
	Mode     string   `json:"mode"`
	GroupIDs []string `json:"group_ids,omitempty"`
}

// CustomFieldValue binds a field ID and type to either an immutable value ID
// or a literal textual value. Exactly one value form must be present.
type CustomFieldValue struct {
	FieldID   string  `json:"field_id"`
	FieldType string  `json:"field_type"`
	ValueID   *string `json:"value_id,omitempty"`
	TextValue *string `json:"text_value,omitempty"`
}

// IssueCreateRequest is the complete typed create payload.
type IssueCreateRequest struct {
	Summary      string             `json:"summary"`
	Description  string             `json:"description"`
	Visibility   Visibility         `json:"visibility"`
	CustomFields []CustomFieldValue `json:"custom_fields,omitempty"`
	Marker       MarkerPolicy       `json:"marker"`
}

// IssueCreateExpected binds the project state observed before the offline
// plan was prepared.
type IssueCreateExpected struct {
	ProjectStateSHA256 string `json:"project_state_sha256"`
}

// IssuePatch contains the exact fields an update intends to replace. Pointer
// strings distinguish omission from replacing a field with an empty string.
type IssuePatch struct {
	Summary      *string            `json:"summary,omitempty"`
	Description  *string            `json:"description,omitempty"`
	CustomFields []CustomFieldValue `json:"custom_fields,omitempty"`
}

// IssueUpdateRequest is the complete typed update payload.
type IssueUpdateRequest struct {
	IssueID string     `json:"issue_id"`
	Set     IssuePatch `json:"set"`
}

// IssueUpdateExpected binds the exact target and touched state read before
// preparation.
type IssueUpdateExpected struct {
	IssueID             string `json:"issue_id"`
	IssueStateSHA256    string `json:"issue_state_sha256"`
	TouchedFieldsSHA256 string `json:"touched_fields_sha256"`
}

// CommentAddRequest is the complete typed comment payload.
type CommentAddRequest struct {
	IssueID    string       `json:"issue_id"`
	Text       string       `json:"text"`
	Visibility Visibility   `json:"visibility"`
	Marker     MarkerPolicy `json:"marker"`
}

// CommentAddExpected binds the exact issue state observed before preparation.
type CommentAddExpected struct {
	IssueID          string `json:"issue_id"`
	IssueStateSHA256 string `json:"issue_state_sha256"`
}

// Operation contains exactly one typed request/expected pair selected by Kind.
type Operation struct {
	IssueCreate *IssueCreateOperation `json:"issue_create,omitempty"`
	IssueUpdate *IssueUpdateOperation `json:"issue_update,omitempty"`
	CommentAdd  *CommentAddOperation  `json:"comment_add,omitempty"`
}

type IssueCreateOperation struct {
	Request  IssueCreateRequest  `json:"request"`
	Expected IssueCreateExpected `json:"expected"`
}

type IssueUpdateOperation struct {
	Request  IssueUpdateRequest  `json:"request"`
	Expected IssueUpdateExpected `json:"expected"`
}

type CommentAddOperation struct {
	Request  CommentAddRequest  `json:"request"`
	Expected CommentAddExpected `json:"expected"`
}

// Plan is the durable, non-secret mutation intent. IntentSHA256 hashes the
// canonical plan bytes returned by CanonicalBytes; RequestSHA256 and
// ExpectedSHA256 make receipt and audit comparisons explicit.
type Plan struct {
	SchemaVersion  int             `json:"schema_version"`
	PlanID         string          `json:"plan_id"`
	Kind           Kind            `json:"kind"`
	Profile        ProfileSnapshot `json:"profile"`
	Policy         ProjectPolicy   `json:"policy"`
	Operation      Operation       `json:"operation"`
	RequestSHA256  string          `json:"request_sha256"`
	ExpectedSHA256 string          `json:"expected_sha256"`
	IntentSHA256   string          `json:"intent_sha256"`
}
