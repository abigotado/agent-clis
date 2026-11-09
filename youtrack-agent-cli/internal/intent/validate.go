package intent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/abigotado/youtrack-agent-cli/internal/endpoint"
	"github.com/abigotado/youtrack-agent-cli/internal/protocolvalue"
)

type canonicalPlan struct {
	SchemaVersion  int             `json:"schema_version"`
	PlanID         string          `json:"plan_id"`
	Kind           Kind            `json:"kind"`
	Profile        ProfileSnapshot `json:"profile"`
	Policy         ProjectPolicy   `json:"policy"`
	Operation      Operation       `json:"operation"`
	RequestSHA256  string          `json:"request_sha256"`
	ExpectedSHA256 string          `json:"expected_sha256"`
}

const (
	maxIdentityLength    = 256
	maxLoginLength       = 256
	maxSummaryLength     = 1024
	maxBodyLength        = 32 << 10
	maxCustomFields      = 100
	maxFieldTypeLength   = 128
	maxLiteralValueBytes = 8 << 10
)

var (
	namePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	issueIDPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,31}-[1-9][0-9]*$`)
)

// CanonicalBytes returns the exact bounded bytes hashed by IntentSHA256. The
// digest field itself is excluded to avoid a self-referential encoding.
func CanonicalBytes(plan Plan) ([]byte, error) {
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	return canonicalBytesUnchecked(plan)
}

// ApprovalDisplayBytes is the only byte representation a trusted approval
// helper may display. The helper stores its digest in receipt.plan_sha256 and
// signs approval.SigningBytes(receipt), making the receipt attest to every
// plan binding plus nonce, TTL, and helper-key identity.
func ApprovalDisplayBytes(plan Plan) ([]byte, error) {
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	if err := ValidateApprovalProfile(plan.Profile); err != nil {
		return nil, err
	}
	return canonicalBytesUnchecked(plan)
}

func canonicalBytesUnchecked(plan Plan) ([]byte, error) {
	raw, err := json.Marshal(canonicalPlan{
		SchemaVersion:  plan.SchemaVersion,
		PlanID:         plan.PlanID,
		Kind:           plan.Kind,
		Profile:        plan.Profile,
		Policy:         plan.Policy,
		Operation:      plan.Operation,
		RequestSHA256:  plan.RequestSHA256,
		ExpectedSHA256: plan.ExpectedSHA256,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal canonical plan: %w", err)
	}
	return boundCanonicalPlan(raw)
}

// ParseApprovalSnapshot strictly decodes one canonical plan representation.
// The caller supplies its protocol-specific byte bound, which is checked
// before JSON decoding or field allocation. IntentSHA256 is reconstructed from
// the exact canonical bytes because that self-referential field is omitted.
func ParseApprovalSnapshot(raw []byte, maximumBytes int) (Plan, error) {
	if maximumBytes <= 0 {
		return Plan{}, fmt.Errorf("%w: approval snapshot maximum must be positive", ErrInvalidPlan)
	}
	if maximumBytes > MaxCanonicalPlanBytes {
		maximumBytes = MaxCanonicalPlanBytes
	}
	if len(raw) == 0 || len(raw) > maximumBytes {
		return Plan{}, fmt.Errorf("%w: approval snapshot is empty or exceeds %d bytes", ErrInputTooLarge, maximumBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var wire canonicalPlan
	if err := decoder.Decode(&wire); err != nil {
		return Plan{}, fmt.Errorf("%w: decode approval snapshot: %v", ErrInvalidPlan, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Plan{}, fmt.Errorf("%w: approval snapshot has trailing data", ErrInvalidPlan)
	}
	plan := Plan{
		SchemaVersion: wire.SchemaVersion, PlanID: wire.PlanID, Kind: wire.Kind,
		Profile: wire.Profile, Policy: wire.Policy, Operation: wire.Operation,
		RequestSHA256: wire.RequestSHA256, ExpectedSHA256: wire.ExpectedSHA256,
		IntentSHA256: digest(raw),
	}
	if err := plan.Validate(); err != nil {
		return Plan{}, err
	}
	if err := ValidateApprovalProfile(plan.Profile); err != nil {
		return Plan{}, err
	}
	canonical, err := canonicalBytesUnchecked(plan)
	if err != nil {
		return Plan{}, err
	}
	if !bytes.Equal(canonical, raw) {
		return Plan{}, fmt.Errorf("%w: approval snapshot is not in canonical field order and encoding", ErrInvalidPlan)
	}
	return plan, nil
}

func boundCanonicalPlan(raw []byte) ([]byte, error) {
	if len(raw) > MaxCanonicalPlanBytes {
		return nil, fmt.Errorf("%w: canonical plan exceeds %d bytes", ErrInputTooLarge, MaxCanonicalPlanBytes)
	}
	return raw, nil
}

// Validate verifies every plan binding and all three hashes. It is suitable
// for journal reads and receipt verification of untrusted local files.
func (plan Plan) Validate() error {
	if plan.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: unsupported schema version %d", ErrInvalidPlan, plan.SchemaVersion)
	}
	if err := ValidatePlanID(plan.PlanID); err != nil {
		return err
	}
	if err := validateProfileLegacy(plan.Profile); err != nil {
		return err
	}
	if err := validatePolicy(plan.Policy); err != nil {
		return err
	}
	if plan.Policy.AuthorizedCapability != authorizedCapability(plan.Kind) {
		return fmt.Errorf("%w: authorized capability does not match operation kind", ErrInvalidPlan)
	}
	if err := validateOperation(plan.Kind, plan.Operation, plan.PlanID); err != nil {
		return err
	}
	requestBytes, expectedBytes, err := operationBytes(plan.Kind, plan.Operation)
	if err != nil {
		return err
	}
	if plan.RequestSHA256 != digest(requestBytes) {
		return fmt.Errorf("%w: request digest mismatch", ErrInvalidPlan)
	}
	if plan.ExpectedSHA256 != digest(expectedBytes) {
		return fmt.Errorf("%w: expected-state digest mismatch", ErrInvalidPlan)
	}
	canonical, err := canonicalBytesUnchecked(plan)
	if err != nil {
		return err
	}
	if plan.IntentSHA256 != digest(canonical) {
		return fmt.Errorf("%w: intent digest mismatch", ErrInvalidPlan)
	}
	return nil
}

func validateProfileLegacy(profile ProfileSnapshot) error {
	if !namePattern.MatchString(profile.Name) {
		return fmt.Errorf("%w: profile name is not canonical", ErrInvalidPlan)
	}
	if err := endpoint.ValidateServiceURL(profile.Instance); err != nil {
		return fmt.Errorf("%w: instance URL is invalid: %v", ErrInvalidPlan, err)
	}
	if err := endpoint.ValidateRESTBaseURL(profile.Instance, profile.RESTBaseURL); err != nil {
		return fmt.Errorf("%w: REST base URL does not derive from the selected instance: %v", ErrInvalidPlan, err)
	}
	if err := endpoint.ValidateServiceURL(profile.OAuthIssuerURL); err != nil {
		return fmt.Errorf("%w: OAuth issuer URL is invalid", ErrInvalidPlan)
	}
	if !protocolvalue.IsSHA256(profile.IdentitySHA256) {
		return fmt.Errorf("%w: profile identity digest is not canonical", ErrInvalidPlan)
	}
	if err := validateBoundString("credential generation", profile.CredentialGeneration, maxIdentityLength); err != nil {
		return err
	}
	if !protocolvalue.IsIdentifier(profile.Account.ID) {
		return fmt.Errorf("%w: account ID is not canonical", ErrInvalidPlan)
	}
	if err := validateBoundString("account login", profile.Account.Login, maxLoginLength); err != nil {
		return err
	}
	return nil
}

// ValidateApprovalProfile applies the narrower, language-neutral URL grammar
// required at the native approval boundary. Plan.Validate deliberately uses
// the legacy profile grammar so existing journals remain readable.
func ValidateApprovalProfile(profile ProfileSnapshot) error {
	if err := protocolvalue.ValidateApprovalURL(profile.Instance); err != nil {
		return fmt.Errorf("%w: instance URL is outside the approval URL grammar: %v", ErrInvalidPlan, err)
	}
	if err := protocolvalue.ValidateApprovalRESTBaseURL(profile.Instance, profile.RESTBaseURL); err != nil {
		return fmt.Errorf("%w: REST base URL is outside the approval URL grammar: %v", ErrInvalidPlan, err)
	}
	if err := protocolvalue.ValidateApprovalURL(profile.OAuthIssuerURL); err != nil {
		return fmt.Errorf("%w: OAuth issuer URL is outside the approval URL grammar: %v", ErrInvalidPlan, err)
	}
	return nil
}

func validatePolicy(policy ProjectPolicy) error {
	if !protocolvalue.IsIdentifier(policy.Project.ID) {
		return fmt.Errorf("%w: project ID is not canonical", ErrInvalidPlan)
	}
	if !protocolvalue.IsProjectKey(policy.Project.Key) {
		return fmt.Errorf("%w: project key is not canonical", ErrInvalidPlan)
	}
	if policy.PolicyRevision == 0 {
		return fmt.Errorf("%w: policy revision must be positive", ErrInvalidPlan)
	}
	if !protocolvalue.IsSHA256(policy.PolicySHA256) || !protocolvalue.IsSHA256(policy.SchemaSHA256) {
		return fmt.Errorf("%w: policy and schema digests must be canonical", ErrInvalidPlan)
	}
	if policy.ExecutorAssurance != "rest-best-effort" && policy.ExecutorAssurance != "custom-mcp-atomic" {
		return fmt.Errorf("%w: executor assurance is unsupported", ErrInvalidPlan)
	}
	if policy.NotificationPolicy != "youtrack-default" {
		return fmt.Errorf("%w: notification policy is unsupported", ErrInvalidPlan)
	}
	if policy.ReconciliationStrategy != "bounded-exact-and-marker" {
		return fmt.Errorf("%w: reconciliation strategy is unsupported", ErrInvalidPlan)
	}
	return nil
}

func validateOperation(kind Kind, operation Operation, planID string) error {
	count := 0
	if operation.IssueCreate != nil {
		count++
	}
	if operation.IssueUpdate != nil {
		count++
	}
	if operation.CommentAdd != nil {
		count++
	}
	if count != 1 {
		return fmt.Errorf("%w: operation must contain exactly one typed payload", ErrInvalidPlan)
	}
	switch kind {
	case KindIssueCreate:
		if operation.IssueCreate == nil {
			return fmt.Errorf("%w: kind does not match payload", ErrInvalidPlan)
		}
		return validateIssueCreate(*operation.IssueCreate, planID)
	case KindIssueUpdate:
		if operation.IssueUpdate == nil {
			return fmt.Errorf("%w: kind does not match payload", ErrInvalidPlan)
		}
		return validateIssueUpdate(*operation.IssueUpdate)
	case KindCommentAdd:
		if operation.CommentAdd == nil {
			return fmt.Errorf("%w: kind does not match payload", ErrInvalidPlan)
		}
		return validateCommentAdd(*operation.CommentAdd, planID)
	default:
		return fmt.Errorf("%w: unsupported operation kind %q", ErrInvalidPlan, kind)
	}
}

func validateRequiredOperationText(operation Operation) error {
	switch {
	case operation.IssueCreate != nil:
		return validateRequiredText("summary", operation.IssueCreate.Request.Summary, maxSummaryLength)
	case operation.IssueUpdate != nil && operation.IssueUpdate.Request.Set.Summary != nil:
		return validateRequiredText("summary", *operation.IssueUpdate.Request.Set.Summary, maxSummaryLength)
	case operation.CommentAdd != nil:
		return validateRequiredText("comment text", operation.CommentAdd.Request.Text, maxBodyLength)
	default:
		return nil
	}
}

func validateIssueCreate(operation IssueCreateOperation, planID string) error {
	if err := validateRequiredText("summary", operation.Request.Summary, maxSummaryLength); err != nil {
		return err
	}
	if err := validateText("description", operation.Request.Description, 0, maxBodyLength); err != nil {
		return err
	}
	if err := validateVisibility(operation.Request.Visibility); err != nil {
		return err
	}
	if err := validateMarker(operation.Request.Marker, operation.Request.Description, planID); err != nil {
		return err
	}
	if err := validateFields(operation.Request.CustomFields); err != nil {
		return err
	}
	if !protocolvalue.IsSHA256(operation.Expected.ProjectStateSHA256) {
		return fmt.Errorf("%w: project-state digest is not canonical", ErrInvalidPlan)
	}
	return nil
}

func validateIssueUpdate(operation IssueUpdateOperation) error {
	if !issueIDPattern.MatchString(operation.Request.IssueID) || operation.Expected.IssueID != operation.Request.IssueID {
		return fmt.Errorf("%w: update target is absent, non-canonical, or inconsistent", ErrInvalidPlan)
	}
	patch := operation.Request.Set
	if patch.Summary == nil && patch.Description == nil && len(patch.CustomFields) == 0 {
		return fmt.Errorf("%w: update patch is empty", ErrInvalidPlan)
	}
	if patch.Summary != nil {
		if err := validateRequiredText("summary", *patch.Summary, maxSummaryLength); err != nil {
			return err
		}
	}
	if patch.Description != nil {
		if err := validateText("description", *patch.Description, 0, maxBodyLength); err != nil {
			return err
		}
	}
	if err := validateFields(patch.CustomFields); err != nil {
		return err
	}
	if !protocolvalue.IsSHA256(operation.Expected.IssueStateSHA256) || !protocolvalue.IsSHA256(operation.Expected.TouchedFieldsSHA256) {
		return fmt.Errorf("%w: update precondition digests are not canonical", ErrInvalidPlan)
	}
	return nil
}

func validateCommentAdd(operation CommentAddOperation, planID string) error {
	if !issueIDPattern.MatchString(operation.Request.IssueID) || operation.Expected.IssueID != operation.Request.IssueID {
		return fmt.Errorf("%w: comment target is absent, non-canonical, or inconsistent", ErrInvalidPlan)
	}
	if err := validateVisibility(operation.Request.Visibility); err != nil {
		return err
	}
	if err := validateText("comment text", operation.Request.Text, 1, maxBodyLength); err != nil {
		return err
	}
	if err := validateMarker(operation.Request.Marker, operation.Request.Text, planID); err != nil {
		return err
	}
	text := operation.Request.Text
	if operation.Request.Marker == MarkerVisibleFooter {
		text = stripVisibleFooter(text, planID)
	}
	if err := validateRequiredText("comment text", text, maxBodyLength); err != nil {
		return err
	}
	if !protocolvalue.IsSHA256(operation.Expected.IssueStateSHA256) {
		return fmt.Errorf("%w: issue-state digest is not canonical", ErrInvalidPlan)
	}
	return nil
}

func validateMarker(marker MarkerPolicy, body, planID string) error {
	if marker != MarkerNone && marker != MarkerVisibleFooter {
		return fmt.Errorf("%w: marker policy must be explicit", ErrInvalidPlan)
	}
	if marker == MarkerVisibleFooter {
		visibleMarker := visibleMarkerPrefix + planID
		if body != visibleMarker && !strings.HasSuffix(body, "\n\n"+visibleMarker) {
			return fmt.Errorf("%w: visible marker was not inserted before hashing", ErrInvalidPlan)
		}
		if strings.Count(body, visibleMarkerPrefix) != 1 {
			return fmt.Errorf("%w: visible marker is ambiguous", ErrInvalidPlan)
		}
	} else if strings.Contains(body, visibleMarkerPrefix) {
		return fmt.Errorf("%w: marker-none body contains the reserved visible marker prefix", ErrInvalidPlan)
	}
	return nil
}

func stripVisibleFooter(body, planID string) string {
	marker := visibleMarkerPrefix + planID
	if body == marker {
		return ""
	}
	return strings.TrimSuffix(body, "\n\n"+marker)
}

func authorizedCapability(kind Kind) string {
	switch kind {
	case KindIssueCreate:
		return "issue-create"
	case KindIssueUpdate:
		return "issue-update"
	case KindCommentAdd:
		return "comment-add"
	default:
		return ""
	}
}

func validateVisibility(visibility Visibility) error {
	switch visibility.Mode {
	case "public":
		if len(visibility.GroupIDs) != 0 {
			return fmt.Errorf("%w: public visibility cannot carry groups", ErrInvalidPlan)
		}
	case "restricted":
		if len(visibility.GroupIDs) == 0 || len(visibility.GroupIDs) > 32 {
			return fmt.Errorf("%w: restricted visibility requires 1..32 groups", ErrInvalidPlan)
		}
		previous := ""
		for _, id := range visibility.GroupIDs {
			if !protocolvalue.IsIdentifier(id) || id <= previous {
				return fmt.Errorf("%w: visibility group IDs must be unique, sorted, and canonical", ErrInvalidPlan)
			}
			previous = id
		}
	default:
		return fmt.Errorf("%w: visibility mode must be public or restricted", ErrInvalidPlan)
	}
	return nil
}

func validateFields(fields []CustomFieldValue) error {
	if len(fields) > maxCustomFields {
		return fmt.Errorf("%w: too many custom fields", ErrInvalidPlan)
	}
	seen := make(map[string]struct{}, len(fields))
	previous := ""
	for index, field := range fields {
		if !protocolvalue.IsIdentifier(field.FieldID) {
			return fmt.Errorf("%w: custom field ID is not canonical", ErrInvalidPlan)
		}
		if index > 0 && field.FieldID <= previous {
			return fmt.Errorf("%w: custom fields must be unique and sorted by ID", ErrInvalidPlan)
		}
		if _, exists := seen[field.FieldID]; exists {
			return fmt.Errorf("%w: duplicate custom field ID %q", ErrInvalidPlan, field.FieldID)
		}
		seen[field.FieldID] = struct{}{}
		previous = field.FieldID
		if err := validateBoundString("custom field type", field.FieldType, maxFieldTypeLength); err != nil {
			return err
		}
		if (field.ValueID == nil) == (field.TextValue == nil) {
			return fmt.Errorf("%w: custom field %q needs exactly one value form", ErrInvalidPlan, field.FieldID)
		}
		if field.ValueID != nil && !protocolvalue.IsIdentifier(*field.ValueID) {
			return fmt.Errorf("%w: custom field value ID is not canonical", ErrInvalidPlan)
		}
		if field.TextValue != nil {
			if err := validateText("custom field text", *field.TextValue, 0, maxLiteralValueBytes); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateText(label, value string, minimum, maximum int) error {
	if !utf8.ValidString(value) || len(value) < minimum || len(value) > maximum || strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("%w: %s is empty, oversized, invalid UTF-8, or contains NUL", ErrInvalidPlan, label)
	}
	return nil
}

func validateRequiredText(label, value string, maximum int) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%w: %s is empty or whitespace-only", ErrInvalidPlan, label)
	}
	return validateText(label, value, 1, maximum)
}

func validateBoundString(label, value string, maximum int) error {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value || strings.ContainsRune(value, '\x00') || !utf8.ValidString(value) {
		return fmt.Errorf("%w: %s is empty, oversized, or non-canonical", ErrInvalidPlan, label)
	}
	return nil
}
