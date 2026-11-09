package journal

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/abigotado/youtrack-agent-cli/internal/intent"
)

// All values in this file describe the journal-v1 plan as it existed when
// journal v2 was introduced. Neither the v1 classifier nor the v2 prepared
// lineage codecs may delegate semantic validation to the evolving intent package.
const (
	legacyPlanSchemaVersion = 1
	legacyPlanMaxBytes      = 512 << 10
	legacyMarkerPrefix      = "Agent plan: "
)

var (
	legacyNamePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	legacyIssueIDPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,31}-[1-9][0-9]*$`)
	legacyReceiptPattern = regexp.MustCompile(`^YTAR-[A-Z2-7]{26}$`)
	legacyNoncePattern   = regexp.MustCompile(`^YTAN-[A-Z2-7]{26}$`)
	legacyRemotePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

type legacyCanonicalPlan struct {
	SchemaVersion  int               `json:"schema_version"`
	PlanID         string            `json:"plan_id"`
	Kind           string            `json:"kind"`
	Profile        legacyV1Profile   `json:"profile"`
	Policy         legacyV1Policy    `json:"policy"`
	Operation      legacyV1Operation `json:"operation"`
	RequestSHA256  string            `json:"request_sha256"`
	ExpectedSHA256 string            `json:"expected_sha256"`
}

func (p legacyV1Plan) canonical() legacyCanonicalPlan {
	return legacyCanonicalPlan{p.SchemaVersion, p.PlanID, p.Kind, p.Profile, p.Policy,
		p.Operation, p.RequestSHA256, p.ExpectedSHA256}
}

func validateLegacyPlan(p legacyV1Plan) error {
	if p.SchemaVersion != legacyPlanSchemaVersion || !legacyPlanID(p.PlanID) ||
		!legacyNamePattern.MatchString(p.Profile.Name) ||
		!legacyServiceURL(p.Profile.Instance) ||
		p.Profile.RESTBaseURL != p.Profile.Instance+"/api" ||
		!legacyServiceURL(p.Profile.RESTBaseURL) ||
		!legacyServiceURL(p.Profile.OAuthIssuerURL) ||
		!legacySHA256(p.Profile.IdentitySHA256) ||
		!legacyBoundString(p.Profile.CredentialGeneration, 256) ||
		!legacyIdentifier(p.Profile.Account.ID) ||
		!legacyBoundString(p.Profile.Account.Login, 256) {
		return errInvalidJournalWire
	}
	policy := p.Policy
	if !legacyIdentifier(policy.Project.ID) || !legacyProjectKey(policy.Project.Key) ||
		policy.PolicyRevision == 0 || !legacySHA256(policy.PolicySHA256) || !legacySHA256(policy.SchemaSHA256) ||
		(policy.ExecutorAssurance != "rest-best-effort" && policy.ExecutorAssurance != "custom-mcp-atomic") ||
		policy.NotificationPolicy != "youtrack-default" ||
		policy.ReconciliationStrategy != "bounded-exact-and-marker" {
		return errInvalidJournalWire
	}
	count := 0
	if p.Operation.IssueCreate != nil {
		count++
	}
	if p.Operation.IssueUpdate != nil {
		count++
	}
	if p.Operation.CommentAdd != nil {
		count++
	}
	if count != 1 {
		return errInvalidJournalWire
	}
	var request, expected any
	switch p.Kind {
	case "issue.create":
		if p.Operation.IssueCreate == nil || policy.AuthorizedCapability != "issue-create" {
			return errInvalidJournalWire
		}
		o := p.Operation.IssueCreate
		if !legacyRequiredText(o.Request.Summary, 1024) || !legacyText(o.Request.Description, 0, 32<<10) ||
			!legacyVisibility(o.Request.Visibility) || !legacyMarker(o.Request.Marker, o.Request.Description, p.PlanID) ||
			!legacyFields(o.Request.CustomFields) || !legacySHA256(o.Expected.ProjectStateSHA256) {
			return errInvalidJournalWire
		}
		request, expected = o.Request, o.Expected
	case "issue.update":
		if p.Operation.IssueUpdate == nil || policy.AuthorizedCapability != "issue-update" {
			return errInvalidJournalWire
		}
		o := p.Operation.IssueUpdate
		set := o.Request.Set
		if !legacyIssueIDPattern.MatchString(o.Request.IssueID) || o.Expected.IssueID != o.Request.IssueID ||
			(set.Summary == nil && set.Description == nil && len(set.CustomFields) == 0) ||
			(set.Summary != nil && !legacyRequiredText(*set.Summary, 1024)) ||
			(set.Description != nil && !legacyText(*set.Description, 0, 32<<10)) ||
			!legacyFields(set.CustomFields) || !legacySHA256(o.Expected.IssueStateSHA256) ||
			!legacySHA256(o.Expected.TouchedFieldsSHA256) {
			return errInvalidJournalWire
		}
		request, expected = o.Request, o.Expected
	case "comment.add":
		if p.Operation.CommentAdd == nil || policy.AuthorizedCapability != "comment-add" {
			return errInvalidJournalWire
		}
		o := p.Operation.CommentAdd
		body := o.Request.Text
		if !legacyIssueIDPattern.MatchString(o.Request.IssueID) || o.Expected.IssueID != o.Request.IssueID ||
			!legacyText(body, 1, 32<<10) || !legacyVisibility(o.Request.Visibility) ||
			!legacyMarker(o.Request.Marker, body, p.PlanID) || !legacySHA256(o.Expected.IssueStateSHA256) {
			return errInvalidJournalWire
		}
		if o.Request.Marker == "visible_footer" {
			marker := legacyMarkerPrefix + p.PlanID
			if body == marker {
				body = ""
			} else {
				body = strings.TrimSuffix(body, "\n\n"+marker)
			}
		}
		if !legacyRequiredText(body, 32<<10) {
			return errInvalidJournalWire
		}
		request, expected = o.Request, o.Expected
	default:
		return errInvalidJournalWire
	}
	requestBytes, requestErr := json.Marshal(request)
	expectedBytes, expectedErr := json.Marshal(expected)
	canonical, canonicalErr := json.Marshal(p.canonical())
	if requestErr != nil || expectedErr != nil || canonicalErr != nil ||
		len(canonical) > legacyPlanMaxBytes ||
		p.RequestSHA256 != legacyDigest(requestBytes) ||
		p.ExpectedSHA256 != legacyDigest(expectedBytes) ||
		p.IntentSHA256 != legacyDigest(canonical) {
		return errInvalidJournalWire
	}
	return nil
}

func legacyV1MigratableToV2(record Record) bool {
	digest := strings.Repeat("0", 64)
	_, err := EncodePreparedV2(PreparedV2Record{
		Revision: 2, Plan: record.Plan, LegacyV1RecordSHA256: &digest,
		CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt,
	})
	return err == nil
}

func validateLegacyV1Record(w legacyV1Wire) error {
	if w.Version != 1 || w.Revision == 0 || w.CreatedAt.IsZero() ||
		w.UpdatedAt.Before(w.CreatedAt) || w.MutationAttempts > 1 ||
		validateLegacyPlan(w.Plan) != nil || len(w.Evidence) > 16 {
		return errInvalidJournalWire
	}
	if w.Receipt != nil {
		r := w.Receipt
		if !legacyReceiptPattern.MatchString(r.ReceiptID) || !legacyNoncePattern.MatchString(r.Nonce) ||
			r.PlanSHA256 != w.Plan.IntentSHA256 || r.ExpiresAt.IsZero() ||
			strings.TrimSpace(r.KeyGeneration) == "" || !legacySHA256(r.ReceiptSHA256) {
			return errInvalidJournalWire
		}
	}
	if w.Outcome != nil {
		o := w.Outcome
		if o.EvidenceSHA256 != "" && !legacySHA256(o.EvidenceSHA256) {
			return errInvalidJournalWire
		}
		switch o.Code {
		case "applied":
			if !legacyRemotePattern.MatchString(o.RemoteID) {
				return errInvalidJournalWire
			}
		case "failed_before_mutation", "ambiguous":
			if o.RemoteID != "" {
				return errInvalidJournalWire
			}
		default:
			return errInvalidJournalWire
		}
	}
	for _, e := range w.Evidence {
		if !legacySHA256(e.SHA256) || e.CollectedAt.IsZero() || e.Summary == "" ||
			len(e.Summary) > 1024 || strings.ContainsRune(e.Summary, 0) {
			return errInvalidJournalWire
		}
	}
	hasReceipt, hasOutcome, hasEvidence := w.Receipt != nil, w.Outcome != nil, len(w.Evidence) > 0
	switch w.State {
	case State("prepared"):
		if hasReceipt || w.MutationAttempts != 0 || hasOutcome || hasEvidence {
			return errInvalidJournalWire
		}
	case State("confirmed"):
		if !hasReceipt || w.MutationAttempts != 0 || hasOutcome || hasEvidence {
			return errInvalidJournalWire
		}
	case State("canceled"), State("expired"):
		if w.MutationAttempts != 0 || hasOutcome || hasEvidence {
			return errInvalidJournalWire
		}
	case State("in_flight"):
		if !hasReceipt || w.MutationAttempts != 1 || hasOutcome || hasEvidence {
			return errInvalidJournalWire
		}
	case State("failed_before_mutation"), State("applied"), State("ambiguous"):
		if !hasReceipt || w.MutationAttempts != 1 || !hasOutcome || hasEvidence ||
			w.Outcome.Code != string(w.State) {
			return errInvalidJournalWire
		}
	case State("reconciled"), State("operator_resolution_required"), State("resolved_applied"), State("resolved_not_applied"):
		if !hasReceipt || w.MutationAttempts != 1 || !hasOutcome || !hasEvidence ||
			(w.Outcome.Code != "applied" && w.Outcome.Code != "ambiguous") {
			return errInvalidJournalWire
		}
	default:
		return errInvalidJournalWire
	}
	return nil
}

func legacyDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func legacySHA256(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == sha256.Size
}

func legacyPlanID(value string) bool {
	if !strings.HasPrefix(value, "YTAP-") || len(value) != 31 {
		return false
	}
	codec := base32.StdEncoding.WithPadding(base32.NoPadding)
	raw, err := codec.DecodeString(value[5:])
	return err == nil && len(raw) == 16 && codec.EncodeToString(raw) == value[5:]
}

func legacyIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 || !legacyAlnum(value[0]) {
		return false
	}
	for i := 1; i < len(value); i++ {
		if !legacyAlnum(value[i]) && !strings.ContainsRune("._:-", rune(value[i])) {
			return false
		}
	}
	return true
}

func legacyProjectKey(value string) bool {
	if len(value) == 0 || len(value) > 32 || value[0] < 'A' || value[0] > 'Z' {
		return false
	}
	for i := 1; i < len(value); i++ {
		if (value[i] < 'A' || value[i] > 'Z') && (value[i] < '0' || value[i] > '9') && value[i] != '_' {
			return false
		}
	}
	return true
}

func legacyAlnum(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func legacyBoundString(value string, max int) bool {
	return value != "" && len(value) <= max && strings.TrimSpace(value) == value &&
		!strings.ContainsRune(value, 0) && utf8.ValidString(value)
}

func legacyText(value string, min, max int) bool {
	return utf8.ValidString(value) && len(value) >= min && len(value) <= max && !strings.ContainsRune(value, 0)
}

func legacyRequiredText(value string, max int) bool {
	return strings.TrimSpace(value) != "" && legacyText(value, 1, max)
}

func legacyMarker(policy, body, planID string) bool {
	marker := legacyMarkerPrefix + planID
	switch policy {
	case "none":
		return !strings.Contains(body, legacyMarkerPrefix)
	case "visible_footer":
		return (body == marker || strings.HasSuffix(body, "\n\n"+marker)) &&
			strings.Count(body, legacyMarkerPrefix) == 1
	default:
		return false
	}
}

func legacyVisibility(value legacyV1Visibility) bool {
	switch value.Mode {
	case "public":
		return len(value.GroupIDs) == 0
	case "restricted":
		if len(value.GroupIDs) == 0 || len(value.GroupIDs) > 32 {
			return false
		}
		prev := ""
		for _, id := range value.GroupIDs {
			if !legacyIdentifier(id) || id <= prev {
				return false
			}
			prev = id
		}
		return true
	default:
		return false
	}
}

func legacyFields(fields []legacyV1CustomField) bool {
	if len(fields) > 100 {
		return false
	}
	prev := ""
	for i, field := range fields {
		if !legacyIdentifier(field.FieldID) || i > 0 && field.FieldID <= prev ||
			!legacyBoundString(field.FieldType, 128) ||
			(field.ValueID == nil) == (field.TextValue == nil) ||
			field.ValueID != nil && !legacyIdentifier(*field.ValueID) ||
			field.TextValue != nil && !legacyText(*field.TextValue, 0, 8<<10) {
			return false
		}
		prev = field.FieldID
	}
	return true
}

// This reproduces the historical profile-plane URL grammar. It is deliberately
// separate from endpoint.ValidateServiceURL, which may tighten in the future.
func legacyServiceURL(raw string) bool {
	if raw == "" || len(raw) > 2048 || strings.TrimSpace(raw) != raw ||
		strings.ContainsAny(raw, "\x00\r\n\t") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil ||
		u.Host == "" || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery ||
		u.Host != strings.ToLower(u.Host) || strings.HasSuffix(u.Host, ".") ||
		u.String() != raw || u.Path == "/" || strings.HasSuffix(u.Path, "/") ||
		strings.Contains(u.Path, "//") || strings.Contains(u.Path, "%") ||
		strings.ContainsAny(u.Path, "\\\x00\r\n\t") {
		return false
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	for _, part := range strings.Split(u.Path, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}

// Keep explicit field-by-field conversion so future intent fields cannot be
// silently accepted by the frozen journal codec.
func (p legacyV1Plan) toIntent() intent.Plan {
	out := intent.Plan{SchemaVersion: p.SchemaVersion, PlanID: p.PlanID, Kind: intent.Kind(p.Kind),
		Profile: intent.ProfileSnapshot{Name: p.Profile.Name, Instance: p.Profile.Instance,
			RESTBaseURL: p.Profile.RESTBaseURL, OAuthIssuerURL: p.Profile.OAuthIssuerURL,
			IdentitySHA256: p.Profile.IdentitySHA256, CredentialGeneration: p.Profile.CredentialGeneration,
			Account: intent.AccountBinding{ID: p.Profile.Account.ID, Login: p.Profile.Account.Login}},
		Policy: intent.ProjectPolicy{Project: intent.ProjectBinding{ID: p.Policy.Project.ID, Key: p.Policy.Project.Key},
			PolicyRevision: p.Policy.PolicyRevision, PolicySHA256: p.Policy.PolicySHA256,
			SchemaSHA256: p.Policy.SchemaSHA256, ExecutorAssurance: p.Policy.ExecutorAssurance,
			AuthorizedCapability: p.Policy.AuthorizedCapability, NotificationPolicy: p.Policy.NotificationPolicy,
			ReconciliationStrategy: p.Policy.ReconciliationStrategy},
		RequestSHA256: p.RequestSHA256, ExpectedSHA256: p.ExpectedSHA256, IntentSHA256: p.IntentSHA256}
	if op := p.Operation.IssueCreate; op != nil {
		out.Operation.IssueCreate = &intent.IssueCreateOperation{
			Request: intent.IssueCreateRequest{Summary: op.Request.Summary, Description: op.Request.Description,
				Visibility: legacyVisibilityToIntent(op.Request.Visibility), CustomFields: legacyFieldsToIntent(op.Request.CustomFields),
				Marker: intent.MarkerPolicy(op.Request.Marker)},
			Expected: intent.IssueCreateExpected{ProjectStateSHA256: op.Expected.ProjectStateSHA256}}
	}
	if op := p.Operation.IssueUpdate; op != nil {
		out.Operation.IssueUpdate = &intent.IssueUpdateOperation{
			Request: intent.IssueUpdateRequest{IssueID: op.Request.IssueID,
				Set: intent.IssuePatch{Summary: op.Request.Set.Summary, Description: op.Request.Set.Description,
					CustomFields: legacyFieldsToIntent(op.Request.Set.CustomFields)}},
			Expected: intent.IssueUpdateExpected{IssueID: op.Expected.IssueID,
				IssueStateSHA256: op.Expected.IssueStateSHA256, TouchedFieldsSHA256: op.Expected.TouchedFieldsSHA256}}
	}
	if op := p.Operation.CommentAdd; op != nil {
		out.Operation.CommentAdd = &intent.CommentAddOperation{
			Request: intent.CommentAddRequest{IssueID: op.Request.IssueID, Text: op.Request.Text,
				Visibility: legacyVisibilityToIntent(op.Request.Visibility), Marker: intent.MarkerPolicy(op.Request.Marker)},
			Expected: intent.CommentAddExpected{IssueID: op.Expected.IssueID,
				IssueStateSHA256: op.Expected.IssueStateSHA256}}
	}
	return out
}

func legacyVisibilityToIntent(v legacyV1Visibility) intent.Visibility {
	return intent.Visibility{Mode: v.Mode, GroupIDs: append([]string(nil), v.GroupIDs...)}
}

func legacyFieldsToIntent(fields []legacyV1CustomField) []intent.CustomFieldValue {
	if fields == nil {
		return nil
	}
	out := make([]intent.CustomFieldValue, len(fields))
	for i, f := range fields {
		out[i] = intent.CustomFieldValue{FieldID: f.FieldID, FieldType: f.FieldType,
			ValueID: f.ValueID, TextValue: f.TextValue}
	}
	return out
}

func legacyPlanFromIntent(p intent.Plan) (legacyV1Plan, error) {
	if !frozenPlanShape(reflect.TypeOf(p), reflect.TypeOf(legacyV1Plan{})) {
		return legacyV1Plan{}, errInvalidJournalWire
	}
	out := legacyV1Plan{SchemaVersion: p.SchemaVersion, PlanID: p.PlanID, Kind: string(p.Kind),
		Profile: legacyV1Profile{Name: p.Profile.Name, Instance: p.Profile.Instance,
			RESTBaseURL: p.Profile.RESTBaseURL, OAuthIssuerURL: p.Profile.OAuthIssuerURL,
			IdentitySHA256: p.Profile.IdentitySHA256, CredentialGeneration: p.Profile.CredentialGeneration,
			Account: legacyV1Account{ID: p.Profile.Account.ID, Login: p.Profile.Account.Login}},
		Policy: legacyV1Policy{Project: legacyV1Project{ID: p.Policy.Project.ID, Key: p.Policy.Project.Key},
			PolicyRevision: p.Policy.PolicyRevision, PolicySHA256: p.Policy.PolicySHA256,
			SchemaSHA256: p.Policy.SchemaSHA256, ExecutorAssurance: p.Policy.ExecutorAssurance,
			AuthorizedCapability: p.Policy.AuthorizedCapability, NotificationPolicy: p.Policy.NotificationPolicy,
			ReconciliationStrategy: p.Policy.ReconciliationStrategy},
		RequestSHA256: p.RequestSHA256, ExpectedSHA256: p.ExpectedSHA256, IntentSHA256: p.IntentSHA256}
	if op := p.Operation.IssueCreate; op != nil {
		out.Operation.IssueCreate = &legacyV1IssueCreate{
			Request: legacyV1CreateRequest{Summary: op.Request.Summary, Description: op.Request.Description,
				Visibility: legacyVisibilityFromIntent(op.Request.Visibility), CustomFields: legacyFieldsFromIntent(op.Request.CustomFields),
				Marker: string(op.Request.Marker)},
			Expected: legacyV1CreateExpected{ProjectStateSHA256: op.Expected.ProjectStateSHA256}}
	}
	if op := p.Operation.IssueUpdate; op != nil {
		out.Operation.IssueUpdate = &legacyV1IssueUpdate{
			Request: legacyV1UpdateRequest{IssueID: op.Request.IssueID,
				Set: legacyV1Patch{Summary: op.Request.Set.Summary, Description: op.Request.Set.Description,
					CustomFields: legacyFieldsFromIntent(op.Request.Set.CustomFields)}},
			Expected: legacyV1UpdateExpected{IssueID: op.Expected.IssueID,
				IssueStateSHA256: op.Expected.IssueStateSHA256, TouchedFieldsSHA256: op.Expected.TouchedFieldsSHA256}}
	}
	if op := p.Operation.CommentAdd; op != nil {
		out.Operation.CommentAdd = &legacyV1CommentAdd{
			Request: legacyV1CommentRequest{IssueID: op.Request.IssueID, Text: op.Request.Text,
				Visibility: legacyVisibilityFromIntent(op.Request.Visibility), Marker: string(op.Request.Marker)},
			Expected: legacyV1CommentExpected{IssueID: op.Expected.IssueID,
				IssueStateSHA256: op.Expected.IssueStateSHA256}}
	}
	return out, nil
}

func legacyVisibilityFromIntent(v intent.Visibility) legacyV1Visibility {
	return legacyV1Visibility{Mode: v.Mode, GroupIDs: append([]string(nil), v.GroupIDs...)}
}

func legacyFieldsFromIntent(fields []intent.CustomFieldValue) []legacyV1CustomField {
	if fields == nil {
		return nil
	}
	out := make([]legacyV1CustomField, len(fields))
	for i, f := range fields {
		out[i] = legacyV1CustomField{FieldID: f.FieldID, FieldType: f.FieldType,
			ValueID: f.ValueID, TextValue: f.TextValue}
	}
	return out
}

// Type shape comparison is a guard on the projection above: even a new
// omitempty field with a zero value changes the live type shape and therefore
// makes encoding fail until this frozen contract is deliberately revised.
func frozenPlanShape(live, frozen reflect.Type) bool {
	if live.Kind() != frozen.Kind() {
		return false
	}
	switch live.Kind() {
	case reflect.Pointer, reflect.Slice:
		return frozenPlanShape(live.Elem(), frozen.Elem())
	case reflect.Struct:
		if live.NumField() != frozen.NumField() {
			return false
		}
		for i := 0; i < live.NumField(); i++ {
			a, b := live.Field(i), frozen.Field(i)
			if a.Name != b.Name || a.Tag.Get("json") != b.Tag.Get("json") ||
				!frozenPlanShape(a.Type, b.Type) {
				return false
			}
		}
	}
	return true
}
