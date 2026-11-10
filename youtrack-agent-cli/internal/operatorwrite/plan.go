package operatorwrite

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/endpoint"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/protocolvalue"
)

func invalid() error {
	e := errx.Usage("invalid or unsupported operator-write data")
	e.Reason = "OPERATOR_WRITE_INVALID"
	return e.WithHint("inspect the exact issue again and prepare a new operator-confirmed plan")
}

func ValidateID(id string) error {
	if protocolvalue.ValidateCanonicalBase32ID(id, PlanIDPrefix) != nil {
		return invalid()
	}
	return nil
}

func newID(prefix string) (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", errx.Internal("generate operator-write identifier").Wrap(err)
	}
	return prefix + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(value[:]), nil
}

func validText(s string, cap int, nonblank bool) bool {
	return len(s) <= cap && utf8.ValidString(s) && !strings.ContainsRune(s, '\x00') && (!nonblank || strings.TrimSpace(s) != "")
}

func ValidateSnapshot(s Snapshot) error {
	b := s.Binding
	if s.Version != Version || s.Lane != Lane ||
		!protocolvalue.IsIdentifier(b.ProfileName) || !protocolvalue.IsSHA256(b.ProfileIdentitySHA256) ||
		!validGeneration(b.CredentialGeneration) || !protocolvalue.IsIdentifier(b.AccountID) || !validText(b.AccountLogin, 256, true) || strings.ContainsAny(b.AccountLogin, " \t\r\n") ||
		!protocolvalue.IsSHA256(b.PolicySHA256) || b.PolicyRevision == 0 ||
		endpoint.ValidateRESTBaseURL(b.InstanceURL, b.RESTBaseURL) != nil ||
		endpoint.ValidateMCPURL(b.InstanceURL, b.MCPURL) != nil ||
		!validText(b.OAuthClientID, 128, true) ||
		endpoint.ValidateOAuthTopology(b.OAuthIssuerURL, b.OAuthAuthorizationEndpoint, b.OAuthTokenEndpoint) != nil ||
		s.CapturedAt.IsZero() || s.CapturedAt.Location() != time.UTC {
		return invalid()
	}
	switch s.Kind {
	case KindIssueCreate:
		if s.Issue != (Issue{}) || s.Field != nil || s.Project == nil || s.Comment != nil || !protocolvalue.IsIdentifier(s.Project.ID) ||
			!protocolvalue.IsProjectKey(s.Project.Key) || len(s.Fields) > MaxCreateFields {
			return invalid()
		}
		// The create payload addresses fields by name, so names are unique and
		// fit the client's identifier bound.
		projectFields, globalFields, names := map[string]bool{}, map[string]bool{}, map[string]bool{}
		for _, f := range s.Fields {
			if f.IssueFieldID != "" || f.CurrentValue != nil || f.Type == userIssueField || !validFieldSchema(f) || !validTarget(f) || len(f.Name) > MaxCreateFieldNameBytes ||
				projectFields[f.ProjectFieldID] || globalFields[f.GlobalFieldID] || names[f.Name] {
				return invalid()
			}
			projectFields[f.ProjectFieldID], globalFields[f.GlobalFieldID], names[f.Name] = true, true, true
		}
	case KindIssueUpdate:
		f := s.Field
		if !validIssue(s.Issue) || s.Project != nil || s.Fields != nil || s.Comment != nil || f == nil || !protocolvalue.IsIdentifier(f.IssueFieldID) || !validFieldSchema(*f) ||
			!validUpdateValues(*f) {
			return invalid()
		}
	case KindCommentAdd:
		if !validIssue(s.Issue) || s.Project != nil || s.Fields != nil || s.Field != nil || s.Comment != nil {
			return invalid()
		}
	case KindCommentDelete:
		if !validIssue(s.Issue) || s.Project != nil || s.Fields != nil || s.Field != nil || s.Comment == nil || !validComment(*s.Comment, s.Binding.AccountID) {
			return invalid()
		}
	default:
		return invalid()
	}
	raw, err := json.Marshal(s)
	if err != nil || len(raw) > snapshotLimit(s.Kind) {
		return invalid()
	}
	return nil
}

func snapshotLimit(kind Kind) int {
	if kind == KindCommentDelete {
		return MaxCommentDeleteSnapshotBytes
	}
	return MaxSnapshotBytes
}

func validComment(comment Comment, accountID string) bool {
	if !protocolvalue.IsIdentifier(comment.ID) || !validText(comment.Text, MaxCommentBytes, true) ||
		!protocolvalue.IsIdentifier(comment.AuthorID) || !validText(comment.AuthorLogin, 256, true) ||
		strings.ContainsAny(comment.AuthorLogin, " \t\r\n") || comment.Created <= 0 || comment.Deleted ||
		comment.Updated != nil && *comment.Updated < 0 || !validCommentVisibility(comment.Visibility) ||
		comment.Attachments == nil || len(comment.Attachments) != 0 ||
		(comment.AuthorID == accountID && comment.RequiredServerPermission != "Delete Comment") ||
		(comment.AuthorID != accountID && comment.RequiredServerPermission != "Delete Not Own Comment") {
		return false
	}
	return true
}

func validCommentVisibility(visibility CommentVisibility) bool {
	switch visibility.Type {
	case "UnlimitedVisibility":
		if visibility.PermittedGroupIDs == nil || visibility.PermittedUserIDs == nil || len(visibility.PermittedGroupIDs) != 0 || len(visibility.PermittedUserIDs) != 0 {
			return false
		}
	case "LimitedVisibility":
		if visibility.PermittedGroupIDs == nil || visibility.PermittedUserIDs == nil {
			return false
		}
	default:
		return false
	}
	previous := ""
	for _, id := range visibility.PermittedGroupIDs {
		if !protocolvalue.IsIdentifier(id) || id <= previous {
			return false
		}
		previous = id
	}
	previous = ""
	for _, id := range visibility.PermittedUserIDs {
		if !protocolvalue.IsIdentifier(id) || id <= previous {
			return false
		}
		previous = id
	}
	return true
}

func validIssue(i Issue) bool {
	return protocolvalue.IsIdentifier(i.ID) && protocolvalue.IsIdentifier(i.ReadableID) &&
		protocolvalue.IsIdentifier(i.ProjectID) && protocolvalue.IsProjectKey(i.ProjectKey) && i.Updated > 0
}

const (
	stateIssueField = "StateIssueCustomField"
	enumIssueField  = "SingleEnumIssueCustomField"
	userIssueField  = "SingleUserIssueCustomField"
)

// validFieldSchema checks the touched single State, Enum, or User schema,
// shared by update and create fields. It does not check the target value.
func validFieldSchema(f Field) bool {
	return protocolvalue.IsIdentifier(f.ProjectFieldID) && protocolvalue.IsIdentifier(f.GlobalFieldID) && validText(f.Name, 256, true) &&
		(f.Type == stateIssueField && f.ProjectFieldType == "StateProjectCustomField" && f.ValueType == "state" && f.BundleType == "StateBundle" ||
			f.Type == enumIssueField && f.ProjectFieldType == "EnumProjectCustomField" && f.ValueType == "enum" && f.BundleType == "EnumBundle" ||
			f.Type == userIssueField && f.ProjectFieldType == "UserProjectCustomField" && f.ValueType == "user" && f.BundleType == "UserBundle") &&
		!f.IsMultiValue && f.FieldTypeType == "FieldType" && protocolvalue.IsIdentifier(f.BundleID) && f.FieldTypeID == f.ValueType+"[1]"
}

// validTarget requires a present, valid, nonarchived target value.
func validTarget(f Field) bool {
	return f.TargetValue != nil && validValue(*f.TargetValue, f.Type) && !f.TargetValue.Archived
}

// validUpdateValues checks an update field's current and target values. A nil
// target clears the field: it needs a clearable field that currently holds a
// value, because clearing an empty field is a no-op that reconciliation could
// not tell from success.
func validUpdateValues(f Field) bool {
	if f.CurrentValue == nil && !f.CanBeEmpty || f.CurrentValue != nil && !validValue(*f.CurrentValue, f.Type) {
		return false
	}
	if f.TargetValue == nil {
		return f.CanBeEmpty && f.CurrentValue != nil
	}
	return validTarget(f)
}

// needsPlanVersion4 reports whether the snapshot carries a User field or a
// null target, which only a version 4 plan may hold.
func needsPlanVersion4(s Snapshot) bool {
	return s.Field != nil && (s.Field.Type == userIssueField || s.Field.TargetValue == nil)
}

func validValue(v Value, fieldType string) bool {
	var expected string
	switch fieldType {
	case stateIssueField:
		expected = "StateBundleElement"
	case enumIssueField:
		expected = "EnumBundleElement"
	case userIssueField:
		// A user is never archived; only id, login (name), and type are frozen.
		if v.Archived {
			return false
		}
		expected = "User"
	default:
		return false
	}
	return protocolvalue.IsIdentifier(v.ID) && validText(v.Name, 256, true) && v.Type == expected
}

func validGeneration(value string) bool {
	if len(value) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == value
}

// Marker is public evidence for bounded reconciliation, not an approval.
func Marker(id string) string { return "[youtrack operator-write " + id + "]" }

// validSummary accepts one canonical line, so an exact response comparison
// cannot fail on server-side trimming.
func validSummary(s string) bool {
	if !validText(s, MaxSummaryBytes, true) || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.In(r, unicode.Zl, unicode.Zp) {
			return false
		}
	}
	return true
}

// validDescriptionBody accepts an empty body or canonical LF-only text without
// surrounding whitespace, so the marker suffix stays exact after storage.
func validDescriptionBody(s string) bool {
	return s == "" || validText(s, MaxDescriptionBytes, true) && strings.TrimSpace(s) == s && !strings.ContainsRune(s, '\r')
}

func finalDescription(body, id string) string {
	if body == "" {
		return Marker(id)
	}
	return body + "\n\n" + Marker(id)
}

func validRequest(q Request) bool {
	switch q.Kind {
	case KindIssueCreate:
		return q.CommentText == "" && validSummary(q.Summary)
	case KindIssueUpdate:
		return q.CommentText == "" && q.Summary == "" && q.Description == ""
	case KindCommentAdd:
		return q.Summary == "" && q.Description == "" && validText(q.CommentText, MaxCommentBytes, true)
	case KindCommentDelete:
		return q.CommentText == "" && q.Summary == "" && q.Description == ""
	default:
		return false
	}
}

// Prepare is network-free. The supplied snapshot fixes the kind and target.
func Prepare(snapshot Snapshot, request Request, now time.Time) (Plan, error) {
	if err := ValidateSnapshot(snapshot); err != nil {
		return Plan{}, err
	}
	if request.Kind != snapshot.Kind || now.IsZero() || snapshot.CapturedAt.After(now) || now.Sub(snapshot.CapturedAt) >= SnapshotTTL {
		return Plan{}, invalid()
	}
	id, err := newID(PlanIDPrefix)
	if err != nil {
		return Plan{}, err
	}
	if !validRequest(request) {
		return Plan{}, invalid()
	}
	switch request.Kind {
	case KindIssueCreate:
		if !validDescriptionBody(request.Description) {
			return Plan{}, invalid()
		}
		request.Description = finalDescription(request.Description, id)
		if len(request.Description) > MaxDescriptionBytes {
			return Plan{}, invalid()
		}
	case KindCommentAdd:
		request.CommentText += "\n\n" + Marker(id)
		if len(request.CommentText) > MaxCommentBytes {
			return Plan{}, invalid()
		}
	case KindIssueUpdate:
		// The frozen snapshot is the complete update payload.
	case KindCommentDelete:
		// The frozen snapshot is the complete hard-delete target.
	default:
		return Plan{}, invalid()
	}
	// Deep-copy the snapshot so subsequent caller edits cannot change the plan.
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return Plan{}, invalid()
	}
	var frozen Snapshot
	if err := json.Unmarshal(raw, &frozen); err != nil {
		return Plan{}, invalid()
	}
	plan := Plan{Version: PlanVersionFor(request.Kind), Lane: Lane, ID: id, ConfirmationMode: ConfirmationMode, Notifications: Notifications,
		Snapshot: frozen, Request: request, CreatedAt: now.UTC()}
	plan.SHA256, err = digest(plan)
	if err != nil {
		return Plan{}, err
	}
	return plan, ValidatePlan(plan)
}

func digest(p Plan) (string, error) {
	p.SHA256 = ""
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > MaxPlanBytes {
		return "", invalid()
	}
	return protocolvalue.SHA256Hex(raw), nil
}

func ValidatePlan(p Plan) error {
	if p.Lane != Lane || ValidateID(p.ID) != nil || p.ConfirmationMode != ConfirmationMode ||
		p.Notifications != Notifications || ValidateSnapshot(p.Snapshot) != nil || p.Request.Kind != p.Snapshot.Kind ||
		p.CreatedAt.IsZero() || p.CreatedAt.Location() != time.UTC || p.Snapshot.CapturedAt.After(p.CreatedAt) ||
		p.CreatedAt.Sub(p.Snapshot.CapturedAt) >= SnapshotTTL || !protocolvalue.IsSHA256(p.SHA256) {
		return invalid()
	}
	switch p.Version {
	case LegacyPlanVersion1:
		if p.Snapshot.Kind == KindCommentDelete || p.ExpiresAt.IsZero() || p.ExpiresAt.Location() != time.UTC || p.ExpiresAt.Sub(p.CreatedAt) != LegacyPlanTTL {
			return invalid()
		}
	case PlanVersion2:
		if p.Snapshot.Kind == KindCommentDelete || !p.ExpiresAt.IsZero() {
			return invalid()
		}
	case PlanVersion3:
		if p.Snapshot.Kind != KindCommentDelete || !p.ExpiresAt.IsZero() {
			return invalid()
		}
	case PlanVersion4:
		if p.Snapshot.Kind != KindIssueUpdate || !p.ExpiresAt.IsZero() {
			return invalid()
		}
	default:
		return invalid()
	}
	if p.Version != PlanVersion4 && needsPlanVersion4(p.Snapshot) {
		return invalid()
	}
	if !validRequest(p.Request) {
		return invalid()
	}
	switch p.Request.Kind {
	case KindIssueCreate:
		d := p.Request.Description
		body := strings.TrimSuffix(strings.TrimSuffix(d, Marker(p.ID)), "\n\n")
		if len(d) > MaxDescriptionBytes || strings.Count(d, Marker(p.ID)) != 1 || !validDescriptionBody(body) || finalDescription(body, p.ID) != d {
			return invalid()
		}
	case KindCommentAdd:
		marker := "\n\n" + Marker(p.ID)
		if !strings.HasSuffix(p.Request.CommentText, marker) || strings.Count(p.Request.CommentText, Marker(p.ID)) != 1 ||
			!validText(strings.TrimSuffix(p.Request.CommentText, marker), MaxCommentBytes, true) {
			return invalid()
		}
	case KindIssueUpdate:
		// validRequest already rejects any text for a frozen field update.
	case KindCommentDelete:
		// validRequest already rejects all mutable payload fields.
	default:
		return invalid()
	}
	sha, err := digest(p)
	if err != nil || sha != p.SHA256 {
		return invalid()
	}
	return nil
}

func CheckFresh(p Plan, now time.Time) error {
	if err := ValidatePlan(p); err != nil {
		return err
	}
	if now.Before(p.CreatedAt) {
		return errx.Conflict("OPERATOR_PLAN_EXPIRED", "operator-write plan is not yet valid on the local clock").
			WithHint("check the local clock; keep the existing plan and do not renew it")
	}
	if p.Version == LegacyPlanVersion1 && !now.Before(p.ExpiresAt) {
		return errx.Conflict("OPERATOR_PLAN_EXPIRED", "operator-write plan is outside its local lifetime").WithHint("inspect again and confirm a newly prepared plan")
	}
	return nil
}

func decode(r io.Reader, limit int, dst any) error {
	if r == nil {
		return invalid()
	}
	raw, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil || len(raw) > limit {
		return invalid()
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil {
		return invalid()
	}
	var extra json.RawMessage
	if d.Decode(&extra) != io.EOF {
		return invalid()
	}
	// JSON duplicate keys are not canonical and could mislead a human reader.
	if hasDuplicateKeys(raw) {
		return invalid()
	}
	return nil
}

func hasDuplicateKeys(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	var walk func() bool
	walk = func() bool {
		token, err := d.Token()
		if err != nil {
			return true
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return false
		}
		if delim == '{' {
			seen := make(map[string]bool)
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return true
				}
				s, ok := key.(string)
				if !ok || seen[s] {
					return true
				}
				seen[s] = true
				if walk() {
					return true
				}
			}
		} else if delim == '[' {
			for d.More() {
				if walk() {
					return true
				}
			}
		} else {
			return true
		}
		_, err = d.Token()
		return err != nil
	}
	return walk()
}

func DecodeSnapshot(r io.Reader) (Snapshot, error) {
	var s Snapshot
	if err := decode(r, MaxCommentDeleteSnapshotBytes, &s); err != nil {
		return Snapshot{}, err
	}
	if err := ValidateSnapshot(s); err != nil {
		return Snapshot{}, err
	}
	return s, nil
}
func DecodeRequest(r io.Reader) (Request, error) {
	var q Request
	if err := decode(r, MaxRequestBytes, &q); err != nil {
		return Request{}, err
	}
	if !validRequest(q) || q.Kind == KindIssueCreate && !validDescriptionBody(q.Description) {
		return Request{}, invalid()
	}
	return q, nil
}
func DecodePlan(r io.Reader) (Plan, error) {
	var p Plan
	if err := decode(r, MaxPlanBytes, &p); err != nil {
		return Plan{}, err
	}
	if err := ValidatePlan(p); err != nil {
		return Plan{}, err
	}
	return p, nil
}
