package youtrack

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
)

const (
	maxSummaryBytes     = 1024
	maxDescriptionBytes = 1 << 20
	maxMutationBodySize = 2 << 20
	maxCommentBytes     = 32 << 10
)

// CustomFieldUpdate is one ID- and type-bound issue custom field mutation.
// Value must be exactly one bounded JSON value.
type CustomFieldUpdate struct {
	ID    string          `json:"id"`
	Type  string          `json:"$type"`
	Value json.RawMessage `json:"value"`
}

// CreateCustomField sets or clears one single-valued field on a new issue. A
// new issue has no issue-field identity, so the payload addresses the field by
// its project-unique Name and Type; ProjectFieldID verifies the response.
// Exactly one of ValueID and Clear is set: Clear sends an explicit JSON null.
type CreateCustomField struct {
	ProjectFieldID string
	Name           string
	Type           string
	ValueID        string
	Clear          bool
}

// CreateIssueInput is the complete supported issue.create payload. ProjectKey
// and the expected reporter bind the verified response, and are never sent.
type CreateIssueInput struct {
	ProjectID             string
	ProjectKey            string
	Summary               string
	Description           *string
	ExpectedReporterID    string
	ExpectedReporterLogin string
	CustomFields          []CreateCustomField
}

// UpdateIssueInput is the complete supported issue.update payload. ProjectID
// and ProjectKey bind the result to the REST best-effort policy preflight and
// are never sent as mutation fields, so this operation cannot move an issue.
type UpdateIssueInput struct {
	IssueID      string
	ProjectID    string
	ProjectKey   string
	Summary      *string
	Description  *string
	CustomFields []CustomFieldUpdate
}

// AddCommentInput binds one public comment to its exact issue and expected
// authenticated author. Text includes any caller-provided reconciliation marker.
type AddCommentInput struct {
	IssueID             string
	ExpectedAuthorID    string
	ExpectedAuthorLogin string
	Text                string
}

// DeleteCommentInput binds one irreversible comment deletion to exact,
// immutable issue and comment identifiers.
type DeleteCommentInput struct {
	IssueID   string
	CommentID string
}

type addCommentPayload struct {
	Text       string                  `json:"text"`
	Visibility publicCommentVisibility `json:"visibility"`
}

type publicCommentVisibility struct {
	Type string `json:"$type"`
}

// commentResponse preserves presence of deleted, so omitted/null
// fields cannot masquerade as a verified non-deleted comment.
type commentResponse struct {
	Comment
	Deleted *bool `json:"deleted"`
}

type createIssuePayload struct {
	Project      projectReference     `json:"project"`
	Summary      string               `json:"summary"`
	Description  *string              `json:"description,omitempty"`
	CustomFields []createFieldPayload `json:"customFields,omitempty"`
}

// createFieldPayload keeps the value a pointer without omitempty, so a clear
// encodes as an explicit null and a set value as {"id":ID}.
type createFieldPayload struct {
	Name  string            `json:"name"`
	Type  string            `json:"$type"`
	Value *projectReference `json:"value"`
}

type updateIssuePayload struct {
	Summary      *string             `json:"summary,omitempty"`
	Description  *string             `json:"description,omitempty"`
	CustomFields []CustomFieldUpdate `json:"customFields,omitempty"`
}

type projectReference struct {
	ID string `json:"id"`
}

// ValidateCreateIssueInput validates create intent without credentials or
// network access.
func ValidateCreateIssueInput(input CreateIssueInput) error {
	if err := validateIdentifier("project", input.ProjectID); err != nil {
		return err
	}
	if err := validateIdentifier("project", input.ProjectKey); err != nil {
		return err
	}
	if err := validateIdentifier("reporter", input.ExpectedReporterID); err != nil {
		return err
	}
	if err := validateRequiredText("reporter login", input.ExpectedReporterLogin, maxIdentifierBytes); err != nil {
		return err
	}
	if err := validateRequiredText("summary", input.Summary, maxSummaryBytes); err != nil {
		return err
	}
	if input.Description != nil {
		if err := validateOptionalText("description", *input.Description, maxDescriptionBytes); err != nil {
			return err
		}
	}
	projectFields, names := map[string]bool{}, map[string]bool{}
	for _, field := range input.CustomFields {
		if err := validateIdentifier("project custom field", field.ProjectFieldID); err != nil {
			return err
		}
		if field.Clear && field.ValueID != "" {
			return errx.Usage("a cleared custom field cannot also set a value")
		}
		if !field.Clear {
			if err := validateIdentifier("custom field value", field.ValueID); err != nil {
				return err
			}
		}
		if err := validateRequiredText("custom field name", field.Name, maxIdentifierBytes); err != nil {
			return err
		}
		if err := validateTypeName(field.Type); err != nil {
			return err
		}
		if projectFields[field.ProjectFieldID] || names[field.Name] {
			return errx.Usage("custom fields must be unique")
		}
		projectFields[field.ProjectFieldID], names[field.Name] = true, true
	}
	return nil
}

// ValidateUpdateIssueInput validates update intent without credentials or
// network access.
func ValidateUpdateIssueInput(input UpdateIssueInput) error {
	if err := validateIdentifier("issue", input.IssueID); err != nil {
		return err
	}
	if err := validateIdentifier("project", input.ProjectID); err != nil {
		return err
	}
	if err := validateIdentifier("project", input.ProjectKey); err != nil {
		return err
	}
	if input.Summary == nil && input.Description == nil && len(input.CustomFields) == 0 {
		return errx.Usage("issue update must change at least one supported field")
	}
	if input.Summary != nil {
		if err := validateRequiredText("summary", *input.Summary, maxSummaryBytes); err != nil {
			return err
		}
	}
	if input.Description != nil {
		if err := validateOptionalText("description", *input.Description, maxDescriptionBytes); err != nil {
			return err
		}
	}
	return validateCustomFieldUpdates(input.CustomFields)
}

// ValidateAddCommentInput validates the full final comment before dispatch.
func ValidateAddCommentInput(input AddCommentInput) error {
	if err := validateIdentifier("issue", input.IssueID); err != nil {
		return err
	}
	if err := validateIdentifier("author", input.ExpectedAuthorID); err != nil {
		return err
	}
	if err := validateRequiredText("author login", input.ExpectedAuthorLogin, maxIdentifierBytes); err != nil {
		return err
	}
	return validateRequiredText("comment text", input.Text, maxCommentBytes)
}

// ValidateDeleteCommentInput validates immutable deletion identifiers before
// the request reaches the transport.
func ValidateDeleteCommentInput(input DeleteCommentInput) error {
	if err := validateIdentifier("issue", input.IssueID); err != nil {
		return err
	}
	return validateIdentifier("comment", input.CommentID)
}

// DeleteComment sends one exact, non-replayable DELETE request. This local
// client recognizes only 204 or a whitespace-only 200 response as success;
// every other result is deliberately ambiguous except the established typed
// authentication, permission, and stale-target responses.
func (client *Client) DeleteComment(ctx context.Context, input DeleteCommentInput) error {
	if err := ValidateDeleteCommentInput(input); err != nil {
		return err
	}
	response, err := client.send(ctx, request{
		method: http.MethodDelete,
		path:   "/issues/" + url.PathEscape(input.IssueID) + "/comments/" + url.PathEscape(input.CommentID),
		body:   []byte{}, operation: "comment.delete", write: true,
	})
	if err != nil || response == nil || response.Body == nil {
		return errx.WriteOutcomeUnknown("comment.delete")
	}
	defer closeAndDrain(response.Body)
	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusOK {
		return client.translateWriteStatus(response, "comment.delete")
	}

	body, tooLarge, readErr := readResponseBody(response)
	if readErr != nil || tooLarge {
		return errx.WriteOutcomeUnknown("comment.delete")
	}
	if (response.StatusCode == http.StatusNoContent || response.StatusCode == http.StatusOK) && len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	return client.translateWriteStatus(response, "comment.delete")
}

// AddComment sends one non-replayable public comment mutation. A successful
// HTTP response is verified before callers can treat the write as applied.
func (client *Client) AddComment(ctx context.Context, input AddCommentInput) (Comment, error) {
	if err := ValidateAddCommentInput(input); err != nil {
		return Comment{}, err
	}
	body, err := json.Marshal(addCommentPayload{
		Text: input.Text, Visibility: publicCommentVisibility{Type: "UnlimitedVisibility"},
	})
	if err != nil {
		return Comment{}, errx.Internal("could not encode the typed YouTrack comment")
	}
	var response commentResponse
	if err := client.writeJSON(ctx, request{
		method: http.MethodPost, path: "/issues/" + url.PathEscape(input.IssueID) + "/comments",
		query: fieldsQuery(commentFields), body: body, operation: "comment.add", write: true,
	}, &response); err != nil {
		return Comment{}, err
	}
	result := response.Comment
	if !validEntityID(result.ID) || result.Text == nil || *result.Text != input.Text ||
		result.Author == nil || result.Author.ID != input.ExpectedAuthorID || result.Author.Login != input.ExpectedAuthorLogin ||
		response.Deleted == nil || *response.Deleted || result.Visibility == nil ||
		result.Visibility.Type != "UnlimitedVisibility" || len(result.Visibility.PermittedGroups) != 0 || len(result.Visibility.PermittedUsers) != 0 {
		return Comment{}, errx.WriteOutcomeUnknown("comment.add")
	}
	result.Deleted = *response.Deleted
	return result, nil
}

// CreateIssue dispatches exactly one non-replayable POST /api/issues request.
// A response that cannot be verified is WRITE_OUTCOME_UNKNOWN; when it still
// names a well-formed issue, those identities are returned with the error so
// reconciliation can read the exact issue instead of searching.
func (client *Client) CreateIssue(ctx context.Context, input CreateIssueInput) (Issue, error) {
	if err := ValidateCreateIssueInput(input); err != nil {
		return Issue{}, err
	}
	payload := createIssuePayload{
		Project: projectReference{ID: input.ProjectID}, Summary: input.Summary, Description: input.Description,
	}
	for _, field := range input.CustomFields {
		entry := createFieldPayload{Name: field.Name, Type: field.Type}
		if !field.Clear {
			entry.Value = &projectReference{ID: field.ValueID}
		}
		payload.CustomFields = append(payload.CustomFields, entry)
	}
	var response issueReadResponse
	if err := client.sendMutation(ctx, "/issues", "issue.create", payload, &response); err != nil {
		return Issue{}, err
	}
	result, err := response.issue()
	if err != nil {
		return Issue{}, errx.WriteOutcomeUnknown("issue.create")
	}
	if !CreatedIssueMatches(result, input) {
		// The immutable ID alone allows an exact reconciliation read.
		var identity Issue
		if validEntityID(result.ID) {
			identity.ID = result.ID
			if validEntityID(result.IDReadable) {
				identity.IDReadable = result.IDReadable
			}
		}
		return identity, errx.WriteOutcomeUnknown("issue.create")
	}
	return result, nil
}

// CreatedIssueMatches reports whether issue carries every value the create
// input set. Reconciliation uses it as exact evidence for a created issue.
func CreatedIssueMatches(issue Issue, input CreateIssueInput) bool {
	if validateIssueResponse(issue, "") != nil || issue.Project.ID != input.ProjectID || issue.Project.ShortName != input.ProjectKey ||
		issue.Summary != input.Summary || issue.Reporter == nil || issue.Reporter.ID != input.ExpectedReporterID || issue.Reporter.Login != input.ExpectedReporterLogin {
		return false
	}
	if input.Description != nil && (issue.Description == nil || *issue.Description != *input.Description) {
		return false
	}
	for _, expected := range input.CustomFields {
		matches := 0
		for _, actual := range issue.CustomFields {
			if actual.ProjectCustomField == nil || actual.ProjectCustomField.ID != expected.ProjectFieldID {
				continue
			}
			matches++
			if actual.Type != expected.Type || !createdFieldValueMatches(expected, actual.Value) {
				return false
			}
		}
		if matches != 1 {
			return false
		}
	}
	return true
}

// createdFieldValueMatches compares one observed create field value. A clear
// matches only an exact JSON null: an absent member, {} or an empty ID is not
// evidence of an emptied field. A single-user value must also be a User, since
// an ID alone cannot tell a user from another entity kind.
func createdFieldValueMatches(expected CreateCustomField, observed json.RawMessage) bool {
	trimmed := bytes.TrimSpace(observed)
	if expected.Clear {
		return bytes.Equal(trimmed, []byte("null"))
	}
	var value struct {
		ID   string `json:"id"`
		Type string `json:"$type"`
	}
	if json.Unmarshal(trimmed, &value) != nil || value.ID != expected.ValueID {
		return false
	}
	return expected.Type != singleUserFieldType || value.Type == "User"
}

// UpdateIssue dispatches exactly one non-replayable POST for the exact issue.
// It is classified rest-best-effort because a project move can race the local
// preflight and this HTTP request.
func (client *Client) UpdateIssue(ctx context.Context, input UpdateIssueInput) (Issue, error) {
	if err := ValidateUpdateIssueInput(input); err != nil {
		return Issue{}, err
	}
	payload := updateIssuePayload{
		Summary: input.Summary, Description: input.Description, CustomFields: input.CustomFields,
	}
	var result Issue
	if err := client.sendMutation(ctx, "/issues/"+url.PathEscape(input.IssueID), "issue.update", payload, &result); err != nil {
		return Issue{}, err
	}
	if validateIssueResponse(result, input.IssueID) != nil || result.Project.ID != input.ProjectID || result.Project.ShortName != input.ProjectKey {
		return Issue{}, errx.WriteOutcomeUnknown("issue.update")
	}
	if input.Summary != nil && result.Summary != *input.Summary {
		return Issue{}, errx.WriteOutcomeUnknown("issue.update")
	}
	if input.Description != nil && (result.Description == nil || *result.Description != *input.Description) {
		return Issue{}, errx.WriteOutcomeUnknown("issue.update")
	}
	for _, expected := range input.CustomFields {
		matches := 0
		for _, actual := range result.CustomFields {
			if actual.ID != expected.ID {
				continue
			}
			matches++
			if actual.Type != expected.Type || !customFieldValueMatches(expected.Type, expected.Value, actual.Value) {
				return Issue{}, errx.WriteOutcomeUnknown("issue.update")
			}
		}
		if matches != 1 {
			return Issue{}, errx.WriteOutcomeUnknown("issue.update")
		}
	}
	return result, nil
}

// singleUserFieldType is the only field type whose nested value type is
// verified: an ID alone cannot distinguish a User from another entity kind.
const singleUserFieldType = "SingleUserIssueCustomField"

func customFieldValueMatches(fieldType string, expectedJSON, actualJSON json.RawMessage) bool {
	var expected, actual any
	expectedDecoder := json.NewDecoder(bytes.NewReader(expectedJSON))
	expectedDecoder.UseNumber()
	actualDecoder := json.NewDecoder(bytes.NewReader(actualJSON))
	actualDecoder.UseNumber()
	if expectedDecoder.Decode(&expected) != nil || actualDecoder.Decode(&actual) != nil {
		return false
	}
	if fieldType == singleUserFieldType && expected != nil {
		actualEntity, ok := actual.(map[string]any)
		if !ok || actualEntity["$type"] != "User" {
			return false
		}
	}
	return customFieldValueEqual(expected, actual)
}

func customFieldValueEqual(expected, actual any) bool {
	if expectedEntity, ok := expected.(map[string]any); ok && len(expectedEntity) == 1 {
		if expectedID, ok := expectedEntity["id"].(string); ok && validEntityID(expectedID) {
			actualEntity, ok := actual.(map[string]any)
			return ok && actualEntity["id"] == expectedID
		}
	}
	if expectedList, ok := expected.([]any); ok {
		actualList, ok := actual.([]any)
		if !ok || len(expectedList) != len(actualList) {
			return false
		}
		for index, value := range expectedList {
			if !customFieldValueEqual(value, actualList[index]) {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(expected, actual)
}

func (client *Client) sendMutation(ctx context.Context, operationPath, operation string, payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return errx.Internal("could not encode the typed YouTrack mutation")
	}
	if len(body) > maxMutationBodySize {
		return errx.Usage("typed mutation body exceeds the %d-byte safety limit", maxMutationBodySize)
	}
	return client.writeJSON(ctx, request{
		method: http.MethodPost, path: operationPath, query: fieldsQuery(issueFields),
		body: body, operation: operation, write: true,
	}, out)
}

func validateCustomFieldUpdates(fields []CustomFieldUpdate) error {
	seen := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		if err := validateIdentifier("custom field", field.ID); err != nil {
			return err
		}
		if err := validateTypeName(field.Type); err != nil {
			return err
		}
		if _, exists := seen[field.ID]; exists {
			return errx.Usage("custom field IDs must be unique")
		}
		seen[field.ID] = struct{}{}
		if len(field.Value) == 0 || len(field.Value) > maxCustomFieldValueSize {
			return errx.Usage("custom field value must be one bounded JSON value")
		}
		decoder := json.NewDecoder(bytes.NewReader(field.Value))
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return errx.Usage("custom field value must be valid JSON")
		}
		var extra json.RawMessage
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			return errx.Usage("custom field value must contain exactly one JSON value")
		}
	}
	return nil
}

func validateTypeName(value string) error {
	if value == "" || len(value) > maxIdentifierBytes {
		return errx.Usage("custom field type is invalid")
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '_' {
			continue
		}
		return errx.Usage("custom field type is invalid")
	}
	return nil
}

func validateRequiredText(name, value string, limit int) error {
	if strings.TrimSpace(value) == "" {
		return errx.Usage("%s is required", name)
	}
	return validateOptionalText(name, value, limit)
}

func validateOptionalText(name, value string, limit int) error {
	if !utf8.ValidString(value) || len(value) > limit || strings.ContainsRune(value, '\x00') {
		return errx.Usage("%s must be valid UTF-8 no longer than %d bytes", name, limit)
	}
	return nil
}
