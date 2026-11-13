package youtrack

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
)

const (
	currentUserFields   = "id,login,name,fullName,email"
	projectFields       = "id,shortName,name,archived"
	issueFields         = "id,idReadable,summary,description,project(id,shortName,name,archived),reporter(id,login,name,fullName),created,updated,commentsCount,customFields(id,name,$type,projectCustomField(id,field(id)),value(id,name,login,fullName,text,presentation,isResolved,$type))"
	issueSummaryFields  = "id,idReadable,summary,project(id,shortName,name,archived),updated,customFields(name,$type,value(name,login))"
	projectFieldFields  = "id,$type,field(id,name,fieldType(id,valueType,isMultiValue,$type)),canBeEmpty,isPublic,bundle(id,$type,values(id,name,localizedName,archived,$type),aggregatedUsers(id,login,name,fullName,banned))"
	commentFields       = "id,author(id,login,name,fullName),created,updated,deleted,text,visibility($type,permittedGroups(id,name),permittedUsers(id,name,login))"
	commentDeleteFields = "id,issue(id),author(id,login),created,updated,deleted,pinned,text,visibility($type,permittedGroups(id,name),permittedUsers(id,name,login)),attachments(id)"
)

type commentDeleteResponse struct {
	ID    string `json:"id"`
	Issue *struct {
		ID string `json:"id"`
	} `json:"issue"`
	Author      *User           `json:"author"`
	Created     *int64          `json:"created"`
	Updated     json.RawMessage `json:"updated"`
	Deleted     *bool           `json:"deleted"`
	Pinned      *bool           `json:"pinned"`
	Text        json.RawMessage `json:"text"`
	Visibility  json.RawMessage `json:"visibility"`
	Attachments json.RawMessage `json:"attachments"`
}

type issueSummaryResponse struct {
	ID         string                      `json:"id"`
	IDReadable string                      `json:"idReadable"`
	Summary    string                      `json:"summary"`
	Project    issueSummaryProjectResponse `json:"project"`
	Updated    *int64                      `json:"updated"`
	// CustomFields holds what the query requests: name, type and the name and
	// login of the value. The summary keeps only those, never a field identity.
	CustomFields []IssueCustomField `json:"customFields"`
}

type issueSummaryProjectResponse struct {
	ID        string `json:"id"`
	ShortName string `json:"shortName"`
	Name      string `json:"name"`
	Archived  *bool  `json:"archived"`
}

type commentDeleteVisibilityResponse struct {
	Type            string          `json:"$type"`
	PermittedGroups json.RawMessage `json:"permittedGroups"`
	PermittedUsers  json.RawMessage `json:"permittedUsers"`
}

type commentDeleteIdentityResponse struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Login string `json:"login"`
	Type  string `json:"$type"`
}

type exactProjectFieldResponse struct {
	ProjectField
	CanBeEmpty *bool `json:"canBeEmpty"`
	IsPublic   *bool `json:"isPublic"`
	Field      struct {
		FieldDefinition
		FieldType struct {
			FieldType
			IsMultiValue *bool `json:"isMultiValue"`
		} `json:"fieldType"`
	} `json:"field"`
	Bundle *struct {
		Bundle
		// Values stay raw: only State and Enum bundles are interpreted, so a
		// valid UserBundle or unsupported bundle type cannot fail the read.
		Values json.RawMessage `json:"values"`
		// AggregatedUsers shadows the embedded field so a missing banned flag
		// is detectable: the write path must not treat it as not banned.
		AggregatedUsers []struct {
			User
			Banned *bool `json:"banned"`
		} `json:"aggregatedUsers"`
	} `json:"bundle"`
}

// strictBundleValue is one State or Enum bundle element. Archived must be
// present because the write path refuses archived targets.
type strictBundleValue struct {
	BundleValue
	Archived *bool `json:"archived"`
}

// decodeStrictBundleValues validates the values of a State or Enum bundle.
func decodeStrictBundleValues(raw json.RawMessage) ([]BundleValue, error) {
	var decoded []strictBundleValue
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return nil, invalidReadResponse()
		}
	}
	values := make([]BundleValue, 0, len(decoded))
	for _, value := range decoded {
		if value.Archived == nil {
			return nil, invalidReadResponse()
		}
		entry := value.BundleValue
		entry.Archived = *value.Archived
		values = append(values, entry)
	}
	return values, nil
}

// CurrentUser reads the authenticated account identity.
func (client *Client) CurrentUser(ctx context.Context) (User, error) {
	var user User
	err := client.readJSON(ctx, request{
		path: "/users/me", query: fieldsQuery(currentUserFields), operation: "users.me",
	}, &user)
	if err != nil {
		return User{}, err
	}
	if !validEntityID(user.ID) || strings.TrimSpace(user.Login) == "" {
		return User{}, invalidReadResponse()
	}
	return user, nil
}

// GetProject reads one project by exact entity ID or exact short name.
func (client *Client) GetProject(ctx context.Context, projectID string) (Project, error) {
	if err := validateIdentifier("project", projectID); err != nil {
		return Project{}, err
	}
	var project Project
	err := client.readJSON(ctx, request{
		path: "/admin/projects/" + url.PathEscape(projectID), query: fieldsQuery(projectFields), operation: "projects.get",
	}, &project)
	if err != nil {
		return Project{}, err
	}
	if !validEntityID(project.ID) || project.ShortName == "" || (project.ID != projectID && project.ShortName != projectID) {
		return Project{}, invalidReadResponse()
	}
	return project, nil
}

// GetIssue reads one issue by exact database ID or exact readable ID.
func (client *Client) GetIssue(ctx context.Context, issueID string) (Issue, error) {
	if err := validateIdentifier("issue", issueID); err != nil {
		return Issue{}, err
	}
	var response issueReadResponse
	err := client.readJSON(ctx, request{
		path: "/issues/" + url.PathEscape(issueID), query: fieldsQuery(issueFields), operation: "issues.get",
	}, &response)
	if err != nil {
		return Issue{}, err
	}
	issue, err := response.issue()
	if err != nil {
		return Issue{}, err
	}
	if err := validateIssueResponse(issue, issueID); err != nil {
		return Issue{}, err
	}
	return issue, nil
}

// issue converts the decoded response, keeping whether the description member
// was present (a null description is present; an omitted one is not).
func (response issueReadResponse) issue() (Issue, error) {
	issue := response.Issue
	if response.Description != nil {
		issue.descriptionPresent = true
		if string(response.Description) != "null" {
			var description string
			if json.Unmarshal(response.Description, &description) != nil {
				return Issue{}, invalidReadResponse()
			}
			issue.Description = &description
		}
	}
	return issue, nil
}

// DescriptionPresent reports whether the response carried a description
// member, null included. An omitted member is not evidence of an empty one.
func (issue Issue) DescriptionPresent() bool { return issue.descriptionPresent }

// issueReadResponse decodes an issue while keeping the presence of the
// description member, which a plain *string cannot distinguish from null.
type issueReadResponse struct {
	Issue
	Description json.RawMessage `json:"description"`
}

// RequireDescription refuses an issue read whose description member was
// omitted. A null description is a valid empty one, but an omitted member is
// a malformed read: issue.edit hashes the value as its stale-text precondition.
func (issue Issue) RequireDescription() error {
	if !issue.descriptionPresent {
		return invalidReadResponse()
	}
	return nil
}

// ListProjectFields reads exactly one bounded page of project field schemas.
// Nested bundle values are additionally bounded by the global response limit.
func (client *Client) ListProjectFields(ctx context.Context, projectID string, options PageOptions) ([]ProjectField, error) {
	if err := validateIdentifier("project", projectID); err != nil {
		return nil, err
	}
	query, err := pageQuery(options, projectFieldFields)
	if err != nil {
		return nil, err
	}
	var fields []ProjectField
	err = client.readJSON(ctx, request{
		path: "/admin/projects/" + url.PathEscape(projectID) + "/customFields", query: query, operation: "project_fields.list", pageReducible: options.CanReduce,
	}, &fields)
	if err != nil {
		return nil, err
	}
	if fields == nil {
		return nil, invalidReadResponse()
	}
	for _, field := range fields {
		if !validEntityID(field.ID) || !validEntityID(field.Field.ID) || field.Field.Name == "" || field.Type == "" {
			return nil, invalidReadResponse()
		}
	}
	return fields, nil
}

// GetProjectField reads the selected schema from the exact project subresource.
func (client *Client) GetProjectField(ctx context.Context, projectID, projectFieldID string) (ProjectField, error) {
	if err := validateIdentifier("project", projectID); err != nil {
		return ProjectField{}, err
	}
	if err := validateIdentifier("project custom field", projectFieldID); err != nil {
		return ProjectField{}, err
	}
	var response exactProjectFieldResponse
	if err := client.readJSON(ctx, request{
		path:  "/admin/projects/" + url.PathEscape(projectID) + "/customFields/" + url.PathEscape(projectFieldID),
		query: fieldsQuery(projectFieldFields + ",project(id)"), operation: "project_fields.get",
	}, &response); err != nil {
		return ProjectField{}, err
	}
	if response.CanBeEmpty == nil || response.IsPublic == nil || response.Field.FieldType.IsMultiValue == nil {
		return ProjectField{}, invalidReadResponse()
	}
	field := response.ProjectField
	field.CanBeEmpty = *response.CanBeEmpty
	field.IsPublic = *response.IsPublic
	field.Field = response.Field.FieldDefinition
	field.Field.FieldType = response.Field.FieldType.FieldType
	field.Field.FieldType.IsMultiValue = *response.Field.FieldType.IsMultiValue
	if response.Bundle != nil {
		bundle := response.Bundle.Bundle
		bundle.Values = nil
		switch bundle.Type {
		case "StateBundle", "EnumBundle":
			values, err := decodeStrictBundleValues(response.Bundle.Values)
			if err != nil {
				return ProjectField{}, err
			}
			bundle.Values = values
			bundle.AggregatedUsers = nil
		case "UserBundle":
			// A user bundle's membership is its aggregated users; the raw
			// values (groups and users) are never interpreted.
			bundle.AggregatedUsers = nil
			for _, user := range response.Bundle.AggregatedUsers {
				if user.Banned == nil {
					return ProjectField{}, invalidReadResponse()
				}
				entry := user.User
				entry.Banned = *user.Banned
				bundle.AggregatedUsers = append(bundle.AggregatedUsers, entry)
			}
		default:
			// Unsupported bundle types are refused by the caller, not here.
			bundle.AggregatedUsers = nil
		}
		field.Bundle = &bundle
	}
	if field.ID != projectFieldID || !validEntityID(field.ID) || !validEntityID(field.Field.ID) ||
		strings.TrimSpace(field.Field.Name) == "" || validateTypeName(field.Type) != nil ||
		field.Field.FieldType.ID == "" || field.Field.FieldType.ValueType == "" || validateTypeName(field.Field.FieldType.Type) != nil ||
		field.Project == nil || field.Project.ID != projectID {
		return ProjectField{}, invalidReadResponse()
	}
	if field.Bundle != nil {
		if !validEntityID(field.Bundle.ID) || validateTypeName(field.Bundle.Type) != nil {
			return ProjectField{}, invalidReadResponse()
		}
		for _, value := range field.Bundle.Values {
			if !validEntityID(value.ID) || strings.TrimSpace(value.Name) == "" || validateTypeName(value.Type) != nil {
				return ProjectField{}, invalidReadResponse()
			}
		}
		for _, user := range field.Bundle.AggregatedUsers {
			if !validEntityID(user.ID) || strings.TrimSpace(user.Login) == "" {
				return ProjectField{}, invalidReadResponse()
			}
		}
	}
	return field, nil
}

// GetComment reads one exact comment for read-only reconciliation.
func (client *Client) GetComment(ctx context.Context, issueID, commentID string) (Comment, error) {
	if err := validateIdentifier("issue", issueID); err != nil {
		return Comment{}, err
	}
	if err := validateIdentifier("comment", commentID); err != nil {
		return Comment{}, err
	}
	var response commentResponse
	if err := client.readJSON(ctx, request{
		path:  "/issues/" + url.PathEscape(issueID) + "/comments/" + url.PathEscape(commentID),
		query: fieldsQuery(commentFields), operation: "comments.get",
	}, &response); err != nil {
		return Comment{}, err
	}
	comment := response.Comment
	if !validEntityID(comment.ID) || comment.ID != commentID || response.Deleted == nil {
		return Comment{}, invalidReadResponse()
	}
	comment.Deleted = *response.Deleted
	return comment, nil
}

// GetCommentForDeletion reads the stricter exact comment projection required
// for a one-shot delete. It accepts only active, attachment-free comments and
// preserves the explicit updated:null distinction in the returned target.
func (client *Client) GetCommentForDeletion(ctx context.Context, issueID, commentID string) (CommentDeleteTarget, error) {
	if err := validateIdentifier("issue", issueID); err != nil {
		return CommentDeleteTarget{}, err
	}
	if err := validateIdentifier("comment", commentID); err != nil {
		return CommentDeleteTarget{}, err
	}
	var response commentDeleteResponse
	if err := client.readJSON(ctx, request{
		path:  "/issues/" + url.PathEscape(issueID) + "/comments/" + url.PathEscape(commentID),
		query: fieldsQuery(commentDeleteFields), operation: "comments.delete_preflight",
	}, &response); err != nil {
		return CommentDeleteTarget{}, err
	}
	return commentDeleteTarget(response, issueID, commentID)
}

// ListComments reads exactly one bounded page. The API documents no ordering,
// author, or time filter, so callers must not infer those server guarantees.
func (client *Client) ListComments(ctx context.Context, issueID string, options PageOptions) ([]Comment, error) {
	if err := validateIdentifier("issue", issueID); err != nil {
		return nil, err
	}
	query, err := pageQuery(options, commentFields)
	if err != nil {
		return nil, err
	}
	var comments []Comment
	err = client.readJSON(ctx, request{
		path: "/issues/" + url.PathEscape(issueID) + "/comments", query: query, operation: "comments.list", pageReducible: options.CanReduce,
	}, &comments)
	if err != nil {
		return nil, err
	}
	if comments == nil {
		return nil, invalidReadResponse()
	}
	for _, comment := range comments {
		if !validEntityID(comment.ID) {
			return nil, invalidReadResponse()
		}
	}
	return comments, nil
}

// SearchIssues runs one bounded YouTrack issue query and never fetches a
// second page. It exists for reconciliation, not open-ended agent discovery.
func (client *Client) SearchIssues(ctx context.Context, queryText string, options PageOptions) ([]Issue, error) {
	if err := ValidateIssueQuery(queryText); err != nil {
		return nil, err
	}
	query, err := pageQuery(options, issueFields)
	if err != nil {
		return nil, err
	}
	query.Set("query", queryText)
	var responses []issueReadResponse
	if err := client.readJSON(ctx, request{path: "/issues", query: query, operation: "issues.search", pageReducible: options.CanReduce}, &responses); err != nil {
		return nil, err
	}
	if responses == nil {
		return nil, invalidReadResponse()
	}
	issues := make([]Issue, 0, len(responses))
	for _, response := range responses {
		issue, err := response.issue()
		if err != nil {
			return nil, err
		}
		if err := validateIssueResponse(issue, ""); err != nil {
			return nil, err
		}
		issues = append(issues, issue)
	}
	return issues, nil
}

// DiscoverIssues runs one bounded issue-discovery query with a compact fixed
// response shape. It never follows or automatically requests another page.
func (client *Client) DiscoverIssues(ctx context.Context, queryText string, options PageOptions) ([]IssueSummary, error) {
	if err := ValidateIssueQuery(queryText); err != nil {
		return nil, err
	}
	query, err := pageQuery(options, issueSummaryFields)
	if err != nil {
		return nil, err
	}
	query.Set("query", queryText)
	var responses []issueSummaryResponse
	if err := client.readJSON(ctx, request{path: "/issues", query: query, operation: "issues.discover", pageReducible: options.CanReduce, callerQuery: true}, &responses); err != nil {
		return nil, err
	}
	if responses == nil {
		return nil, invalidReadResponse()
	}
	issues := make([]IssueSummary, len(responses))
	for index, response := range responses {
		if err := validateIssueSummaryResponse(response); err != nil {
			return nil, err
		}
		issues[index] = IssueSummary{
			ID: response.ID, IDReadable: response.IDReadable, Summary: response.Summary,
			Project: Project{ID: response.Project.ID, ShortName: response.Project.ShortName, Name: response.Project.Name, Archived: *response.Project.Archived},
			Updated: *response.Updated, CustomFields: summaryCustomFields(response.CustomFields),
		}
	}
	return issues, nil
}

// summaryCustomFields keeps only what the compact query asked for, so a server
// that returns field identities cannot widen the discovery shape. One odd field
// must not fail a whole search page: an unclassifiable field is dropped and an
// oversized value is withheld, which the summary reports as unreadable.
func summaryCustomFields(fields []IssueCustomField) []IssueCustomField {
	result := make([]IssueCustomField, 0, len(fields))
	for _, field := range fields {
		if field.Name == "" || field.Type == "" {
			continue
		}
		value := field.Value
		if len(value) > maxCustomFieldValueSize {
			value = nil
		}
		result = append(result, IssueCustomField{Name: field.Name, Type: field.Type, Value: value})
	}
	return result
}

func fieldsQuery(fields string) url.Values {
	query := url.Values{}
	query.Set("fields", fields)
	return query
}

func pageQuery(options PageOptions, fields string) (url.Values, error) {
	if options.Top == 0 {
		options.Top = defaultCollectionLimit
	}
	if options.Top < 1 || options.Top > maxCollectionPageSize {
		return nil, errx.Usage("top must be between 1 and %d", maxCollectionPageSize)
	}
	if options.Skip < 0 {
		return nil, errx.Usage("skip must not be negative")
	}
	query := fieldsQuery(fields)
	query.Set("$top", strconv.Itoa(options.Top))
	query.Set("$skip", strconv.Itoa(options.Skip))
	return query, nil
}

func validateIdentifier(kind, value string) error {
	if validEntityID(value) {
		return nil
	}
	return errx.Usage("%s identifier must be 1-%d ASCII letters, digits, dot, dash, or underscore", kind, maxIdentifierBytes)
}

func commentDeleteTarget(response commentDeleteResponse, issueID, commentID string) (CommentDeleteTarget, error) {
	if !validEntityID(response.ID) || response.ID != commentID || response.Issue == nil || response.Issue.ID != issueID ||
		!validEntityID(response.Issue.ID) || response.Author == nil || !validEntityID(response.Author.ID) ||
		strings.TrimSpace(response.Author.Login) == "" || response.Created == nil || *response.Created < 0 ||
		response.Deleted == nil || *response.Deleted || response.Pinned == nil || len(response.Updated) == 0 ||
		len(response.Text) == 0 || len(response.Visibility) == 0 || len(response.Attachments) == 0 {
		return CommentDeleteTarget{}, invalidReadResponse()
	}

	updated, err := decodeOptionalTimestamp(response.Updated)
	if err != nil {
		return CommentDeleteTarget{}, invalidReadResponse()
	}
	text, err := decodeRequiredCommentText(response.Text)
	if err != nil {
		return CommentDeleteTarget{}, invalidReadResponse()
	}
	visibility, err := decodeCommentDeleteVisibility(response.Visibility)
	if err != nil {
		return CommentDeleteTarget{}, invalidReadResponse()
	}
	attachments, err := decodeEmptyCommentAttachments(response.Attachments)
	if err != nil {
		return CommentDeleteTarget{}, invalidReadResponse()
	}
	return CommentDeleteTarget{
		ID: response.ID, IssueID: response.Issue.ID, Text: text,
		AuthorID: response.Author.ID, AuthorLogin: response.Author.Login,
		Created: *response.Created, Updated: updated, Deleted: *response.Deleted,
		Pinned: *response.Pinned, Visibility: visibility, Attachments: attachments,
	}, nil
}

func decodeOptionalTimestamp(raw json.RawMessage) (*int64, error) {
	raw = bytes.TrimSpace(raw)
	if bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	var value int64
	if err := json.Unmarshal(raw, &value); err != nil || value < 0 {
		return nil, errors.New("updated is not a timestamp")
	}
	return &value, nil
}

func decodeRequiredCommentText(raw json.RawMessage) (string, error) {
	raw = bytes.TrimSpace(raw)
	if bytes.Equal(raw, []byte("null")) {
		return "", errors.New("comment text is null")
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return "", err
	}
	if err := validateOptionalText("comment text", text, maxCommentBytes); err != nil {
		return "", err
	}
	return text, nil
}

func decodeCommentDeleteVisibility(raw json.RawMessage) (Visibility, error) {
	raw = bytes.TrimSpace(raw)
	if bytes.Equal(raw, []byte("null")) {
		return Visibility{}, errors.New("comment visibility is null")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var response commentDeleteVisibilityResponse
	if err := decoder.Decode(&response); err != nil {
		return Visibility{}, errors.New("comment visibility is invalid")
	}
	groups, groupsPresent, err := decodeVisibilityPrincipals(response.PermittedGroups)
	if err != nil {
		return Visibility{}, err
	}
	users, usersPresent, err := decodeVisibilityPrincipals(response.PermittedUsers)
	if err != nil {
		return Visibility{}, err
	}
	switch response.Type {
	case "UnlimitedVisibility":
		if len(groups) != 0 || len(users) != 0 {
			return Visibility{}, errors.New("unlimited comment visibility has principals")
		}
		if !groupsPresent {
			groups = []Identity{}
		}
		if !usersPresent {
			users = []Identity{}
		}
	case "LimitedVisibility":
		if !groupsPresent || !usersPresent {
			return Visibility{}, errors.New("limited comment visibility omits principals")
		}
	default:
		return Visibility{}, errors.New("comment visibility type is invalid")
	}
	return Visibility{Type: response.Type, PermittedGroups: groups, PermittedUsers: users}, nil
}

func decodeVisibilityPrincipals(raw json.RawMessage) ([]Identity, bool, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, false, nil
	}
	if bytes.Equal(raw, []byte("null")) {
		return nil, false, errors.New("comment visibility principals are null")
	}
	var wire []commentDeleteIdentityResponse
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil || wire == nil {
		return nil, false, errors.New("comment visibility principals are invalid")
	}
	principals := make([]Identity, 0, len(wire))
	for _, principal := range wire {
		if !validEntityID(principal.ID) {
			return nil, false, errors.New("comment visibility principal is invalid")
		}
		principals = append(principals, Identity{ID: principal.ID, Name: principal.Name, Login: principal.Login})
	}
	return principals, true, nil
}

func decodeEmptyCommentAttachments(raw json.RawMessage) ([]string, error) {
	raw = bytes.TrimSpace(raw)
	if bytes.Equal(raw, []byte("null")) {
		return nil, errors.New("comment attachments are null")
	}
	var attachments []string
	if err := json.Unmarshal(raw, &attachments); err != nil || attachments == nil || len(attachments) != 0 {
		return nil, errors.New("comment has attachments")
	}
	return attachments, nil
}

func validEntityID(value string) bool {
	if value == "" || len(value) > maxIdentifierBytes {
		return false
	}
	first := value[0]
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || (first >= '0' && first <= '9')) {
		return false
	}
	for _, character := range []byte(value) {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

// ValidateIssueQuery rejects malformed bounded search input without requiring
// a client, credential, or network access.
func ValidateIssueQuery(value string) error {
	if strings.TrimSpace(value) == "" || len(value) > maxQueryBytes || strings.ContainsAny(value, "\x00\r\n") {
		return errx.Usage("query must be one non-empty line no longer than %d bytes", maxQueryBytes)
	}
	return nil
}

func validateIssueSummaryResponse(issue issueSummaryResponse) error {
	if !validEntityID(issue.ID) || !validEntityID(issue.IDReadable) || issue.Summary == "" || issue.Updated == nil || *issue.Updated < 0 ||
		!validEntityID(issue.Project.ID) || strings.TrimSpace(issue.Project.ShortName) == "" || strings.TrimSpace(issue.Project.Name) == "" || issue.Project.Archived == nil {
		return invalidReadResponse()
	}
	return nil
}

func validateIssueResponse(issue Issue, requestedID string) error {
	if !validEntityID(issue.ID) || !validEntityID(issue.IDReadable) || issue.Summary == "" ||
		!validEntityID(issue.Project.ID) || issue.Project.ShortName == "" || issue.CommentsCount < 0 {
		return invalidReadResponse()
	}
	if requestedID != "" && issue.ID != requestedID && issue.IDReadable != requestedID {
		return invalidReadResponse()
	}
	for _, field := range issue.CustomFields {
		if !validEntityID(field.ID) || field.Name == "" || field.Type == "" || len(field.Value) > maxCustomFieldValueSize {
			return invalidReadResponse()
		}
		if field.ProjectCustomField != nil && (!validEntityID(field.ProjectCustomField.ID) || !validEntityID(field.ProjectCustomField.Field.ID)) {
			return invalidReadResponse()
		}
	}
	return nil
}
