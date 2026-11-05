package cli

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/abigotado/youtrack-agent-cli/internal/application"
	"github.com/abigotado/youtrack-agent-cli/internal/output"
)

const untrustedYouTrackContent = "untrusted_youtrack_content"

type profileView struct {
	Name         string   `json:"name"`
	Instance     string   `json:"instance"`
	MCPURL       string   `json:"mcp_url"`
	AccountID    string   `json:"account_id"`
	Login        string   `json:"login"`
	Capabilities []string `json:"capabilities"`
	Executor     string   `json:"executor"`
	Assurance    string   `json:"assurance"`
	State        string   `json:"state,omitempty"`
}

func newProfileView(value application.ProfileInfo) profileView {
	return profileView{
		Name: value.Name, Instance: value.Instance, MCPURL: value.MCPURL,
		AccountID: value.AccountID, Login: value.Login,
		Capabilities: append([]string(nil), value.Capabilities...), Executor: value.Executor, Assurance: value.Assurance,
	}
}

func (view profileView) Fields() []output.Field {
	return []output.Field{
		{Name: "name", Value: view.Name, Raw: view.Name},
		{Name: "instance", Value: view.Instance, Raw: view.Instance},
		{Name: "account_id", Value: view.AccountID, Raw: view.AccountID},
		{Name: "login", Value: view.Login, Raw: view.Login},
		{Name: "capabilities", Value: strings.Join(view.Capabilities, ","), Raw: view.Capabilities},
		{Name: "executor", Value: view.Executor, Raw: view.Executor},
		{Name: "assurance", Value: view.Assurance, Raw: view.Assurance},
		{Name: "state", Value: view.State, Raw: view.State, OnRequest: view.State == ""},
		{Name: "mcp_url", Value: view.MCPURL, Raw: view.MCPURL, OnRequest: true},
	}
}

type policyView struct {
	Profile        string                   `json:"profile"`
	IdentitySHA256 string                   `json:"identity_sha256"`
	Revision       uint64                   `json:"revision"`
	Projects       []application.ProjectRef `json:"projects"`
	DryRun         bool                     `json:"dry_run"`
	Applied        bool                     `json:"applied"`
}

func newPolicyView(value application.PolicyInfo, dryRun, applied bool) policyView {
	return policyView{Profile: value.Profile, IdentitySHA256: value.IdentitySHA256, Revision: value.Revision, Projects: append([]application.ProjectRef(nil), value.Projects...), DryRun: dryRun, Applied: applied}
}

func (view policyView) Fields() []output.Field {
	return []output.Field{
		{Name: "profile", Value: view.Profile, Raw: view.Profile},
		{Name: "projects", Raw: view.Projects},
		{Name: "revision", Value: strconv.FormatUint(view.Revision, 10), Raw: view.Revision},
		{Name: "dry_run", Value: strconv.FormatBool(view.DryRun), Raw: view.DryRun},
		{Name: "applied", Value: strconv.FormatBool(view.Applied), Raw: view.Applied},
		{Name: "identity_sha256", Value: view.IdentitySHA256, Raw: view.IdentitySHA256, OnRequest: true},
	}
}

type mutationView struct {
	PlanID           string `json:"plan_id"`
	State            string `json:"state"`
	Revision         uint64 `json:"revision"`
	Kind             string `json:"kind"`
	Profile          string `json:"profile"`
	Instance         string `json:"instance"`
	AccountID        string `json:"account_id"`
	AccountLogin     string `json:"account_login"`
	ProjectID        string `json:"project_id"`
	ProjectKey       string `json:"project_key"`
	IntentSHA256     string `json:"intent_sha256"`
	RequestSHA256    string `json:"request_sha256"`
	ExpectedSHA256   string `json:"expected_sha256"`
	MutationAttempts uint8  `json:"mutation_attempts"`
	NonReplayable    bool   `json:"non_replayable"`
	OutputPath       string `json:"output_path,omitempty"`
}

func newMutationView(value application.MutationInfo) mutationView {
	return mutationView(value)
}

func (view mutationView) Fields() []output.Field {
	return []output.Field{
		{Name: "plan_id", Value: view.PlanID, Raw: view.PlanID},
		{Name: "state", Value: view.State, Raw: view.State},
		{Name: "kind", Value: view.Kind, Raw: view.Kind},
		{Name: "profile", Value: view.Profile, Raw: view.Profile},
		{Name: "instance", Value: view.Instance, Raw: view.Instance},
		{Name: "project_id", Value: view.ProjectID, Raw: view.ProjectID},
		{Name: "project_key", Value: view.ProjectKey, Raw: view.ProjectKey},
		{Name: "intent_sha256", Value: view.IntentSHA256, Raw: view.IntentSHA256},
		{Name: "mutation_attempts", Value: strconv.Itoa(int(view.MutationAttempts)), Raw: view.MutationAttempts},
		{Name: "non_replayable", Value: strconv.FormatBool(view.NonReplayable), Raw: view.NonReplayable},
		{Name: "account_id", Value: view.AccountID, Raw: view.AccountID, OnRequest: true},
		{Name: "account_login", Value: view.AccountLogin, Raw: view.AccountLogin, OnRequest: true},
		{Name: "request_sha256", Value: view.RequestSHA256, Raw: view.RequestSHA256, OnRequest: true},
		{Name: "expected_sha256", Value: view.ExpectedSHA256, Raw: view.ExpectedSHA256, OnRequest: true},
		{Name: "revision", Value: strconv.FormatUint(view.Revision, 10), Raw: view.Revision, OnRequest: true},
		{Name: "output_path", Value: view.OutputPath, Raw: view.OutputPath, OnRequest: view.OutputPath == ""},
	}
}

type authStatusView struct {
	Profile           string    `json:"profile"`
	CredentialPresent bool      `json:"credential_present"`
	State             string    `json:"state"`
	Account           *userView `json:"account,omitempty"`
}

func newAuthStatusView(value application.AuthStatusInfo) authStatusView {
	view := authStatusView{Profile: value.Profile, CredentialPresent: value.CredentialPresent, State: value.State}
	if value.Account != nil {
		account := newUserView(*value.Account)
		view.Account = &account
	}
	return view
}

func (view authStatusView) Fields() []output.Field {
	accountID, accountLogin := "", ""
	if view.Account != nil {
		accountID, accountLogin = view.Account.ID, view.Account.Login
	}
	return []output.Field{
		{Name: "profile", Value: view.Profile, Raw: view.Profile},
		{Name: "state", Value: view.State, Raw: view.State},
		{Name: "credential_present", Value: strconv.FormatBool(view.CredentialPresent), Raw: view.CredentialPresent},
		{Name: "account_id", Value: accountID, Raw: accountID, OnRequest: accountID == ""},
		{Name: "account_login", Value: accountLogin, Raw: accountLogin, OnRequest: accountLogin == ""},
	}
}

type userView struct {
	Trust    string `json:"trust"`
	ID       string `json:"id"`
	Login    string `json:"login"`
	Name     string `json:"name,omitempty"`
	FullName string `json:"full_name,omitempty"`
	Email    string `json:"email,omitempty"`
}

func newUserView(value application.UserInfo) userView {
	return userView{Trust: untrustedYouTrackContent, ID: value.ID, Login: value.Login, Name: value.Name, FullName: value.FullName, Email: value.Email}
}

func (view userView) Fields() []output.Field {
	return []output.Field{
		{Name: "trust", Value: view.Trust, Raw: view.Trust, Always: true},
		{Name: "id", Value: view.ID, Raw: view.ID},
		{Name: "login", Value: view.Login, Raw: view.Login},
		{Name: "name", Value: view.Name, Raw: view.Name},
		{Name: "full_name", Value: view.FullName, Raw: view.FullName, OnRequest: true},
		{Name: "email", Value: view.Email, Raw: view.Email, OnRequest: true},
	}
}

type projectView struct {
	Trust    string `json:"trust"`
	ID       string `json:"id"`
	Key      string `json:"key"`
	Name     string `json:"name"`
	Archived bool   `json:"archived"`
}

func newProjectView(value application.ProjectInfo) projectView {
	return projectView{Trust: untrustedYouTrackContent, ID: value.ID, Key: value.Key, Name: value.Name, Archived: value.Archived}
}

func (view projectView) Fields() []output.Field {
	return []output.Field{
		{Name: "trust", Value: view.Trust, Raw: view.Trust, Always: true},
		{Name: "id", Value: view.ID, Raw: view.ID},
		{Name: "key", Value: view.Key, Raw: view.Key},
		{Name: "name", Value: view.Name, Raw: view.Name},
		{Name: "archived", Value: strconv.FormatBool(view.Archived), Raw: view.Archived},
	}
}

type issueView struct {
	Trust         string                             `json:"trust"`
	ID            string                             `json:"id"`
	ReadableID    string                             `json:"readable_id"`
	Summary       string                             `json:"summary"`
	Description   *string                            `json:"description,omitempty"`
	Project       projectView                        `json:"project"`
	Reporter      *userView                          `json:"reporter,omitempty"`
	Created       int64                              `json:"created"`
	Updated       int64                              `json:"updated"`
	CommentsCount int                                `json:"comments_count"`
	StateFields   []issueFieldSummary                `json:"state_fields"`
	UserFields    []issueFieldSummary                `json:"user_fields"`
	CustomFields  []application.IssueCustomFieldInfo `json:"custom_fields,omitempty"`
}

// issueFieldSummary keeps a field's project-defined name beside its readable
// values, because stage and assignee fields are named per project. Nil Values
// means the value could not be read as expected, which differs from an empty
// field; the unmodified value stays available through custom_fields.
type issueFieldSummary struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

type customFieldValue struct {
	Login string `json:"login"`
	Name  string `json:"name"`
}

func newIssueView(value application.IssueInfo) issueView {
	view := issueView{
		Trust: untrustedYouTrackContent, ID: value.ID, ReadableID: value.ReadableID, Summary: value.Summary, Description: value.Description,
		Project: newProjectView(value.Project), Created: value.Created, Updated: value.Updated,
		CommentsCount: value.CommentsCount, CustomFields: append([]application.IssueCustomFieldInfo(nil), value.CustomFields...),
		StateFields: []issueFieldSummary{}, UserFields: []issueFieldSummary{},
	}
	for _, field := range value.CustomFields {
		switch field.Type {
		case "StateIssueCustomField", "StateMachineIssueCustomField":
			view.StateFields = append(view.StateFields, issueFieldSummary{Name: field.Name, Values: customFieldLabels(field.Value, func(value customFieldValue) string { return value.Name })})
		case "SingleUserIssueCustomField", "MultiUserIssueCustomField":
			view.UserFields = append(view.UserFields, issueFieldSummary{Name: field.Name, Values: customFieldLabels(field.Value, func(value customFieldValue) string { return value.Login })})
		}
	}
	if value.Reporter != nil {
		reporter := newUserView(*value.Reporter)
		view.Reporter = &reporter
	}
	return view
}

// customFieldLabels reads a single or multi-value state or user field. An
// unexpected shape must neither fail the read nor look like an empty field.
func customFieldLabels(raw json.RawMessage, label func(customFieldValue) string) []string {
	var values []customFieldValue
	if err := json.Unmarshal(raw, &values); err != nil {
		var single customFieldValue
		if err := json.Unmarshal(raw, &single); err != nil {
			return nil
		}
		values = []customFieldValue{single}
	}
	labels := make([]string, len(values))
	for index, value := range values {
		labels[index] = label(value)
		if labels[index] == "" {
			return nil
		}
	}
	return labels
}

// issueFieldsText quotes names and values so that untrusted content cannot
// forge another field in a text line.
func issueFieldsText(fields []issueFieldSummary) string {
	parts := make([]string, len(fields))
	for index, field := range fields {
		values := "?"
		if field.Values != nil {
			quoted := make([]string, len(field.Values))
			for position, value := range field.Values {
				quoted[position] = strconv.Quote(value)
			}
			values = strings.Join(quoted, ",")
		}
		parts[index] = strconv.Quote(field.Name) + "=" + values
	}
	return strings.Join(parts, "; ")
}

func (view issueView) Fields() []output.Field {
	description := ""
	if view.Description != nil {
		description = *view.Description
	}
	return []output.Field{
		{Name: "trust", Value: view.Trust, Raw: view.Trust, Always: true},
		{Name: "id", Value: view.ID, Raw: view.ID},
		{Name: "readable_id", Value: view.ReadableID, Raw: view.ReadableID},
		{Name: "summary", Value: view.Summary, Raw: view.Summary},
		{Name: "project_id", Value: view.Project.ID, Raw: view.Project.ID},
		{Name: "project_key", Value: view.Project.Key, Raw: view.Project.Key},
		{Name: "updated", Value: strconv.FormatInt(view.Updated, 10), Raw: view.Updated},
		{Name: "comments_count", Value: strconv.Itoa(view.CommentsCount), Raw: view.CommentsCount},
		{Name: "state_fields", Value: issueFieldsText(view.StateFields), Raw: view.StateFields},
		{Name: "user_fields", Value: issueFieldsText(view.UserFields), Raw: view.UserFields},
		{Name: "description", Value: description, Raw: view.Description, OnRequest: true},
		{Name: "reporter", Raw: view.Reporter, OnRequest: true},
		{Name: "created", Value: strconv.FormatInt(view.Created, 10), Raw: view.Created, OnRequest: true},
		{Name: "custom_fields", Raw: view.CustomFields, OnRequest: true},
	}
}

type commentView struct {
	Trust      string                      `json:"trust"`
	ID         string                      `json:"id"`
	Author     *userView                   `json:"author"`
	Created    int64                       `json:"created"`
	Updated    *int64                      `json:"updated"`
	Deleted    bool                        `json:"deleted"`
	Text       *string                     `json:"text"`
	Visibility *application.VisibilityInfo `json:"visibility"`
}

func newCommentView(value application.CommentInfo) commentView {
	view := commentView{
		Trust: untrustedYouTrackContent, ID: value.ID, Created: value.Created,
		Updated: value.Updated, Deleted: value.Deleted, Text: value.Text, Visibility: value.Visibility,
	}
	if value.Author != nil {
		author := newUserView(*value.Author)
		view.Author = &author
	}
	return view
}

func (view commentView) Fields() []output.Field {
	var authorLogin *string
	if view.Author != nil {
		authorLogin = &view.Author.Login
	}
	authorLoginText, updatedText, text := "", "", ""
	if authorLogin != nil {
		authorLoginText = *authorLogin
	}
	if view.Updated != nil {
		updatedText = strconv.FormatInt(*view.Updated, 10)
	}
	if view.Text != nil {
		text = *view.Text
	}
	return []output.Field{
		{Name: "trust", Value: view.Trust, Raw: view.Trust, Always: true},
		{Name: "id", Value: view.ID, Raw: view.ID},
		{Name: "author_login", Value: authorLoginText, Raw: authorLogin},
		{Name: "created", Value: strconv.FormatInt(view.Created, 10), Raw: view.Created},
		{Name: "updated", Value: updatedText, Raw: view.Updated},
		{Name: "deleted", Value: strconv.FormatBool(view.Deleted), Raw: view.Deleted},
		{Name: "text", Value: text, Raw: view.Text},
		{Name: "author", Raw: view.Author, OnRequest: true},
		{Name: "visibility", Raw: view.Visibility, OnRequest: true},
	}
}

type projectFieldView struct {
	Trust        string                  `json:"trust"`
	ID           string                  `json:"id"`
	Name         string                  `json:"name"`
	Type         string                  `json:"type"`
	ValueType    string                  `json:"value_type"`
	IsMultiValue bool                    `json:"is_multi_value"`
	CanBeEmpty   bool                    `json:"can_be_empty"`
	IsPublic     bool                    `json:"is_public"`
	Bundle       *application.BundleInfo `json:"bundle,omitempty"`
}

func newProjectFieldView(value application.ProjectFieldInfo) projectFieldView {
	return projectFieldView{
		Trust: untrustedYouTrackContent, ID: value.ID, Name: value.Name, Type: value.Type, ValueType: value.ValueType,
		IsMultiValue: value.IsMultiValue, CanBeEmpty: value.CanBeEmpty, IsPublic: value.IsPublic,
		Bundle: value.Bundle,
	}
}

func (view projectFieldView) Fields() []output.Field {
	return []output.Field{
		{Name: "trust", Value: view.Trust, Raw: view.Trust, Always: true},
		{Name: "id", Value: view.ID, Raw: view.ID},
		{Name: "name", Value: view.Name, Raw: view.Name},
		{Name: "value_type", Value: view.ValueType, Raw: view.ValueType},
		{Name: "is_multi_value", Value: strconv.FormatBool(view.IsMultiValue), Raw: view.IsMultiValue},
		{Name: "can_be_empty", Value: strconv.FormatBool(view.CanBeEmpty), Raw: view.CanBeEmpty},
		{Name: "is_public", Value: strconv.FormatBool(view.IsPublic), Raw: view.IsPublic},
		{Name: "type", Value: view.Type, Raw: view.Type, OnRequest: true},
		{Name: "bundle", Raw: view.Bundle, OnRequest: true},
	}
}

type versionView struct {
	Version    string `json:"version"`
	Commit     string `json:"commit,omitempty"`
	CommitTime string `json:"commit_time,omitempty"`
	Go         string `json:"go"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
}

func (view versionView) Fields() []output.Field {
	return []output.Field{
		{Name: "version", Value: view.Version, Raw: view.Version},
		{Name: "commit", Value: view.Commit, Raw: view.Commit},
		{Name: "commit_time", Value: view.CommitTime, Raw: view.CommitTime},
		{Name: "go", Value: view.Go, Raw: view.Go},
		{Name: "os", Value: view.OS, Raw: view.OS},
		{Name: "arch", Value: view.Arch, Raw: view.Arch},
	}
}
