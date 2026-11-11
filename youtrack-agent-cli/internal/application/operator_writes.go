package application

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/operatorwrite"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/profile"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/writepolicy"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/youtrack"
)

func (s *Service) requireOperatorDependencies(store bool) error {
	if !s.OperatorBackendSupported() {
		return errx.Permission("OPERATOR_WRITE_UNSUPPORTED", "operator-confirmed writes require the standard macOS CGO build")
	}
	if s == nil || s.Profiles == nil || s.Policies == nil || store && s.OperatorWrites == nil {
		return errx.Internal("operator-write local dependencies are unavailable")
	}
	return nil
}

func requireOperatorProfile(selected profile.Profile, kind operatorwrite.Kind) error {
	if selected.CredentialGeneration == "" {
		return errx.Auth("PROFILE_NOT_AUTHENTICATED", "selected profile has no bound credential generation")
	}
	if selected.Executor != profile.ExecutorRESTBestEffort || selected.Assurance != profile.AssuranceBestEffort {
		return errx.Permission("OPERATOR_EXECUTOR_REQUIRED", "operator-confirmed writes require rest-best-effort and best-effort")
	}
	var capability profile.Capability
	switch kind {
	case operatorwrite.KindIssueCreate:
		capability = profile.CapabilityIssueCreate
	case operatorwrite.KindIssueUpdate:
		capability = profile.CapabilityIssueUpdate
	case operatorwrite.KindCommentAdd:
		capability = profile.CapabilityCommentAdd
	case operatorwrite.KindCommentDelete:
		capability = profile.CapabilityCommentDelete
	case operatorwrite.KindIssueEdit:
		capability = profile.CapabilityIssueEdit
	default:
		return errx.Usage("unsupported operator-write kind")
	}
	if !selected.HasCapability(capability) {
		return errx.Permission("OPERATOR_CAPABILITY_REQUIRED", "selected profile does not declare the requested operator-write capability")
	}
	return nil
}

func operatorBinding(selected profile.Profile, policy writepolicy.Policy) operatorwrite.Binding {
	encoded, _ := json.Marshal(policy) // Policy contains only concrete, JSON-safe metadata.
	return operatorwrite.Binding{ProfileName: selected.Name, ProfileIdentitySHA256: profile.CredentialIdentity(selected),
		CredentialGeneration: selected.CredentialGeneration, AccountID: selected.ExpectedAccountID, AccountLogin: selected.ExpectedLogin,
		InstanceURL: selected.ServiceURL, RESTBaseURL: selected.RESTBaseURL, MCPURL: selected.MCPURL,
		OAuthClientID: selected.OAuth.ClientID, OAuthAuthorizationEndpoint: selected.OAuth.AuthorizationURL,
		OAuthTokenEndpoint: selected.OAuth.TokenURL, OAuthIssuerURL: selected.OAuth.IssuerURL,
		PolicySHA256: sha256Hex(encoded), PolicyRevision: policy.Revision}
}

func (s *Service) checkOperatorBinding(ctx context.Context, snapshot operatorwrite.Snapshot, name string) error {
	if snapshot.Binding.ProfileName != name {
		return errx.Conflict("OPERATOR_PROFILE_MISMATCH", "operator plan belongs to a different profile")
	}
	selected, err := s.GetProfile(ctx, name)
	if err != nil {
		return err
	}
	if err := requireOperatorProfile(selected, snapshot.Kind); err != nil {
		return err
	}
	projectID, projectKey := snapshot.ProjectRef()
	policy, err := s.Policies.RequireProject(ctx, selected, projectID, projectKey)
	if err != nil {
		return err
	}
	if operatorBinding(selected, policy) != snapshot.Binding {
		return errx.Conflict("OPERATOR_BINDING_STALE", "operator profile or project policy changed after snapshot").WithHint("inspect a fresh snapshot and prepare a new intent before confirming it")
	}
	return nil
}

// SnapshotOperatorWrite reads exactly one target and its selected field schema.
// Account verification precedes issue, project, and schema reads.
func (s *Service) SnapshotOperatorWrite(ctx context.Context, input OperatorSnapshotInput) (OperatorWriteInfo, error) {
	if err := s.requireOperatorDependencies(false); err != nil {
		return OperatorWriteInfo{}, err
	}
	if input.OutputPath != "" {
		if err := operatorwrite.ValidateExportPath(ctx, input.OutputPath); err != nil {
			return OperatorWriteInfo{}, err
		}
	}
	kind := operatorwrite.Kind(input.Kind)
	selected, err := s.GetProfile(ctx, input.Profile)
	if err != nil {
		return OperatorWriteInfo{}, err
	}
	if err := requireOperatorProfile(selected, kind); err != nil {
		return OperatorWriteInfo{}, err
	}
	if _, err := s.Policies.GetBound(ctx, selected); err != nil {
		return OperatorWriteInfo{}, err
	}
	if err := validateOperatorTarget(kind, input); err != nil {
		return OperatorWriteInfo{}, err
	}
	client, selected, err := s.client(ctx, input.Profile)
	if err != nil {
		return OperatorWriteInfo{}, err
	}
	if err := verifyClientAccount(ctx, client, selected); err != nil {
		return OperatorWriteInfo{}, err
	}
	snapshot := operatorwrite.Snapshot{Version: operatorwrite.Version, Lane: operatorwrite.Lane, Kind: kind, CapturedAt: s.currentTime()}
	var projectFields []youtrack.ProjectField
	if kind == operatorwrite.KindIssueCreate {
		project, err := client.GetProject(ctx, input.ProjectID)
		if err != nil {
			return OperatorWriteInfo{}, err
		}
		if project.Archived {
			return OperatorWriteInfo{}, errx.Permission("OPERATOR_PROJECT_ARCHIVED", "target project is archived")
		}
		policy, err := s.Policies.RequireProject(ctx, selected, project.ID, project.ShortName)
		if err != nil {
			return OperatorWriteInfo{}, err
		}
		snapshot.Binding, snapshot.Project = operatorBinding(selected, policy), &operatorwrite.Project{ID: project.ID, Key: project.ShortName}
		for _, selection := range input.Fields {
			schema, err := resolveOperatorField(ctx, client, project.ID, selection, &projectFields)
			if err != nil {
				return OperatorWriteInfo{}, err
			}
			field, err := freezeCreateField(schema, selection.ValueID, selection.ValueName)
			if err != nil {
				return OperatorWriteInfo{}, err
			}
			for _, frozen := range snapshot.Fields {
				if frozen.ProjectFieldID == field.ProjectFieldID {
					return OperatorWriteInfo{}, errx.Usage("each custom field may be selected only once")
				}
			}
			snapshot.Fields = append(snapshot.Fields, field)
		}
	} else {
		issue, err := client.GetIssue(ctx, input.IssueID)
		if err != nil {
			return OperatorWriteInfo{}, err
		}
		if issue.Project.Archived {
			return OperatorWriteInfo{}, errx.Permission("OPERATOR_PROJECT_ARCHIVED", "target issue belongs to an archived project")
		}
		policy, err := s.Policies.RequireProject(ctx, selected, issue.Project.ID, issue.Project.ShortName)
		if err != nil {
			return OperatorWriteInfo{}, err
		}
		snapshot.Binding = operatorBinding(selected, policy)
		snapshot.Issue = operatorwrite.Issue{ID: issue.ID, ReadableID: issue.IDReadable, ProjectID: issue.Project.ID, ProjectKey: issue.Project.ShortName, Updated: issue.Updated}
		if kind == operatorwrite.KindIssueUpdate {
			selection := input.Fields[0]
			schema, err := resolveOperatorField(ctx, client, issue.Project.ID, selection, &projectFields)
			if err != nil {
				return OperatorWriteInfo{}, err
			}
			field, err := freezeOperatorField(issue, schema, selection.ValueID, selection.ValueName, selection.Clear)
			if err != nil {
				return OperatorWriteInfo{}, err
			}
			snapshot.Field = &field
		}
		if kind == operatorwrite.KindIssueEdit {
			// Only hashes of the current text are frozen, never the text.
			text, err := operatorEditPrecondition(issue)
			if err != nil {
				return OperatorWriteInfo{}, err
			}
			snapshot.Text = text
		}
		if kind == operatorwrite.KindCommentDelete {
			target, err := client.GetCommentForDeletion(ctx, issue.ID, input.CommentID)
			if err != nil {
				return OperatorWriteInfo{}, err
			}
			comment := operatorDeleteComment(target, snapshot.Binding.AccountID)
			snapshot.Comment = &comment
		}
	}
	if err := operatorwrite.ValidateSnapshot(snapshot); err != nil {
		return OperatorWriteInfo{}, err
	}
	if input.OutputPath != "" {
		if err := operatorwrite.WriteSnapshot(ctx, input.OutputPath, snapshot); err != nil {
			return OperatorWriteInfo{}, errx.Internal("operator snapshot export failed safely")
		}
	}
	result := operatorSnapshotInfo(snapshot)
	result.OutputPath = input.OutputPath
	return result, nil
}

// validateOperatorTarget checks the kind-specific selectors before any
// credential or network access.
func validateOperatorTarget(kind operatorwrite.Kind, input OperatorSnapshotInput) error {
	for _, selection := range input.Fields {
		if selection.Clear {
			if kind != operatorwrite.KindIssueUpdate {
				return errx.Usage("--clear-value is accepted only by issue.update")
			}
			if len(input.Fields) != 1 {
				return errx.Usage("--clear-value requires exactly one field selection")
			}
			hasName, hasID := selection.FieldName != "", selection.FieldID != ""
			if hasName == hasID {
				return errx.Usage("--clear-value requires exactly one of --field or --field-id")
			}
			if selection.ValueName != "" || selection.ValueID != "" {
				return errx.Usage("--clear-value cannot be combined with --value or --value-id")
			}
			continue
		}
		byName := selection.FieldName != "" && selection.ValueName != "" && selection.FieldID == "" && selection.ValueID == ""
		byID := selection.FieldID != "" && selection.ValueID != "" && selection.FieldName == "" && selection.ValueName == ""
		if !byName && !byID {
			return errx.Usage("each field selection requires either --field and --value or --field-id and --value-id")
		}
	}
	selected := make(map[OperatorFieldSelection]bool, len(input.Fields))
	for _, selection := range input.Fields {
		key := OperatorFieldSelection{FieldName: selection.FieldName, FieldID: selection.FieldID}
		if selected[key] {
			return errx.Usage("each custom field may be selected only once")
		}
		selected[key] = true
	}
	switch kind {
	case operatorwrite.KindIssueCreate:
		if input.ProjectID == "" || input.IssueID != "" || input.CommentID != "" {
			return errx.Usage("issue.create snapshot requires an exact --project and no --id")
		}
		if len(input.Fields) > operatorwrite.MaxCreateFields {
			return errx.Usage("issue.create snapshot accepts at most %d field selections", operatorwrite.MaxCreateFields)
		}
	case operatorwrite.KindIssueUpdate:
		if input.IssueID == "" || input.ProjectID != "" || input.CommentID != "" {
			return errx.Usage("issue.update snapshot requires an exact --id and no --project")
		}
		if len(input.Fields) != 1 {
			return errx.Usage("issue snapshot requires either --field and --value or --field-id and --value-id")
		}
	case operatorwrite.KindCommentAdd:
		if input.IssueID == "" || input.ProjectID != "" || input.CommentID != "" {
			return errx.Usage("comment.add snapshot requires an exact --id and no --project")
		}
		if len(input.Fields) != 0 {
			return errx.Usage("comment snapshot does not accept field or value selectors")
		}
	case operatorwrite.KindCommentDelete:
		if input.IssueID == "" || input.CommentID == "" || input.ProjectID != "" {
			return errx.Usage("comment.delete snapshot requires exact --id and --comment-id with no --project")
		}
		if len(input.Fields) != 0 {
			return errx.Usage("comment.delete snapshot does not accept field or value selectors")
		}
		if err := youtrack.ValidateDeleteCommentInput(youtrack.DeleteCommentInput{IssueID: input.IssueID, CommentID: input.CommentID}); err != nil {
			return err
		}
	case operatorwrite.KindIssueEdit:
		if input.IssueID == "" || input.ProjectID != "" || input.CommentID != "" {
			return errx.Usage("issue.edit snapshot requires an exact --id and no --project")
		}
		if len(input.Fields) != 0 {
			return errx.Usage("issue.edit snapshot does not accept field or value selectors")
		}
	default:
		return errx.Usage("unsupported operator-write kind")
	}
	return nil
}

// operatorEditPrecondition is the one place that turns the current issue text
// into the frozen hashes, used at snapshot and again at apply.
func operatorEditPrecondition(issue youtrack.Issue) (*operatorwrite.TextPrecondition, error) {
	if err := issue.RequireDescription(); err != nil {
		return nil, err
	}
	summary := issue.Summary
	return &operatorwrite.TextPrecondition{SummarySHA256: operatorwrite.HashText(&summary), DescriptionSHA256: operatorwrite.HashText(issue.Description)}, nil
}

func errTextUnchanged() *errx.Error {
	return errx.Unsupported("OPERATOR_TEXT_UNCHANGED", "the requested text equals the current text").WithHint("nothing to change; do not retry unchanged")
}

// requireEditChangesText refuses an issue.edit whose every requested text
// already equals the current one, judged by hash so the old text is never held.
func requireEditChangesText(plan operatorwrite.Plan) error {
	if plan.Snapshot.Kind != operatorwrite.KindIssueEdit || plan.Snapshot.Text == nil {
		return nil
	}
	summary, description := plan.Request.Summary, plan.Request.Description
	changed := summary != "" && operatorwrite.HashText(&summary) != plan.Snapshot.Text.SummarySHA256 ||
		description != "" && operatorwrite.HashText(&description) != plan.Snapshot.Text.DescriptionSHA256
	if !changed {
		return errTextUnchanged()
	}
	return nil
}

func operatorDeleteComment(target youtrack.CommentDeleteTarget, accountID string) operatorwrite.Comment {
	visibility := operatorwrite.CommentVisibility{Type: target.Visibility.Type,
		PermittedGroupIDs: make([]string, len(target.Visibility.PermittedGroups)),
		PermittedUserIDs:  make([]string, len(target.Visibility.PermittedUsers))}
	for index, group := range target.Visibility.PermittedGroups {
		visibility.PermittedGroupIDs[index] = group.ID
	}
	for index, user := range target.Visibility.PermittedUsers {
		visibility.PermittedUserIDs[index] = user.ID
	}
	sort.Strings(visibility.PermittedGroupIDs)
	sort.Strings(visibility.PermittedUserIDs)
	permission := "Delete Not Own Comment"
	if target.AuthorID == accountID {
		permission = "Delete Comment"
	}
	attachments := make([]string, len(target.Attachments))
	copy(attachments, target.Attachments)
	return operatorwrite.Comment{ID: target.ID, Text: target.Text, AuthorID: target.AuthorID, AuthorLogin: target.AuthorLogin,
		Created: target.Created, Updated: target.Updated, Deleted: target.Deleted, Pinned: target.Pinned,
		Visibility: visibility, Attachments: attachments, RequiredServerPermission: permission}
}

// resolveOperatorField reads the exact selected schema. Name resolution uses
// one bounded page, read at most once per snapshot, and refuses ambiguity.
func resolveOperatorField(ctx context.Context, client *youtrack.Client, projectID string, selection OperatorFieldSelection, listed *[]youtrack.ProjectField) (youtrack.ProjectField, error) {
	fieldID := selection.FieldID
	if fieldID == "" {
		if *listed == nil {
			fields, err := client.ListProjectFields(ctx, projectID, youtrack.PageOptions{Top: 101})
			if err != nil {
				return youtrack.ProjectField{}, err
			}
			if len(fields) > 100 {
				// --clear-value takes no --value-id, so its exact retry differs.
				hint := "use exact --field-id and --value-id"
				if selection.Clear {
					hint = "use exact --field-id with --clear-value"
				}
				return youtrack.ProjectField{}, errx.Conflict("OPERATOR_SCHEMA_TRUNCATED", "bounded field lookup is truncated").WithHint("%s", hint)
			}
			*listed = fields
		}
		matches := 0
		for _, field := range *listed {
			if field.Field.Name == selection.FieldName {
				fieldID = field.ID
				matches++
			}
		}
		if matches != 1 {
			return youtrack.ProjectField{}, errx.Usage("field name must resolve to exactly one project field; use immutable IDs")
		}
	}
	schema, err := client.GetProjectField(ctx, projectID, fieldID)
	if err != nil {
		return youtrack.ProjectField{}, err
	}
	if selection.FieldName != "" && schema.Field.Name != selection.FieldName {
		return youtrack.ProjectField{}, errx.Conflict("OPERATOR_FIELD_STALE", "selected field name changed during snapshot")
	}
	return schema, nil
}

// supportedOperatorSchema reports whether the project field is a single State,
// Enum, or User field backed by the matching bundle type. Everything else is
// refused as unsupported rather than invalid. Creating an issue freezes only
// State and Enum fields; freezeCreateField refuses the user schema itself.
func supportedOperatorSchema(schema youtrack.ProjectField) bool {
	if schema.Bundle == nil {
		return false
	}
	switch schema.Type {
	case "StateProjectCustomField":
		return schema.Bundle.Type == "StateBundle"
	case "EnumProjectCustomField":
		return schema.Bundle.Type == "EnumBundle"
	case "UserProjectCustomField":
		return schema.Bundle.Type == "UserBundle" && schema.Field.FieldType.ValueType == "user" && !schema.Field.FieldType.IsMultiValue
	default:
		return false
	}
}

// freezeCreateField freezes one project schema and nonarchived target value
// for a new issue. There is no issue field or current value to bind yet.
func freezeCreateField(schema youtrack.ProjectField, valueID, valueName string) (operatorwrite.Field, error) {
	if schema.ID == "" || schema.Field.ID == "" || schema.Field.FieldType.IsMultiValue || schema.Bundle == nil || !supportedOperatorSchema(schema) {
		return operatorwrite.Field{}, errx.Unsupported("OPERATOR_FIELD_UNSUPPORTED", "only single State and Enum fields are supported")
	}
	var issueType, valueType string
	switch schema.Type {
	case "StateProjectCustomField":
		issueType, valueType = "StateIssueCustomField", "StateBundleElement"
	case "EnumProjectCustomField":
		issueType, valueType = "SingleEnumIssueCustomField", "EnumBundleElement"
	default:
		return operatorwrite.Field{}, errx.Unsupported("OPERATOR_FIELD_UNSUPPORTED", "only single State and Enum fields are supported")
	}
	field := operatorwrite.Field{ProjectFieldID: schema.ID, GlobalFieldID: schema.Field.ID, Name: schema.Field.Name,
		Type: issueType, ProjectFieldType: schema.Type, ValueType: schema.Field.FieldType.ValueType, IsMultiValue: schema.Field.FieldType.IsMultiValue,
		CanBeEmpty: schema.CanBeEmpty, IsPublic: schema.IsPublic, FieldTypeID: schema.Field.FieldType.ID, FieldTypeType: schema.Field.FieldType.Type,
		BundleID: schema.Bundle.ID, BundleType: schema.Bundle.Type}
	targetMatches := 0
	seen := make(map[string]bool, len(schema.Bundle.Values))
	for _, value := range schema.Bundle.Values {
		if value.ID == "" || seen[value.ID] {
			return field, errx.Conflict("OPERATOR_BUNDLE_INVALID", "field bundle has missing or duplicate value IDs")
		}
		seen[value.ID] = true
		if valueID != "" && value.ID == valueID || valueName != "" && value.Name == valueName {
			field.TargetValue = &operatorwrite.Value{ID: value.ID, Name: value.Name, Archived: value.Archived, Type: value.Type}
			targetMatches++
		}
	}
	if targetMatches != 1 || field.TargetValue == nil || field.TargetValue.Archived {
		return field, errx.Usage("the target value must be known, unique, and not archived")
	}
	if field.TargetValue.Type != valueType {
		return field, errx.Conflict("OPERATOR_FIELD_VALUE_INVALID", "selected field value has an incompatible bundle type")
	}
	return field, nil
}

// freezeOperatorField freezes the touched issue field. With clearTarget set no target
// value is selected and the frozen target stays nil (an explicit clear), which
// needs a clearable field that currently holds a value. Setting a field to the
// value it already holds is refused the same way, so a no-op can never be mistaken
// for a successful write during reconciliation.
func freezeOperatorField(issue youtrack.Issue, schema youtrack.ProjectField, valueID, valueName string, clearTarget bool) (operatorwrite.Field, error) {
	if schema.ID == "" || schema.Field.ID == "" || schema.Field.FieldType.IsMultiValue || schema.Bundle == nil || !supportedOperatorSchema(schema) {
		return operatorwrite.Field{}, errx.Unsupported("OPERATOR_FIELD_UNSUPPORTED", "only single State, Enum, and User fields are supported")
	}
	var issueField youtrack.IssueCustomField
	matches := 0
	globalMatches := 0
	for _, field := range issue.CustomFields {
		if field.ProjectCustomField != nil && field.ProjectCustomField.Field.ID == schema.Field.ID {
			globalMatches++
		}
		if field.ProjectCustomField != nil && field.ProjectCustomField.ID == schema.ID {
			if field.ProjectCustomField.Field.ID != schema.Field.ID {
				return operatorwrite.Field{}, errx.Conflict("OPERATOR_FIELD_MAPPING_INVALID", "issue field does not match the global field identity")
			}
			issueField = field
			matches++
		}
	}
	if matches != 1 || globalMatches != 1 {
		return operatorwrite.Field{}, errx.Conflict("OPERATOR_FIELD_MAPPING_INVALID", "project field must map to exactly one issue custom field")
	}
	issueIDMatches := 0
	for _, candidate := range issue.CustomFields {
		if candidate.ID == issueField.ID {
			issueIDMatches++
		}
	}
	if issueIDMatches != 1 {
		return operatorwrite.Field{}, errx.Conflict("OPERATOR_FIELD_MAPPING_INVALID", "issue custom-field identity is duplicated")
	}
	field := operatorwrite.Field{IssueFieldID: issueField.ID, ProjectFieldID: schema.ID, GlobalFieldID: schema.Field.ID, Name: schema.Field.Name,
		Type: issueField.Type, ProjectFieldType: schema.Type, ValueType: schema.Field.FieldType.ValueType, IsMultiValue: schema.Field.FieldType.IsMultiValue,
		CanBeEmpty: schema.CanBeEmpty, IsPublic: schema.IsPublic, FieldTypeID: schema.Field.FieldType.ID, FieldTypeType: schema.Field.FieldType.Type,
		BundleID: schema.Bundle.ID, BundleType: schema.Bundle.Type}
	valueType, projectType := "", ""
	switch issueField.Type {
	case "StateIssueCustomField":
		valueType, projectType = "StateBundleElement", "StateProjectCustomField"
	case "SingleEnumIssueCustomField":
		valueType, projectType = "EnumBundleElement", "EnumProjectCustomField"
	case "SingleUserIssueCustomField":
		valueType, projectType = "User", "UserProjectCustomField"
	default:
		return field, errx.Unsupported("OPERATOR_FIELD_UNSUPPORTED", "only single State, Enum, and User fields are supported")
	}
	if schema.Type != projectType {
		return field, errx.Conflict("OPERATOR_FIELD_MAPPING_INVALID", "issue field type does not match the project field type")
	}
	if clearTarget && !schema.CanBeEmpty {
		return field, errx.Unsupported("OPERATOR_FIELD_REQUIRED", "the field cannot be empty, so it cannot be cleared").WithHint("choose a clearable field or set a value instead")
	}
	if valueType == "User" {
		return freezeUserField(field, issueField, schema, valueID, valueName, clearTarget)
	}
	var current struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Type string `json:"$type"`
	}
	if bytes.Equal(bytes.TrimSpace(issueField.Value), []byte("null")) {
		if !schema.CanBeEmpty {
			return field, errx.Conflict("OPERATOR_FIELD_VALUE_INVALID", "non-empty field has a null current value")
		}
	} else {
		if err := json.Unmarshal(issueField.Value, &current); err != nil || current.ID == "" || current.Type != valueType {
			return field, errx.Conflict("OPERATOR_FIELD_VALUE_INVALID", "current field value is not an immutable single bundle value")
		}
	}
	targetMatches, currentMatches := 0, 0
	seen := make(map[string]bool, len(schema.Bundle.Values))
	for _, value := range schema.Bundle.Values {
		if value.ID == "" || seen[value.ID] {
			return field, errx.Conflict("OPERATOR_BUNDLE_INVALID", "field bundle has missing or duplicate value IDs")
		}
		seen[value.ID] = true
		frozen := operatorwrite.Value{ID: value.ID, Name: value.Name, Archived: value.Archived, Type: value.Type}
		if value.ID == current.ID && current.ID != "" {
			field.CurrentValue = &frozen
			currentMatches++
		}
		if !clearTarget && (valueID != "" && value.ID == valueID || valueName != "" && value.Name == valueName) {
			field.TargetValue = &frozen
			targetMatches++
		}
	}
	if current.ID != "" && currentMatches != 1 {
		return field, errx.Usage("current and target values must be known and the unique target must not be archived")
	}
	if clearTarget {
		if field.CurrentValue == nil {
			return field, errAlreadyEmpty()
		}
	} else if targetMatches != 1 || field.TargetValue == nil || field.TargetValue.Archived {
		return field, errx.Usage("current and target values must be known and the unique target must not be archived")
	}
	if field.TargetValue != nil && field.TargetValue.Type != valueType || field.CurrentValue != nil && field.CurrentValue.Type != valueType {
		return field, errx.Conflict("OPERATOR_FIELD_VALUE_INVALID", "selected field values have an incompatible bundle type")
	}
	if field.CurrentValue != nil && current.Name != "" && current.Name != field.CurrentValue.Name {
		return field, errx.Conflict("OPERATOR_FIELD_VALUE_INVALID", "current field value disagrees with its bundle")
	}
	if field.TargetValue != nil && field.CurrentValue != nil && field.TargetValue.ID == field.CurrentValue.ID {
		return field, errAlreadySet()
	}
	return field, nil
}

func errAlreadyEmpty() *errx.Error {
	return errx.Unsupported("OPERATOR_FIELD_ALREADY_EMPTY", "the field is already empty").WithHint("nothing to clear; do not retry unchanged")
}

func errAlreadySet() *errx.Error {
	return errx.Unsupported("OPERATOR_FIELD_ALREADY_SET", "the field already holds the target value").WithHint("nothing to change; do not retry unchanged")
}

// freezeUserField freezes a single user field. The current user comes from the
// issue and need not be in the bundle (a departed assignee is the main clearing
// case). Only id, login, and type are frozen, never fullName or email, and users
// are compared by login. A set target must match exactly one nonbanned bundle
// user by exact login or ID.
func freezeUserField(field operatorwrite.Field, issueField youtrack.IssueCustomField, schema youtrack.ProjectField, valueID, valueName string, clearTarget bool) (operatorwrite.Field, error) {
	var current struct {
		ID    string `json:"id"`
		Login string `json:"login"`
		Type  string `json:"$type"`
	}
	if bytes.Equal(bytes.TrimSpace(issueField.Value), []byte("null")) {
		if !schema.CanBeEmpty {
			return field, errx.Conflict("OPERATOR_FIELD_VALUE_INVALID", "non-empty field has a null current value")
		}
	} else {
		if err := json.Unmarshal(issueField.Value, &current); err != nil || current.ID == "" || current.Login == "" || current.Type != "User" {
			return field, errx.Conflict("OPERATOR_FIELD_VALUE_INVALID", "current field value is not an immutable single user value")
		}
		field.CurrentValue = &operatorwrite.Value{ID: current.ID, Name: current.Login, Type: "User"}
	}
	if clearTarget {
		if field.CurrentValue == nil {
			return field, errAlreadyEmpty()
		}
		return field, nil
	}
	targetMatches := 0
	var target youtrack.User
	seen := make(map[string]bool, len(schema.Bundle.AggregatedUsers))
	for _, user := range schema.Bundle.AggregatedUsers {
		if user.ID == "" || user.Login == "" || seen[user.ID] {
			return field, errx.Conflict("OPERATOR_BUNDLE_INVALID", "field bundle has missing or duplicate user IDs")
		}
		seen[user.ID] = true
		if valueID != "" && user.ID == valueID || valueName != "" && user.Login == valueName {
			target = user
			targetMatches++
		}
	}
	if targetMatches != 1 || target.Banned {
		return field, errx.Usage("the target user must be one known, unbanned user of the field bundle, selected by exact login or ID")
	}
	field.TargetValue = &operatorwrite.Value{ID: target.ID, Name: target.Login, Type: "User"}
	if field.CurrentValue != nil && field.CurrentValue.ID == target.ID {
		return field, errAlreadySet()
	}
	return field, nil
}

// PrepareOperatorWrite accepts bounded strict JSON and performs only local
// metadata checks. Dry-run performs no plan, ledger, or export writes.
func (s *Service) PrepareOperatorWrite(ctx context.Context, input OperatorPrepareInput) (OperatorWriteInfo, error) {
	if err := s.requireOperatorDependencies(!input.DryRun); err != nil {
		return OperatorWriteInfo{}, err
	}
	if !input.DryRun && input.OutputPath != "" {
		if err := operatorwrite.ValidateExportPath(ctx, input.OutputPath); err != nil {
			return OperatorWriteInfo{}, err
		}
	}
	snapshot, err := operatorwrite.DecodeSnapshot(bytes.NewReader(input.SnapshotJSON))
	if err != nil {
		return OperatorWriteInfo{}, err
	}
	request, err := operatorwrite.DecodeRequest(bytes.NewReader(input.RequestJSON))
	if err != nil {
		return OperatorWriteInfo{}, err
	}
	if err := s.checkOperatorBinding(ctx, snapshot, input.Profile); err != nil {
		return OperatorWriteInfo{}, err
	}
	plan, err := operatorwrite.Prepare(snapshot, request, s.currentTime())
	if err != nil {
		return OperatorWriteInfo{}, err
	}
	if err := requireEditChangesText(plan); err != nil {
		return OperatorWriteInfo{}, err
	}
	if input.DryRun {
		result := operatorRecordInfo(operatorwrite.Record{Plan: plan, State: operatorwrite.StatePrepared})
		result.State = "validated_not_applied"
		return result, nil
	}
	var record operatorwrite.Record
	err = s.Profiles.WithProfileLock(ctx, input.Profile, func() error {
		return s.Policies.WithPolicyLock(ctx, input.Profile, func() error {
			if err := s.checkOperatorBinding(ctx, snapshot, input.Profile); err != nil {
				return err
			}
			var createErr error
			record, createErr = s.OperatorWrites.Create(ctx, plan)
			return createErr
		})
	})
	if err != nil {
		return OperatorWriteInfo{}, err
	}
	result := operatorRecordInfo(record)
	if input.OutputPath != "" {
		if err := operatorwrite.WritePlan(ctx, input.OutputPath, plan); err != nil {
			return result, errx.Internal("operator plan was saved, but its exclusive export failed").WithHint("inspect operator-write status for the saved plan; choose a new export path")
		}
		result.OutputPath = input.OutputPath
	}
	return result, nil
}

// OperatorWriteStatus reads the authoritative local record without credentials.
func (s *Service) OperatorWriteStatus(ctx context.Context, id string) (OperatorWriteInfo, error) {
	if err := s.requireOperatorDependencies(true); err != nil {
		return OperatorWriteInfo{}, err
	}
	record, err := s.OperatorWrites.Get(ctx, id)
	if err != nil {
		return OperatorWriteInfo{}, err
	}
	return operatorRecordInfo(record), nil
}

// ApplyOperatorWrite verifies exact operator consent and local authorization
// before credentials, then claims the authoritative plan durably before one POST.
func (s *Service) ApplyOperatorWrite(ctx context.Context, input OperatorApplyInput) (OperatorWriteInfo, error) {
	if err := s.requireOperatorDependencies(true); err != nil {
		return OperatorWriteInfo{}, err
	}
	record, err := s.OperatorWrites.Get(ctx, input.PlanID)
	if err != nil {
		return OperatorWriteInfo{}, err
	}
	plan := record.Plan
	if record.NonReplayable() {
		return operatorRecordInfo(record), operatorConsumedError()
	}
	if !input.Yes || input.ConfirmIntent == "" {
		return OperatorWriteInfo{}, errx.OperatorConfirmRequired()
	}
	if input.ConfirmIntent != plan.SHA256 {
		return OperatorWriteInfo{}, errx.OperatorConfirmRequired()
	}
	if err := operatorwrite.ValidatePlan(plan); err != nil {
		return OperatorWriteInfo{}, err
	}
	if err := operatorwrite.CheckFresh(plan, s.currentTime()); err != nil {
		return OperatorWriteInfo{}, err
	}
	// A payload the client would refuse must fail here, before Claim consumes
	// the plan, not be recorded as a remote rejection.
	if plan.Snapshot.Kind == operatorwrite.KindIssueCreate {
		if err := youtrack.ValidateCreateIssueInput(operatorCreateInput(plan)); err != nil {
			return OperatorWriteInfo{}, err
		}
	}
	var updateInput youtrack.UpdateIssueInput
	if plan.Snapshot.Kind == operatorwrite.KindIssueUpdate {
		updateInput, err = operatorUpdateInput(plan)
		if err != nil {
			return OperatorWriteInfo{}, err
		}
	}
	if plan.Snapshot.Kind == operatorwrite.KindIssueEdit {
		updateInput, err = operatorEditInput(plan)
		if err != nil {
			return OperatorWriteInfo{}, err
		}
	}
	if plan.Snapshot.Kind == operatorwrite.KindCommentDelete {
		if err := youtrack.ValidateDeleteCommentInput(youtrack.DeleteCommentInput{IssueID: plan.Snapshot.Issue.ID, CommentID: plan.Snapshot.Comment.ID}); err != nil {
			return OperatorWriteInfo{}, err
		}
	}
	if err := s.checkOperatorBinding(ctx, plan.Snapshot, input.Profile); err != nil {
		return OperatorWriteInfo{}, err
	}
	// client takes its own profile lock and can refresh credentials; construct it
	// before the final profile -> policy -> durable-claim lock sequence.
	client, selected, err := s.client(ctx, input.Profile)
	if err != nil {
		return OperatorWriteInfo{}, err
	}
	if err := verifyClientAccount(ctx, client, selected); err != nil {
		return OperatorWriteInfo{}, err
	}
	if plan.Snapshot.Kind != operatorwrite.KindCommentDelete {
		if err := verifyOperatorRemote(ctx, client, plan.Snapshot); err != nil {
			return OperatorWriteInfo{}, err
		}
	}
	var result operatorwrite.Record
	err = s.Profiles.WithProfileLock(ctx, input.Profile, func() error {
		return s.Policies.WithPolicyLock(ctx, input.Profile, func() error {
			if err := s.checkOperatorBinding(ctx, plan.Snapshot, input.Profile); err != nil {
				return err
			}
			if err := operatorwrite.CheckFresh(plan, s.currentTime()); err != nil {
				return err
			}
			if plan.Snapshot.Kind == operatorwrite.KindCommentDelete {
				if err := verifyClientAccount(ctx, client, selected); err != nil {
					return err
				}
				if err := verifyOperatorRemote(ctx, client, plan.Snapshot); err != nil {
					return err
				}
			}
			attempt, claimErr := s.OperatorWrites.Claim(ctx, plan.ID, plan.SHA256, s.currentTime())
			if claimErr != nil {
				return claimErr
			}
			// Claim releases its own ledger lock before this remote call.
			remoteID, remoteReadableID, writeErr := dispatchOperatorWrite(ctx, client, plan, updateInput)
			outcome := operatorwrite.Result{State: operatorwrite.StateApplied, Code: "WRITE_APPLIED", RemoteID: remoteID, RemoteReadableID: remoteReadableID}
			if writeErr != nil {
				outcome.State, outcome.Code = operatorwrite.StateUnknown, "WRITE_OUTCOME_UNKNOWN"
				var typed *errx.Error
				if errors.As(writeErr, &typed) && typed.Reason != "WRITE_OUTCOME_UNKNOWN" {
					outcome.State, outcome.Code = operatorwrite.StateRejected, typed.Reason
				}
			}
			var finishErr error
			result, finishErr = s.OperatorWrites.Finalize(context.WithoutCancel(ctx), plan.ID, attempt, outcome, s.currentTime())
			if writeErr != nil {
				if outcome.State == operatorwrite.StateUnknown {
					return operatorUnknownError()
				}
				var typed *errx.Error
				if errors.As(writeErr, &typed) {
					clone := *typed
					clone.Hint = "this plan is consumed; inspect the issue and prepare a new intent with fresh operator confirmation before any further write"
					return &clone
				}
				return operatorUnknownError()
			}
			if finishErr != nil {
				return errx.WriteAppliedLocalFailure(string(plan.Snapshot.Kind))
			}
			return nil
		})
	})
	if result.Plan.ID == "" {
		result = record
	}
	return operatorRecordInfo(result), err
}

func verifyOperatorRemote(ctx context.Context, client *youtrack.Client, snapshot operatorwrite.Snapshot) error {
	switch snapshot.Kind {
	case operatorwrite.KindIssueCreate:
		project, err := client.GetProject(ctx, snapshot.Project.ID)
		if err != nil {
			return err
		}
		if project.Archived || project.ID != snapshot.Project.ID || project.ShortName != snapshot.Project.Key {
			return errx.Conflict("OPERATOR_PROJECT_STALE", "target project identity or archive state changed").WithHint("inspect a new snapshot and prepare a fresh intent")
		}
		for _, frozen := range snapshot.Fields {
			schema, err := client.GetProjectField(ctx, project.ID, frozen.ProjectFieldID)
			if err != nil {
				return err
			}
			if frozen.TargetValue == nil {
				return errx.Conflict("OPERATOR_FIELD_STALE", "touched field schema or target changed").WithHint("inspect a new snapshot and prepare a fresh intent")
			}
			field, err := freezeCreateField(schema, frozen.TargetValue.ID, "")
			if err != nil {
				// The snapshot froze a valid field, so a refusal now is drift.
				return errx.Conflict("OPERATOR_FIELD_STALE", "touched field schema or target changed").WithHint("inspect a new snapshot and prepare a fresh intent")
			}
			if err := requireSameField(frozen, field); err != nil {
				return err
			}
		}
		return nil
	case operatorwrite.KindIssueUpdate, operatorwrite.KindIssueEdit, operatorwrite.KindCommentAdd, operatorwrite.KindCommentDelete:
		issue, err := client.GetIssue(ctx, snapshot.Issue.ID)
		if err != nil {
			return err
		}
		if issue.Project.Archived || issue.Project.ID != snapshot.Issue.ProjectID || issue.Project.ShortName != snapshot.Issue.ProjectKey || issue.Updated != snapshot.Issue.Updated {
			return errx.Conflict("OPERATOR_ISSUE_STALE", "target issue project or updated timestamp changed").WithHint("inspect a new snapshot and prepare a fresh intent")
		}
		if snapshot.Kind == operatorwrite.KindIssueEdit {
			// A text change that left `updated` untouched is still drift.
			current, err := operatorEditPrecondition(issue)
			if err != nil {
				return err
			}
			if snapshot.Text == nil || *current != *snapshot.Text {
				return errx.Conflict("OPERATOR_ISSUE_STALE", "target issue summary or description changed").WithHint("inspect a new snapshot and prepare a fresh intent")
			}
			return nil
		}
		if snapshot.Kind == operatorwrite.KindCommentAdd {
			return nil
		}
		if snapshot.Kind == operatorwrite.KindCommentDelete {
			target, err := client.GetCommentForDeletion(ctx, issue.ID, snapshot.Comment.ID)
			if err != nil {
				return err
			}
			return requireSameComment(*snapshot.Comment, operatorDeleteComment(target, snapshot.Binding.AccountID))
		}
		schema, err := client.GetProjectField(ctx, issue.Project.ID, snapshot.Field.ProjectFieldID)
		if err != nil {
			return err
		}
		targetID := ""
		if snapshot.Field.TargetValue != nil {
			targetID = snapshot.Field.TargetValue.ID
		}
		field, err := freezeOperatorField(issue, schema, targetID, "", snapshot.Field.TargetValue == nil)
		if err != nil {
			// The snapshot froze a valid field, so a refusal now is drift.
			return errx.Conflict("OPERATOR_FIELD_STALE", "touched field schema, current value, or target changed").WithHint("inspect a new snapshot and prepare a fresh intent")
		}
		return requireSameField(*snapshot.Field, field)
	default:
		return errx.Usage("unsupported operator-write kind")
	}
}

func requireSameComment(frozen, current operatorwrite.Comment) error {
	frozenJSON, err := json.Marshal(frozen)
	if err != nil {
		return errx.Internal("encode frozen delete comment")
	}
	currentJSON, err := json.Marshal(current)
	if err != nil {
		return errx.Internal("encode current delete comment")
	}
	if !bytes.Equal(frozenJSON, currentJSON) {
		return errx.Conflict("OPERATOR_COMMENT_STALE", "target comment changed after snapshot").WithHint("inspect a new snapshot and prepare a fresh intent")
	}
	return nil
}

func requireSameField(frozen, current operatorwrite.Field) error {
	frozenJSON, err := json.Marshal(frozen)
	if err != nil {
		return errx.Internal("encode frozen touched field")
	}
	currentJSON, err := json.Marshal(current)
	if err != nil {
		return errx.Internal("encode current touched field")
	}
	if !bytes.Equal(frozenJSON, currentJSON) {
		return errx.Conflict("OPERATOR_FIELD_STALE", "touched field schema, current value, or target changed").WithHint("inspect a new snapshot and prepare a fresh intent")
	}
	return nil
}

// dispatchOperatorWrite sends the plan's single POST and returns the remote
// entity ID and, for a created issue, its readable ID. update is the already
// validated issue.update payload, built before the plan was claimed.
func dispatchOperatorWrite(ctx context.Context, client *youtrack.Client, plan operatorwrite.Plan, update youtrack.UpdateIssueInput) (string, string, error) {
	snapshot := plan.Snapshot
	switch snapshot.Kind {
	case operatorwrite.KindIssueCreate:
		issue, err := client.CreateIssue(ctx, operatorCreateInput(plan))
		return issue.ID, issue.IDReadable, err
	case operatorwrite.KindIssueUpdate, operatorwrite.KindIssueEdit:
		issue, err := client.UpdateIssue(ctx, update)
		return issue.ID, "", err
	case operatorwrite.KindCommentAdd:
		comment, err := client.AddComment(ctx, youtrack.AddCommentInput{IssueID: snapshot.Issue.ID, ExpectedAuthorID: snapshot.Binding.AccountID, ExpectedAuthorLogin: snapshot.Binding.AccountLogin, Text: plan.Request.CommentText})
		if err != nil {
			return "", "", err
		}
		issue, err := client.GetIssue(ctx, snapshot.Issue.ID)
		if err != nil || issue.Project.ID != snapshot.Issue.ProjectID || issue.Project.ShortName != snapshot.Issue.ProjectKey {
			return comment.ID, "", operatorUnknownError()
		}
		return comment.ID, "", nil
	case operatorwrite.KindCommentDelete:
		if err := client.DeleteComment(ctx, youtrack.DeleteCommentInput{IssueID: snapshot.Issue.ID, CommentID: snapshot.Comment.ID}); err != nil {
			return "", "", err
		}
		return snapshot.Comment.ID, "", nil
	default:
		// Unreachable for a validated plan; it is classified unknown, never rejected.
		return "", "", operatorUnknownError()
	}
}

// operatorCreateInput is the one create payload, shared by dispatch and the
// reconciliation evidence check.
func operatorCreateInput(plan operatorwrite.Plan) youtrack.CreateIssueInput {
	snapshot, description := plan.Snapshot, plan.Request.Description
	input := youtrack.CreateIssueInput{ProjectID: snapshot.Project.ID, ProjectKey: snapshot.Project.Key, Summary: plan.Request.Summary, Description: &description,
		ExpectedReporterID: snapshot.Binding.AccountID, ExpectedReporterLogin: snapshot.Binding.AccountLogin}
	for _, field := range snapshot.Fields {
		// A validated create field always has a target; an empty ID makes the
		// client's validation refuse the payload instead of dereferencing nil.
		valueID := ""
		if field.TargetValue != nil {
			valueID = field.TargetValue.ID
		}
		input.CustomFields = append(input.CustomFields, youtrack.CreateCustomField{ProjectFieldID: field.ProjectFieldID, Name: field.Name, Type: field.Type, ValueID: valueID})
	}
	return input
}

// operatorUpdateInput is the one issue.update payload: it is built and
// validated before the plan is claimed and then dispatched unchanged. A bundle
// or user target is sent as {"id":ID} only; a nil target clears with JSON null.
func operatorUpdateInput(plan operatorwrite.Plan) (youtrack.UpdateIssueInput, error) {
	snapshot := plan.Snapshot
	if snapshot.Field == nil {
		return youtrack.UpdateIssueInput{}, errx.Usage("issue.update plan has no field")
	}
	value := json.RawMessage("null")
	if snapshot.Field.TargetValue != nil {
		encoded, err := json.Marshal(struct {
			ID string `json:"id"`
		}{snapshot.Field.TargetValue.ID})
		if err != nil {
			return youtrack.UpdateIssueInput{}, errx.Internal("encode frozen field value")
		}
		value = encoded
	}
	input := youtrack.UpdateIssueInput{IssueID: snapshot.Issue.ID, ProjectID: snapshot.Issue.ProjectID, ProjectKey: snapshot.Issue.ProjectKey,
		CustomFields: []youtrack.CustomFieldUpdate{{ID: snapshot.Field.IssueFieldID, Type: snapshot.Field.Type, Value: value}}}
	if err := youtrack.ValidateUpdateIssueInput(input); err != nil {
		return youtrack.UpdateIssueInput{}, err
	}
	return input, nil
}

// operatorEditInput is the one issue.edit payload: summary and description
// only, no custom fields. It is built and validated before the plan is claimed
// and then dispatched unchanged. An empty request text means "not edited".
func operatorEditInput(plan operatorwrite.Plan) (youtrack.UpdateIssueInput, error) {
	snapshot := plan.Snapshot
	input := youtrack.UpdateIssueInput{IssueID: snapshot.Issue.ID, ProjectID: snapshot.Issue.ProjectID, ProjectKey: snapshot.Issue.ProjectKey}
	if summary := plan.Request.Summary; summary != "" {
		input.Summary = &summary
	}
	if description := plan.Request.Description; description != "" {
		input.Description = &description
	}
	if err := youtrack.ValidateUpdateIssueInput(input); err != nil {
		return youtrack.UpdateIssueInput{}, err
	}
	return input, nil
}

// operatorFieldValueObserved reports whether an observed issue field value is
// the plan's desired one: an exact JSON null for a clear, otherwise a value of
// the frozen type (User for a user field) with the frozen ID.
func operatorFieldValueObserved(frozen operatorwrite.Field, observed json.RawMessage) bool {
	if frozen.TargetValue == nil {
		return bytes.Equal(bytes.TrimSpace(observed), []byte("null"))
	}
	var value struct {
		ID   string `json:"id"`
		Type string `json:"$type"`
	}
	return json.Unmarshal(observed, &value) == nil && value.ID == frozen.TargetValue.ID && value.Type == frozen.TargetValue.Type
}

func operatorConsumedError() *errx.Error {
	return errx.Conflict("OPERATOR_PLAN_CONSUMED", "operator plan has already been consumed").WithHint("use operator-write status or reconcile; never apply this plan again")
}
func operatorUnknownError() *errx.Error {
	return errx.WriteOutcomeUnknown("operator-write").WithHint("this plan is consumed; run operator-write reconcile and request operator resolution if evidence is inconclusive; never replay this plan")
}

// ReconcileOperatorWrite collects one bounded read-only observation; it never
// restores consumed eligibility or proves a negative from absent comments.
func (s *Service) ReconcileOperatorWrite(ctx context.Context, input OperatorReconcileInput) (OperatorWriteInfo, error) {
	if err := s.requireOperatorDependencies(true); err != nil {
		return OperatorWriteInfo{}, err
	}
	if input.Limit < 1 || input.Limit > 100 || input.Offset < 0 {
		return OperatorWriteInfo{}, errx.Usage("reconcile limit must be 1-100 and offset nonnegative")
	}
	record, err := s.OperatorWrites.Get(ctx, input.PlanID)
	if err != nil {
		return OperatorWriteInfo{}, err
	}
	if !record.NonReplayable() || record.Attempt == nil {
		return OperatorWriteInfo{}, errx.Usage("only a consumed operator plan can be reconciled")
	}
	if record.Plan.Snapshot.Binding.ProfileName != input.Profile {
		return OperatorWriteInfo{}, errx.Conflict("OPERATOR_PROFILE_MISMATCH", "operator plan belongs to a different profile")
	}
	switch record.State {
	case operatorwrite.StateApplied, operatorwrite.StateRejected, operatorwrite.StateReconciled:
		result := operatorRecordInfo(record)
		result.Evidence = "verified_terminal_record_preserved"
		return result, nil
	case operatorwrite.StateInFlight, operatorwrite.StateUnknown, operatorwrite.StateOperatorRequired:
		// Only an unresolved consumed outcome needs remote observations.
	default:
		return OperatorWriteInfo{}, operatorConsumedError()
	}
	if record.Plan.Snapshot.Kind == operatorwrite.KindIssueCreate && input.Offset != 0 {
		return OperatorWriteInfo{}, errx.Usage("issue.create reconcile reads only the first search page; pass --offset 0")
	}
	if err := s.checkOperatorBinding(ctx, record.Plan.Snapshot, input.Profile); err != nil {
		return OperatorWriteInfo{}, err
	}
	client, selected, err := s.client(ctx, input.Profile)
	if err != nil {
		return OperatorWriteInfo{}, err
	}
	if err := verifyClientAccount(ctx, client, selected); err != nil {
		return OperatorWriteInfo{}, err
	}
	snapshot := record.Plan.Snapshot
	outcome := operatorwrite.Result{State: operatorwrite.StateOperatorRequired, Code: "OPERATOR_RESOLUTION_REQUIRED"}
	if record.Result != nil {
		outcome.RemoteID, outcome.RemoteReadableID = record.Result.RemoteID, record.Result.RemoteReadableID
	}
	evidence := "inconclusive"
	switch snapshot.Kind {
	case operatorwrite.KindIssueCreate:
		observed, observedEvidence, err := observeCreatedIssue(ctx, client, record.Plan, *record.Attempt, outcome.RemoteID, input.Limit)
		if err != nil {
			return OperatorWriteInfo{}, err
		}
		if observed.ID != "" {
			outcome.State, outcome.Code = operatorwrite.StateReconciled, "ISSUE_OBSERVED"
			outcome.RemoteID, outcome.RemoteReadableID = observed.ID, observed.IDReadable
			evidence = observedEvidence
		}
	case operatorwrite.KindIssueUpdate, operatorwrite.KindIssueEdit, operatorwrite.KindCommentAdd:
		issue, err := client.GetIssue(ctx, snapshot.Issue.ID)
		if err != nil {
			return OperatorWriteInfo{}, err
		}
		if issue.Project.ID != snapshot.Issue.ProjectID || issue.Project.ShortName != snapshot.Issue.ProjectKey {
			return OperatorWriteInfo{}, errx.Conflict("OPERATOR_PROJECT_CHANGED", "target issue moved from the frozen project")
		}
		if snapshot.Kind == operatorwrite.KindIssueEdit {
			request := record.Plan.Request
			if (request.Summary == "" || issue.Summary == request.Summary) &&
				(request.Description == "" || issue.Description != nil && *issue.Description == request.Description) {
				evidence = "desired_value_observed_without_causal_proof"
			}
		} else if snapshot.Kind == operatorwrite.KindIssueUpdate {
			for _, field := range issue.CustomFields {
				if field.ID == snapshot.Field.IssueFieldID && field.Type == snapshot.Field.Type {
					if operatorFieldValueObserved(*snapshot.Field, field.Value) {
						evidence = "desired_value_observed_without_causal_proof"
					}
				}
			}
		} else {
			var comments []youtrack.Comment
			truncated := false
			exactFetched := false
			if record.Result != nil && record.Result.RemoteID != "" {
				comment, getErr := client.GetComment(ctx, snapshot.Issue.ID, record.Result.RemoteID)
				if getErr != nil {
					return OperatorWriteInfo{}, getErr
				}
				comments = []youtrack.Comment{comment}
				exactFetched = true
			} else {
				comments, err = client.ListComments(ctx, snapshot.Issue.ID, youtrack.PageOptions{Top: input.Limit + 1, Skip: input.Offset})
				if err != nil {
					return OperatorWriteInfo{}, err
				}
				truncated = len(comments) > input.Limit
				if truncated {
					comments = comments[:input.Limit]
				}
			}
			matches := 0
			var matchedComment youtrack.Comment
			for _, comment := range comments {
				if operatorCommentMatches(comment, record.Plan) {
					matches++
					matchedComment = comment
				}
			}
			if matches == 1 && !truncated {
				// Collection reads use the legacy shape. An exact GET verifies the
				// required deleted flag and every evidence field before success.
				verified := matchedComment
				if !exactFetched {
					var getErr error
					verified, getErr = client.GetComment(ctx, snapshot.Issue.ID, matchedComment.ID)
					if getErr != nil {
						return OperatorWriteInfo{}, getErr
					}
				}
				if operatorCommentMatches(verified, record.Plan) {
					outcome.State, outcome.Code = operatorwrite.StateReconciled, "COMMENT_OBSERVED"
					outcome.RemoteID = verified.ID
					evidence = "matching_comment_observed"
				}
			}
		}
	case operatorwrite.KindCommentDelete:
		issue, issueErr := client.GetIssue(ctx, snapshot.Issue.ID)
		if issueErr != nil {
			switch errx.ExitCode(issueErr) {
			case errx.CodeAuth, errx.CodePermission, errx.CodeNotFound:
				// The exact issue cannot prove a hard deletion, so do not cross-read a comment.
			default:
				return OperatorWriteInfo{}, issueErr
			}
		} else if issue.Project.ID == snapshot.Issue.ProjectID && issue.Project.ShortName == snapshot.Issue.ProjectKey {
			_, commentErr := client.GetComment(ctx, snapshot.Issue.ID, snapshot.Comment.ID)
			if commentErr != nil {
				switch errx.ExitCode(commentErr) {
				case errx.CodeAuth, errx.CodePermission, errx.CodeNotFound:
					// Absence or inaccessible content cannot prove a hard deletion.
				default:
					return OperatorWriteInfo{}, commentErr
				}
			}
		}
		evidence = "hard_delete_not_proven"
	default:
		return OperatorWriteInfo{}, errx.Usage("unsupported operator-write kind")
	}
	outcome.EvidenceSHA256 = sha256Hex([]byte(evidence))
	record, err = s.OperatorWrites.Finalize(ctx, record.Plan.ID, *record.Attempt, outcome, s.currentTime())
	if err != nil {
		return OperatorWriteInfo{}, errx.Internal("operator reconciliation evidence could not be saved")
	}
	result := operatorRecordInfo(record)
	result.Evidence = evidence
	return result, nil
}

// observeCreatedIssue collects one bounded GET-only observation of the issue
// a create plan may have made. A zero Issue means absent, duplicate, or
// truncated evidence, which never proves non-application.
func observeCreatedIssue(ctx context.Context, client *youtrack.Client, plan operatorwrite.Plan, attempt operatorwrite.Attempt, remoteID string, limit int) (youtrack.Issue, string, error) {
	snapshot := plan.Snapshot
	project, err := client.GetProject(ctx, snapshot.Project.ID)
	if err != nil {
		return youtrack.Issue{}, "", err
	}
	if project.ID != snapshot.Project.ID || project.ShortName != snapshot.Project.Key {
		return youtrack.Issue{}, "", errx.Conflict("OPERATOR_PROJECT_CHANGED", "target project key changed from the frozen project")
	}
	expected := operatorCreateInput(plan)
	// Workflows and people may change fields after creation, so identity
	// evidence is the marker-bearing text, project, and reporter only.
	identity := expected
	identity.CustomFields = nil
	// A search hit is only text evidence: an older issue edited to carry the
	// marker was not created by this attempt. No clock-skew allowance: a
	// server clock trailing the claim leaves the outcome for the operator.
	// YouTrack reports milliseconds, so the cutoff rounds the claim up.
	notBefore := attempt.ClaimedAt.UnixMilli()
	if attempt.ClaimedAt.After(time.UnixMilli(notBefore)) {
		notBefore++
	}
	var candidates []youtrack.Issue
	if remoteID != "" {
		issue, err := client.GetIssue(ctx, remoteID)
		if err != nil {
			return youtrack.Issue{}, "", err
		}
		candidates = []youtrack.Issue{issue}
	} else {
		issues, err := client.SearchIssues(ctx, "project: "+snapshot.Project.Key+` "`+plan.ID+`"`, youtrack.PageOptions{Top: limit + 1})
		if err != nil {
			return youtrack.Issue{}, "", err
		}
		if len(issues) > limit {
			return youtrack.Issue{}, "", nil
		}
		candidates = issues
	}
	matches := 0
	var match youtrack.Issue
	for _, issue := range candidates {
		if youtrack.CreatedIssueMatches(issue, identity) && (remoteID != "" || issue.Created >= notBefore) {
			matches++
			match = issue
		}
	}
	if matches != 1 {
		return youtrack.Issue{}, "", nil
	}
	if remoteID == "" {
		verified, err := client.GetIssue(ctx, match.ID)
		if err != nil {
			return youtrack.Issue{}, "", err
		}
		if verified.ID != match.ID || verified.Created < notBefore || !youtrack.CreatedIssueMatches(verified, identity) {
			return youtrack.Issue{}, "", nil
		}
		match = verified
	}
	if youtrack.CreatedIssueMatches(match, expected) {
		return match, "matching_issue_observed", nil
	}
	return match, "matching_issue_observed_fields_differ", nil
}

func operatorCommentMatches(comment youtrack.Comment, plan operatorwrite.Plan) bool {
	binding := plan.Snapshot.Binding
	return comment.ID != "" && !comment.Deleted && comment.Text != nil && *comment.Text == plan.Request.CommentText &&
		strings.Contains(*comment.Text, operatorwrite.Marker(plan.ID)) && comment.Author != nil && comment.Author.ID == binding.AccountID &&
		comment.Author.Login == binding.AccountLogin && comment.Visibility != nil && comment.Visibility.Type == "UnlimitedVisibility" &&
		len(comment.Visibility.PermittedGroups) == 0 && len(comment.Visibility.PermittedUsers) == 0
}
