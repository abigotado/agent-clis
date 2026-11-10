package cli

import (
	"encoding/json"
	"strconv"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/application"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/output"
	"github.com/spf13/cobra"
)

type operatorWriteView struct {
	application.OperatorWriteInfo
	Trust  string `json:"trust"`
	Source string `json:"source"`
}

func (view operatorWriteView) Fields() []output.Field {
	field := output.Field{Name: "field"}
	fields := output.Field{Name: "fields", OnRequest: true}
	deleteTarget := view.Kind == "comment.delete"
	commentText, summary, description := "", "", ""
	comment := output.Field{Name: "comment", OnRequest: true}
	requiredPermission := output.Field{Name: "required_server_permission", OnRequest: true}
	if view.Snapshot != nil {
		field.Raw = view.Snapshot.Field
		fields.Raw, fields.OnRequest = view.Snapshot.Fields, len(view.Snapshot.Fields) == 0
		if view.Snapshot.Comment != nil {
			comment.Raw, comment.Always, comment.OnRequest = view.Snapshot.Comment, true, false
			requiredPermission.Value, requiredPermission.Raw, requiredPermission.Always, requiredPermission.OnRequest = view.Snapshot.Comment.RequiredServerPermission, view.Snapshot.Comment.RequiredServerPermission, true, false
		}
	}
	if view.Plan != nil {
		field.Raw = view.Plan.Snapshot.Field
		fields.Raw, fields.OnRequest = view.Plan.Snapshot.Fields, len(view.Plan.Snapshot.Fields) == 0
		commentText, summary, description = view.Plan.Request.CommentText, view.Plan.Request.Summary, view.Plan.Request.Description
		if view.Plan.Snapshot.Comment != nil {
			comment.Raw, comment.Always, comment.OnRequest = view.Plan.Snapshot.Comment, true, false
			requiredPermission.Value, requiredPermission.Raw, requiredPermission.Always, requiredPermission.OnRequest = view.Plan.Snapshot.Comment.RequiredServerPermission, view.Plan.Snapshot.Comment.RequiredServerPermission, true, false
		}
	}
	if comment.Raw != nil {
		raw, err := json.Marshal(comment.Raw)
		if err != nil {
			comment.Value = "<invalid frozen comment>"
		} else {
			comment.Value = string(raw)
		}
	}
	return []output.Field{
		{Name: "trust", Value: untrustedYouTrackContent, Raw: untrustedYouTrackContent, Always: true},
		{Name: "source", Value: "operator-write-v1", Raw: "operator-write-v1", Always: true},
		{Name: "plan_version", Value: strconv.Itoa(view.PlanVersion), Raw: view.PlanVersion},
		{Name: "plan_lifetime", Value: view.PlanLifetime, Raw: view.PlanLifetime},
		{Name: "confirmation_mode", Value: view.ConfirmationMode, Raw: view.ConfirmationMode, Always: true},
		{Name: "notifications", Value: view.Notifications, Raw: view.Notifications, Always: true},
		{Name: "expires_at", Value: view.ExpiresAt, Raw: view.ExpiresAt, OnRequest: view.ExpiresAt == ""},
		{Name: "plan_id", Value: view.PlanID, Raw: view.PlanID},
		{Name: "state", Value: view.State, Raw: view.State},
		{Name: "kind", Value: view.Kind, Raw: view.Kind},
		{Name: "intent_sha256", Value: view.IntentSHA256, Raw: view.IntentSHA256},
		{Name: "profile", Value: view.Profile, Raw: view.Profile},
		{Name: "issue_id", Value: view.IssueID, Raw: view.IssueID, Always: deleteTarget},
		{Name: "comment_id", Value: view.CommentID, Raw: view.CommentID, OnRequest: !deleteTarget, Always: deleteTarget},
		{Name: "project_id", Value: view.ProjectID, Raw: view.ProjectID, Always: deleteTarget},
		{Name: "project_key", Value: view.ProjectKey, Raw: view.ProjectKey, Always: deleteTarget},
		{Name: "non_replayable", Value: strconv.FormatBool(view.NonReplayable), Raw: view.NonReplayable, Always: true},
		{Name: "remote_id", Value: view.RemoteID, Raw: view.RemoteID},
		{Name: "remote_readable_id", Value: view.RemoteReadableID, Raw: view.RemoteReadableID},
		{Name: "output_path", Value: view.OutputPath, Raw: view.OutputPath},
		field,
		fields,
		{Name: "summary", Value: summary, Raw: summary, OnRequest: summary == ""},
		{Name: "description", Value: description, Raw: description, OnRequest: description == ""},
		{Name: "comment_text", Value: commentText, Raw: commentText, OnRequest: commentText == ""},
		comment,
		requiredPermission,
		{Name: "evidence", Value: view.Evidence, Raw: view.Evidence, OnRequest: view.Evidence == ""},
		{Name: "snapshot", Raw: view.Snapshot, OnRequest: true},
		{Name: "plan", Raw: view.Plan, OnRequest: true},
	}
}

func (a *App) renderOperatorWrite(result application.OperatorWriteInfo) error {
	a.out.WithContext(result.Profile, result.Instance, result.AccountID, result.AccountLogin)
	return a.out.Success(operatorWriteView{OperatorWriteInfo: result, Trust: untrustedYouTrackContent, Source: "operator-write-v1"})
}

func (a *App) newOperatorWriteCommand() *cobra.Command {
	command := commandGroup("operator-write", "Prepare and apply exact operator-confirmed best-effort writes")
	command.AddCommand(a.newOperatorSnapshotCommand(), a.newOperatorPrepareCommand(), a.newOperatorApplyCommand(), a.newOperatorStatusCommand(), a.newOperatorReconcileCommand())
	return command
}

func (a *App) newOperatorSnapshotCommand() *cobra.Command {
	var input application.OperatorSnapshotInput
	var fieldNames, valueNames, fieldIDs, valueIDs []string
	var clearValue bool
	command := &cobra.Command{Use: "snapshot", Short: "Read one exact issue or project and freeze a supported write target", Args: usageArgs(cobra.NoArgs), RunE: func(cmd *cobra.Command, _ []string) error {
		if err := a.resolveOperationProfile(cmd, "write"); err != nil {
			return err
		}
		if a.assumeYes || a.dryRun {
			return errx.Usage("operator-write snapshot does not accept --yes or --dry-run")
		}
		if input.Kind == "" || input.IssueID == "" && input.ProjectID == "" || input.OutputPath == "" {
			return errx.Usage("operator-write snapshot requires --kind, --id or --project, and --out")
		}
		if input.Kind == "comment.delete" && (len(fieldNames) != 0 || len(valueNames) != 0 || len(fieldIDs) != 0 || len(valueIDs) != 0) {
			return errx.Usage("comment.delete snapshot does not accept field or value selectors")
		}
		if clearValue {
			// Checked on the raw flags: --value "" must conflict, never clear.
			if input.Kind != "issue.update" {
				return errx.Usage("--clear-value is accepted only with --kind issue.update")
			}
			if len(valueNames) != 0 || len(valueIDs) != 0 {
				return errx.Usage("--clear-value cannot be combined with --value or --value-id")
			}
			if len(fieldNames)+len(fieldIDs) != 1 {
				return errx.Usage("--clear-value requires exactly one --field or --field-id")
			}
			if len(fieldNames) == 1 && fieldNames[0] == "" || len(fieldIDs) == 1 && fieldIDs[0] == "" {
				return errx.Usage("--clear-value requires a nonempty --field or --field-id")
			}
			input.Fields = []application.OperatorFieldSelection{{Clear: true}}
			if len(fieldNames) == 1 {
				input.Fields[0].FieldName = fieldNames[0]
			} else {
				input.Fields[0].FieldID = fieldIDs[0]
			}
			fieldNames, valueNames, fieldIDs, valueIDs = nil, nil, nil, nil
		}
		if input.Kind != "issue.create" {
			// Single-field kinds keep the scalar flags' last-value-wins meaning.
			fieldNames, valueNames, fieldIDs, valueIDs = lastValue(fieldNames), lastValue(valueNames), lastValue(fieldIDs), lastValue(valueIDs)
		}
		// Selectors pair by position, so one call uses names or IDs, never both.
		if len(fieldNames) != len(valueNames) || len(fieldIDs) != len(valueIDs) || len(fieldNames) > 0 && len(fieldIDs) > 0 {
			return errx.Usage("pair each --field with one --value, or each --field-id with one --value-id, without mixing names and IDs")
		}
		for index := range fieldNames {
			input.Fields = append(input.Fields, application.OperatorFieldSelection{FieldName: fieldNames[index], ValueName: valueNames[index]})
		}
		for index := range fieldIDs {
			input.Fields = append(input.Fields, application.OperatorFieldSelection{FieldID: fieldIDs[index], ValueID: valueIDs[index]})
		}
		if err := a.out.Validate(operatorWriteView{}); err != nil {
			return err
		}
		input.Profile = a.profileName
		result, err := a.service.SnapshotOperatorWrite(cmd.Context(), input)
		if err != nil {
			return err
		}
		return a.renderOperatorWrite(result)
	}}
	flags := command.Flags()
	flags.StringVar(&input.Kind, "kind", "", "supported write kind: issue.create, issue.update, comment.add, or comment.delete")
	flags.StringVar(&input.IssueID, "id", "", "exact issue entity or readable ID for issue.update, comment.add, or comment.delete")
	flags.StringVar(&input.CommentID, "comment-id", "", "immutable exact comment ID for comment.delete")
	flags.StringVar(&input.ProjectID, "project", "", "exact project entity ID or key for issue.create")
	flags.StringArrayVar(&fieldNames, "field", nil, "exact field name, for example Stage; repeatable for issue.create, last wins otherwise")
	flags.StringArrayVar(&valueNames, "value", nil, "exact target bundle value name, or exact user login for a user field, paired with --field")
	flags.StringArrayVar(&fieldIDs, "field-id", nil, "immutable project custom-field ID; repeatable for issue.create, last wins otherwise")
	flags.StringArrayVar(&valueIDs, "value-id", nil, "immutable target bundle value ID, or user ID for a user field, paired with --field-id")
	flags.BoolVar(&clearValue, "clear-value", false, "empty the selected field instead of setting a value; only with --kind issue.update and exactly one --field or --field-id, never with --value or --value-id. The field must allow empty values (canBeEmpty) and currently hold one")
	flags.StringVar(&input.OutputPath, "out", "", "new exclusive 0600 snapshot path in an existing private directory")
	return command
}

// lastValue keeps the scalar flag meaning: the last occurrence wins, and an
// empty last occurrence clears the selector.
func lastValue(values []string) []string {
	if len(values) == 0 || values[len(values)-1] == "" {
		return nil
	}
	return values[len(values)-1:]
}

func (a *App) newOperatorPrepareCommand() *cobra.Command {
	var offline, requestStdin bool
	var snapshotPath, outputPath string
	command := &cobra.Command{Use: "prepare", Short: "Prepare a single-use intent offline from a frozen snapshot", Args: usageArgs(cobra.NoArgs), RunE: func(cmd *cobra.Command, _ []string) error {
		if err := a.resolveOperationProfile(cmd, "write"); err != nil {
			return err
		}
		if !offline || !requestStdin || snapshotPath == "" {
			return errx.Usage("operator-write prepare requires --offline, --snapshot FILE, and --request-stdin")
		}
		if a.assumeYes {
			return errx.Usage("operator-write prepare does not accept --yes")
		}
		if err := a.out.Validate(operatorWriteView{}); err != nil {
			return err
		}
		snapshot, err := readBoundedRegular(snapshotPath, application.MaxOperatorSnapshotBytes)
		if err != nil {
			return errx.Usage("operator snapshot input failed bounded validation")
		}
		request, err := readBounded(a.stdin, application.MaxOperatorRequestBytes)
		if err != nil {
			return errx.Usage("operator request input failed bounded validation")
		}
		result, err := a.service.PrepareOperatorWrite(cmd.Context(), application.OperatorPrepareInput{Profile: a.profileName, SnapshotJSON: snapshot, RequestJSON: request, OutputPath: outputPath, DryRun: a.dryRun})
		if err != nil {
			return err
		}
		return a.renderOperatorWrite(result)
	}}
	command.Flags().BoolVar(&offline, "offline", false, "guarantee no credentials, browser, OAuth, or network access")
	command.Flags().BoolVar(&requestStdin, "request-stdin", false, "read bounded typed operator request JSON from stdin")
	command.Flags().StringVar(&snapshotPath, "snapshot", "", "bounded frozen snapshot JSON file")
	command.Flags().StringVar(&outputPath, "out", "", "optional new exclusive 0600 plan export path")
	return command
}

func (a *App) newOperatorApplyCommand() *cobra.Command {
	var planID, digest string
	command := &cobra.Command{Use: "apply", Short: "Consume one exact confirmed intent for at most one mutation", Args: usageArgs(cobra.NoArgs), RunE: func(cmd *cobra.Command, _ []string) error {
		if err := a.resolveOperationProfile(cmd, "write"); err != nil {
			return err
		}
		if a.dryRun {
			return errx.Usage("operator-write apply does not accept --dry-run")
		}
		if planID == "" {
			return errx.Usage("operator-write apply requires --plan-id")
		}
		if err := a.out.Validate(operatorWriteView{}); err != nil {
			return err
		}
		result, err := a.service.ApplyOperatorWrite(cmd.Context(), application.OperatorApplyInput{Profile: a.profileName, PlanID: planID, ConfirmIntent: digest, Yes: a.assumeYes})
		if err != nil {
			return err
		}
		if err := a.renderOperatorWrite(result); err != nil {
			return errx.WriteAppliedLocalFailure(result.Kind).Wrap(err)
		}
		return nil
	}}
	command.Flags().StringVar(&planID, "plan-id", "", "exact authoritative local operator plan ID")
	command.Flags().StringVar(&digest, "confirm-intent", "", "exact SHA-256 operator assertion for the reviewed plan")
	return command
}

func (a *App) newOperatorStatusCommand() *cobra.Command {
	var planID string
	command := &cobra.Command{Use: "status", Short: "Read one authoritative local operator record offline", Args: usageArgs(cobra.NoArgs), RunE: func(cmd *cobra.Command, _ []string) error {
		if a.assumeYes || a.dryRun {
			return errx.Usage("operator-write status does not accept --yes or --dry-run")
		}
		if planID == "" {
			return errx.Usage("operator-write status requires --plan-id")
		}
		if err := a.out.Validate(operatorWriteView{}); err != nil {
			return err
		}
		result, err := a.service.OperatorWriteStatus(cmd.Context(), planID)
		if err != nil {
			return err
		}
		if a.profileName != "" && a.profileName != result.Profile {
			return errx.Conflict("OPERATOR_PROFILE_MISMATCH", "operator plan belongs to a different profile")
		}
		return a.renderOperatorWrite(result)
	}}
	command.Flags().StringVar(&planID, "plan-id", "", "exact local operator plan ID")
	return command
}

func (a *App) newOperatorReconcileCommand() *cobra.Command {
	var input application.OperatorReconcileInput
	command := &cobra.Command{Use: "reconcile", Short: "Collect one bounded GET-only observation for a consumed intent", Args: usageArgs(cobra.NoArgs), RunE: func(cmd *cobra.Command, _ []string) error {
		if err := a.resolveOperationProfile(cmd, "write"); err != nil {
			return err
		}
		if a.assumeYes || a.dryRun {
			return errx.Usage("operator-write reconcile does not accept --yes or --dry-run")
		}
		if input.PlanID == "" {
			return errx.Usage("operator-write reconcile requires --plan-id")
		}
		if err := a.out.Validate(operatorWriteView{}); err != nil {
			return err
		}
		input.Profile = a.profileName
		result, err := a.service.ReconcileOperatorWrite(cmd.Context(), input)
		if err != nil {
			return err
		}
		return a.renderOperatorWrite(result)
	}}
	command.Flags().StringVar(&input.PlanID, "plan-id", "", "exact consumed local operator plan ID")
	command.Flags().IntVar(&input.Limit, "limit", 20, "one comments page limit, 1-100")
	command.Flags().IntVar(&input.Offset, "offset", 0, "one nonnegative comments page offset")
	return command
}
