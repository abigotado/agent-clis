package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/application"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
)

func TestOperatorCLIClearValueFlagValidation(t *testing.T) {
	for _, test := range []struct {
		name       string
		args       []string
		wantCode   errx.Code
		wantReason string
	}{
		{"clear with field accepted", []string{"--kind", "issue.update", "--id", "APP-12", "--clear-value", "--field", "Assignee"}, errx.CodePermission, "OPERATOR_CAPABILITY_REQUIRED"},
		{"clear with field id accepted", []string{"--kind", "issue.update", "--id", "APP-12", "--clear-value", "--field-id", "92-1"}, errx.CodePermission, "OPERATOR_CAPABILITY_REQUIRED"},
		{"clear with value", []string{"--kind", "issue.update", "--id", "APP-12", "--clear-value", "--field", "Assignee", "--value", "bob"}, errx.CodeUsage, "USAGE"},
		{"clear with empty value", []string{"--kind", "issue.update", "--id", "APP-12", "--clear-value", "--field", "Assignee", "--value", ""}, errx.CodeUsage, "USAGE"},
		{"clear with value id", []string{"--kind", "issue.update", "--id", "APP-12", "--clear-value", "--field-id", "92-1", "--value-id", "1-5"}, errx.CodeUsage, "USAGE"},
		{"clear with issue.create", []string{"--kind", "issue.create", "--project", "APP", "--clear-value", "--field", "Assignee"}, errx.CodeUsage, "USAGE"},
		{"clear with comment.add", []string{"--kind", "comment.add", "--id", "APP-12", "--clear-value", "--field", "Assignee"}, errx.CodeUsage, "USAGE"},
		{"clear with comment.delete", []string{"--kind", "comment.delete", "--id", "APP-12", "--comment-id", "4-1", "--clear-value", "--field", "Assignee"}, errx.CodeUsage, "USAGE"},
		{"clear without a field", []string{"--kind", "issue.update", "--id", "APP-12", "--clear-value"}, errx.CodeUsage, "USAGE"},
		{"clear with two fields", []string{"--kind", "issue.update", "--id", "APP-12", "--clear-value", "--field", "Assignee", "--field", "Stage"}, errx.CodeUsage, "USAGE"},
		{"clear with name and id", []string{"--kind", "issue.update", "--id", "APP-12", "--clear-value", "--field", "Assignee", "--field-id", "92-1"}, errx.CodeUsage, "USAGE"},
		{"clear with empty field", []string{"--kind", "issue.update", "--id", "APP-12", "--clear-value", "--field", ""}, errx.CodeUsage, "USAGE"},
		{"clear-field on issue.create accepted", []string{"--kind", "issue.create", "--project", "APP", "--clear-field", "Assignee"}, errx.CodePermission, "OPERATOR_CAPABILITY_REQUIRED"},
		{"clear-field-id on issue.create accepted", []string{"--kind", "issue.create", "--project", "APP", "--clear-field-id", "93-1"}, errx.CodePermission, "OPERATOR_CAPABILITY_REQUIRED"},
		{"clear-field with clear-value", []string{"--kind", "issue.create", "--project", "APP", "--clear-field", "Assignee", "--clear-value", "--field", "Stage"}, errx.CodeUsage, "USAGE"},
		{"clear-field on issue.update", []string{"--kind", "issue.update", "--id", "APP-12", "--clear-field", "Assignee"}, errx.CodeUsage, "USAGE"},
		{"clear-field-id on issue.edit", []string{"--kind", "issue.edit", "--id", "APP-12", "--clear-field-id", "93-1"}, errx.CodeUsage, "USAGE"},
		{"clear-field on comment.delete", []string{"--kind", "comment.delete", "--id", "APP-12", "--comment-id", "4-1", "--clear-field", "Assignee"}, errx.CodeUsage, "USAGE"},
		{"clear-field mixed with field ids", []string{"--kind", "issue.create", "--project", "APP", "--clear-field", "Assignee", "--field-id", "92-1", "--value-id", "101-2"}, errx.CodeUsage, "USAGE"},
		{"clear-field-id mixed with field names", []string{"--kind", "issue.create", "--project", "APP", "--clear-field-id", "93-1", "--field", "Stage", "--value", "Done"}, errx.CodeUsage, "USAGE"},
		{"clear-field mixed with clear-field-id", []string{"--kind", "issue.create", "--project", "APP", "--clear-field", "Assignee", "--clear-field-id", "93-1"}, errx.CodeUsage, "USAGE"},
		{"empty clear-field", []string{"--kind", "issue.create", "--project", "APP", "--clear-field", ""}, errx.CodeUsage, "USAGE"},
		{"unassigned is an ordinary login", []string{"--kind", "issue.update", "--id", "APP-12", "--field", "Assignee", "--value", "Unassigned"}, errx.CodePermission, "OPERATOR_CAPABILITY_REQUIRED"},
		{"empty value never clears", []string{"--kind", "issue.update", "--id", "APP-12", "--field", "Assignee", "--value", ""}, errx.CodeUsage, "USAGE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, creds, posts := operatorCLIService(t)
			creds.loads = 0
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			app, _, _, _, stdout, stderr := testApp(t)
			app.service = s
			args := append([]string{"operator-write", "snapshot", "--profile", "work", "--out", filepath.Join(dir, "snapshot.json"), "-o", "json"}, test.args...)
			code := runApp(app, args...)
			// The fixture profile lacks issue-update, so reaching the capability
			// check proves the CLI accepted the selection and built a valid shape.
			if code != test.wantCode || decode(t, stdout)["error"].(map[string]any)["code"] != test.wantReason || creds.loads != 0 || posts.Load() != 0 {
				t.Fatalf("code=%d loads=%d posts=%d stdout=%s stderr=%s", code, creds.loads, posts.Load(), stdout, stderr)
			}
		})
	}
}

func TestOperatorFieldSelectionsMapping(t *testing.T) {
	one := func(s ...string) []string { return s }
	for _, test := range []struct {
		name                                       string
		kind                                       string
		fieldNames, valueNames, fieldIDs, valueIDs []string
		clearNames, clearIDs                       []string
		clear                                      bool
		want                                       []application.OperatorFieldSelection
		wantUsage                                  bool
	}{
		{name: "clear by name", kind: "issue.update", fieldNames: one("Assignee"), clear: true,
			want: []application.OperatorFieldSelection{{FieldName: "Assignee", Clear: true}}},
		{name: "clear by id", kind: "issue.update", fieldIDs: one("92-1"), clear: true,
			want: []application.OperatorFieldSelection{{FieldID: "92-1", Clear: true}}},
		{name: "unassigned is a plain value", kind: "issue.update", fieldNames: one("Assignee"), valueNames: one("Unassigned"),
			want: []application.OperatorFieldSelection{{FieldName: "Assignee", ValueName: "Unassigned"}}},
		{name: "empty value is not a clear", kind: "issue.update", fieldNames: one("Assignee"), valueNames: one(""), wantUsage: true},
		{name: "create sets then clears by name", kind: "issue.create", fieldNames: one("Stage"), valueNames: one("Done"), clearNames: one("Assignee", "Subsystem"),
			want: []application.OperatorFieldSelection{{FieldName: "Stage", ValueName: "Done"}, {FieldName: "Assignee", Clear: true}, {FieldName: "Subsystem", Clear: true}}},
		{name: "create sets then clears by id", kind: "issue.create", fieldIDs: one("92-1"), valueIDs: one("101-2"), clearIDs: one("93-1"),
			want: []application.OperatorFieldSelection{{FieldID: "92-1", ValueID: "101-2"}, {FieldID: "93-1", Clear: true}}},
		{name: "create clears only", kind: "issue.create", clearIDs: one("93-1"),
			want: []application.OperatorFieldSelection{{FieldID: "93-1", Clear: true}}},
		{name: "clear-field on issue.update", kind: "issue.update", clearNames: one("Assignee"), wantUsage: true},
		{name: "clear-field-id on comment.add", kind: "comment.add", clearIDs: one("93-1"), wantUsage: true},
		{name: "clear-field with clear-value", kind: "issue.create", clearNames: one("Assignee"), clear: true, wantUsage: true},
		{name: "clear-field with field ids", kind: "issue.create", fieldIDs: one("92-1"), valueIDs: one("101-2"), clearNames: one("Assignee"), wantUsage: true},
		{name: "clear-field-id with field names", kind: "issue.create", fieldNames: one("Stage"), valueNames: one("Done"), clearIDs: one("93-1"), wantUsage: true},
		{name: "clear-field with clear-field-id", kind: "issue.create", clearNames: one("Assignee"), clearIDs: one("93-1"), wantUsage: true},
		{name: "empty clear-field", kind: "issue.create", clearNames: one(""), wantUsage: true},
		{name: "empty clear-field-id", kind: "issue.create", clearIDs: one("93-1", ""), wantUsage: true},
		{name: "clear with empty value conflicts", kind: "issue.update", fieldNames: one("Assignee"), valueNames: one(""), clear: true, wantUsage: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := operatorFieldSelections(test.kind, test.fieldNames, test.valueNames, test.fieldIDs, test.valueIDs, test.clearNames, test.clearIDs, test.clear)
			if test.wantUsage {
				if err == nil || errx.ExitCode(err) != errx.CodeUsage {
					t.Fatalf("got %v, %v", got, err)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("got %#v, %v want %#v", got, err, test.want)
			}
		})
	}
}
