package cli

import (
	"os"
	"path/filepath"
	"testing"

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
