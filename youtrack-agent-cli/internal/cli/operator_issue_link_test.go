package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/application"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/output"
)

func TestIssueLinkCLISnapshotRoutingAndConflicts(t *testing.T) {
	link := []string{"--kind", "issue.link", "--id", "APP-12", "--target-id", "OPS-7", "--link-type", "Depend", "--direction", "depends on"}
	with := func(extra ...string) []string { return append(append([]string{}, link...), extra...) }
	tests := []struct {
		name     string
		args     []string
		wantCode errx.Code
		wantErr  string
	}{
		{"kind reaches the capability check", link, errx.CodePermission, "OPERATOR_CAPABILITY_REQUIRED"},
		{"field selector conflicts", with("--field", "Stage", "--value", "Done"), errx.CodeUsage, "USAGE"},
		{"clear value conflicts", with("--field", "Stage", "--clear-value"), errx.CodeUsage, "USAGE"},
		{"project conflicts", with("--project", "APP"), errx.CodeUsage, "USAGE"},
		{"comment id conflicts", with("--comment-id", "4-1"), errx.CodeUsage, "USAGE"},
		{"link flags on issue.edit", []string{"--kind", "issue.edit", "--id", "APP-12", "--target-id", "OPS-7"}, errx.CodeUsage, "USAGE"},
		{"direction on issue.update", []string{"--kind", "issue.update", "--id", "APP-12", "--field", "Stage", "--value", "Done", "--direction", "depends on"}, errx.CodeUsage, "USAGE"},
		{"link type on comment.add", []string{"--kind", "comment.add", "--id", "APP-12", "--link-type", "Depend"}, errx.CodeUsage, "USAGE"},
		{"link type id on issue.create", []string{"--kind", "issue.create", "--project", "APP", "--link-type-id", "105-1"}, errx.CodeUsage, "USAGE"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, credentials, posts := operatorCLIService(t)
			credentials.loads = 0
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			app, _, _, _, stdout, stderr := testApp(t)
			app.service = service
			args := append([]string{"operator-write", "snapshot", "--profile", "work", "--out", filepath.Join(dir, "snapshot.json"), "-o", "json"}, test.args...)
			code := runApp(app, args...)
			got, _ := decode(t, stdout)["error"].(map[string]any)
			if code != test.wantCode || posts.Load() != 0 || got == nil || got["code"] != test.wantErr {
				t.Fatalf("code=%d posts=%d stdout=%s stderr=%s", code, posts.Load(), stdout, stderr)
			}
			if strings.Count(strings.TrimSpace(stdout.String()), "\n") != 0 {
				t.Fatalf("stdout is not exactly one envelope: %s", stdout)
			}
			if test.wantCode == errx.CodeUsage && credentials.loads != 0 {
				t.Fatalf("usage refusal loaded credentials: %d", credentials.loads)
			}
		})
	}
}

func TestIssueLinkViewShowsTheFrozenLinkByDefault(t *testing.T) {
	info := application.OperatorWriteInfo{State: "snapshot", Kind: "issue.link", PlanVersion: 4, IssueID: "2-12", ProjectID: "0-3", ProjectKey: "APP",
		TargetIssueID: "2-19", TargetReadableID: "OPS-7", TargetProjectKey: "OPS", LinkType: "Depend", Direction: "depends on", LinkID: "lnk-1"}
	for _, format := range []output.Format{output.FormatText, output.FormatJSON} {
		t.Run(string(format), func(t *testing.T) {
			app, _, _, _, stdout, stderr := testApp(t)
			app.out = &output.Writer{Format: format, Out: stdout, Err: stderr}
			if err := app.renderOperatorWrite(info); err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"2-19", "OPS-7", "OPS", "Depend", "depends on", "lnk-1"} {
				if !strings.Contains(stdout.String(), want) {
					t.Fatalf("output omitted %q: %s", want, stdout)
				}
			}
		})
	}
	t.Run("other kinds do not print empty link fields", func(t *testing.T) {
		app, _, _, _, stdout, stderr := testApp(t)
		app.out = &output.Writer{Format: output.FormatText, Out: stdout, Err: stderr}
		if err := app.renderOperatorWrite(application.OperatorWriteInfo{State: "snapshot", Kind: "issue.edit", PlanVersion: 4, IssueID: "2-12"}); err != nil {
			t.Fatal(err)
		}
		for _, unwanted := range []string{"target_issue_id", "link_type", "link_id"} {
			if strings.Contains(stdout.String(), unwanted) {
				t.Fatalf("issue.edit output shows %q: %s", unwanted, stdout)
			}
		}
	})
}
