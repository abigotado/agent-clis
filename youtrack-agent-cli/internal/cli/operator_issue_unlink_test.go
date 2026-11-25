package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/application"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
)

func TestIssueUnlinkCLISnapshotRoutingAndConflicts(t *testing.T) {
	unlink := []string{"--kind", "issue.unlink", "--id", "APP-12", "--target-id", "OPS-7", "--link-type", "Depend", "--direction", "depends on"}
	with := func(extra ...string) []string { return append(append([]string{}, unlink...), extra...) }
	tests := []struct {
		name     string
		args     []string
		wantCode errx.Code
		wantErr  string
	}{
		{"kind reaches the capability check", unlink, errx.CodePermission, "OPERATOR_CAPABILITY_REQUIRED"},
		{"link type id reaches the capability check", []string{"--kind", "issue.unlink", "--id", "APP-12", "--target-id", "OPS-7", "--link-type-id", "105-1", "--direction", "depends on"}, errx.CodePermission, "OPERATOR_CAPABILITY_REQUIRED"},
		{"field selector conflicts", with("--field", "Stage", "--value", "Done"), errx.CodeUsage, "USAGE"},
		{"project conflicts", with("--project", "APP"), errx.CodeUsage, "USAGE"},
		{"comment id conflicts", with("--comment-id", "4-1"), errx.CodeUsage, "USAGE"},
		{"empty project conflicts", with("--project", ""), errx.CodeUsage, "USAGE"},
		{"both link type flags", with("--link-type-id", "105-1"), errx.CodeUsage, "USAGE"},
		{"empty link type id with link type", with("--link-type-id", ""), errx.CodeUsage, "USAGE"},
		{"missing target id (checked after the capability gate)", []string{"--kind", "issue.unlink", "--id", "APP-12", "--link-type", "Depend", "--direction", "depends on"}, errx.CodePermission, "OPERATOR_CAPABILITY_REQUIRED"},
		{"missing link type (checked after the capability gate)", []string{"--kind", "issue.unlink", "--id", "APP-12", "--target-id", "OPS-7", "--direction", "depends on"}, errx.CodePermission, "OPERATOR_CAPABILITY_REQUIRED"},
		{"missing direction (checked after the capability gate)", []string{"--kind", "issue.unlink", "--id", "APP-12", "--target-id", "OPS-7", "--link-type", "Depend"}, errx.CodePermission, "OPERATOR_CAPABILITY_REQUIRED"},
		{"link flags on issue.edit", []string{"--kind", "issue.edit", "--id", "APP-12", "--target-id", "OPS-7"}, errx.CodeUsage, "USAGE"},
		{"direction on comment.delete", []string{"--kind", "comment.delete", "--id", "APP-12", "--comment-id", "4-1", "--direction", "x"}, errx.CodeUsage, "USAGE"},
		{"link type on comment.add", []string{"--kind", "comment.add", "--id", "APP-12", "--link-type", "Depend"}, errx.CodeUsage, "USAGE"},
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

func TestIssueUnlinkViewShowsTheFrozenLinkByDefault(t *testing.T) {
	info := application.OperatorWriteInfo{State: "snapshot", Kind: "issue.unlink", PlanVersion: 4, IssueID: "2-12", ProjectID: "0-3", ProjectKey: "APP",
		TargetIssueID: "2-19", TargetReadableID: "OPS-7", TargetProjectKey: "OPS", LinkType: "Depend", Direction: "depends on", LinkID: "lnk-1"}
	view := operatorWriteView{OperatorWriteInfo: info}
	shown := map[string]bool{}
	for _, field := range view.Fields() {
		if field.Always {
			shown[field.Name] = true
		}
	}
	for _, name := range []string{"issue_id", "target_issue_id", "target_readable_id", "target_project_key", "link_type", "direction", "link_id"} {
		if !shown[name] {
			t.Errorf("issue.unlink view hides %s by default", name)
		}
	}
}
