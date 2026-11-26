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

func TestIssueTagCLISnapshotRoutingAndConflicts(t *testing.T) {
	gate := func(kind string, extra ...string) []string {
		return append([]string{"--kind", kind, "--id", "APP-12"}, extra...)
	}
	tests := []struct {
		name     string
		args     []string
		wantCode errx.Code
		wantErr  string
	}{
		{"tag by name", gate("issue.tag", "--tag", "urgent"), errx.CodePermission, "OPERATOR_CAPABILITY_REQUIRED"},
		{"tag by id", gate("issue.tag", "--tag-id", "6-1"), errx.CodePermission, "OPERATOR_CAPABILITY_REQUIRED"},
		{"untag by name", gate("issue.untag", "--tag", "urgent"), errx.CodePermission, "OPERATOR_CAPABILITY_REQUIRED"},
		{"untag by id", gate("issue.untag", "--tag-id", "6-1"), errx.CodePermission, "OPERATOR_CAPABILITY_REQUIRED"},
		{"both selectors on tag", gate("issue.tag", "--tag", "urgent", "--tag-id", "6-1"), errx.CodeUsage, "USAGE"},
		{"both selectors on untag", gate("issue.untag", "--tag", "urgent", "--tag-id", "6-1"), errx.CodeUsage, "USAGE"},
		{"field on tag", gate("issue.tag", "--tag", "urgent", "--field", "Stage"), errx.CodeUsage, "USAGE"},
		{"value on untag", gate("issue.untag", "--tag", "urgent", "--value", "Done"), errx.CodeUsage, "USAGE"},
		{"project on tag", gate("issue.tag", "--tag", "urgent", "--project", "APP"), errx.CodeUsage, "USAGE"},
		{"comment id on tag", gate("issue.tag", "--tag", "urgent", "--comment-id", "4-1"), errx.CodeUsage, "USAGE"},
		{"target id on tag", gate("issue.tag", "--tag", "urgent", "--target-id", "OPS-7"), errx.CodeUsage, "USAGE"},
		{"link type on untag", gate("issue.untag", "--tag", "urgent", "--link-type", "Depend"), errx.CodeUsage, "USAGE"},
		{"link type id on untag", gate("issue.untag", "--tag", "urgent", "--link-type-id", "1"), errx.CodeUsage, "USAGE"},
		{"direction on tag", gate("issue.tag", "--tag", "urgent", "--direction", "x"), errx.CodeUsage, "USAGE"},
		{"file on tag", gate("issue.tag", "--tag", "urgent", "--file", "x"), errx.CodeUsage, "USAGE"},
		{"tag on issue.link", []string{"--kind", "issue.link", "--id", "APP-12", "--tag", "urgent"}, errx.CodeUsage, "USAGE"},
		{"tag on comment.add", []string{"--kind", "comment.add", "--id", "APP-12", "--tag", "urgent"}, errx.CodeUsage, "USAGE"},
		{"tag id on issue.edit", []string{"--kind", "issue.edit", "--id", "APP-12", "--tag-id", "6-1"}, errx.CodeUsage, "USAGE"},
		{"tag on issue.edit", []string{"--kind", "issue.edit", "--id", "APP-12", "--tag", "urgent"}, errx.CodeUsage, "USAGE"},
		{"missing selectors (checked after the capability gate)", gate("issue.tag"), errx.CodePermission, "OPERATOR_CAPABILITY_REQUIRED"},
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

func TestIssueTagViewShowsTheFrozenTagAndDisclosuresByDefault(t *testing.T) {
	for _, kind := range []string{"issue.tag", "issue.untag", "issue.unlink"} {
		t.Run(kind, func(t *testing.T) {
			info := application.OperatorWriteInfo{State: "snapshot", Kind: kind, PlanVersion: 4, IssueID: "2-12", TagID: "6-1", TagName: "urgent", Disclosures: []string{"shared_tag"}}
			shown := map[string]bool{}
			for _, field := range (operatorWriteView{OperatorWriteInfo: info}).Fields() {
				if field.Always {
					shown[field.Name] = true
				}
			}
			want := []string{"issue_id", "disclosures"}
			if kind != "issue.unlink" {
				want = append(want, "tag_id", "tag_name")
			}
			for _, name := range want {
				if !shown[name] {
					t.Errorf("%s view hides %s by default", kind, name)
				}
			}
		})
	}
}

func TestOperatorWriteJSONCarriesDisclosuresOnlyWhenPresent(t *testing.T) {
	tests := []struct {
		name        string
		kind        string
		disclosures []string
	}{
		{"unlink aggregation", "issue.unlink", []string{"aggregation_parent_removed"}},
		{"unlink plain", "issue.unlink", nil},
		{"tag shared", "issue.tag", []string{"shared_tag"}},
		{"untag shared", "issue.untag", []string{"shared_tag"}},
		{"untag plain", "issue.untag", nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			app, _, _, _, stdout, stderr := testApp(t)
			info := application.OperatorWriteInfo{State: "snapshot", Kind: test.kind, PlanVersion: 4, IssueID: "2-12", TagID: "6-1", TagName: "urgent", Disclosures: test.disclosures}
			app.out = output.New(output.FormatJSON, nil)
			app.out.Out, app.out.Err = stdout, stderr
			if err := app.renderOperatorWrite(info); err != nil {
				t.Fatalf("render: %v stderr=%s", err, stderr)
			}
			data, _ := decode(t, stdout)["data"].(map[string]any)
			got, present := data["disclosures"]
			if len(test.disclosures) == 0 {
				if present {
					t.Fatalf("unexpected disclosures member: %s", stdout)
				}
				return
			}
			list, _ := got.([]any)
			if len(list) != 1 || list[0] != test.disclosures[0] {
				t.Fatalf("disclosures=%v stdout=%s", got, stdout)
			}
		})
	}
}
