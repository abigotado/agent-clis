package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/application"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/operatorwrite"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/output"
)

func TestIssueEditCLISnapshotRoutingAndConflicts(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode errx.Code
		wantErr  string
	}{
		{"kind reaches the capability check", []string{"--kind", "issue.edit", "--id", "APP-12"}, errx.CodePermission, "OPERATOR_CAPABILITY_REQUIRED"},
		{"field selector conflicts", []string{"--kind", "issue.edit", "--id", "APP-12", "--field", "Stage", "--value", "Done"}, errx.CodeUsage, "USAGE"},
		{"clear value conflicts", []string{"--kind", "issue.edit", "--id", "APP-12", "--field", "Stage", "--clear-value"}, errx.CodeUsage, "USAGE"},
		{"project conflicts", []string{"--kind", "issue.edit", "--id", "APP-12", "--project", "APP"}, errx.CodeUsage, "USAGE"},
		{"comment id conflicts", []string{"--kind", "issue.edit", "--id", "APP-12", "--comment-id", "4-1"}, errx.CodeUsage, "USAGE"},
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
			if test.wantCode == errx.CodeUsage && credentials.loads != 0 {
				t.Fatalf("usage refusal loaded credentials: %d", credentials.loads)
			}
		})
	}
}

func TestIssueEditPlanTextShowsNewTextWithoutOldHashes(t *testing.T) {
	const oldHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, format := range []output.Format{output.FormatText, output.FormatJSON} {
		t.Run(string(format), func(t *testing.T) {
			app, _, _, _, stdout, stderr := testApp(t)
			app.out = &output.Writer{Format: format, Out: stdout, Err: stderr}
			plan := &operatorwrite.Plan{
				Snapshot: operatorwrite.Snapshot{Kind: operatorwrite.KindIssueEdit, Text: &operatorwrite.TextPrecondition{SummarySHA256: oldHash, DescriptionSHA256: oldHash}},
				Request:  operatorwrite.Request{Kind: operatorwrite.KindIssueEdit, Summary: "UNTRUSTED new summary", Description: "UNTRUSTED new description"},
			}
			result := application.OperatorWriteInfo{State: "prepared", Kind: "issue.edit", PlanVersion: 4, Plan: plan, Snapshot: &plan.Snapshot}
			if err := app.renderOperatorWrite(result); err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"UNTRUSTED new summary", "UNTRUSTED new description", "untrusted_youtrack_content"} {
				if !strings.Contains(stdout.String(), want) {
					t.Fatalf("output omitted %q: %s", want, stdout)
				}
			}
			if strings.Contains(stdout.String(), oldHash) {
				t.Fatalf("default output leaked old-text hash: %s", stdout)
			}
		})
	}
}

func TestAttachmentCLISnapshotFlagMatrix(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"file on comment.add", []string{"--kind", "comment.add", "--id", "APP-12", "--file", "x.png"}},
		{"name on issue.edit", []string{"--kind", "issue.edit", "--id", "APP-12", "--name", "x.png"}},
		{"attachment without file", []string{"--kind", "attachment.add", "--id", "APP-12"}},
		{"name without file", []string{"--kind", "attachment.add", "--id", "APP-12", "--name", "x.png"}},
		{"with field", []string{"--kind", "attachment.add", "--id", "APP-12", "--file", "x.png", "--field", "Stage", "--value", "Done"}},
		{"with project", []string{"--kind", "attachment.add", "--id", "APP-12", "--file", "x.png", "--project", "APP"}},
		{"with comment id", []string{"--kind", "attachment.add", "--id", "APP-12", "--file", "x.png", "--comment-id", "4-1"}},
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
			if code != errx.CodeUsage || posts.Load() != 0 || credentials.loads != 0 || got == nil || got["code"] != "USAGE" {
				t.Fatalf("code=%d posts=%d loads=%d stdout=%s stderr=%s", code, posts.Load(), credentials.loads, stdout, stderr)
			}
		})
	}
}

func TestAttachmentViewShowsFrozenAttachmentByDefault(t *testing.T) {
	const sum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	snapshot := &operatorwrite.Snapshot{Kind: operatorwrite.KindAttachmentAdd, Attachment: &operatorwrite.Attachment{SourcePath: "/private/secret/dir/x.png", Name: "x.png", Size: 12, SHA256: sum, ContentType: "image/png"}}
	result := application.OperatorWriteInfo{State: "snapshotted", Kind: "attachment.add", PlanVersion: 4, Snapshot: snapshot, Attachment: snapshot.Attachment}
	t.Run("json", func(t *testing.T) {
		app, _, _, _, stdout, stderr := testApp(t)
		app.out = &output.Writer{Format: output.FormatJSON, Out: stdout, Err: stderr}
		if err := app.renderOperatorWrite(result); err != nil {
			t.Fatal(err)
		}
		data, _ := decode(t, stdout)["data"].(map[string]any)
		attachment, _ := data["attachment"].(map[string]any)
		if attachment == nil || attachment["name"] != "x.png" || attachment["sha256"] != sum {
			t.Fatalf("attachment missing by default: %s", stdout)
		}
	})
	t.Run("text one line without the path", func(t *testing.T) {
		app, _, _, _, stdout, stderr := testApp(t)
		app.out = &output.Writer{Format: output.FormatText, Out: stdout, Err: stderr}
		if err := app.renderOperatorWrite(result); err != nil {
			t.Fatal(err)
		}
		out := strings.TrimSpace(stdout.String())
		if strings.Contains(out, "\n") || !strings.Contains(out, `name="x.png"`) || !strings.Contains(out, "size=12") || !strings.Contains(out, "content_type=image/png") || !strings.Contains(out, "sha256="+sum[:12]) || strings.Contains(out, "/private/secret") || strings.Contains(out, sum) {
			t.Fatalf("unexpected text output: %q", out)
		}
	})
}
