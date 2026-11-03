package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/application"
	"github.com/abigotado/youtrack-agent-cli/internal/auth"
	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/operatorwrite"
	"github.com/abigotado/youtrack-agent-cli/internal/output"
	"github.com/abigotado/youtrack-agent-cli/internal/profile"
	"github.com/abigotado/youtrack-agent-cli/internal/writepolicy"
)

func enableCLICommentDelete(t *testing.T, service *application.Service, credentials *commentsCredentials) {
	t.Helper()
	selected, err := service.Profiles.Get(t.Context(), "work")
	if err != nil {
		t.Fatal(err)
	}
	selected.Capabilities = append(selected.Capabilities, profile.CapabilityCommentDelete)
	if err := service.Profiles.Put(t.Context(), selected); err != nil {
		t.Fatal(err)
	}
	credentials.value, err = auth.BindCredential(auth.Credential{Kind: auth.CredentialPermanentToken, PermanentToken: "perm:CLI_DELETE_TEST_SENTINEL"}, selected)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Policies.Set(t.Context(), selected, []writepolicy.Project{{ID: "0-3", Key: "APP"}}); err != nil {
		t.Fatal(err)
	}
}

func TestCommentDeleteCLISnapshotSelectorsFailBeforeCredentialAccess(t *testing.T) {
	tests := []struct {
		name            string
		args            []string
		useWriteDefault bool
	}{
		{"missing comment id", []string{"--kind", "comment.delete", "--id", "APP-12"}, false},
		{"project conflicts with delete target", []string{"--kind", "comment.delete", "--id", "APP-12", "--comment-id", "4-1", "--project", "APP"}, false},
		{"field selector conflicts with delete target", []string{"--kind", "comment.delete", "--id", "APP-12", "--comment-id", "4-1", "--field", "Stage", "--value", "Done"}, false},
		{"comment id conflicts with comment add", []string{"--kind", "comment.add", "--id", "APP-12", "--comment-id", "4-1"}, false},
		{"saved write default resolves without profile before selector refusal", []string{"--kind", "comment.delete", "--id", "APP-12"}, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, credentials, posts := operatorCLIService(t)
			enableCLICommentDelete(t, service, credentials)
			if test.useWriteDefault {
				if _, err := service.ChangeProfileDefaults(t.Context(), nil, funcName("work"), false); err != nil {
					t.Fatal(err)
				}
			}
			credentials.loads = 0
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			app, _, _, _, stdout, stderr := testApp(t)
			app.service = service
			args := []string{"operator-write", "snapshot", "--out", filepath.Join(dir, "snapshot.json"), "-o", "json"}
			if !test.useWriteDefault {
				args = append(args, "--profile", "work")
			}
			args = append(args, test.args...)
			if code := runApp(app, args...); code != errx.CodeUsage || credentials.loads != 0 || posts.Load() != 0 || decode(t, stdout)["error"].(map[string]any)["code"] != "USAGE" {
				t.Fatalf("code=%d loads=%d posts=%d stdout=%s stderr=%s", code, credentials.loads, posts.Load(), stdout, stderr)
			}
		})
	}
}

func TestCommentDeleteOutputAlwaysRendersFullUntrustedTarget(t *testing.T) {
	tests := []struct {
		name   string
		format output.Format
		fields []string
	}{
		{"default json", output.FormatJSON, nil},
		{"fields json keeps delete context", output.FormatJSON, []string{"state"}},
		{"default text", output.FormatText, nil},
		{"fields text keeps delete context", output.FormatText, []string{"state"}},
		{"raw ignores projection", output.FormatRaw, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			app, _, _, _, stdout, stderr := testApp(t)
			app.out = &output.Writer{Format: test.format, Fields: test.fields, Out: stdout, Err: stderr}
			result := application.OperatorWriteInfo{State: "snapshot", Kind: "comment.delete", IssueID: "2-12", CommentID: "4-1", ProjectID: "0-3", ProjectKey: "APP", Snapshot: &operatorwrite.Snapshot{Kind: operatorwrite.KindCommentDelete, Comment: &operatorwrite.Comment{
				ID: "4-1", Text: "UNTRUSTED complete text", RequiredServerPermission: "Delete Comment", Attachments: []string{},
			}}}
			if err := app.renderOperatorWrite(result); err != nil {
				t.Fatal(err)
			}
			want := []string{"UNTRUSTED complete text", "Delete Comment", "untrusted_youtrack_content", "operator-write-v1", "4-1", "2-12", "0-3"}
			for _, value := range want {
				if !strings.Contains(stdout.String(), value) {
					t.Fatalf("output omitted %q: %s", value, stdout)
				}
			}
		})
	}
}

type cliCommentDeleteTransport struct {
	base  http.RoundTripper
	calls atomic.Int32
}

func (transport *cliCommentDeleteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Path == "/api/issues/2-12/comments/4-1" && request.Method == http.MethodGet {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"id":"4-1","issue":{"id":"2-12"},"author":{"id":"1-2","login":"alice"},"created":10,"updated":null,"deleted":false,"pinned":false,"text":"CLI complete delete target","visibility":{"$type":"UnlimitedVisibility","permittedGroups":[],"permittedUsers":[]},"attachments":[]}`)), Request: request}, nil
	}
	if request.URL.Path == "/api/issues/2-12/comments/4-1" && request.Method == http.MethodDelete {
		transport.calls.Add(1)
		if request.GetBody != nil {
			return nil, io.ErrUnexpectedEOF
		}
		return &http.Response{StatusCode: http.StatusNoContent, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	}
	return transport.base.RoundTrip(request)
}

func TestCommentDeleteCLIApplyUsesSavedWriteDefaultAndNeverReplays(t *testing.T) {
	service, credentials, posts := operatorCLIService(t)
	enableCLICommentDelete(t, service, credentials)
	selected, err := service.Profiles.Get(t.Context(), "work")
	if err != nil {
		t.Fatal(err)
	}
	selected.Capabilities = []profile.Capability{profile.CapabilityRead, profile.CapabilityCommentDelete}
	if err := service.Profiles.Put(t.Context(), selected); err != nil {
		t.Fatal(err)
	}
	credentials.value, err = auth.BindCredential(auth.Credential{Kind: auth.CredentialPermanentToken, PermanentToken: "perm:CLI_DELETE_ONLY_TEST_SENTINEL"}, selected)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Policies.Set(t.Context(), selected, []writepolicy.Project{{ID: "0-3", Key: "APP"}}); err != nil {
		t.Fatal(err)
	}
	transport := &cliCommentDeleteTransport{base: service.HTTP}
	service.HTTP = transport
	snapshot, err := service.SnapshotOperatorWrite(t.Context(), application.OperatorSnapshotInput{Profile: "work", Kind: "comment.delete", IssueID: "APP-12", CommentID: "4-1"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(snapshot.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := service.PrepareOperatorWrite(t.Context(), application.OperatorPrepareInput{Profile: "work", SnapshotJSON: raw, RequestJSON: []byte(`{"kind":"comment.delete"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ChangeProfileDefaults(t.Context(), nil, funcName("work"), false); err != nil {
		t.Fatal(err)
	}
	if guarded, name, err := service.ResolveSavedProfile(t.Context(), "write"); err != nil || name != "work" || guarded == nil {
		t.Fatalf("ResolveSavedProfile(write) context=%#v name=%q err=%v", guarded, name, err)
	}
	credentials.loads = 0
	app, _, _, _, stdout, stderr := testApp(t)
	app.service = service
	code := runApp(app, "operator-write", "apply", "--plan-id", plan.PlanID, "--confirm-intent", plan.IntentSHA256, "--yes", "-o", "json")
	if code != errx.CodeOK || credentials.loads != 1 || posts.Load() != 0 || transport.calls.Load() != 1 || stderr.Len() != 0 {
		t.Fatalf("code=%d loads=%d posts=%d deletes=%d stdout=%s stderr=%s", code, credentials.loads, posts.Load(), transport.calls.Load(), stdout, stderr)
	}
	envelope := decode(t, stdout)
	if envelope["meta"].(map[string]any)["profile"] != "work" || envelope["data"].(map[string]any)["remote_id"] != "4-1" {
		t.Fatalf("envelope=%#v", envelope)
	}
	app, _, _, _, stdout, _ = testApp(t)
	app.service = service
	code = runApp(app, "operator-write", "apply", "--plan-id", plan.PlanID, "--confirm-intent", plan.IntentSHA256, "--yes", "-o", "json")
	if code != errx.CodeConflict || transport.calls.Load() != 1 || decode(t, stdout)["error"].(map[string]any)["code"] != "OPERATOR_PLAN_CONSUMED" {
		t.Fatalf("replay code=%d deletes=%d stdout=%s", code, transport.calls.Load(), stdout)
	}
}
