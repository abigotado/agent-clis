package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/application"
	"github.com/abigotado/youtrack-agent-cli/internal/auth"
	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/operatorwrite"
	"github.com/abigotado/youtrack-agent-cli/internal/profile"
	"github.com/abigotado/youtrack-agent-cli/internal/writepolicy"
)

func operatorCLIService(t *testing.T) (*application.Service, *commentsCredentials, *atomic.Int32) {
	t.Helper()
	if runtime.GOOS == "darwin" && !application.OperatorWriteSupported() {
		t.Skip("Darwin without CGO cannot audit operator-store ACLs; Linux fake-boundary tests remain enabled")
	}
	posts := &atomic.Int32{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			posts.Add(1)
			var body struct {
				Text string `json:"text"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if err := json.NewEncoder(w).Encode(map[string]any{"id": "4-1", "text": body.Text, "author": map[string]string{"id": "1-2", "login": "alice"}, "deleted": false, "visibility": map[string]string{"$type": "UnlimitedVisibility"}}); err != nil {
				t.Error(err)
			}
			return
		}
		switch r.URL.Path {
		case "/api/users/me":
			_, _ = io.WriteString(w, `{"id":"1-2","login":"alice"}`)
		case "/api/issues/APP-12", "/api/issues/2-12":
			_, _ = io.WriteString(w, `{"id":"2-12","idReadable":"APP-12","summary":"Example","description":null,"project":{"id":"0-3","shortName":"APP","name":"Application","archived":false},"reporter":{"id":"1-2","login":"alice"},"created":1,"updated":2,"commentsCount":0,"customFields":[]}`)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	s, creds := commentsTestService(t, server)
	s.OperatorWriteSupport = func() bool { return true }
	p, err := s.Profiles.Get(t.Context(), "work")
	if err != nil {
		t.Fatal(err)
	}
	p.Capabilities = append(p.Capabilities, profile.CapabilityCommentAdd)
	if err := s.Profiles.Put(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	creds.value, err = auth.BindCredential(auth.Credential{Kind: auth.CredentialPermanentToken, PermanentToken: "perm:CLI_OPERATOR_SENTINEL"}, p)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	s.OperatorWrites = operatorwrite.New(dir)
	s.Policies = writepolicy.NewRegistry(filepath.Join(dir, "config", "policies.json"))
	if _, err := s.Policies.Set(t.Context(), p, []writepolicy.Project{{ID: "0-3", Key: "APP"}}); err != nil {
		t.Fatal(err)
	}
	return s, creds, posts
}

func operatorCLIPlan(t *testing.T, s *application.Service) (application.OperatorWriteInfo, []byte) {
	t.Helper()
	snapshot, err := s.SnapshotOperatorWrite(t.Context(), application.OperatorSnapshotInput{Profile: "work", Kind: "comment.add", IssueID: "APP-12"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(snapshot.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := s.PrepareOperatorWrite(t.Context(), application.OperatorPrepareInput{Profile: "work", SnapshotJSON: raw, RequestJSON: []byte(`{"kind":"comment.add","comment_text":"Full public comment\nwith complete body"}`)})
	if err != nil {
		t.Fatal(err)
	}
	return plan, raw
}

func TestOperatorCLIValidatesInvocationAndProjectionBeforeCredentialAccess(t *testing.T) {
	for _, test := range []struct {
		name   string
		args   []string
		code   errx.Code
		reason string
	}{
		{"profile", []string{}, errx.CodeUsage, "PROFILE_REQUIRED"},
		{"yes", []string{"--profile", "work"}, errx.CodeConfirm, "OPERATOR_CONFIRMATION_REQUIRED"},
		{"digest", []string{"--profile", "work", "--yes"}, errx.CodeConfirm, "OPERATOR_CONFIRMATION_REQUIRED"},
		{"wrong digest", []string{"--profile", "work", "--yes", "--confirm-intent", strings.Repeat("a", 64)}, errx.CodeConfirm, "OPERATOR_CONFIRMATION_REQUIRED"},
		{"projection", []string{"--profile", "work", "--yes", "--fields", "nonexistent"}, errx.CodeUsage, "USAGE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, creds, posts := operatorCLIService(t)
			p, _ := operatorCLIPlan(t, s)
			creds.loads = 0
			app, _, _, _, stdout, stderr := testApp(t)
			app.service = s
			args := append([]string{"operator-write", "apply", "--plan-id", p.PlanID, "-o", "json"}, test.args...)
			code := runApp(app, args...)
			if code != test.code || decode(t, stdout)["error"].(map[string]any)["code"] != test.reason || creds.loads != 0 || posts.Load() != 0 {
				t.Fatalf("code=%d loads=%d posts=%d stdout=%s stderr=%s", code, creds.loads, posts.Load(), stdout, stderr)
			}
		})
	}
}

func TestOperatorCLIApplyUsesSavedWriteDefaultAndRefusesReplay(t *testing.T) {
	s, creds, posts := operatorCLIService(t)
	if _, err := s.ChangeProfileDefaults(t.Context(), nil, funcName("work"), false); err != nil {
		t.Fatal(err)
	}
	plan, _ := operatorCLIPlan(t, s)
	creds.loads = 0
	app, _, _, _, stdout, stderr := testApp(t)
	app.service = s
	if code := runApp(app, "operator-write", "apply", "--plan-id", plan.PlanID, "--confirm-intent", plan.IntentSHA256, "--yes", "-o", "json"); code != errx.CodeOK {
		t.Fatalf("apply code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if posts.Load() != 1 || creds.loads != 1 || decode(t, stdout)["meta"].(map[string]any)["profile"] != "work" {
		t.Fatalf("posts=%d loads=%d stdout=%s", posts.Load(), creds.loads, stdout)
	}
	app, _, _, _, stdout, stderr = testApp(t)
	app.service = s
	if code := runApp(app, "operator-write", "apply", "--plan-id", plan.PlanID, "--confirm-intent", plan.IntentSHA256, "--yes", "-o", "json"); code != errx.CodeConflict || posts.Load() != 1 || decode(t, stdout)["error"].(map[string]any)["code"] != "OPERATOR_PLAN_CONSUMED" {
		t.Fatalf("replay code=%d posts=%d stdout=%s stderr=%s", code, posts.Load(), stdout, stderr)
	}
}

func TestOperatorCLIChangedSavedWriteDefaultRefusesPreparedPlanBeforeCredentialOrPost(t *testing.T) {
	s, creds, posts := operatorCLIService(t)
	if _, err := s.ChangeProfileDefaults(t.Context(), nil, funcName("work"), false); err != nil {
		t.Fatal(err)
	}
	plan, _ := operatorCLIPlan(t, s)
	replacement, err := s.Profiles.Get(t.Context(), "work")
	if err != nil {
		t.Fatal(err)
	}
	replacement.ExpectedLogin = "bob"
	if err := s.Profiles.Put(t.Context(), replacement); err != nil {
		t.Fatal(err)
	}
	creds.loads = 0
	app, _, _, _, stdout, stderr := testApp(t)
	app.service = s
	code := runApp(app, "operator-write", "apply", "--plan-id", plan.PlanID, "--confirm-intent", plan.IntentSHA256, "--yes", "-o", "json")
	if code != errx.CodeConflict || creds.loads != 0 || posts.Load() != 0 || decode(t, stdout)["error"].(map[string]any)["code"] != "PROFILE_DEFAULT_STALE" {
		t.Fatalf("code=%d loads=%d posts=%d stdout=%s stderr=%s", code, creds.loads, posts.Load(), stdout, stderr)
	}
}

func TestOperatorCLIValidSavedWriteDefaultSwitchRejectsOtherProfilePlanBeforeCredentialOrPost(t *testing.T) {
	s, creds, posts := operatorCLIService(t)
	if _, err := s.ChangeProfileDefaults(t.Context(), nil, funcName("work"), false); err != nil {
		t.Fatal(err)
	}
	plan, _ := operatorCLIPlan(t, s)
	other, err := s.Profiles.Get(t.Context(), "work")
	if err != nil {
		t.Fatal(err)
	}
	other.Name = "other"
	if err := s.Profiles.Add(t.Context(), other); err != nil {
		t.Fatal(err)
	}
	defaults, err := s.ChangeProfileDefaults(t.Context(), nil, funcName("other"), false)
	if err != nil {
		t.Fatal(err)
	}
	if defaults.Write.State != "valid" || defaults.Write.ProfileName != "other" {
		t.Fatalf("defaults=%#v", defaults)
	}
	creds.loads = 0
	app, _, _, _, stdout, stderr := testApp(t)
	app.service = s
	code := runApp(app, "operator-write", "apply", "--plan-id", plan.PlanID, "--confirm-intent", plan.IntentSHA256, "--yes", "-o", "json")
	if code != errx.CodeConflict || creds.loads != 0 || posts.Load() != 0 || decode(t, stdout)["error"].(map[string]any)["code"] != "OPERATOR_PROFILE_MISMATCH" {
		t.Fatalf("code=%d loads=%d posts=%d stdout=%s stderr=%s", code, creds.loads, posts.Load(), stdout, stderr)
	}
}

func TestOperatorCLIOfflinePrepareValidSavedWriteSwitchRejectsOtherProfileSnapshotWithoutArtifacts(t *testing.T) {
	s, creds, posts := operatorCLIService(t)
	snapshot, err := s.SnapshotOperatorWrite(t.Context(), application.OperatorSnapshotInput{Profile: "work", Kind: "comment.add", IssueID: "APP-12"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(snapshot.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.Profiles.Get(t.Context(), "work")
	if err != nil {
		t.Fatal(err)
	}
	other.Name = "other"
	if err := s.Profiles.Add(t.Context(), other); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ChangeProfileDefaults(t.Context(), nil, funcName("other"), false); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	snapshotPath := filepath.Join(directory, "snapshot.json")
	if err := os.WriteFile(snapshotPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	creds.loads = 0
	app, _, _, _, stdout, stderr := testApp(t)
	app.service = s
	app.stdin = strings.NewReader(`{"kind":"comment.add","comment_text":"offline comment"}`)
	code := runApp(app, "operator-write", "prepare", "--offline", "--snapshot", snapshotPath, "--request-stdin", "--dry-run", "-o", "json")
	if code != errx.CodeConflict || creds.loads != 0 || posts.Load() != 0 || decode(t, stdout)["error"].(map[string]any)["code"] != "OPERATOR_PROFILE_MISMATCH" {
		t.Fatalf("code=%d loads=%d posts=%d stdout=%s stderr=%s", code, creds.loads, posts.Load(), stdout, stderr)
	}
	if _, err := os.Stat(s.OperatorWrites.Root()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("offline mismatch created plan storage: %v", err)
	}
}

func TestOperatorCLIOfflinePrepareDryRunHasFullFrozenCommentAndNoArtifacts(t *testing.T) {
	s, creds, posts := operatorCLIService(t)
	snapshot, err := s.SnapshotOperatorWrite(t.Context(), application.OperatorSnapshotInput{Profile: "work", Kind: "comment.add", IssueID: "APP-12"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(snapshot.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	input := filepath.Join(dir, "snapshot.json")
	if err := os.WriteFile(input, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	app, _, _, _, stdout, stderr := testApp(t)
	app.service = s
	app.stdin = strings.NewReader(`{"kind":"comment.add","comment_text":"Full public body\nUNTRUSTED text"}`)
	creds.loads = 0
	export := filepath.Join(dir, "plan.json")
	code := runApp(app, "operator-write", "prepare", "--profile", "work", "--offline", "--snapshot", input, "--request-stdin", "--dry-run", "--out", export, "--fields", "plan_id,state,intent_sha256,comment_text", "-o", "json")
	if code != errx.CodeOK || creds.loads != 0 || posts.Load() != 0 {
		t.Fatalf("code=%d loads=%d posts=%d stdout=%s stderr=%s", code, creds.loads, posts.Load(), stdout, stderr)
	}
	data := decode(t, stdout)["data"].(map[string]any)
	if data["state"] != "validated_not_applied" || data["confirmation_mode"] != "operator_confirmed" || !strings.HasPrefix(data["comment_text"].(string), "Full public body\nUNTRUSTED text\n\n[youtrack operator-write ") || data["intent_sha256"] == "" {
		t.Fatalf("projection=%#v", data)
	}
	for _, path := range []string{export, s.OperatorWrites.Root()} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("dry-run wrote %s: %v", path, err)
		}
	}
}

type operatorFailOutput struct{}

func (operatorFailOutput) Write([]byte) (int, error) { return 0, errors.New("output sink failed") }

func TestOperatorCLIVerifiedApplyWithFailedStdoutIsConsumedAppliedFailure(t *testing.T) {
	s, _, posts := operatorCLIService(t)
	p, _ := operatorCLIPlan(t, s)
	app, _, _, _, _, stderr := testApp(t)
	app.service = s
	app.stdout = operatorFailOutput{}
	code := runApp(app, "operator-write", "apply", "--profile", "work", "--plan-id", p.PlanID, "--confirm-intent", p.IntentSHA256, "--yes", "-o", "json")
	if code != errx.CodeInternal || posts.Load() != 1 || !strings.Contains(stderr.String(), "WRITE_APPLIED_LOCAL_FAILURE") {
		t.Fatalf("code=%d posts=%d stderr=%s", code, posts.Load(), stderr)
	}
	status, err := s.OperatorWriteStatus(t.Context(), p.PlanID)
	if err != nil || status.State != "applied" || !status.NonReplayable {
		t.Fatalf("status=%#v %v", status, err)
	}
	app, _, _, _, stdout, _ := testApp(t)
	app.service = s
	if code := runApp(app, "operator-write", "apply", "--profile", "work", "--plan-id", p.PlanID, "--confirm-intent", p.IntentSHA256, "--yes", "-o", "json"); code != errx.CodeConflict || posts.Load() != 1 || decode(t, stdout)["error"].(map[string]any)["code"] != "OPERATOR_PLAN_CONSUMED" {
		t.Fatalf("replay code=%d posts=%d stdout=%s", code, posts.Load(), stdout)
	}
}

type operatorPartialRecoveringOutput struct {
	bytes.Buffer
	calls        int
	firstPayload []byte
}

func (sink *operatorPartialRecoveringOutput) Write(value []byte) (int, error) {
	sink.calls++
	if sink.calls == 1 {
		sink.firstPayload = append([]byte(nil), value...)
		n := min(17, len(value))
		if _, err := sink.Buffer.Write(value[:n]); err != nil {
			return 0, err
		}
		return n, errors.New("partial output sink failure")
	}
	return sink.Buffer.Write(value)
}

func TestOperatorCLIPartialStdoutFailureNeverAppendsSecondEnvelope(t *testing.T) {
	s, _, posts := operatorCLIService(t)
	plan, _ := operatorCLIPlan(t, s)
	app, _, _, _, _, stderr := testApp(t)
	sink := &operatorPartialRecoveringOutput{}
	app.service, app.stdout = s, sink
	code := runApp(app, "operator-write", "apply", "--profile", "work", "--plan-id", plan.PlanID, "--confirm-intent", plan.IntentSHA256, "--yes", "-o", "json")
	if code != errx.CodeInternal || posts.Load() != 1 || sink.calls != 1 || !bytes.Equal(sink.Bytes(), sink.firstPayload[:17]) || !strings.Contains(stderr.String(), "WRITE_APPLIED_LOCAL_FAILURE") {
		t.Fatalf("partial output acquired a second envelope or lost applied outcome: code=%d posts=%d writes=%d stdout=%q stderr=%s", code, posts.Load(), sink.calls, sink.Bytes(), stderr)
	}
	status, err := s.OperatorWriteStatus(t.Context(), plan.PlanID)
	if err != nil || status.State != "applied" || !status.NonReplayable {
		t.Fatalf("output failure lost consumed result: %#v %v", status, err)
	}
}

func TestOperatorCLIUnsupportedBackendKeepsTreeAndRefusesBeforeCredentials(t *testing.T) {
	app, _, _, _, stdout, stderr := testApp(t)
	creds := &commentsCredentials{}
	app.service = &application.Service{Credentials: creds, OperatorWriteSupport: func() bool { return false }}
	found := false
	for _, cmd := range app.NewRootCommand().Commands() {
		if cmd.Name() == "operator-write" {
			found = true
		}
	}
	if !found {
		t.Fatal("standard command tree omits the documented operator-write group")
	}
	code := runApp(app, "operator-write", "apply", "--profile", "work", "--plan-id", "YTOW-AAAAAAAAAAAAAAAAAAAAAAAAAA", "--confirm-intent", strings.Repeat("a", 64), "--yes", "-o", "json")
	if code != errx.CodePermission || creds.loads != 0 || decode(t, stdout)["error"].(map[string]any)["code"] != "OPERATOR_WRITE_UNSUPPORTED" {
		t.Fatalf("code=%d loads=%d stdout=%s stderr=%s", code, creds.loads, stdout, stderr)
	}
}

func TestOperatorCLIPublicCommentProjectionKeepsCompleteTextAndIdentity(t *testing.T) {
	s, _, posts := operatorCLIService(t)
	p, _ := operatorCLIPlan(t, s)
	app, _, _, _, stdout, stderr := testApp(t)
	app.service = s
	code := runApp(app, "operator-write", "apply", "--profile", "work", "--plan-id", p.PlanID, "--confirm-intent", p.IntentSHA256, "--yes", "--fields", "comment_text,remote_id,state", "-o", "json")
	if code != errx.CodeOK || posts.Load() != 1 || stderr.Len() != 0 {
		t.Fatalf("code=%d posts=%d stdout=%s stderr=%s", code, posts.Load(), stdout, stderr)
	}
	envelope := decode(t, stdout)
	data := envelope["data"].(map[string]any)
	meta := envelope["meta"].(map[string]any)
	if data["comment_text"] != p.Plan.Request.CommentText || data["remote_id"] != "4-1" || data["state"] != "applied" || data["non_replayable"] != true || meta["account_id"] != "1-2" || meta["account_login"] != "alice" || meta["profile"] != "work" {
		t.Fatalf("envelope=%#v", envelope)
	}
	if bytes.Contains(stdout.Bytes(), []byte("CLI_OPERATOR_SENTINEL")) {
		t.Fatal("credential leaked to output")
	}
}

func TestOperatorCLICreateSnapshotRefusesMalformedSelectorsBeforeCredentialAccess(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
	}{
		{"field without value", []string{"--kind", "issue.create", "--project", "APP", "--field", "Stage"}},
		{"value without field", []string{"--kind", "issue.create", "--project", "APP", "--value", "Done"}},
		{"field id without value id", []string{"--kind", "issue.create", "--project", "APP", "--field-id", "92-1"}},
		{"value id without field id", []string{"--kind", "issue.create", "--project", "APP", "--value-id", "101-2"}},
		{"unequal field and value counts", []string{"--kind", "issue.create", "--project", "APP", "--field", "Stage", "--field", "Priority", "--value", "Done"}},
		{"names mixed with ids", []string{"--kind", "issue.create", "--project", "APP", "--field", "Stage", "--value", "Done", "--field-id", "92-1", "--value-id", "101-2"}},
		{"missing project and id", []string{"--kind", "issue.create", "--field", "Stage", "--value", "Done"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, creds, posts := operatorCLIService(t)
			creds.loads = 0
			out := filepath.Join(t.TempDir(), "snapshot.json")
			app, _, _, _, stdout, stderr := testApp(t)
			app.service = s
			args := append([]string{"operator-write", "snapshot", "--profile", "work", "--out", out, "-o", "json"}, test.args...)
			code := runApp(app, args...)
			if code != errx.CodeUsage || decode(t, stdout)["error"].(map[string]any)["code"] != "USAGE" || creds.loads != 0 || posts.Load() != 0 {
				t.Fatalf("code=%d loads=%d posts=%d stdout=%s stderr=%s", code, creds.loads, posts.Load(), stdout, stderr)
			}
			if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("refused snapshot wrote %s: %v", out, err)
			}
		})
	}
}

// Before issue.create the selectors were scalar flags, so a repeated flag on a
// single-field kind still means "last value wins" and must not become USAGE.
func TestOperatorCLISingleFieldKindsKeepLastValueWinsSelectors(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
	}{
		{"value overridden", []string{"--field", "Stage", "--value", "Open", "--value", "Done"}},
		{"field overridden", []string{"--field", "Priority", "--field", "Stage", "--value", "Done"}},
		{"value id overridden", []string{"--field-id", "92-1", "--value-id", "101-1", "--value-id", "101-2"}},
		{"names cleared for ids", []string{"--field", "Stage", "--value", "Done", "--field=", "--value=", "--field-id", "92-1", "--value-id", "101-2"}},
		{"ids cleared for names", []string{"--field-id", "92-1", "--value-id", "101-2", "--field-id=", "--value-id=", "--field", "Stage", "--value", "Done"}},
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
			args := append([]string{"operator-write", "snapshot", "--profile", "work", "--kind", "issue.update", "--id", "APP-12",
				"--out", filepath.Join(dir, "snapshot.json"), "-o", "json"}, test.args...)
			code := runApp(app, args...)
			// The fixture profile lacks issue-update, so reaching the capability
			// check proves the CLI accepted the overridden selectors.
			if code != errx.CodePermission || decode(t, stdout)["error"].(map[string]any)["code"] != "OPERATOR_CAPABILITY_REQUIRED" || creds.loads != 0 || posts.Load() != 0 {
				t.Fatalf("code=%d loads=%d posts=%d stdout=%s stderr=%s", code, creds.loads, posts.Load(), stdout, stderr)
			}
		})
	}
}
