package application

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/auth"
	"github.com/abigotado/youtrack-agent-cli/internal/endpoint"
	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/operatorwrite"
	"github.com/abigotado/youtrack-agent-cli/internal/profile"
	"github.com/abigotado/youtrack-agent-cli/internal/writepolicy"
)

const operatorIssueJSON = `{"id":"2-12","idReadable":"APP-12","summary":"Example","description":"body","project":{"id":"0-3","shortName":"APP","name":"Application","archived":false},"reporter":{"id":"1-2","login":"alice"},"created":1,"updated":2,"commentsCount":0,"customFields":[{"id":"issue-field-7","name":"Stage","$type":"StateIssueCustomField","value":null,"projectCustomField":{"id":"92-1","field":{"id":"42-1"}}}]}`
const operatorSchemaJSON = `{"id":"92-1","$type":"StateProjectCustomField","project":{"id":"0-3"},"field":{"id":"42-1","name":"Stage","fieldType":{"id":"state[1]","valueType":"state","isMultiValue":false,"$type":"FieldType"}},"canBeEmpty":true,"isPublic":true,"bundle":{"id":"100-1","$type":"StateBundle","values":[{"id":"101-1","name":"Open","$type":"StateBundleElement","archived":false},{"id":"101-2","name":"Done","$type":"StateBundleElement","archived":false}]}}`

type operatorFixture struct {
	service                     *Service
	mu                          sync.Mutex
	issue, schema               string
	fieldList                   string
	beforeSchema, beforePost    func()
	postStatus                  int
	postBody                    string
	commentText                 string
	exactCommentBody            string
	comments                    []map[string]any
	posts, pages, exactComments atomic.Int32
}

func newOperatorFixture(t *testing.T) *operatorFixture {
	t.Helper()
	if runtime.GOOS == "darwin" && !OperatorWriteSupported() {
		t.Skip("Darwin without CGO cannot audit operator-store ACLs; Linux fake-boundary tests remain enabled")
	}
	f := &operatorFixture{issue: operatorIssueJSON, schema: operatorSchemaJSON}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			f.posts.Add(1)
			if f.beforePost != nil {
				f.beforePost()
			}
			if f.postStatus != 0 {
				w.WriteHeader(f.postStatus)
				_, _ = io.WriteString(w, f.postBody)
				return
			}
			if strings.HasSuffix(r.URL.Path, "/comments") {
				var body struct {
					Text       string `json:"text"`
					Visibility struct {
						Type string `json:"$type"`
					} `json:"visibility"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				f.commentText = body.Text
				if body.Visibility.Type != "UnlimitedVisibility" {
					t.Errorf("visibility=%q", body.Visibility.Type)
				}
				if err := json.NewEncoder(w).Encode(operatorComment(body.Text, "4-1", "1-2")); err != nil {
					t.Error(err)
				}
				return
			}
			var body struct {
				CustomFields []struct {
					ID    string `json:"id"`
					Type  string `json:"$type"`
					Value struct{ ID string }
				} `json:"customFields"`
			}
			var raw map[string]json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
				t.Error(err)
			}
			if err := json.Unmarshal(raw["customFields"], &body.CustomFields); err != nil {
				t.Error(err)
			}
			if len(body.CustomFields) != 1 || body.CustomFields[0].ID != "issue-field-7" || body.CustomFields[0].Type != "StateIssueCustomField" || body.CustomFields[0].Value.ID != "101-2" || len(raw) != 1 {
				t.Errorf("write payload=%s", raw["customFields"])
			}
			f.issue = strings.Replace(operatorIssueJSON, `"value":null`, `"value":{"id":"101-2","name":"Done"}`, 1)
			_, _ = io.WriteString(w, f.issue)
			return
		}
		switch r.URL.Path {
		case "/api/users/me":
			_, _ = io.WriteString(w, `{"id":"1-2","login":"alice"}`)
		case "/api/issues/2-12", "/api/issues/APP-12":
			_, _ = io.WriteString(w, f.issue)
		case "/api/admin/projects/0-3/customFields/92-1":
			if f.beforeSchema != nil {
				f.beforeSchema()
			}
			_, _ = io.WriteString(w, f.schema)
		case "/api/admin/projects/0-3/customFields":
			if f.fieldList != "" {
				_, _ = io.WriteString(w, f.fieldList)
				return
			}
			_, _ = io.WriteString(w, "["+f.schema+"]")
		case "/api/issues/2-12/comments":
			f.pages.Add(1)
			if r.URL.Query().Get("$top") != "3" || r.URL.Query().Get("$skip") != "7" {
				t.Errorf("unbounded reconciliation request=%s", r.URL)
			}
			if err := json.NewEncoder(w).Encode(f.comments); err != nil {
				t.Error(err)
			}
		case "/api/issues/2-12/comments/4-1":
			f.exactComments.Add(1)
			if f.exactCommentBody != "" {
				_, _ = io.WriteString(w, f.exactCommentBody)
				return
			}
			if err := json.NewEncoder(w).Encode(operatorComment(f.commentText, "4-1", "1-2")); err != nil {
				t.Error(err)
			}
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	dir := t.TempDir()
	mcp, err := endpoint.CanonicalMCPURL(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	p := profile.Profile{Name: "work", ServiceURL: server.URL, RESTBaseURL: server.URL + "/api", MCPURL: mcp,
		OAuth:             profile.OAuthConfig{IssuerURL: "https://hub.example.test", AuthorizationURL: "https://hub.example.test" + endpoint.OAuthAuthorizationPath, TokenURL: "https://hub.example.test" + endpoint.OAuthTokenPath, ClientID: "client", Scopes: []string{"YouTrack"}, RedirectURI: "http://127.0.0.1:18987/oauth/callback"},
		ExpectedAccountID: "1-2", ExpectedLogin: "alice", Capabilities: []profile.Capability{profile.CapabilityRead, profile.CapabilityIssueUpdate, profile.CapabilityCommentAdd}, Executor: profile.ExecutorRESTBestEffort, Assurance: profile.AssuranceBestEffort}
	p, err = p.WithNewCredentialGeneration()
	if err != nil {
		t.Fatal(err)
	}
	profiles := profile.NewRegistry(filepath.Join(dir, "config", "profiles.json"))
	if err := profiles.Add(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	policies := writepolicy.NewRegistry(filepath.Join(dir, "config", "policies.json"))
	if _, err := policies.Set(t.Context(), p, []writepolicy.Project{{ID: "0-3", Key: "APP"}}); err != nil {
		t.Fatal(err)
	}
	credential, err := auth.BindCredential(auth.Credential{Kind: auth.CredentialPermanentToken, PermanentToken: "perm:OPERATOR_TEST_SENTINEL"}, p)
	if err != nil {
		t.Fatal(err)
	}
	f.service = &Service{Profiles: profiles, Policies: policies, Credentials: &fixedCredentials{value: credential}, HTTP: server.Client().Transport, OperatorWrites: operatorwrite.New(dir), OperatorWriteSupport: func() bool { return true }}
	return f
}

func operatorComment(text, id, author string) map[string]any {
	return map[string]any{"id": id, "text": text, "author": map[string]string{"id": author, "login": "alice"}, "deleted": false, "visibility": map[string]string{"$type": "UnlimitedVisibility"}}
}

func (f *operatorFixture) prepare(t *testing.T, kind string) OperatorWriteInfo {
	t.Helper()
	input := OperatorSnapshotInput{Profile: "work", Kind: kind, IssueID: "APP-12"}
	if kind == "issue.update" {
		input.Fields = []OperatorFieldSelection{{FieldID: "92-1", ValueID: "101-2"}}
	}
	snapshot, err := f.service.SnapshotOperatorWrite(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if kind == "issue.update" && (snapshot.Snapshot.Field.IssueFieldID != "issue-field-7" || snapshot.Snapshot.Field.GlobalFieldID != "42-1" || snapshot.Snapshot.Field.CurrentValue != nil) {
		t.Fatalf("field crosswalk=%#v", snapshot.Snapshot.Field)
	}
	raw, err := json.Marshal(snapshot.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	request, err := json.Marshal(operatorwrite.Request{Kind: operatorwrite.Kind(kind), CommentText: map[string]string{"comment.add": "Full body\n\nUNTRUSTED content"}[kind]})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := f.service.PrepareOperatorWrite(t.Context(), OperatorPrepareInput{Profile: "work", SnapshotJSON: raw, RequestJSON: request})
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func operatorReason(t *testing.T, err error) string {
	t.Helper()
	var typed *errx.Error
	if !errors.As(err, &typed) {
		t.Fatalf("expected typed error, got %v", err)
	}
	return typed.Reason
}

func TestOperatorApplyConsentAndLocalDriftBeforeCredentials(t *testing.T) {
	for _, mode := range []string{"missing yes", "missing digest", "wrong digest", "wrong profile", "policy revision", "generation"} {
		t.Run(mode, func(t *testing.T) {
			f := newOperatorFixture(t)
			p := f.prepare(t, "issue.update")
			input := OperatorApplyInput{Profile: "work", PlanID: p.PlanID, ConfirmIntent: p.IntentSHA256, Yes: true}
			selected, err := f.service.Profiles.Get(t.Context(), "work")
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "missing yes":
				input.Yes = false
			case "missing digest":
				input.ConfirmIntent = ""
			case "wrong digest":
				input.ConfirmIntent = strings.Repeat("a", 64)
			case "wrong profile":
				input.Profile = "other"
			case "policy revision":
				if _, err := f.service.Policies.Set(t.Context(), selected, []writepolicy.Project{{ID: "0-3", Key: "APP"}}); err != nil {
					t.Fatal(err)
				}
			case "generation":
				selected.CredentialGeneration, err = profile.NewCredentialGeneration()
				if err != nil {
					t.Fatal(err)
				}
				if err := f.service.Profiles.Put(t.Context(), selected); err != nil {
					t.Fatal(err)
				}
			}
			creds, network := &trapCredentials{}, &trapTransport{}
			f.service.Credentials, f.service.HTTP = creds, network
			_, err = f.service.ApplyOperatorWrite(t.Context(), input)
			if err == nil || creds.calls != 0 || network.calls != 0 || f.posts.Load() != 0 {
				t.Fatalf("error=%v credentials=%d network=%d posts=%d", err, creds.calls, network.calls, f.posts.Load())
			}
			if (strings.HasPrefix(mode, "missing") || mode == "wrong digest") && (operatorReason(t, err) != "OPERATOR_CONFIRMATION_REQUIRED" || errx.ExitCode(err) != errx.CodeConfirm) {
				t.Fatalf("error=%v", err)
			}
			record, err := f.service.OperatorWrites.Get(t.Context(), p.PlanID)
			if err != nil || record.NonReplayable() {
				t.Fatalf("refusal consumed plan: %#v %v", record, err)
			}
		})
	}
}

func TestOfflinePrepareSavedWriteGuardRejectsReplacementWithoutArtifactsOrCredentialAccess(t *testing.T) {
	f := newOperatorFixture(t)
	if _, err := f.service.ChangeProfileDefaults(t.Context(), nil, defaultName("work"), false); err != nil {
		t.Fatal(err)
	}
	snapshot, err := f.service.SnapshotOperatorWrite(t.Context(), OperatorSnapshotInput{Profile: "work", Kind: "comment.add", IssueID: "APP-12"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(snapshot.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	guarded, name, err := f.service.ResolveSavedProfile(t.Context(), "write")
	if err != nil || name != "work" {
		t.Fatalf("ResolveSavedProfile() name=%q err=%v", name, err)
	}
	replacement, err := f.service.Profiles.Get(t.Context(), name)
	if err != nil {
		t.Fatal(err)
	}
	replacement.ExpectedLogin = "bob"
	if err := f.service.Profiles.Put(t.Context(), replacement); err != nil {
		t.Fatal(err)
	}
	credentials := &trapCredentials{}
	f.service.Credentials = credentials
	_, err = f.service.PrepareOperatorWrite(guarded, OperatorPrepareInput{
		Profile: name, SnapshotJSON: raw,
		RequestJSON: []byte(`{"kind":"comment.add","comment_text":"offline comment"}`),
	})
	if operatorReason(t, err) != "PROFILE_DEFAULT_STALE" {
		t.Fatalf("prepare error=%v", err)
	}
	if credentials.calls != 0 || f.posts.Load() != 0 {
		t.Fatalf("stale offline prepare touched credentials=%d posts=%d", credentials.calls, f.posts.Load())
	}
	if _, err := os.Stat(f.service.OperatorWrites.Root()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale offline prepare created plan storage: %v", err)
	}
}

func TestOperatorPrepareAndStatusAreOfflineAndDryRunWritesNothing(t *testing.T) {
	f := newOperatorFixture(t)
	snapshot, err := f.service.SnapshotOperatorWrite(t.Context(), OperatorSnapshotInput{Profile: "work", Kind: "comment.add", IssueID: "APP-12"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(snapshot.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	creds, network := &trapCredentials{}, &trapTransport{}
	f.service.Credentials, f.service.HTTP = creds, network
	export := filepath.Join(t.TempDir(), "dry.json")
	input := OperatorPrepareInput{Profile: "work", SnapshotJSON: raw, RequestJSON: []byte(`{"kind":"comment.add","comment_text":"hello"}`), DryRun: true, OutputPath: export}
	result, err := f.service.PrepareOperatorWrite(t.Context(), input)
	if err != nil || result.State != "validated_not_applied" {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	for _, path := range []string{export, f.service.OperatorWrites.Root()} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("dry-run wrote %s: %v", path, err)
		}
	}
	input.DryRun = false
	input.OutputPath = ""
	prepared, err := f.service.PrepareOperatorWrite(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	status, err := f.service.OperatorWriteStatus(t.Context(), prepared.PlanID)
	if err != nil || status.IntentSHA256 != prepared.IntentSHA256 {
		t.Fatalf("status=%#v %v", status, err)
	}
	if creds.calls != 0 || network.calls != 0 {
		t.Fatalf("offline credentials=%d network=%d", creds.calls, network.calls)
	}
	if !strings.HasSuffix(prepared.Plan.Request.CommentText, "\n\n"+operatorwrite.Marker(prepared.PlanID)) {
		t.Fatalf("missing frozen public marker: %q", prepared.Plan.Request.CommentText)
	}
}

func TestOperatorRemoteDriftStopsBeforeDispatch(t *testing.T) {
	for _, mode := range []string{"project", "updated", "schema", "target name", "target archived", "current value", "global identity", "field privacy", "field type id", "field type type", "target value type"} {
		t.Run(mode, func(t *testing.T) {
			f := newOperatorFixture(t)
			p := f.prepare(t, "issue.update")
			f.mu.Lock()
			switch mode {
			case "project":
				f.issue = strings.Replace(f.issue, `"shortName":"APP"`, `"shortName":"OTHER"`, 1)
			case "updated":
				f.issue = strings.Replace(f.issue, `"updated":2`, `"updated":3`, 1)
			case "schema":
				f.schema = strings.Replace(f.schema, `"canBeEmpty":true`, `"canBeEmpty":false`, 1)
			case "target name":
				f.schema = strings.Replace(f.schema, `"name":"Done"`, `"name":"Finished"`, 1)
			case "target archived":
				f.schema = strings.Replace(f.schema, `"name":"Done","$type":"StateBundleElement","archived":false`, `"name":"Done","$type":"StateBundleElement","archived":true`, 1)
			case "current value":
				f.issue = strings.Replace(f.issue, `"value":null`, `"value":{"id":"101-1","name":"Open"}`, 1)
			case "global identity":
				f.issue = strings.Replace(f.issue, `"id":"42-1"`, `"id":"42-2"`, 1)
			case "field privacy":
				f.schema = strings.Replace(f.schema, `"isPublic":true`, `"isPublic":false`, 1)
			case "field type id":
				f.schema = strings.Replace(f.schema, `"id":"state[1]"`, `"id":"state-other[1]"`, 1)
			case "field type type":
				f.schema = strings.Replace(f.schema, `"$type":"FieldType"`, `"$type":"OtherFieldType"`, 1)
			case "target value type":
				f.schema = strings.Replace(f.schema, `"name":"Done","$type":"StateBundleElement"`, `"name":"Done","$type":"EnumBundleElement"`, 1)
			}
			f.mu.Unlock()
			_, err := f.service.ApplyOperatorWrite(t.Context(), OperatorApplyInput{Profile: "work", PlanID: p.PlanID, ConfirmIntent: p.IntentSHA256, Yes: true})
			if err == nil || f.posts.Load() != 0 {
				t.Fatalf("drift dispatched: error=%v posts=%d", err, f.posts.Load())
			}
			record, err := f.service.OperatorWrites.Get(t.Context(), p.PlanID)
			if err != nil || record.NonReplayable() {
				t.Fatalf("preflight consumed plan: %#v %v", record, err)
			}
		})
	}
}

func TestOperatorVerifiedApplyConcurrentAndRepeatedUsesOnePost(t *testing.T) {
	for _, kind := range []string{"issue.update", "comment.add"} {
		t.Run(kind, func(t *testing.T) {
			f := newOperatorFixture(t)
			p := f.prepare(t, kind)
			input := OperatorApplyInput{Profile: "work", PlanID: p.PlanID, ConfirmIntent: p.IntentSHA256, Yes: true}
			var wg sync.WaitGroup
			errs := make(chan error, 2)
			for range 2 {
				wg.Add(1)
				go func() { defer wg.Done(); _, err := f.service.ApplyOperatorWrite(t.Context(), input); errs <- err }()
			}
			wg.Wait()
			close(errs)
			successes := 0
			for err := range errs {
				if err == nil {
					successes++
				}
			}
			status, err := f.service.OperatorWriteStatus(t.Context(), p.PlanID)
			if err != nil || successes != 1 || f.posts.Load() != 1 || status.State != "applied" || !status.NonReplayable || status.RemoteID == "" {
				t.Fatalf("successes=%d posts=%d status=%#v error=%v", successes, f.posts.Load(), status, err)
			}
			if _, err := f.service.ApplyOperatorWrite(t.Context(), input); operatorReason(t, err) != "OPERATOR_PLAN_CONSUMED" || f.posts.Load() != 1 {
				t.Fatalf("replayed plan: %v", err)
			}
			if kind == "comment.add" && f.commentText != p.Plan.Request.CommentText {
				t.Fatalf("comment changed after confirmation: %q", f.commentText)
			}
		})
	}
}

func TestOperatorUncertainAndRejectedAttemptsRemainConsumed(t *testing.T) {
	for _, test := range []struct {
		name                string
		status              int
		body, state, reason string
	}{
		{"429", 429, `{"error":"sentinel"}`, "unknown", "WRITE_OUTCOME_UNKNOWN"},
		{"malformed", 200, `{"broken":`, "unknown", "WRITE_OUTCOME_UNKNOWN"},
		{"forbidden", 403, `{"error":"sentinel"}`, "rejected", "PERMISSION_DENIED"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newOperatorFixture(t)
			p := f.prepare(t, "comment.add")
			f.postStatus, f.postBody = test.status, test.body
			input := OperatorApplyInput{Profile: "work", PlanID: p.PlanID, ConfirmIntent: p.IntentSHA256, Yes: true}
			_, err := f.service.ApplyOperatorWrite(t.Context(), input)
			if operatorReason(t, err) != test.reason {
				t.Fatalf("error=%v", err)
			}
			status, err := f.service.OperatorWriteStatus(t.Context(), p.PlanID)
			if err != nil || status.State != test.state || !status.NonReplayable || f.posts.Load() != 1 {
				t.Fatalf("status=%#v posts=%d error=%v", status, f.posts.Load(), err)
			}
			if _, err := f.service.ApplyOperatorWrite(t.Context(), input); operatorReason(t, err) != "OPERATOR_PLAN_CONSUMED" || f.posts.Load() != 1 {
				t.Fatalf("replayed: %v", err)
			}
		})
	}
}

func TestOperatorReconcileCommentEvidenceIsBoundedAndNeverRestoresClaim(t *testing.T) {
	for _, mode := range []string{"none", "one", "duplicate", "truncated", "wrong author", "wrong full text", "known id", "known id inconclusive"} {
		t.Run(mode, func(t *testing.T) {
			f := newOperatorFixture(t)
			p := f.prepare(t, "comment.add")
			attempt, err := f.service.OperatorWrites.Claim(t.Context(), p.PlanID, p.IntentSHA256, f.service.currentTime())
			if err != nil {
				t.Fatal(err)
			}
			text := p.Plan.Request.CommentText
			f.commentText = text
			f.comments = []map[string]any{}
			switch mode {
			case "one":
				f.comments = []map[string]any{operatorComment(text, "4-1", "1-2")}
			case "duplicate":
				f.comments = []map[string]any{operatorComment(text, "4-1", "1-2"), operatorComment(text, "4-2", "1-2")}
			case "truncated":
				f.comments = []map[string]any{operatorComment(text, "4-1", "1-2"), operatorComment("different", "4-2", "1-2"), operatorComment("sentinel", "4-3", "1-2")}
			case "wrong author":
				f.comments = []map[string]any{operatorComment(text, "4-1", "1-3")}
			case "wrong full text":
				f.comments = []map[string]any{operatorComment(operatorwrite.Marker(p.PlanID), "4-1", "1-2")}
			case "known id", "known id inconclusive":
				if mode == "known id inconclusive" {
					f.commentText = operatorwrite.Marker(p.PlanID)
				}
				if _, err := f.service.OperatorWrites.Finalize(t.Context(), p.PlanID, attempt, operatorwrite.Result{State: operatorwrite.StateUnknown, Code: "WRITE_OUTCOME_UNKNOWN", RemoteID: "4-1"}, f.service.currentTime()); err != nil {
					t.Fatal(err)
				}
			}
			result, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: p.PlanID, Limit: 2, Offset: 7})
			want := "operator_resolution_required"
			if mode == "one" || mode == "known id" {
				want = "reconciled"
			}
			if err != nil || result.State != want || !result.NonReplayable || f.posts.Load() != 0 {
				t.Fatalf("result=%#v posts=%d error=%v", result, f.posts.Load(), err)
			}
			wantPages, wantExact := int32(1), int32(0)
			if strings.HasPrefix(mode, "known id") {
				wantPages, wantExact = 0, 1
			} else if mode == "one" {
				wantExact = 1
			}
			if f.pages.Load() != wantPages || f.exactComments.Load() != wantExact {
				t.Fatalf("pages=%d exact=%d", f.pages.Load(), f.exactComments.Load())
			}
			if mode == "duplicate" || mode == "truncated" {
				if result.RemoteID != "" {
					t.Fatalf("ambiguous page persisted an unverified exact-read target: %#v", result)
				}
				repeated, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: p.PlanID, Limit: 2, Offset: 7})
				if err != nil || repeated.State != "operator_resolution_required" || repeated.RemoteID != "" || !repeated.NonReplayable || f.pages.Load() != 2 || f.exactComments.Load() != 0 || f.posts.Load() != 0 {
					t.Fatalf("repeat upgraded ambiguous evidence: result=%#v error=%v pages=%d exact=%d posts=%d", repeated, err, f.pages.Load(), f.exactComments.Load(), f.posts.Load())
				}
			}
			if mode == "known id inconclusive" {
				if result.RemoteID != "4-1" {
					t.Fatalf("inconclusive exact evidence lost dispatch-known ID: %#v", result)
				}
				repeated, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: p.PlanID, Limit: 2, Offset: 7})
				if err != nil || repeated.State != "operator_resolution_required" || repeated.RemoteID != "4-1" || f.pages.Load() != 0 || f.exactComments.Load() != 2 || f.posts.Load() != 0 {
					t.Fatalf("known-ID repeat broadened or upgraded evidence: result=%#v error=%v pages=%d exact=%d posts=%d", repeated, err, f.pages.Load(), f.exactComments.Load(), f.posts.Load())
				}
			}
			if _, err := f.service.ApplyOperatorWrite(t.Context(), OperatorApplyInput{Profile: "work", PlanID: p.PlanID, ConfirmIntent: p.IntentSHA256, Yes: true}); operatorReason(t, err) != "OPERATOR_PLAN_CONSUMED" {
				t.Fatalf("reconciliation restored eligibility: %v", err)
			}
		})
	}
}

func TestOperatorStageReconcileObservationCannotProveCausality(t *testing.T) {
	f := newOperatorFixture(t)
	p := f.prepare(t, "issue.update")
	if _, err := f.service.OperatorWrites.Claim(t.Context(), p.PlanID, p.IntentSHA256, f.service.currentTime()); err != nil {
		t.Fatal(err)
	}
	f.issue = strings.Replace(f.issue, `"value":null`, `"value":{"id":"101-2","name":"Done","$type":"StateBundleElement"}`, 1)
	result, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: p.PlanID, Limit: 2})
	if err != nil || result.State != "operator_resolution_required" || result.Evidence != "desired_value_observed_without_causal_proof" || !result.NonReplayable || f.posts.Load() != 0 {
		t.Fatalf("result=%#v error=%v posts=%d", result, err, f.posts.Load())
	}
}

func TestOperatorSnapshotRejectsUnsupportedAndUnresolvedFields(t *testing.T) {
	for _, mode := range []string{"null prohibited", "multi value", "unsupported type", "target absent", "target archived", "target ambiguous", "field absent", "field ambiguous", "field truncated", "missing crosswalk"} {
		t.Run(mode, func(t *testing.T) {
			f := newOperatorFixture(t)
			input := OperatorSnapshotInput{Profile: "work", Kind: "issue.update", IssueID: "APP-12", Fields: []OperatorFieldSelection{{FieldName: "Stage", ValueName: "Done"}}}
			switch mode {
			case "null prohibited":
				f.schema = strings.Replace(f.schema, `"canBeEmpty":true`, `"canBeEmpty":false`, 1)
			case "multi value":
				f.schema = strings.Replace(f.schema, `"isMultiValue":false`, `"isMultiValue":true`, 1)
			case "unsupported type":
				f.issue = strings.Replace(f.issue, "StateIssueCustomField", "MultiEnumIssueCustomField", 1)
			case "target absent":
				input.Fields[0].ValueName = "Absent"
			case "target archived":
				f.schema = strings.Replace(f.schema, `"name":"Done","$type":"StateBundleElement","archived":false`, `"name":"Done","$type":"StateBundleElement","archived":true`, 1)
			case "target ambiguous":
				f.schema = strings.Replace(f.schema, `"name":"Open"`, `"name":"Done"`, 1)
			case "field absent":
				input.Fields[0].FieldName = "Absent"
			case "field ambiguous":
				f.fieldList = "[" + f.schema + "," + strings.Replace(f.schema, `"id":"92-1"`, `"id":"92-2"`, 1) + "]"
			case "field truncated":
				fields := make([]json.RawMessage, 101)
				for i := range fields {
					fields[i] = json.RawMessage(f.schema)
				}
				raw, err := json.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}
				f.fieldList = string(raw)
			case "missing crosswalk":
				f.issue = strings.Replace(f.issue, `,"projectCustomField":{"id":"92-1","field":{"id":"42-1"}}`, "", 1)
			}
			if _, err := f.service.SnapshotOperatorWrite(t.Context(), input); err == nil || f.posts.Load() != 0 {
				t.Fatalf("unsupported target accepted: error=%v posts=%d", err, f.posts.Load())
			}
		})
	}
}

func TestOperatorCapabilitiesReadOnlyLocalConfiguration(t *testing.T) {
	for _, mode := range []string{"ready", "no policy", "stale policy", "no generation", "unsupported backend"} {
		t.Run(mode, func(t *testing.T) {
			f := newOperatorFixture(t)
			selected, err := f.service.Profiles.Get(t.Context(), "work")
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "no policy":
				if err := f.service.Policies.Clear(t.Context(), "work"); err != nil {
					t.Fatal(err)
				}
			case "stale policy":
				selected.ExpectedLogin = "other"
				if err := f.service.Profiles.Put(t.Context(), selected); err != nil {
					t.Fatal(err)
				}
			case "no generation":
				selected = profile.Profile{Name: selected.Name, ServiceURL: selected.ServiceURL, RESTBaseURL: selected.RESTBaseURL, MCPURL: selected.MCPURL, OAuth: selected.OAuth, ExpectedAccountID: selected.ExpectedAccountID, ExpectedLogin: selected.ExpectedLogin, Capabilities: selected.Capabilities, Executor: selected.Executor, Assurance: selected.Assurance}
				if err := f.service.Profiles.Put(t.Context(), selected); err != nil {
					t.Fatal(err)
				}
			case "unsupported backend":
				f.service.OperatorWriteSupport = func() bool { return false }
			}
			creds, network := &trapCredentials{}, &trapTransport{}
			f.service.Credentials, f.service.HTTP = creds, network
			got, err := f.service.Capabilities(t.Context(), "work")
			if err != nil || got.LocallyReady != (mode == "ready") || got.ReadinessScope != "local_configuration_only" || got.NativeUserPresenceSupported || creds.calls != 0 || network.calls != 0 {
				t.Fatalf("capabilities=%#v error=%v credentials=%d network=%d", got, err, creds.calls, network.calls)
			}
			if mode == "ready" && (!got.CredentialGenerationConfigured || !got.ProjectPolicyConfigured || len(got.Kinds) != 2) {
				t.Fatalf("ready configuration incomplete: %#v", got)
			}
		})
	}
}

func TestOperatorReconcileMissingDeletedCannotBecomePositiveProof(t *testing.T) {
	f := newOperatorFixture(t)
	p := f.prepare(t, "comment.add")
	if _, err := f.service.OperatorWrites.Claim(t.Context(), p.PlanID, p.IntentSHA256, f.service.currentTime()); err != nil {
		t.Fatal(err)
	}
	comment := operatorComment(p.Plan.Request.CommentText, "4-1", "1-2")
	delete(comment, "deleted")
	f.comments = []map[string]any{comment}
	raw, err := json.Marshal(comment)
	if err != nil {
		t.Fatal(err)
	}
	f.exactCommentBody = string(raw)
	result, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: p.PlanID, Limit: 2, Offset: 7})
	if err == nil || result.State == "reconciled" || f.pages.Load() != 1 || f.exactComments.Load() != 1 || f.posts.Load() != 0 {
		t.Fatalf("missing deleted became proof: result=%#v error=%v pages=%d exact=%d posts=%d", result, err, f.pages.Load(), f.exactComments.Load(), f.posts.Load())
	}
	status, err := f.service.OperatorWriteStatus(t.Context(), p.PlanID)
	if err != nil || !status.NonReplayable {
		t.Fatalf("failed reconciliation restored claim: %#v %v", status, err)
	}
}

func TestOperatorClaimStorageFailureNeverDispatchesOrBecomesUnknown(t *testing.T) {
	f := newOperatorFixture(t)
	p := f.prepare(t, "issue.update")
	root := f.service.OperatorWrites.Root()
	f.beforeSchema = func() {
		if err := os.Chmod(root, 0o500); err != nil {
			t.Error(err)
		}
	}
	_, err := f.service.ApplyOperatorWrite(t.Context(), OperatorApplyInput{Profile: "work", PlanID: p.PlanID, ConfirmIntent: p.IntentSHA256, Yes: true})
	if err == nil || operatorReason(t, err) == "WRITE_OUTCOME_UNKNOWN" || f.posts.Load() != 0 {
		t.Fatalf("failed local claim dispatched or became unknown: %v posts=%d", err, f.posts.Load())
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	record, err := f.service.OperatorWrites.Get(t.Context(), p.PlanID)
	if err != nil || record.NonReplayable() {
		t.Fatalf("failed claim record=%#v error=%v", record, err)
	}
}

func TestOperatorVerifiedSuccessLedgerFailureRetainsPermanentClaim(t *testing.T) {
	f := newOperatorFixture(t)
	p := f.prepare(t, "comment.add")
	resultPath := filepath.Join(f.service.OperatorWrites.Root(), p.PlanID+".result")
	f.beforePost = func() {
		if err := os.Mkdir(resultPath, 0o700); err != nil {
			t.Error(err)
		}
	}
	input := OperatorApplyInput{Profile: "work", PlanID: p.PlanID, ConfirmIntent: p.IntentSHA256, Yes: true}
	_, err := f.service.ApplyOperatorWrite(t.Context(), input)
	if operatorReason(t, err) != "WRITE_APPLIED_LOCAL_FAILURE" || f.posts.Load() != 1 {
		t.Fatalf("verified write failure misclassified: %v posts=%d", err, f.posts.Load())
	}
	if err := os.Remove(resultPath); err != nil {
		t.Fatal(err)
	}
	status, err := f.service.OperatorWriteStatus(t.Context(), p.PlanID)
	if err != nil || !status.NonReplayable || status.State != "in_flight" {
		t.Fatalf("claim lost after ledger failure: %#v %v", status, err)
	}
	if _, err := f.service.ApplyOperatorWrite(t.Context(), input); operatorReason(t, err) != "OPERATOR_PLAN_CONSUMED" || f.posts.Load() != 1 {
		t.Fatalf("ledger failure replayed: %v posts=%d", err, f.posts.Load())
	}
}

func TestOperatorCapabilitiesWithoutProfileReportsActualBuildOffline(t *testing.T) {
	creds, network := &trapCredentials{}, &trapTransport{}
	s := &Service{Credentials: creds, HTTP: network}
	got, err := s.Capabilities(t.Context(), "")
	if err != nil || got.OperatorWriteSupported != OperatorWriteSupported() || got.NativeUserPresenceSupported || got.LocallyReady || len(got.Kinds) != 0 || got.ReadinessScope != "local_configuration_only" || creds.calls != 0 || network.calls != 0 {
		t.Fatalf("capabilities=%#v error=%v credentials=%d network=%d", got, err, creds.calls, network.calls)
	}
}

func TestOperatorSnapshotSupportsExactScalarStateAndEnumValues(t *testing.T) {
	for _, kind := range []string{"State", "Enum"} {
		t.Run(kind, func(t *testing.T) {
			f := newOperatorFixture(t)
			f.issue = strings.Replace(f.issue, `"value":null`, `"value":{"id":"101-1","name":"Open","$type":"StateBundleElement"}`, 1)
			wantType := "StateIssueCustomField"
			if kind == "Enum" {
				f.schema = strings.NewReplacer("StateProjectCustomField", "EnumProjectCustomField", "StateBundle", "EnumBundle", `"id":"state[1]"`, `"id":"enum[1]"`, `"valueType":"state"`, `"valueType":"enum"`).Replace(f.schema)
				f.issue = strings.NewReplacer("StateIssueCustomField", "SingleEnumIssueCustomField", "StateBundleElement", "EnumBundleElement").Replace(f.issue)
				wantType = "SingleEnumIssueCustomField"
			}
			result, err := f.service.SnapshotOperatorWrite(t.Context(), OperatorSnapshotInput{Profile: "work", Kind: "issue.update", IssueID: "APP-12", Fields: []OperatorFieldSelection{{FieldID: "92-1", ValueID: "101-2"}}})
			if err != nil || result.Snapshot == nil {
				t.Fatalf("snapshot=%#v error=%v", result, err)
			}
			field := result.Snapshot.Field
			if field.Type != wantType || field.CurrentValue == nil || field.CurrentValue.ID != "101-1" || field.CurrentValue.Type != kind+"BundleElement" || field.TargetValue.Type != kind+"BundleElement" || !field.IsPublic || field.FieldTypeType != "FieldType" || f.posts.Load() != 0 {
				t.Fatalf("frozen field=%#v posts=%d", field, f.posts.Load())
			}
		})
	}
}

func TestOperatorReconcilePreservesTerminalResultWithoutCredentialsOrNetwork(t *testing.T) {
	for _, test := range []struct {
		state          operatorwrite.State
		code, remoteID string
	}{
		{operatorwrite.StateApplied, "WRITE_APPLIED", "4-1"},
		{operatorwrite.StateRejected, "PERMISSION_DENIED", ""},
		{operatorwrite.StateReconciled, "COMMENT_OBSERVED", "4-1"},
	} {
		t.Run(string(test.state), func(t *testing.T) {
			f := newOperatorFixture(t)
			plan := f.prepare(t, "comment.add")
			attempt, err := f.service.OperatorWrites.Claim(t.Context(), plan.PlanID, plan.IntentSHA256, f.service.currentTime())
			if err != nil {
				t.Fatal(err)
			}
			outcome := operatorwrite.Result{State: test.state, Code: test.code, RemoteID: test.remoteID, EvidenceSHA256: strings.Repeat("b", 64)}
			if _, err := f.service.OperatorWrites.Finalize(t.Context(), plan.PlanID, attempt, outcome, f.service.currentTime()); err != nil {
				t.Fatal(err)
			}
			resultPath := filepath.Join(f.service.OperatorWrites.Root(), plan.PlanID+".result")
			before, err := os.ReadFile(resultPath)
			if err != nil {
				t.Fatal(err)
			}
			// Terminal evidence remains available after authorization metadata changes.
			selected, err := f.service.Profiles.Get(t.Context(), "work")
			if err != nil {
				t.Fatal(err)
			}
			selected.CredentialGeneration, err = profile.NewCredentialGeneration()
			if err != nil {
				t.Fatal(err)
			}
			if err := f.service.Profiles.Put(t.Context(), selected); err != nil {
				t.Fatal(err)
			}
			if err := f.service.Policies.Clear(t.Context(), "work"); err != nil {
				t.Fatal(err)
			}
			credentials, network := &trapCredentials{}, &trapTransport{}
			f.service.Credentials, f.service.HTTP = credentials, network
			result, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: plan.PlanID, Limit: 2, Offset: 7})
			if err != nil || result.State != string(test.state) || result.RemoteID != test.remoteID || !result.NonReplayable || result.IntentSHA256 != plan.IntentSHA256 || credentials.calls != 0 || network.calls != 0 || f.posts.Load() != 0 {
				t.Fatalf("terminal result changed or contacted remote: result=%#v error=%v credentials=%d network=%d posts=%d", result, err, credentials.calls, network.calls, f.posts.Load())
			}
			after, err := os.ReadFile(resultPath)
			if err != nil || string(after) != string(before) {
				t.Fatalf("terminal evidence was rewritten: error=%v before=%s after=%s", err, before, after)
			}
			record, err := f.service.OperatorWrites.Get(t.Context(), plan.PlanID)
			if err != nil || record.Result == nil || *record.Result != outcome {
				t.Fatalf("terminal outcome downgraded: record=%#v error=%v", record, err)
			}
		})
	}
}
