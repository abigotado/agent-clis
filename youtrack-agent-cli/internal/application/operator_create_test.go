package application

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/auth"
	"github.com/abigotado/youtrack-agent-cli/internal/endpoint"
	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/operatorwrite"
	"github.com/abigotado/youtrack-agent-cli/internal/profile"
	"github.com/abigotado/youtrack-agent-cli/internal/writepolicy"
)

const (
	createProjectJSON = `{"id":"0-3","shortName":"APP","name":"Application","archived":false}`
	createRequestJSON = `{"kind":"issue.create","summary":"New ticket","description":"Line one"}`
)

var createStageFields = []OperatorFieldSelection{{FieldName: "Stage", ValueName: "Done"}}

type requestRecord struct {
	method, path string
	query        url.Values
	body         []byte
}

// createdIssue is the wire shape of an issue the fake server returns.
type createdIssue struct {
	ID, Readable, Summary, Description                        string
	ReporterID, ReporterLogin, ProjectID, ProjectKey, ValueID string
	FieldType                                                 string
	Created                                                   int64
}

// matchingIssue is exactly the issue a successful create of planID produces.
func matchingIssue(planID string) createdIssue {
	return createdIssue{ID: "2-99", Readable: "APP-99", Summary: "New ticket", Description: "Line one\n\n" + operatorwrite.Marker(planID),
		ReporterID: "1-2", ReporterLogin: "alice", ProjectID: "0-3", ProjectKey: "APP", ValueID: "101-2", FieldType: "StateIssueCustomField",
		Created: time.Now().UnixMilli()}
}

func (c createdIssue) json(t testing.TB) string {
	t.Helper()
	issue := map[string]any{"id": c.ID, "idReadable": c.Readable, "summary": c.Summary, "description": c.Description,
		"project":  map[string]any{"id": c.ProjectID, "shortName": c.ProjectKey, "name": "Application", "archived": false},
		"reporter": map[string]any{"id": c.ReporterID, "login": c.ReporterLogin},
		"created":  c.Created, "updated": c.Created, "commentsCount": 0}
	if c.ValueID != "" {
		issue["customFields"] = []any{map[string]any{"id": "issue-field-7", "name": "Stage", "$type": c.FieldType,
			"value":              map[string]any{"id": c.ValueID, "name": "Done"},
			"projectCustomField": map[string]any{"id": "92-1", "field": map[string]any{"id": "42-1"}}}}
	}
	raw, err := json.Marshal(issue)
	if err != nil {
		t.Errorf("encode issue: %v", err)
	}
	return string(raw)
}

func issueList(t testing.TB, issues ...createdIssue) string {
	t.Helper()
	parts := make([]string, len(issues))
	for index, issue := range issues {
		parts[index] = issue.json(t)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

type createFixture struct {
	service *Service
	t       *testing.T

	mu           sync.Mutex
	project      string
	schema       string
	issues       map[string]string
	search       string
	postStatus   int
	postBody     string
	postResponse func(body []byte) string
	requests     []requestRecord
}

func newCreateFixture(t *testing.T, capabilities ...profile.Capability) *createFixture {
	t.Helper()
	if runtime.GOOS == "darwin" && !OperatorWriteSupported() {
		t.Skip("Darwin without CGO cannot audit operator-store ACLs; Linux fake-boundary tests remain enabled")
	}
	if len(capabilities) == 0 {
		capabilities = []profile.Capability{profile.CapabilityRead, profile.CapabilityIssueCreate}
	}
	f := &createFixture{t: t, project: createProjectJSON, schema: operatorSchemaJSON, issues: map[string]string{}, search: `[]`}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	dir := t.TempDir()
	mcp, err := endpoint.CanonicalMCPURL(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	p := profile.Profile{Name: "work", ServiceURL: server.URL, RESTBaseURL: server.URL + "/api", MCPURL: mcp,
		OAuth:             profile.OAuthConfig{IssuerURL: "https://hub.example.test", AuthorizationURL: "https://hub.example.test" + endpoint.OAuthAuthorizationPath, TokenURL: "https://hub.example.test" + endpoint.OAuthTokenPath, ClientID: "client", Scopes: []string{"YouTrack"}, RedirectURI: "http://127.0.0.1:18987/oauth/callback"},
		ExpectedAccountID: "1-2", ExpectedLogin: "alice", Capabilities: capabilities, Executor: profile.ExecutorRESTBestEffort, Assurance: profile.AssuranceBestEffort}
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
	credential, err := auth.BindCredential(auth.Credential{Kind: auth.CredentialPermanentToken, PermanentToken: "perm:OPERATOR_CREATE_SENTINEL"}, p)
	if err != nil {
		t.Fatal(err)
	}
	f.service = &Service{Profiles: profiles, Policies: policies, Credentials: &fixedCredentials{value: credential}, HTTP: server.Client().Transport, OperatorWrites: operatorwrite.New(dir), OperatorWriteSupport: func() bool { return true }}
	return f
}

// echo answers a create POST with the issue the request asked for.
func (f *createFixture) echo(body []byte) string {
	var request struct {
		Project struct {
			ID string `json:"id"`
		} `json:"project"`
		Summary      string `json:"summary"`
		Description  string `json:"description"`
		CustomFields []struct {
			Type  string `json:"$type"`
			Value struct {
				ID string `json:"id"`
			} `json:"value"`
		} `json:"customFields"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		f.t.Errorf("create body is not JSON: %v", err)
	}
	issue := createdIssue{ID: "2-99", Readable: "APP-99", Summary: request.Summary, Description: request.Description,
		ReporterID: "1-2", ReporterLogin: "alice", ProjectID: request.Project.ID, ProjectKey: "APP"}
	if len(request.CustomFields) > 0 {
		issue.ValueID, issue.FieldType = request.CustomFields[0].Value.ID, request.CustomFields[0].Type
	}
	return issue.json(f.t)
}

func (f *createFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		f.t.Errorf("read request body: %v", err)
	}
	f.requests = append(f.requests, requestRecord{method: r.Method, path: r.URL.Path, query: r.URL.Query(), body: body})
	w.Header().Set("Content-Type", "application/json")
	notFound := func() {
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL)
		w.WriteHeader(http.StatusNotFound)
	}
	const projects = "/api/admin/projects/"
	if r.Method == http.MethodPost {
		switch {
		case r.URL.Path != "/api/issues":
			notFound()
		case f.postStatus != 0:
			w.WriteHeader(f.postStatus)
			_, _ = io.WriteString(w, f.postBody)
		case f.postResponse != nil:
			_, _ = io.WriteString(w, f.postResponse(body))
		default:
			_, _ = io.WriteString(w, f.echo(body))
		}
		return
	}
	switch {
	case r.URL.Path == "/api/users/me":
		_, _ = io.WriteString(w, `{"id":"1-2","login":"alice"}`)
	case r.URL.Path == projects+"0-3/customFields/92-1":
		_, _ = io.WriteString(w, f.schema)
	case r.URL.Path == projects+"0-3/customFields":
		_, _ = io.WriteString(w, "["+f.schema+"]")
	case strings.HasPrefix(r.URL.Path, projects) && !strings.Contains(strings.TrimPrefix(r.URL.Path, projects), "/"):
		_, _ = io.WriteString(w, f.project)
	case r.URL.Path == "/api/issues":
		_, _ = io.WriteString(w, f.search)
	case strings.HasPrefix(r.URL.Path, "/api/issues/"):
		issue, ok := f.issues[strings.TrimPrefix(r.URL.Path, "/api/issues/")]
		if !ok {
			notFound()
			return
		}
		_, _ = io.WriteString(w, issue)
	default:
		notFound()
	}
}

func (f *createFixture) set(change func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change()
}

func (f *createFixture) count(method, path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	total := 0
	for _, request := range f.requests {
		if request.method == method && request.path == path {
			total++
		}
	}
	return total
}

func (f *createFixture) last(method, path string) (requestRecord, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for index := len(f.requests) - 1; index >= 0; index-- {
		if f.requests[index].method == method && f.requests[index].path == path {
			return f.requests[index], true
		}
	}
	return requestRecord{}, false
}

func (f *createFixture) posts() int    { return f.count(http.MethodPost, "/api/issues") }
func (f *createFixture) searches() int { return f.count(http.MethodGet, "/api/issues") }

func (f *createFixture) trap() (*trapCredentials, *trapTransport) {
	creds, network := &trapCredentials{}, &trapTransport{}
	f.service.Credentials, f.service.HTTP = creds, network
	return creds, network
}

func (f *createFixture) snapshot(fields []OperatorFieldSelection) (OperatorWriteInfo, error) {
	return f.service.SnapshotOperatorWrite(f.t.Context(), OperatorSnapshotInput{Profile: "work", Kind: "issue.create", ProjectID: "APP", Fields: fields})
}

func (f *createFixture) prepareFrom(snapshot OperatorWriteInfo, request string) (OperatorWriteInfo, error) {
	raw, err := json.Marshal(snapshot.Snapshot)
	if err != nil {
		f.t.Fatal(err)
	}
	return f.service.PrepareOperatorWrite(f.t.Context(), OperatorPrepareInput{Profile: "work", SnapshotJSON: raw, RequestJSON: []byte(request)})
}

func (f *createFixture) prepare(fields []OperatorFieldSelection, request string) OperatorWriteInfo {
	f.t.Helper()
	snapshot, err := f.snapshot(fields)
	if err != nil {
		f.t.Fatal(err)
	}
	prepared, err := f.prepareFrom(snapshot, request)
	if err != nil {
		f.t.Fatal(err)
	}
	return prepared
}

func (f *createFixture) apply(p OperatorWriteInfo) (OperatorWriteInfo, error) {
	return f.service.ApplyOperatorWrite(f.t.Context(), OperatorApplyInput{Profile: "work", PlanID: p.PlanID, ConfirmIntent: p.IntentSHA256, Yes: true})
}

func (f *createFixture) record(planID string) operatorwrite.Record {
	f.t.Helper()
	record, err := f.service.OperatorWrites.Get(f.t.Context(), planID)
	if err != nil {
		f.t.Fatal(err)
	}
	return record
}

func (f *createFixture) requireNotConsumed(planID string) {
	f.t.Helper()
	if record := f.record(planID); record.NonReplayable() {
		f.t.Fatalf("plan was consumed: %#v", record)
	}
}

func requireFailure(t *testing.T, err error, reason string, code errx.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got success", reason)
	}
	translated := TranslateError(err, "work")
	if operatorReason(t, translated) != reason || errx.ExitCode(translated) != code {
		t.Fatalf("error=%v reason=%q code=%d, want reason=%q code=%d", err, operatorReason(t, translated), errx.ExitCode(translated), reason, code)
	}
}

func TestOperatorCreateApplyDispatchesOneFrozenPostAndIsNonReplayable(t *testing.T) {
	stageEntry := []any{map[string]any{"name": "Stage", "$type": "StateIssueCustomField", "value": map[string]any{"id": "101-2"}}}
	for _, test := range []struct {
		name         string
		fields       []OperatorFieldSelection
		schema       func(string) string
		request      string
		wantBody     string
		wantCustom   []any
		wantFieldTyp string
	}{
		{"state field selected by name", createStageFields, nil, createRequestJSON, "Line one", stageEntry, "StateIssueCustomField"},
		{"state field selected by immutable ids", []OperatorFieldSelection{{FieldID: "92-1", ValueID: "101-2"}}, nil, createRequestJSON, "Line one", stageEntry, "StateIssueCustomField"},
		{"empty description is exactly the marker", createStageFields, nil, `{"kind":"issue.create","summary":"New ticket"}`, "", stageEntry, "StateIssueCustomField"},
		{"multi-line description is preserved", createStageFields, nil, `{"kind":"issue.create","summary":"New ticket","description":"a\n\nb\nc"}`, "a\n\nb\nc", stageEntry, "StateIssueCustomField"},
		{"no fields sends no customFields key", nil, nil, createRequestJSON, "Line one", nil, ""},
		{"enum field uses single-enum type", createStageFields, func(schema string) string {
			return strings.NewReplacer("StateProjectCustomField", "EnumProjectCustomField", "StateBundle", "EnumBundle", `"id":"state[1]"`, `"id":"enum[1]"`, `"valueType":"state"`, `"valueType":"enum"`).Replace(schema)
		}, createRequestJSON, "Line one", []any{map[string]any{"name": "Stage", "$type": "SingleEnumIssueCustomField", "value": map[string]any{"id": "101-2"}}}, "SingleEnumIssueCustomField"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCreateFixture(t)
			if test.schema != nil {
				f.set(func() { f.schema = test.schema(f.schema) })
			}
			snapshot, err := f.snapshot(test.fields)
			if err != nil {
				t.Fatal(err)
			}
			frozen := snapshot.Snapshot
			if frozen.Kind != operatorwrite.KindIssueCreate || frozen.Project == nil || *frozen.Project != (operatorwrite.Project{ID: "0-3", Key: "APP"}) || frozen.Issue != (operatorwrite.Issue{}) || frozen.Field != nil || len(frozen.Fields) != len(test.fields) || snapshot.ProjectID != "0-3" || snapshot.ProjectKey != "APP" {
				t.Fatalf("create snapshot=%#v", frozen)
			}
			for _, field := range frozen.Fields {
				if field.IssueFieldID != "" || field.CurrentValue != nil || field.ProjectFieldID != "92-1" || field.GlobalFieldID != "42-1" || field.Type != test.wantFieldTyp || field.TargetValue.ID != "101-2" {
					t.Fatalf("frozen create field=%#v", field)
				}
			}
			p, err := f.prepareFrom(snapshot, test.request)
			if err != nil {
				t.Fatal(err)
			}
			wantDescription := operatorwrite.Marker(p.PlanID)
			if test.wantBody != "" {
				wantDescription = test.wantBody + "\n\n" + operatorwrite.Marker(p.PlanID)
			}
			if p.Plan.Request.Description != wantDescription || f.posts() != 0 {
				t.Fatalf("frozen description=%q posts=%d", p.Plan.Request.Description, f.posts())
			}
			result, err := f.apply(p)
			if err != nil || f.posts() != 1 {
				t.Fatalf("apply error=%v posts=%d", err, f.posts())
			}
			if result.State != "applied" || !result.NonReplayable || result.RemoteID != "2-99" || result.RemoteReadableID != "APP-99" || result.Kind != "issue.create" {
				t.Fatalf("result=%#v", result)
			}
			post, ok := f.last(http.MethodPost, "/api/issues")
			if !ok {
				t.Fatal("no POST recorded")
			}
			var payload map[string]json.RawMessage
			if err := json.Unmarshal(post.body, &payload); err != nil {
				t.Fatal(err)
			}
			wantKeys := []string{"description", "project", "summary"}
			if test.wantCustom != nil {
				wantKeys = []string{"customFields", "description", "project", "summary"}
			}
			keys := make([]string, 0, len(payload))
			for key := range payload {
				keys = append(keys, key)
			}
			slices.Sort(keys)
			if !slices.Equal(keys, wantKeys) {
				t.Fatalf("payload keys=%v want %v body=%s", keys, wantKeys, post.body)
			}
			var summary, description string
			if err := json.Unmarshal(payload["summary"], &summary); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(payload["description"], &description); err != nil {
				t.Fatal(err)
			}
			if string(payload["project"]) != `{"id":"0-3"}` || summary != "New ticket" || description != wantDescription {
				t.Fatalf("payload project=%s summary=%q description=%q", payload["project"], summary, description)
			}
			if test.wantCustom != nil {
				// DeepEqual on the decoded entry proves there is no "id" key.
				var custom []any
				if err := json.Unmarshal(payload["customFields"], &custom); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(custom, test.wantCustom) {
					t.Fatalf("customFields=%s want %v", payload["customFields"], test.wantCustom)
				}
			}
			status, err := f.service.OperatorWriteStatus(t.Context(), p.PlanID)
			if err != nil || status.State != "applied" || status.RemoteID != "2-99" || status.RemoteReadableID != "APP-99" || !status.NonReplayable {
				t.Fatalf("status=%#v error=%v", status, err)
			}
			if record := f.record(p.PlanID); record.Result == nil || record.Result.Code != "WRITE_APPLIED" {
				t.Fatalf("record=%#v", record)
			}
			if _, err := f.apply(p); operatorReason(t, err) != "OPERATOR_PLAN_CONSUMED" || errx.ExitCode(err) != errx.CodeConflict || f.posts() != 1 {
				t.Fatalf("replay error=%v posts=%d", err, f.posts())
			}
		})
	}
}

func TestOperatorCreateSnapshotEnforcesExactProjectPolicyBeforeSchemaReads(t *testing.T) {
	for _, test := range []struct{ name, selector, project string }{
		{"project outside the allowlist", "OTHER", `{"id":"0-9","shortName":"OTHER","name":"Other","archived":false}`},
		{"allowlisted id with a different key", "0-3", `{"id":"0-3","shortName":"OTHER","name":"Other","archived":false}`},
		{"allowlisted key with a different id", "APP", `{"id":"0-9","shortName":"APP","name":"Application","archived":false}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCreateFixture(t)
			f.set(func() { f.project = test.project })
			_, err := f.service.SnapshotOperatorWrite(t.Context(), OperatorSnapshotInput{Profile: "work", Kind: "issue.create", ProjectID: test.selector, Fields: createStageFields})
			requireFailure(t, err, "PROJECT_POLICY_DENIED", errx.CodePermission)
			if f.posts() != 0 || f.count(http.MethodGet, "/api/admin/projects/0-3/customFields") != 0 || f.count(http.MethodGet, "/api/admin/projects/0-3/customFields/92-1") != 0 {
				t.Fatalf("denied project reached schema reads or POST: %+v", f.requests)
			}
		})
	}
}

func TestOperatorCreateRefusesMissingCapabilityBeforeAnyNetworkOrCredential(t *testing.T) {
	t.Run("snapshot", func(t *testing.T) {
		f := newCreateFixture(t, profile.CapabilityRead, profile.CapabilityIssueUpdate, profile.CapabilityCommentAdd)
		creds, network := f.trap()
		_, err := f.snapshot(createStageFields)
		requireFailure(t, err, "OPERATOR_CAPABILITY_REQUIRED", errx.CodePermission)
		if creds.calls != 0 || network.calls != 0 || f.posts() != 0 {
			t.Fatalf("credentials=%d network=%d posts=%d", creds.calls, network.calls, f.posts())
		}
	})
	t.Run("apply after the capability is revoked", func(t *testing.T) {
		f := newCreateFixture(t, profile.CapabilityRead, profile.CapabilityIssueCreate, profile.CapabilityIssueUpdate)
		p := f.prepare(createStageFields, createRequestJSON)
		selected, err := f.service.Profiles.Get(t.Context(), "work")
		if err != nil {
			t.Fatal(err)
		}
		selected.Capabilities = []profile.Capability{profile.CapabilityRead, profile.CapabilityIssueUpdate}
		if err := f.service.Profiles.Put(t.Context(), selected); err != nil {
			t.Fatal(err)
		}
		creds, network := f.trap()
		_, err = f.apply(p)
		requireFailure(t, err, "OPERATOR_CAPABILITY_REQUIRED", errx.CodePermission)
		if creds.calls != 0 || network.calls != 0 || f.posts() != 0 {
			t.Fatalf("credentials=%d network=%d posts=%d", creds.calls, network.calls, f.posts())
		}
		f.requireNotConsumed(p.PlanID)
	})
}

func TestOperatorCreateSnapshotRefusesArchivedProject(t *testing.T) {
	f := newCreateFixture(t)
	f.set(func() { f.project = strings.Replace(createProjectJSON, `"archived":false`, `"archived":true`, 1) })
	_, err := f.snapshot(createStageFields)
	requireFailure(t, err, "OPERATOR_PROJECT_ARCHIVED", errx.CodePermission)
	if f.posts() != 0 || f.count(http.MethodGet, "/api/admin/projects/0-3/customFields/92-1") != 0 {
		t.Fatalf("archived project reached later stages: %+v", f.requests)
	}
}

func TestOperatorCreateSnapshotSelectorsAreValidatedBeforeNetwork(t *testing.T) {
	nineFields := make([]OperatorFieldSelection, operatorwrite.MaxCreateFields+1)
	for index := range nineFields {
		nineFields[index] = OperatorFieldSelection{FieldID: "92-" + strconv.Itoa(index+1), ValueID: "101-2"}
	}
	for _, test := range []struct {
		name  string
		input OperatorSnapshotInput
	}{
		{"create with an issue id", OperatorSnapshotInput{Kind: "issue.create", ProjectID: "APP", IssueID: "APP-1"}},
		{"create without a project", OperatorSnapshotInput{Kind: "issue.create", Fields: createStageFields}},
		{"field without value", OperatorSnapshotInput{Kind: "issue.create", ProjectID: "APP", Fields: []OperatorFieldSelection{{FieldName: "Stage"}}}},
		{"value without field", OperatorSnapshotInput{Kind: "issue.create", ProjectID: "APP", Fields: []OperatorFieldSelection{{ValueName: "Done"}}}},
		{"field id without value id", OperatorSnapshotInput{Kind: "issue.create", ProjectID: "APP", Fields: []OperatorFieldSelection{{FieldID: "92-1"}}}},
		{"name field with id value", OperatorSnapshotInput{Kind: "issue.create", ProjectID: "APP", Fields: []OperatorFieldSelection{{FieldName: "Stage", ValueID: "101-2"}}}},
		{"names mixed with ids in one selection", OperatorSnapshotInput{Kind: "issue.create", ProjectID: "APP", Fields: []OperatorFieldSelection{{FieldName: "Stage", ValueName: "Done", FieldID: "92-1", ValueID: "101-2"}}}},
		{"empty selection", OperatorSnapshotInput{Kind: "issue.create", ProjectID: "APP", Fields: []OperatorFieldSelection{{}}}},
		{"one valid and one incomplete selection", OperatorSnapshotInput{Kind: "issue.create", ProjectID: "APP", Fields: []OperatorFieldSelection{{FieldID: "92-1", ValueID: "101-2"}, {FieldID: "92-2"}}}},
		{"more than eight selections", OperatorSnapshotInput{Kind: "issue.create", ProjectID: "APP", Fields: nineFields}},
		{"same field name selected twice", OperatorSnapshotInput{Kind: "issue.create", ProjectID: "APP", Fields: []OperatorFieldSelection{{FieldName: "Stage", ValueName: "Done"}, {FieldName: "Stage", ValueName: "Open"}}}},
		{"same field id selected twice", OperatorSnapshotInput{Kind: "issue.create", ProjectID: "APP", Fields: []OperatorFieldSelection{{FieldID: "92-1", ValueID: "101-2"}, {FieldID: "92-1", ValueID: "101-1"}}}},
		{"update with two fields", OperatorSnapshotInput{Kind: "issue.update", IssueID: "APP-1", Fields: []OperatorFieldSelection{{FieldName: "Stage", ValueName: "Done"}, {FieldName: "Priority", ValueName: "Major"}}}},
		{"update with a project", OperatorSnapshotInput{Kind: "issue.update", IssueID: "APP-1", ProjectID: "APP", Fields: createStageFields}},
		{"update without an issue", OperatorSnapshotInput{Kind: "issue.update", ProjectID: "APP", Fields: createStageFields}},
		{"comment with a project", OperatorSnapshotInput{Kind: "comment.add", IssueID: "APP-1", ProjectID: "APP"}},
		{"unknown kind", OperatorSnapshotInput{Kind: "issue.delete", ProjectID: "APP"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCreateFixture(t, profile.CapabilityRead, profile.CapabilityIssueCreate, profile.CapabilityIssueUpdate, profile.CapabilityCommentAdd)
			creds, network := f.trap()
			input := test.input
			input.Profile = "work"
			_, err := f.service.SnapshotOperatorWrite(t.Context(), input)
			requireFailure(t, err, "USAGE", errx.CodeUsage)
			if creds.calls != 0 || network.calls != 0 {
				t.Fatalf("credentials=%d network=%d", creds.calls, network.calls)
			}
		})
	}
}

func TestOperatorCreateSnapshotRejectsFieldsThatCannotBeFrozen(t *testing.T) {
	duplicateBundle := func(schema string) string {
		return strings.Replace(schema, `"id":"101-1"`, `"id":"101-2"`, 1)
	}
	for _, test := range []struct {
		name   string
		fields []OperatorFieldSelection
		schema func(string) string
		reason string
		code   errx.Code
	}{
		{"same field named twice", []OperatorFieldSelection{createStageFields[0], createStageFields[0]}, nil, "USAGE", errx.CodeUsage},
		{"same field by name and by id", []OperatorFieldSelection{createStageFields[0], {FieldID: "92-1", ValueID: "101-1"}}, nil, "USAGE", errx.CodeUsage},
		{"unknown field name", []OperatorFieldSelection{{FieldName: "Missing", ValueName: "Done"}}, nil, "USAGE", errx.CodeUsage},
		{"unknown value", []OperatorFieldSelection{{FieldName: "Stage", ValueName: "Missing"}}, nil, "USAGE", errx.CodeUsage},
		{"archived target value", createStageFields, func(s string) string {
			return strings.Replace(s, `"name":"Done","$type":"StateBundleElement","archived":false`, `"name":"Done","$type":"StateBundleElement","archived":true`, 1)
		}, "USAGE", errx.CodeUsage},
		{"multi-value field", createStageFields, func(s string) string { return strings.Replace(s, `"isMultiValue":false`, `"isMultiValue":true`, 1) }, "USAGE", errx.CodeUsage},
		{"unsupported project field type", createStageFields, func(s string) string {
			return strings.Replace(s, "StateProjectCustomField", "SimpleProjectCustomField", 1)
		}, "USAGE", errx.CodeUsage},
		{"target value of the wrong bundle type", createStageFields, func(s string) string {
			return strings.Replace(s, `"name":"Done","$type":"StateBundleElement"`, `"name":"Done","$type":"EnumBundleElement"`, 1)
		}, "OPERATOR_FIELD_VALUE_INVALID", errx.CodeConflict},
		{"duplicate bundle value ids", createStageFields, duplicateBundle, "OPERATOR_BUNDLE_INVALID", errx.CodeConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCreateFixture(t)
			if test.schema != nil {
				f.set(func() { f.schema = test.schema(f.schema) })
			}
			_, err := f.snapshot(test.fields)
			requireFailure(t, err, test.reason, test.code)
			if f.posts() != 0 {
				t.Fatalf("snapshot dispatched a POST")
			}
		})
	}
}

func TestOperatorCreatePrepareRejectsNonCanonicalTextWithoutStoringAPlan(t *testing.T) {
	longBody := strings.Repeat("a", operatorwrite.MaxDescriptionBytes)
	for _, test := range []struct {
		name, request string
		valid         bool
	}{
		{"canonical request", createRequestJSON, true},
		{"summary with leading space", `{"kind":"issue.create","summary":" New ticket"}`, false},
		{"summary with trailing space", `{"kind":"issue.create","summary":"New ticket "}`, false},
		{"summary with newline", `{"kind":"issue.create","summary":"New\nticket"}`, false},
		{"summary with tab", `{"kind":"issue.create","summary":"New\tticket"}`, false},
		{"empty summary", `{"kind":"issue.create","summary":""}`, false},
		{"missing summary", `{"kind":"issue.create","description":"body"}`, false},
		{"whitespace summary", `{"kind":"issue.create","summary":"   "}`, false},
		{"summary over the byte cap", `{"kind":"issue.create","summary":"` + strings.Repeat("s", operatorwrite.MaxSummaryBytes+1) + `"}`, false},
		{"description with carriage return", `{"kind":"issue.create","summary":"s","description":"a\r\nb"}`, false},
		{"description with trailing whitespace", `{"kind":"issue.create","summary":"s","description":"body "}`, false},
		{"description with trailing newline", `{"kind":"issue.create","summary":"s","description":"body\n"}`, false},
		{"description with leading whitespace", `{"kind":"issue.create","summary":"s","description":" body"}`, false},
		{"whitespace-only description", `{"kind":"issue.create","summary":"s","description":"  "}`, false},
		{"description pushed over the cap by the marker", `{"kind":"issue.create","summary":"s","description":"` + longBody + `"}`, false},
		{"comment text for a create", `{"kind":"issue.create","summary":"s","comment_text":"c"}`, false},
		{"kind mismatch comment.add", `{"kind":"comment.add","comment_text":"c"}`, false},
		{"kind mismatch issue.update", `{"kind":"issue.update"}`, false},
		{"unknown request field", `{"kind":"issue.create","summary":"s","labels":["x"]}`, false},
		{"duplicate keys", `{"kind":"issue.create","summary":"a","summary":"b"}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCreateFixture(t)
			snapshot, err := f.snapshot(createStageFields)
			if err != nil {
				t.Fatal(err)
			}
			creds, network := f.trap()
			prepared, err := f.prepareFrom(snapshot, test.request)
			if creds.calls != 0 || network.calls != 0 || f.posts() != 0 {
				t.Fatalf("prepare was not offline: credentials=%d network=%d", creds.calls, network.calls)
			}
			if test.valid {
				if err != nil || prepared.State != "prepared" {
					t.Fatalf("prepared=%#v error=%v", prepared, err)
				}
				return
			}
			requireFailure(t, err, "OPERATOR_WRITE_INVALID", errx.CodeUsage)
			if _, statErr := os.Stat(f.service.OperatorWrites.Root()); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("rejected request stored plan data: %v", statErr)
			}
		})
	}
}

func TestOperatorCreateApplyPreflightDriftStopsBeforeDispatchAndKeepsPlan(t *testing.T) {
	for _, test := range []struct {
		name    string
		project func(string) string
		schema  func(string) string
		reason  string
	}{
		{"project archived", func(s string) string { return strings.Replace(s, `"archived":false`, `"archived":true`, 1) }, nil, "OPERATOR_PROJECT_STALE"},
		{"project key renamed", func(s string) string { return strings.Replace(s, `"shortName":"APP"`, `"shortName":"OTHER"`, 1) }, nil, "OPERATOR_PROJECT_STALE"},
		{"field optionality changed", nil, func(s string) string { return strings.Replace(s, `"canBeEmpty":true`, `"canBeEmpty":false`, 1) }, "OPERATOR_FIELD_STALE"},
		{"field privacy changed", nil, func(s string) string { return strings.Replace(s, `"isPublic":true`, `"isPublic":false`, 1) }, "OPERATOR_FIELD_STALE"},
		{"field renamed", nil, func(s string) string { return strings.Replace(s, `"name":"Stage"`, `"name":"Phase"`, 1) }, "OPERATOR_FIELD_STALE"},
		{"target value renamed", nil, func(s string) string { return strings.Replace(s, `"name":"Done"`, `"name":"Finished"`, 1) }, "OPERATOR_FIELD_STALE"},
		{"bundle replaced", nil, func(s string) string { return strings.Replace(s, `"id":"100-1"`, `"id":"100-2"`, 1) }, "OPERATOR_FIELD_STALE"},
		{"global field identity changed", nil, func(s string) string { return strings.Replace(s, `"id":"42-1"`, `"id":"42-2"`, 1) }, "OPERATOR_FIELD_STALE"},
		{"field type changed", nil, func(s string) string { return strings.Replace(s, `"id":"state[1]"`, `"id":"state-other[1]"`, 1) }, "OPERATOR_FIELD_STALE"},
		{"target value archived", nil, func(s string) string {
			return strings.Replace(s, `"name":"Done","$type":"StateBundleElement","archived":false`, `"name":"Done","$type":"StateBundleElement","archived":true`, 1)
		}, "OPERATOR_FIELD_STALE"},
		{"target value removed", nil, func(s string) string {
			return strings.Replace(s, `,{"id":"101-2","name":"Done","$type":"StateBundleElement","archived":false}`, ``, 1)
		}, "OPERATOR_FIELD_STALE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCreateFixture(t)
			p := f.prepare(createStageFields, createRequestJSON)
			f.set(func() {
				if test.project != nil {
					f.project = test.project(f.project)
				}
				if test.schema != nil {
					f.schema = test.schema(f.schema)
				}
			})
			_, err := f.apply(p)
			if err == nil {
				t.Fatal("drift was accepted")
			}
			requireFailure(t, err, test.reason, errx.CodeConflict)
			if f.posts() != 0 {
				t.Fatalf("drift dispatched a POST")
			}
			f.requireNotConsumed(p.PlanID)
		})
	}
}

func TestOperatorCreateApplyOutcomesConsumeThePlanWithoutReplay(t *testing.T) {
	withIssue := func(change func(*createdIssue)) func(string) string {
		return func(planID string) string {
			issue := matchingIssue(planID)
			change(&issue)
			return issue.json(t)
		}
	}
	for _, test := range []struct {
		name         string
		status       int
		body         func(planID string) string
		wantState    operatorwrite.State
		wantReason   string
		wantRemoteID string
		wantReadable string
	}{
		{"400 is rejected", 400, func(string) string { return `{"error":"sentinel"}` }, operatorwrite.StateRejected, "USAGE", "", ""},
		{"403 is rejected", 403, func(string) string { return `<html>not json</html>` }, operatorwrite.StateRejected, "PERMISSION_DENIED", "", ""},
		{"409 is rejected", 409, func(string) string { return `{"error":"stale"}` }, operatorwrite.StateRejected, "PRECONDITION_FAILED", "", ""},
		{"500 is unknown", 500, func(string) string { return `boom` }, operatorwrite.StateUnknown, "WRITE_OUTCOME_UNKNOWN", "", ""},
		{"429 is unknown", 429, func(string) string { return `{"error":"slow down"}` }, operatorwrite.StateUnknown, "WRITE_OUTCOME_UNKNOWN", "", ""},
		{"malformed 200 is unknown", 200, func(string) string { return `{"broken":` }, operatorwrite.StateUnknown, "WRITE_OUTCOME_UNKNOWN", "", ""},
		{"200 without an issue identity is unknown", 200, func(string) string { return `{}` }, operatorwrite.StateUnknown, "WRITE_OUTCOME_UNKNOWN", "", ""},
		{"200 with a different Stage keeps the issue identity", 200, withIssue(func(i *createdIssue) { i.ValueID = "101-1" }), operatorwrite.StateUnknown, "WRITE_OUTCOME_UNKNOWN", "2-99", "APP-99"},
		{"200 with a different summary keeps the issue identity", 200, withIssue(func(i *createdIssue) { i.Summary = "Other" }), operatorwrite.StateUnknown, "WRITE_OUTCOME_UNKNOWN", "2-99", "APP-99"},
		{"200 by another reporter keeps the issue identity", 200, withIssue(func(i *createdIssue) { i.ReporterID, i.ReporterLogin = "1-9", "bob" }), operatorwrite.StateUnknown, "WRITE_OUTCOME_UNKNOWN", "2-99", "APP-99"},
		{"200 in another project keeps the issue identity", 200, withIssue(func(i *createdIssue) { i.ProjectID, i.ProjectKey = "0-9", "OTHER" }), operatorwrite.StateUnknown, "WRITE_OUTCOME_UNKNOWN", "2-99", "APP-99"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCreateFixture(t)
			p := f.prepare(createStageFields, createRequestJSON)
			f.set(func() { f.postStatus, f.postBody = test.status, test.body(p.PlanID) })
			_, err := f.apply(p)
			wantExit := errx.CodeConflict
			switch test.wantReason {
			case "USAGE":
				wantExit = errx.CodeUsage
			case "PERMISSION_DENIED":
				wantExit = errx.CodePermission
			}
			requireFailure(t, err, test.wantReason, wantExit)
			if f.posts() != 1 {
				t.Fatalf("posts=%d", f.posts())
			}
			record := f.record(p.PlanID)
			if !record.NonReplayable() || record.State != test.wantState || record.Result == nil || record.Result.Code != test.wantReason ||
				record.Result.RemoteID != test.wantRemoteID || record.Result.RemoteReadableID != test.wantReadable {
				t.Fatalf("record=%#v result=%#v", record, record.Result)
			}
			status, statusErr := f.service.OperatorWriteStatus(t.Context(), p.PlanID)
			if statusErr != nil || status.RemoteID != test.wantRemoteID || status.RemoteReadableID != test.wantReadable {
				t.Fatalf("status=%#v error=%v", status, statusErr)
			}
			if _, err := f.apply(p); operatorReason(t, err) != "OPERATOR_PLAN_CONSUMED" || f.posts() != 1 {
				t.Fatalf("consumed plan was replayed: %v posts=%d", err, f.posts())
			}
		})
	}
}

// unknownCreate applies a plan against a server that fails the POST, leaving a
// consumed unknown record. With keepIdentity the server answers 200 with the
// right issue but a different Stage, so the record persists its identity.
func unknownCreate(t *testing.T, f *createFixture, keepIdentity bool) OperatorWriteInfo {
	t.Helper()
	p := f.prepare(createStageFields, createRequestJSON)
	f.set(func() {
		if keepIdentity {
			issue := matchingIssue(p.PlanID)
			issue.ValueID = "101-1"
			f.postStatus, f.postBody = 200, issue.json(t)
			return
		}
		f.postStatus, f.postBody = 500, "boom"
	})
	_, err := f.apply(p)
	requireFailure(t, err, "WRITE_OUTCOME_UNKNOWN", errx.CodeConflict)
	record := f.record(p.PlanID)
	hasIdentity := record.Result != nil && record.Result.RemoteID == "2-99" && record.Result.RemoteReadableID == "APP-99"
	if record.State != operatorwrite.StateUnknown || hasIdentity != keepIdentity || f.posts() != 1 {
		t.Fatalf("setup record=%#v posts=%d", record, f.posts())
	}
	return p
}

func TestOperatorCreateReconcileWithPersistedIssueIDReadsOnlyThatIssue(t *testing.T) {
	for _, test := range []struct {
		name         string
		change       func(*createdIssue)
		wantState    operatorwrite.State
		wantCode     string
		wantEvidence string
	}{
		{"observed with the Stage the plan set", func(i *createdIssue) { i.ValueID = "101-2" }, operatorwrite.StateReconciled, "ISSUE_OBSERVED", "matching_issue_observed"},
		{"observed with a different Stage", func(i *createdIssue) { i.ValueID = "101-1" }, operatorwrite.StateReconciled, "ISSUE_OBSERVED", "matching_issue_observed_fields_differ"},
		{"observed with the Stage cleared by a workflow", func(i *createdIssue) { i.ValueID = "" }, operatorwrite.StateReconciled, "ISSUE_OBSERVED", "matching_issue_observed_fields_differ"},
		{"different description", func(i *createdIssue) { i.Description = "tampered" }, operatorwrite.StateOperatorRequired, "OPERATOR_RESOLUTION_REQUIRED", "inconclusive"},
		{"description without the marker", func(i *createdIssue) { i.Description = "Line one" }, operatorwrite.StateOperatorRequired, "OPERATOR_RESOLUTION_REQUIRED", "inconclusive"},
		{"different summary", func(i *createdIssue) { i.Summary = "Other" }, operatorwrite.StateOperatorRequired, "OPERATOR_RESOLUTION_REQUIRED", "inconclusive"},
		{"another reporter", func(i *createdIssue) { i.ReporterID, i.ReporterLogin = "1-9", "bob" }, operatorwrite.StateOperatorRequired, "OPERATOR_RESOLUTION_REQUIRED", "inconclusive"},
		{"another project", func(i *createdIssue) { i.ProjectID, i.ProjectKey = "0-9", "OTHER" }, operatorwrite.StateOperatorRequired, "OPERATOR_RESOLUTION_REQUIRED", "inconclusive"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCreateFixture(t)
			p := unknownCreate(t, f, true)
			observed := matchingIssue(p.PlanID)
			test.change(&observed)
			f.set(func() { f.issues["2-99"] = observed.json(t) })
			result, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: p.PlanID, Limit: 5})
			if err != nil {
				t.Fatal(err)
			}
			if result.State != string(test.wantState) || result.Evidence != test.wantEvidence || !result.NonReplayable || result.RemoteID != "2-99" || result.RemoteReadableID != "APP-99" {
				t.Fatalf("result=%#v", result)
			}
			if record := f.record(p.PlanID); record.Result == nil || record.Result.Code != test.wantCode || record.Result.EvidenceSHA256 != sha256Hex([]byte(test.wantEvidence)) {
				t.Fatalf("record result=%#v", record.Result)
			}
			if f.searches() != 0 || f.count(http.MethodGet, "/api/issues/2-99") != 1 || f.posts() != 1 {
				t.Fatalf("searches=%d exact=%d posts=%d", f.searches(), f.count(http.MethodGet, "/api/issues/2-99"), f.posts())
			}
			if _, err := f.apply(p); operatorReason(t, err) != "OPERATOR_PLAN_CONSUMED" || f.posts() != 1 {
				t.Fatalf("reconciliation restored eligibility: %v posts=%d", err, f.posts())
			}
		})
	}
}

func TestOperatorCreateReconcileSearchesOnePageByMarkerAndVerifiesWithExactRead(t *testing.T) {
	for _, test := range []struct {
		name         string
		limit        int
		results      func(match createdIssue) []createdIssue
		exact        func(*createdIssue)
		wantState    operatorwrite.State
		wantEvidence string
		wantExact    int
	}{
		{"unique match", 5, func(m createdIssue) []createdIssue { return []createdIssue{m} }, nil, operatorwrite.StateReconciled, "matching_issue_observed", 1},
		{"unique match among unrelated issues", 3, func(m createdIssue) []createdIssue {
			other := m
			other.ID, other.Readable, other.Summary = "2-100", "APP-100", "Unrelated"
			return []createdIssue{other, m}
		}, nil, operatorwrite.StateReconciled, "matching_issue_observed", 1},
		{"page exactly at the limit still reconciles", 2, func(m createdIssue) []createdIssue {
			other := m
			other.ID, other.Readable, other.Summary = "2-100", "APP-100", "Unrelated"
			return []createdIssue{m, other}
		}, nil, operatorwrite.StateReconciled, "matching_issue_observed", 1},
		{"unique match with a different Stage", 5, func(m createdIssue) []createdIssue { m.ValueID = "101-1"; return []createdIssue{m} },
			func(i *createdIssue) { i.ValueID = "101-1" }, operatorwrite.StateReconciled, "matching_issue_observed_fields_differ", 1},
		{"no matches", 5, func(createdIssue) []createdIssue { return nil }, nil, operatorwrite.StateOperatorRequired, "inconclusive", 0},
		{"two matches", 5, func(m createdIssue) []createdIssue {
			twin := m
			twin.ID, twin.Readable = "2-100", "APP-100"
			return []createdIssue{m, twin}
		}, nil, operatorwrite.StateOperatorRequired, "inconclusive", 0},
		{"truncated page hides a possible duplicate", 2, func(m createdIssue) []createdIssue {
			first, second := m, m
			first.ID, first.Readable, first.Summary = "2-100", "APP-100", "Unrelated"
			second.ID, second.Readable, second.Summary = "2-101", "APP-101", "Unrelated"
			return []createdIssue{m, first, second}
		}, nil, operatorwrite.StateOperatorRequired, "inconclusive", 0},
		{"match with a different description", 5, func(m createdIssue) []createdIssue { m.Description = "tampered"; return []createdIssue{m} }, nil, operatorwrite.StateOperatorRequired, "inconclusive", 0},
		{"match by another reporter", 5, func(m createdIssue) []createdIssue {
			m.ReporterID, m.ReporterLogin = "1-9", "bob"
			return []createdIssue{m}
		}, nil, operatorwrite.StateOperatorRequired, "inconclusive", 0},
		{"search match contradicted by the exact read", 5, func(m createdIssue) []createdIssue { return []createdIssue{m} },
			func(i *createdIssue) { i.Description = "tampered" }, operatorwrite.StateOperatorRequired, "inconclusive", 1},
		{"older issue carrying a copied marker", 5, func(m createdIssue) []createdIssue {
			m.Created = time.Now().Add(-time.Hour).UnixMilli()
			return []createdIssue{m}
		}, nil, operatorwrite.StateOperatorRequired, "inconclusive", 0},
		{"issue created one minute before the claim", 5, func(m createdIssue) []createdIssue {
			m.Created = time.Now().Add(-time.Minute).UnixMilli()
			return []createdIssue{m}
		}, nil, operatorwrite.StateOperatorRequired, "inconclusive", 0},
		{"exact read reports a creation one minute before the claim", 5, func(m createdIssue) []createdIssue { return []createdIssue{m} },
			func(i *createdIssue) { i.Created = time.Now().Add(-time.Minute).UnixMilli() }, operatorwrite.StateOperatorRequired, "inconclusive", 1},
		{"exact read reports an older creation time", 5, func(m createdIssue) []createdIssue { return []createdIssue{m} },
			func(i *createdIssue) { i.Created = time.Now().Add(-time.Hour).UnixMilli() }, operatorwrite.StateOperatorRequired, "inconclusive", 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCreateFixture(t)
			p := unknownCreate(t, f, false)
			match := matchingIssue(p.PlanID)
			exact := match
			if test.exact != nil {
				test.exact(&exact)
			}
			f.set(func() { f.search, f.issues["2-99"] = issueList(t, test.results(match)...), exact.json(t) })
			result, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: p.PlanID, Limit: test.limit})
			if err != nil {
				t.Fatal(err)
			}
			if result.State != string(test.wantState) || result.Evidence != test.wantEvidence || !result.NonReplayable {
				t.Fatalf("result=%#v", result)
			}
			wantID, wantReadable := "", ""
			if test.wantState == operatorwrite.StateReconciled {
				wantID, wantReadable = "2-99", "APP-99"
			}
			if result.RemoteID != wantID || result.RemoteReadableID != wantReadable {
				t.Fatalf("remote identity=%q/%q want %q/%q", result.RemoteID, result.RemoteReadableID, wantID, wantReadable)
			}
			search, ok := f.last(http.MethodGet, "/api/issues")
			if !ok || f.searches() != 1 || search.query.Get("query") != `project: APP "`+p.PlanID+`"` || search.query.Get("$top") != strconv.Itoa(test.limit+1) {
				t.Fatalf("search count=%d request=%#v", f.searches(), search)
			}
			if got := f.count(http.MethodGet, "/api/issues/2-99"); got != test.wantExact || f.posts() != 1 {
				t.Fatalf("exact reads=%d posts=%d", got, f.posts())
			}
			if _, err := f.apply(p); operatorReason(t, err) != "OPERATOR_PLAN_CONSUMED" || f.posts() != 1 {
				t.Fatalf("reconciliation restored eligibility: %v posts=%d", err, f.posts())
			}
			if test.wantState == operatorwrite.StateReconciled {
				before := len(f.requests)
				repeated, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: p.PlanID, Limit: test.limit})
				if err != nil || repeated.State != "reconciled" || repeated.Evidence != "verified_terminal_record_preserved" || len(f.requests) != before {
					t.Fatalf("terminal repeat=%#v error=%v extra requests=%d", repeated, err, len(f.requests)-before)
				}
			}
		})
	}
}

func TestOperatorCreateReconcileRefusesBadInvocationBeforeNetwork(t *testing.T) {
	for _, test := range []struct {
		name     string
		profile  string
		limit    int
		offset   int
		prepared bool // reconcile the plan before it is ever applied
		reason   string
		code     errx.Code
	}{
		{"nonzero offset", "work", 5, 1, false, "USAGE", errx.CodeUsage},
		{"negative offset", "work", 5, -1, false, "USAGE", errx.CodeUsage},
		{"zero limit", "work", 0, 0, false, "USAGE", errx.CodeUsage},
		{"limit above 100", "work", 101, 0, false, "USAGE", errx.CodeUsage},
		{"unconsumed plan", "work", 5, 0, true, "USAGE", errx.CodeUsage},
		{"other profile", "other", 5, 0, false, "OPERATOR_PROFILE_MISMATCH", errx.CodeConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCreateFixture(t)
			var p OperatorWriteInfo
			if test.prepared {
				p = f.prepare(createStageFields, createRequestJSON)
			} else {
				p = unknownCreate(t, f, false)
			}
			before := len(f.requests)
			creds, network := f.trap()
			_, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: test.profile, PlanID: p.PlanID, Limit: test.limit, Offset: test.offset})
			requireFailure(t, err, test.reason, test.code)
			if creds.calls != 0 || network.calls != 0 || len(f.requests) != before {
				t.Fatalf("credentials=%d network=%d requests=%d", creds.calls, network.calls, len(f.requests)-before)
			}
			record := f.record(p.PlanID)
			if test.prepared && record.NonReplayable() || !test.prepared && record.State != operatorwrite.StateUnknown {
				t.Fatalf("refused reconcile changed the record: %#v", record)
			}
		})
	}
}

func TestOperatorCreateReconcileRefusesProjectKeyChangeWithoutSearching(t *testing.T) {
	f := newCreateFixture(t)
	p := unknownCreate(t, f, false)
	f.set(func() { f.project = strings.Replace(f.project, `"shortName":"APP"`, `"shortName":"OTHER"`, 1) })
	_, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: p.PlanID, Limit: 5})
	requireFailure(t, err, "OPERATOR_PROJECT_CHANGED", errx.CodeConflict)
	if f.searches() != 0 || f.posts() != 1 || !f.record(p.PlanID).NonReplayable() {
		t.Fatalf("searches=%d posts=%d", f.searches(), f.posts())
	}
}

func TestOperatorCapabilitiesListsCreateFirstInCanonicalOrder(t *testing.T) {
	for _, test := range []struct {
		name         string
		capabilities []profile.Capability
		kinds        []string
	}{
		{"all three kinds", []profile.Capability{profile.CapabilityRead, profile.CapabilityIssueCreate, profile.CapabilityIssueUpdate, profile.CapabilityCommentAdd}, []string{"issue.create", "issue.update", "comment.add"}},
		{"create only", []profile.Capability{profile.CapabilityRead, profile.CapabilityIssueCreate}, []string{"issue.create"}},
		{"update and comment only", []profile.Capability{profile.CapabilityRead, profile.CapabilityIssueUpdate, profile.CapabilityCommentAdd}, []string{"issue.update", "comment.add"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCreateFixture(t, test.capabilities...)
			creds, network := f.trap()
			got, err := f.service.Capabilities(t.Context(), "work")
			if err != nil || !reflect.DeepEqual(got.Kinds, test.kinds) || creds.calls != 0 || network.calls != 0 {
				t.Fatalf("capabilities=%#v error=%v credentials=%d network=%d", got, err, creds.calls, network.calls)
			}
			raw, err := json.Marshal(got)
			if err != nil || !strings.Contains(string(raw), fmt.Sprintf(`"kinds":%s`, mustJSON(t, test.kinds))) {
				t.Fatalf("kinds JSON=%s error=%v", raw, err)
			}
		})
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// YouTrack reports creation in whole milliseconds, so an issue stamped with the
// claim's own millisecond may predate a claim made later in that millisecond.
func TestOperatorCreateReconcileRoundsTheClaimCutoffUp(t *testing.T) {
	claim := time.Now().UTC().Truncate(time.Millisecond).Add(900 * time.Microsecond)
	for _, test := range []struct {
		name      string
		created   int64
		wantState operatorwrite.State
	}{
		{"created in the claim millisecond", claim.UnixMilli(), operatorwrite.StateOperatorRequired},
		{"created in the next millisecond", claim.UnixMilli() + 1, operatorwrite.StateReconciled},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCreateFixture(t)
			f.service.Now = func() time.Time { return claim }
			p := unknownCreate(t, f, false)
			match := matchingIssue(p.PlanID)
			match.Created = test.created
			f.set(func() { f.search, f.issues["2-99"] = issueList(t, match), match.json(t) })
			result, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: p.PlanID, Limit: 5})
			if err != nil || result.State != string(test.wantState) {
				t.Fatalf("result=%#v err=%v", result, err)
			}
		})
	}
}
