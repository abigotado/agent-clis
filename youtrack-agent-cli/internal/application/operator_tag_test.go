package application

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/auth"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/endpoint"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/operatorwrite"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/profile"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/writepolicy"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/youtrack"
)

const tagTokenSentinel = "TAG_TOKEN_SENTINEL"

type tagState struct {
	id, name, typ, ownerID, ownerLogin string
	untagOnResolve, shared             bool
}

// tagFixture is a stateful fake YouTrack with issues, tags and per-issue tag
// membership. Tag t-1 "bug" is on no issue; t-2 "urgent" is on APP-12.
type tagFixture struct {
	service  *Service
	dir      string
	mu       sync.Mutex
	issues   map[string]*linkIssueState
	tags     map[string]*tagState
	order    []string
	onIssue  map[string][]string
	requests []string
	bodies   []string
	writes   atomic.Int32
	// writeStatus, when set, answers every POST/DELETE with it;
	// writeEffect false makes a 2xx write change nothing.
	writeStatus int
	writeEffect bool
}

func newTagFixture(t *testing.T, capabilities ...profile.Capability) *tagFixture {
	t.Helper()
	if runtime.GOOS == "darwin" && !OperatorWriteSupported() {
		t.Skip("Darwin without CGO cannot audit operator-store ACLs; Linux fake-boundary tests remain enabled")
	}
	if len(capabilities) == 0 {
		capabilities = []profile.Capability{profile.CapabilityRead, profile.CapabilityIssueTag}
	}
	f := &tagFixture{issues: map[string]*linkIssueState{}, tags: map[string]*tagState{}, onIssue: map[string][]string{}, writeEffect: true}
	for _, issue := range []*linkIssueState{
		{id: "2-12", readable: "APP-12", projectID: "0-3", projectKey: "APP", updated: 2},
		{id: "2-19", readable: "OPS-7", projectID: "0-4", projectKey: "OPS", updated: 2},
	} {
		f.issues[issue.id] = issue
	}
	f.addTag(&tagState{id: "t-1", name: "bug", typ: "Tag", ownerID: "1-2", ownerLogin: "alice"})
	f.addTag(&tagState{id: "t-2", name: "urgent", typ: "IssueTag", ownerID: "1-2", ownerLogin: "alice"})
	f.onIssue["2-12"] = []string{"t-2"}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serve(t)))
	t.Cleanup(server.Close)
	f.dir = t.TempDir()
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
	profiles := profile.NewRegistry(filepath.Join(f.dir, "config", "profiles.json"))
	if err := profiles.Add(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	policies := writepolicy.NewRegistry(filepath.Join(f.dir, "config", "policies.json"))
	if _, err := policies.Set(t.Context(), p, []writepolicy.Project{{ID: "0-3", Key: "APP"}, {ID: "0-4", Key: "OPS"}}); err != nil {
		t.Fatal(err)
	}
	credential, err := auth.BindCredential(auth.Credential{Kind: auth.CredentialPermanentToken, PermanentToken: "perm:" + tagTokenSentinel}, p)
	if err != nil {
		t.Fatal(err)
	}
	f.service = &Service{Profiles: profiles, Policies: policies, Credentials: &fixedCredentials{value: credential}, HTTP: server.Client().Transport,
		OperatorWrites: operatorwrite.New(f.dir), OperatorWriteSupport: func() bool { return true }}
	return f
}

func (f *tagFixture) addTag(tag *tagState) {
	f.tags[tag.id] = tag
	f.order = append(f.order, tag.id)
}

func (f *tagFixture) edit(change func(*tagFixture)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}

func (f *tagFixture) writeCount() int { return int(f.writes.Load()) }

func (f *tagFixture) nonGET() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, request := range f.requests {
		if !strings.HasPrefix(request, "GET ") {
			out = append(out, request)
		}
	}
	return out
}

func tagJSON(tag *tagState) map[string]any {
	out := map[string]any{"id": tag.id, "name": tag.name, "$type": tag.typ, "untagOnResolve": tag.untagOnResolve, "visibleFor": nil, "updateableBy": nil}
	if tag.ownerID != "" {
		out["owner"] = map[string]any{"id": tag.ownerID, "login": tag.ownerLogin}
	}
	if tag.shared {
		out["visibleFor"] = map[string]any{"id": "g-1"}
	}
	return out
}

func (f *tagFixture) serve(t *testing.T) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		if !strings.HasSuffix(r.Header.Get("Authorization"), tagTokenSentinel) {
			t.Errorf("request carried no credential: %s", r.URL)
		}
		encode := func(value any) {
			if err := json.NewEncoder(w).Encode(value); err != nil {
				t.Error(err)
			}
		}
		parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api"), "/"), "/")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/users/me":
			_, _ = io.WriteString(w, `{"id":"1-2","login":"alice"}`)
		case r.Method == http.MethodGet && len(parts) == 2 && parts[0] == "issues":
			issue := f.issues[parts[1]]
			if issue == nil {
				for _, candidate := range f.issues {
					if candidate.readable == parts[1] {
						issue = candidate
					}
				}
			}
			if issue == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			encode(map[string]any{"id": issue.id, "idReadable": issue.readable, "summary": "Summary", "description": nil,
				"project":  map[string]any{"id": issue.projectID, "shortName": issue.projectKey, "name": issue.projectKey + " project", "archived": issue.archived},
				"reporter": map[string]any{"id": "1-2", "login": "alice"}, "created": 1, "updated": issue.updated, "commentsCount": 0, "customFields": []any{}})
		case r.Method == http.MethodGet && len(parts) == 1 && parts[0] == "tags":
			query := strings.ToLower(r.URL.Query().Get("query"))
			out := []map[string]any{}
			for _, id := range f.order {
				if tag := f.tags[id]; tag != nil && strings.Contains(strings.ToLower(tag.name), query) {
					out = append(out, tagJSON(tag))
				}
			}
			from, to := page(r, len(out))
			encode(out[from:to])
		case r.Method == http.MethodGet && len(parts) == 2 && parts[0] == "tags":
			if tag := f.tags[parts[1]]; tag != nil {
				encode(tagJSON(tag))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodGet && len(parts) == 3 && parts[0] == "issues" && parts[2] == "tags":
			out := []map[string]any{}
			for _, id := range f.onIssue[parts[1]] {
				out = append(out, tagJSON(f.tags[id]))
			}
			from, to := page(r, len(out))
			encode(out[from:to])
		case r.Method == http.MethodGet && len(parts) == 4 && parts[0] == "issues" && parts[2] == "tags":
			if slices.Contains(f.onIssue[parts[1]], parts[3]) && f.tags[parts[3]] != nil {
				encode(tagJSON(f.tags[parts[3]]))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodPost && len(parts) == 3 && parts[0] == "issues" && parts[2] == "tags":
			f.writes.Add(1)
			raw, _ := io.ReadAll(r.Body)
			f.bodies = append(f.bodies, string(raw))
			if f.writeStatus != 0 {
				w.WriteHeader(f.writeStatus)
				return
			}
			var body struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(raw, &body); err != nil || f.tags[body.ID] == nil || string(raw) != fmt.Sprintf(`{"id":%q}`, body.ID) {
				t.Errorf("unexpected tag body %q", raw)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if f.writeEffect && !slices.Contains(f.onIssue[parts[1]], body.ID) {
				f.onIssue[parts[1]] = append(f.onIssue[parts[1]], body.ID)
			}
			encode(map[string]any{"id": body.ID})
		case r.Method == http.MethodDelete && len(parts) == 4 && parts[0] == "issues" && parts[2] == "tags":
			f.writes.Add(1)
			if f.writeStatus != 0 {
				w.WriteHeader(f.writeStatus)
				return
			}
			if f.writeEffect {
				f.onIssue[parts[1]] = slices.DeleteFunc(f.onIssue[parts[1]], func(id string) bool { return id == parts[3] })
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func tagInput(kind, name string) OperatorSnapshotInput {
	return OperatorSnapshotInput{Profile: "work", Kind: kind, IssueID: "APP-12", Tag: name}
}

func defaultTagInput(kind string) OperatorSnapshotInput {
	if kind == "issue.untag" {
		return tagInput(kind, "urgent")
	}
	return tagInput(kind, "bug")
}

func (f *tagFixture) snapshot(t *testing.T, kind string, change func(*OperatorSnapshotInput)) (OperatorWriteInfo, error) {
	t.Helper()
	input := defaultTagInput(kind)
	if change != nil {
		change(&input)
	}
	return f.service.SnapshotOperatorWrite(t.Context(), input)
}

func (f *tagFixture) prepare(t *testing.T, kind string, change func(*OperatorSnapshotInput)) OperatorWriteInfo {
	t.Helper()
	snapshot, err := f.snapshot(t, kind, change)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(snapshot.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := f.service.PrepareOperatorWrite(t.Context(), OperatorPrepareInput{Profile: "work", SnapshotJSON: raw, RequestJSON: []byte(`{"kind":"` + kind + `"}`)})
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func (f *tagFixture) apply(t *testing.T, plan OperatorWriteInfo) (OperatorWriteInfo, error) {
	t.Helper()
	return f.service.ApplyOperatorWrite(t.Context(), OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: plan.IntentSHA256, Yes: true})
}

func (f *tagFixture) requireNoSentinel(t *testing.T, values ...any) {
	t.Helper()
	for _, value := range values {
		if strings.Contains(fmt.Sprint(value), tagTokenSentinel) {
			t.Fatalf("token sentinel reached an output: %v", value)
		}
	}
	err := filepath.WalkDir(f.dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(raw), tagTokenSentinel) {
			t.Fatalf("token sentinel reached %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// writeLossTransport fails every request of one method as a connection loss.
type writeLossTransport struct {
	next   http.RoundTripper
	method string
	losses int
}

func (w *writeLossTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method == w.method {
		w.losses++
		return nil, errors.New("simulated connection loss")
	}
	return w.next.RoundTrip(request)
}

// afterWriteFailTransport fails every GET once a write of the method has gone out.
type afterWriteFailTransport struct {
	next   http.RoundTripper
	method string
	mu     sync.Mutex
	wrote  bool
}

func (a *afterWriteFailTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	a.mu.Lock()
	wrote := a.wrote
	if request.Method == a.method {
		a.wrote = true
	}
	a.mu.Unlock()
	if wrote && request.Method == http.MethodGet {
		return nil, errors.New("simulated read failure")
	}
	return a.next.RoundTrip(request)
}

func methodOf(kind string) string {
	if kind == "issue.untag" {
		return http.MethodDelete
	}
	return http.MethodPost
}

func TestOperatorIssueTagWritesOnceByNameAndByID(t *testing.T) {
	tests := []struct {
		name, kind string
		change     func(*OperatorSnapshotInput)
		wantWrite  string
	}{
		{name: "tag by name", kind: "issue.tag", wantWrite: "POST /api/issues/2-12/tags"},
		{name: "tag by id", kind: "issue.tag", change: func(i *OperatorSnapshotInput) { i.Tag, i.TagID = "", "t-1" }, wantWrite: "POST /api/issues/2-12/tags"},
		{name: "untag by name", kind: "issue.untag", wantWrite: "DELETE /api/issues/2-12/tags/t-2"},
		{name: "untag by id", kind: "issue.untag", change: func(i *OperatorSnapshotInput) { i.Tag, i.TagID = "", "t-2" }, wantWrite: "DELETE /api/issues/2-12/tags/t-2"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newTagFixture(t)
			plan := f.prepare(t, test.kind, test.change)
			wantTag := map[string]string{"issue.tag": "t-1", "issue.untag": "t-2"}[test.kind]
			if plan.Kind != test.kind || plan.PlanVersion != operatorwrite.PlanVersion4 || plan.TagID != wantTag || plan.Plan.Snapshot.Tag == nil || len(f.nonGET()) != 0 {
				t.Fatalf("plan=%#v writes=%v", plan, f.nonGET())
			}
			applied, err := f.apply(t, plan)
			if err != nil || applied.State != string(operatorwrite.StateApplied) || applied.RemoteID != wantTag || f.writeCount() != 1 {
				t.Fatalf("applied=%#v err=%v writes=%d", applied, err, f.writeCount())
			}
			if got := f.nonGET(); len(got) != 1 || !strings.HasPrefix(got[0], test.wantWrite) {
				t.Fatalf("writes=%q", got)
			}
			if test.kind == "issue.tag" && f.bodies[0] != `{"id":"t-1"}` {
				t.Fatalf("body=%q", f.bodies)
			}
			_, err = f.apply(t, plan)
			requireRefusal(t, err, "OPERATOR_PLAN_CONSUMED", errx.CodeConflict)
			if f.writeCount() != 1 {
				t.Fatalf("replay wrote: %d", f.writeCount())
			}
			f.requireNoSentinel(t, applied, err)
		})
	}
}

func TestOperatorIssueTagNameResolution(t *testing.T) {
	many := func(count int, name func(int) string) func(*tagFixture) {
		return func(f *tagFixture) {
			for index := range count {
				f.addTag(&tagState{id: fmt.Sprintf("m-%d", index), name: name(index), typ: "Tag", ownerID: "1-2", ownerLogin: "alice"})
			}
		}
	}
	long := strings.Repeat("é", 100)
	tests := []struct {
		name, kind, tag string
		setup           func(*tagFixture)
		wantReason      string
		wantCode        errx.Code
		wantCandidates  int
		wantMessage     string
	}{
		{name: "tag truncated list with one exact match", kind: "issue.tag", tag: "bug", setup: many(101, func(i int) string { return fmt.Sprintf("bug-%d", i) }), wantReason: "OPERATOR_SCHEMA_TRUNCATED", wantCode: errx.CodeConflict},
		{name: "tag not found", kind: "issue.tag", tag: "nothing", wantReason: "NOT_FOUND_TAG", wantCode: errx.CodeNotFound},
		{name: "tag inexact", kind: "issue.tag", tag: "BUG", wantReason: "INEXACT_TAG", wantCode: errx.CodeUsage, wantCandidates: 1},
		{name: "tag ambiguous bounded", kind: "issue.tag", tag: "dup", setup: many(12, func(int) string { return "dup" }), wantReason: "AMBIGUOUS_TAG", wantCode: errx.CodeAmbiguous, wantCandidates: 10, wantMessage: "12"},
		{name: "tag long names bounded", kind: "issue.tag", tag: long, setup: many(2, func(int) string { return long }), wantReason: "AMBIGUOUS_TAG", wantCode: errx.CodeAmbiguous, wantCandidates: 2},
		{name: "untag truncated list", kind: "issue.untag", tag: "urgent", setup: func(f *tagFixture) {
			many(101, func(i int) string { return fmt.Sprintf("x-%d", i) })(f)
			f.onIssue["2-12"] = nil
			for id := range f.tags {
				f.onIssue["2-12"] = append(f.onIssue["2-12"], id)
			}
		}, wantReason: "OPERATOR_TAGS_TRUNCATED", wantCode: errx.CodeConflict},
		{name: "untag absent", kind: "issue.untag", tag: "bug", wantReason: "OPERATOR_TAG_ABSENT", wantCode: errx.CodeUsage},
		{name: "untag inexact", kind: "issue.untag", tag: "Urgent", wantReason: "INEXACT_TAG", wantCode: errx.CodeUsage, wantCandidates: 1},
		{name: "untag ambiguous", kind: "issue.untag", tag: "urgent", setup: func(f *tagFixture) {
			many(2, func(int) string { return "urgent" })(f)
			f.onIssue["2-12"] = []string{"t-2", "m-0"}
		}, wantReason: "AMBIGUOUS_TAG", wantCode: errx.CodeAmbiguous, wantCandidates: 2, wantMessage: "2"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newTagFixture(t)
			if test.setup != nil {
				f.edit(test.setup)
			}
			_, err := f.snapshot(t, test.kind, func(i *OperatorSnapshotInput) { i.Tag = test.tag })
			requireRefusal(t, err, test.wantReason, test.wantCode)
			var typed *errx.Error
			errors.As(err, &typed)
			candidates := append(slices.Clone(typed.Candidates), typed.DidYouMean...)
			if len(candidates) != test.wantCandidates && test.wantCandidates != 0 || len(candidates) > 10 || !strings.Contains(typed.Message, test.wantMessage) {
				t.Fatalf("candidates=%d message=%q", len(candidates), typed.Message)
			}
			for _, candidate := range candidates {
				if len([]rune(candidate.Name)) > 64 {
					t.Fatalf("candidate name not bounded: %d", len([]rune(candidate.Name)))
				}
			}
			if len(f.nonGET()) != 0 {
				t.Fatalf("wrote: %v", f.nonGET())
			}
		})
	}
}

func TestTagCandidatesStripControlCharactersAndBoundNames(t *testing.T) {
	got := tagCandidates([]youtrack.Tag{{ID: "t-1", Name: "a\x1b[31mb\n"}, {ID: "t-2", Name: strings.Repeat("ж", 200)}})
	if got[0].Name != "a[31mb" || len([]rune(got[1].Name)) != 64 || got[0].Kind != "tag" {
		t.Fatalf("candidates=%#v", got)
	}
}

func TestOperatorIssueTagRefusals(t *testing.T) {
	tests := []struct {
		name, kind string
		tag        *tagState
		change     func(*OperatorSnapshotInput)
		setup      func(*tagFixture)
		wantReason string
		wantCode   errx.Code
	}{
		{name: "star folder", kind: "issue.tag", tag: &tagState{id: "s-1", name: "Starred", typ: "StarWatchFolder", ownerID: "1-2", ownerLogin: "alice"}, wantReason: "OPERATOR_TAG_STAR_UNSUPPORTED", wantCode: errx.CodeUsage},
		{name: "own tag named Star", kind: "issue.tag", tag: &tagState{id: "s-2", name: "Star", typ: "Tag", ownerID: "1-2", ownerLogin: "alice"}, wantReason: "OPERATOR_TAG_STAR_UNSUPPORTED", wantCode: errx.CodeUsage},
		{name: "unknown type", kind: "issue.tag", tag: &tagState{id: "s-3", name: "odd", typ: "SavedQuery", ownerID: "1-2", ownerLogin: "alice"}, wantReason: "OPERATOR_TAG_TYPE_UNSUPPORTED", wantCode: errx.CodeUsage},
		{name: "ownerless", kind: "issue.tag", tag: &tagState{id: "s-4", name: "orphan", typ: "Tag"}, wantReason: "OPERATOR_TAG_TYPE_UNSUPPORTED", wantCode: errx.CodeUsage},
		{name: "already present", kind: "issue.tag", change: func(i *OperatorSnapshotInput) { i.Tag = "urgent" }, wantReason: "OPERATOR_TAG_ALREADY_PRESENT", wantCode: errx.CodeUsage},
		{name: "absent by id", kind: "issue.untag", change: func(i *OperatorSnapshotInput) { i.Tag, i.TagID = "", "t-1" }, wantReason: "OPERATOR_TAG_ABSENT", wantCode: errx.CodeUsage},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newTagFixture(t)
			input := defaultTagInput(test.kind)
			if test.tag != nil {
				f.addTag(test.tag)
				input.Tag = test.tag.name
			}
			if test.change != nil {
				test.change(&input)
			}
			if test.setup != nil {
				f.edit(test.setup)
			}
			_, err := f.service.SnapshotOperatorWrite(t.Context(), input)
			requireRefusal(t, err, test.wantReason, test.wantCode)
			var typed *errx.Error
			errors.As(err, &typed)
			if strings.Contains(test.wantReason, "PRESENT") || strings.Contains(test.wantReason, "ABSENT") {
				if !strings.Contains(typed.Hint, "do not retry unchanged") {
					t.Fatalf("hint=%q", typed.Hint)
				}
			}
		})
	}
	t.Run("someone else's Star is allowed", func(t *testing.T) {
		f := newTagFixture(t)
		f.addTag(&tagState{id: "s-5", name: "Star", typ: "Tag", ownerID: "1-9", ownerLogin: "bob"})
		if plan := f.prepare(t, "issue.tag", func(i *OperatorSnapshotInput) { i.Tag = "Star" }); plan.TagID != "s-5" {
			t.Fatalf("plan=%#v", plan)
		}
	})
	for _, status := range []int{403, 404} {
		t.Run(fmt.Sprintf("untag by name GetTag %d", status), func(t *testing.T) {
			f := newTagFixture(t)
			f.service.HTTP = &getStatusTransport{next: f.service.HTTP, path: "/api/tags/t-2", status: status}
			_, err := f.snapshot(t, "issue.untag", nil)
			if status == 404 {
				requireRefusal(t, err, "OPERATOR_TAG_UNREADABLE", errx.CodeConflict)
			} else if errx.ExitCode(err) != errx.CodePermission {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestOperatorIssueTagSelectorsAreRefusedBeforeCredentials(t *testing.T) {
	tests := []struct {
		name   string
		kind   string
		change func(*OperatorSnapshotInput)
	}{
		{name: "both selectors", kind: "issue.tag", change: func(i *OperatorSnapshotInput) { i.TagID = "t-1" }},
		{name: "no selector", kind: "issue.tag", change: func(i *OperatorSnapshotInput) { i.Tag = "" }},
		{name: "bad id", kind: "issue.untag", change: func(i *OperatorSnapshotInput) { i.Tag, i.TagID = "", "t/1" }},
		{name: "long name", kind: "issue.tag", change: func(i *OperatorSnapshotInput) { i.Tag = strings.Repeat("a", 256) }},
		{name: "control name", kind: "issue.tag", change: func(i *OperatorSnapshotInput) { i.Tag = "a\x00b" }},
		{name: "no issue", kind: "issue.tag", change: func(i *OperatorSnapshotInput) { i.IssueID = "" }},
		{name: "project", kind: "issue.tag", change: func(i *OperatorSnapshotInput) { i.ProjectID = "0-3" }},
		{name: "comment", kind: "issue.untag", change: func(i *OperatorSnapshotInput) { i.CommentID = "4-1" }},
		{name: "field", kind: "issue.tag", change: func(i *OperatorSnapshotInput) {
			i.Fields = []OperatorFieldSelection{{FieldName: "a", ValueName: "b"}}
		}},
		{name: "link flag", kind: "issue.tag", change: func(i *OperatorSnapshotInput) { i.TargetID = "OPS-7" }},
		{name: "file", kind: "issue.tag", change: func(i *OperatorSnapshotInput) { i.FilePath = "x" }},
		{name: "tag on another kind", kind: "issue.edit", change: func(i *OperatorSnapshotInput) {}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newTagFixture(t, profile.CapabilityRead, profile.CapabilityIssueEdit, profile.CapabilityIssueTag)
			creds, network := &trapCredentials{}, &trapTransport{}
			f.service.Credentials, f.service.HTTP = creds, network
			input := defaultTagInput(test.kind)
			test.change(&input)
			_, err := f.service.SnapshotOperatorWrite(t.Context(), input)
			if errx.ExitCode(err) != errx.CodeUsage || creds.calls != 0 || network.calls != 0 {
				t.Fatalf("err=%v credentials=%d network=%d", err, creds.calls, network.calls)
			}
		})
	}
}

func TestOperatorIssueTagPrepareIsOfflineAndDigestMismatchPrecedesCredentials(t *testing.T) {
	f := newTagFixture(t)
	snapshot, err := f.snapshot(t, "issue.tag", nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(snapshot.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	creds, network := &trapCredentials{}, &trapTransport{}
	f.service.Credentials, f.service.HTTP = creds, network
	plan, err := f.service.PrepareOperatorWrite(t.Context(), OperatorPrepareInput{Profile: "work", SnapshotJSON: raw, RequestJSON: []byte(`{"kind":"issue.tag"}`)})
	if err != nil || plan.PlanID == "" || creds.calls != 0 || network.calls != 0 {
		t.Fatalf("prepare=%#v err=%v credentials=%d network=%d", plan, err, creds.calls, network.calls)
	}
	_, err = f.service.ApplyOperatorWrite(t.Context(), OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: strings.Repeat("a", 64), Yes: true})
	requireRefusal(t, err, "OPERATOR_CONFIRMATION_REQUIRED", errx.CodeConfirm)
	if creds.calls != 0 || network.calls != 0 {
		t.Fatalf("mismatch reached credentials=%d network=%d", creds.calls, network.calls)
	}
}

func TestOperatorIssueTagDriftInLockIsConflictWithZeroWrites(t *testing.T) {
	tests := []struct {
		name, kind string
		drift      func(*tagFixture)
		wantReason string
	}{
		{name: "tag renamed", kind: "issue.tag", drift: func(f *tagFixture) { f.tags["t-1"].name = "renamed" }, wantReason: "OPERATOR_TAG_STALE"},
		{name: "tag shared", kind: "issue.tag", drift: func(f *tagFixture) { f.tags["t-1"].shared = true }, wantReason: "OPERATOR_TAG_STALE"},
		{name: "untag on resolve flipped", kind: "issue.untag", drift: func(f *tagFixture) { f.tags["t-2"].untagOnResolve = true }, wantReason: "OPERATOR_TAG_STALE"},
		{name: "tag deleted", kind: "issue.tag", drift: func(f *tagFixture) { delete(f.tags, "t-1") }, wantReason: "OPERATOR_TAG_STALE"},
		{name: "issue deleted", kind: "issue.tag", drift: func(f *tagFixture) { delete(f.issues, "2-12") }, wantReason: "OPERATOR_TAG_STALE"},
		{name: "issue moved", kind: "issue.untag", drift: func(f *tagFixture) { f.issues["2-12"].projectID, f.issues["2-12"].projectKey = "0-4", "OPS" }, wantReason: "OPERATOR_ISSUE_STALE"},
		{name: "tag appeared", kind: "issue.tag", drift: func(f *tagFixture) { f.onIssue["2-12"] = append(f.onIssue["2-12"], "t-1") }, wantReason: "OPERATOR_TAG_STALE"},
		{name: "tag disappeared", kind: "issue.untag", drift: func(f *tagFixture) { f.onIssue["2-12"] = nil }, wantReason: "OPERATOR_TAG_STALE"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newTagFixture(t)
			plan := f.prepare(t, test.kind, nil)
			f.edit(test.drift)
			_, err := f.apply(t, plan)
			requireRefusal(t, err, test.wantReason, errx.CodeConflict)
			record, getErr := f.service.OperatorWrites.Get(t.Context(), plan.PlanID)
			if getErr != nil || record.NonReplayable() || f.writeCount() != 0 {
				t.Fatalf("record=%#v err=%v writes=%d", record, getErr, f.writeCount())
			}
		})
	}
	for _, status := range []int{401, 403, 429} {
		t.Run(fmt.Sprintf("auth class %d", status), func(t *testing.T) {
			f := newTagFixture(t)
			plan := f.prepare(t, "issue.tag", nil)
			f.service.HTTP = &getStatusTransport{next: f.service.HTTP, path: "/api/tags/t-1", status: status}
			_, err := f.apply(t, plan)
			want := map[int]errx.Code{401: errx.CodeAuth, 403: errx.CodePermission, 429: errx.CodeRetryable}[status]
			if errx.ExitCode(err) != want || f.writeCount() != 0 {
				t.Fatalf("err=%v writes=%d", err, f.writeCount())
			}
		})
	}
}

func TestOperatorIssueTagConcurrentApplyWritesOnce(t *testing.T) {
	for _, kind := range []string{"issue.tag", "issue.untag"} {
		t.Run(kind, func(t *testing.T) {
			f := newTagFixture(t)
			plan := f.prepare(t, kind, nil)
			var wg sync.WaitGroup
			errs := make([]error, 4)
			for index := range errs {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, errs[index] = f.apply(t, plan)
				}()
			}
			wg.Wait()
			succeeded := 0
			for _, err := range errs {
				if err == nil {
					succeeded++
				} else if reason := operatorReason(t, err); reason != "OPERATOR_PLAN_CONSUMED" && reason != "OPERATOR_TAG_STALE" {
					t.Fatalf("loser err=%v", err)
				}
			}
			if succeeded != 1 || f.writeCount() != 1 {
				t.Fatalf("succeeded=%d writes=%d errs=%v", succeeded, f.writeCount(), errs)
			}
		})
	}
}

func TestOperatorIssueTagTransportLossIsUnknownWithoutReplay(t *testing.T) {
	for _, kind := range []string{"issue.tag", "issue.untag"} {
		t.Run(kind, func(t *testing.T) {
			f := newTagFixture(t)
			plan := f.prepare(t, kind, nil)
			transport := &writeLossTransport{next: f.service.HTTP, method: methodOf(kind)}
			f.service.HTTP = transport
			_, err := f.apply(t, plan)
			if operatorReason(t, err) != "WRITE_OUTCOME_UNKNOWN" {
				t.Fatalf("err=%v", err)
			}
			status, statusErr := f.service.OperatorWriteStatus(t.Context(), plan.PlanID)
			if statusErr != nil || status.State != string(operatorwrite.StateUnknown) || !status.NonReplayable {
				t.Fatalf("status=%#v err=%v", status, statusErr)
			}
			_, err = f.apply(t, plan)
			requireRefusal(t, err, "OPERATOR_PLAN_CONSUMED", errx.CodeConflict)
			if transport.losses != 1 || f.writeCount() != 0 {
				t.Fatalf("replay attempted: losses=%d server writes=%d", transport.losses, f.writeCount())
			}
		})
	}
}

func TestOperatorIssueTagWriteOutcomesAreSingleAndClassified(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		noEffect   bool
		wantState  operatorwrite.State
		wantReason string
		wantCode   errx.Code
	}{
		{name: "rate limited", status: 429, wantState: operatorwrite.StateUnknown, wantReason: "WRITE_OUTCOME_UNKNOWN", wantCode: errx.CodeConflict},
		{name: "server error", status: 503, wantState: operatorwrite.StateUnknown, wantReason: "WRITE_OUTCOME_UNKNOWN", wantCode: errx.CodeConflict},
		{name: "success that left the wrong state", noEffect: true, wantState: operatorwrite.StateUnknown, wantReason: "WRITE_OUTCOME_UNKNOWN", wantCode: errx.CodeConflict},
		{name: "forbidden", status: 403, wantState: operatorwrite.StateRejected, wantReason: "PERMISSION_DENIED", wantCode: errx.CodePermission},
		{name: "not found", status: 404, wantState: operatorwrite.StateRejected, wantReason: "TARGET_CHANGED", wantCode: errx.CodeConflict},
	}
	for _, kind := range []string{"issue.tag", "issue.untag"} {
		for _, test := range tests {
			t.Run(kind+" "+test.name, func(t *testing.T) {
				f := newTagFixture(t)
				plan := f.prepare(t, kind, nil)
				f.writeStatus, f.writeEffect = test.status, !test.noEffect
				_, err := f.apply(t, plan)
				requireRefusal(t, err, test.wantReason, test.wantCode)
				status, statusErr := f.service.OperatorWriteStatus(t.Context(), plan.PlanID)
				if statusErr != nil || status.State != string(test.wantState) || !status.NonReplayable || f.writeCount() != 1 {
					t.Fatalf("status=%#v err=%v writes=%d", status, statusErr, f.writeCount())
				}
				_, err = f.apply(t, plan)
				requireRefusal(t, err, "OPERATOR_PLAN_CONSUMED", errx.CodeConflict)
				if f.writeCount() != 1 {
					t.Fatalf("replay wrote: %d", f.writeCount())
				}
			})
		}
	}
}

func TestOperatorIssueTagReadBackFailureAfterSuccessIsUnknown(t *testing.T) {
	for _, kind := range []string{"issue.tag", "issue.untag"} {
		t.Run(kind, func(t *testing.T) {
			f := newTagFixture(t)
			plan := f.prepare(t, kind, nil)
			f.service.HTTP = &afterWriteFailTransport{next: f.service.HTTP, method: methodOf(kind)}
			_, err := f.apply(t, plan)
			requireRefusal(t, err, "WRITE_OUTCOME_UNKNOWN", errx.CodeConflict)
			status, statusErr := f.service.OperatorWriteStatus(t.Context(), plan.PlanID)
			if statusErr != nil || status.State != string(operatorwrite.StateUnknown) || f.writeCount() != 1 {
				t.Fatalf("status=%#v err=%v writes=%d", status, statusErr, f.writeCount())
			}
		})
	}
}

func TestOperatorIssueTagReconcileIsGETOnlyAndNeverProvesCausation(t *testing.T) {
	tests := []struct {
		name, kind   string
		setup        func(*tagFixture)
		blockGet     int
		wantEvidence string
	}{
		{name: "tag observed", kind: "issue.tag", setup: func(f *tagFixture) { f.onIssue["2-12"] = append(f.onIssue["2-12"], "t-1") }, wantEvidence: "desired_tag_observed_without_causal_proof"},
		{name: "tag still absent", kind: "issue.tag", wantEvidence: "tag_still_absent"},
		{name: "tag issue deleted", kind: "issue.tag", setup: func(f *tagFixture) { delete(f.issues, "2-12") }, wantEvidence: "tagged_issue_unavailable"},
		{name: "tag presence forbidden", kind: "issue.tag", blockGet: 403, wantEvidence: "inconclusive"},
		{name: "untag absence observed", kind: "issue.untag", setup: func(f *tagFixture) { f.onIssue["2-12"] = nil }, wantEvidence: "desired_tag_absence_observed_without_causal_proof"},
		{name: "untag still present", kind: "issue.untag", wantEvidence: "tag_still_present"},
		{name: "untag presence forbidden", kind: "issue.untag", blockGet: 401, wantEvidence: "inconclusive"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newTagFixture(t)
			plan := f.prepare(t, test.kind, nil)
			if _, err := f.service.OperatorWrites.Claim(t.Context(), plan.PlanID, plan.IntentSHA256, f.service.currentTime()); err != nil {
				t.Fatal(err)
			}
			if test.setup != nil {
				f.edit(test.setup)
			}
			if test.blockGet != 0 {
				f.service.HTTP = &getStatusTransport{next: f.service.HTTP, path: "/api/issues/2-12/tags/" + plan.TagID, status: test.blockGet}
			}
			result, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: plan.PlanID, Limit: 20})
			if err != nil || result.State != string(operatorwrite.StateOperatorRequired) || result.Evidence != test.wantEvidence || !result.NonReplayable {
				t.Fatalf("result=%#v err=%v", result, err)
			}
			if len(f.nonGET()) != 0 {
				t.Fatalf("reconcile wrote: %v", f.nonGET())
			}
			_, err = f.apply(t, plan)
			requireRefusal(t, err, "OPERATOR_PLAN_CONSUMED", errx.CodeConflict)
		})
	}
}

func TestOperatorIssueTagDisclosuresCapabilityAndSurface(t *testing.T) {
	f := newTagFixture(t)
	f.tags["t-1"].shared, f.tags["t-1"].untagOnResolve = true, true
	plan := f.prepare(t, "issue.tag", nil)
	if !slices.Equal(plan.Disclosures, []string{"shared_tag", "untag_on_resolve"}) || plan.TagName != "bug" {
		t.Fatalf("plan=%#v", plan)
	}
	info, err := f.service.Capabilities(t.Context(), "work")
	if err != nil || !slices.Contains(info.Kinds, "issue.tag") || !slices.Contains(info.Kinds, "issue.untag") || info.PlanVersions["issue.tag"] != operatorwrite.PlanVersion4 {
		t.Fatalf("info=%#v err=%v", info, err)
	}
	other := newTagFixture(t, profile.CapabilityRead, profile.CapabilityIssueLink)
	_, err = other.snapshot(t, "issue.tag", nil)
	requireRefusal(t, err, "OPERATOR_CAPABILITY_REQUIRED", errx.CodePermission)
	info, err = other.service.Capabilities(t.Context(), "work")
	if err != nil || slices.Contains(info.Kinds, "issue.tag") || slices.Contains(info.Kinds, "issue.untag") {
		t.Fatalf("info=%#v err=%v", info, err)
	}
}
