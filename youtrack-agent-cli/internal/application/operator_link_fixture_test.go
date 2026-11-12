package application

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/auth"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/endpoint"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/operatorwrite"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/profile"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/writepolicy"
)

const linkTokenSentinel = "LINK_TOKEN_SENTINEL"

type linkIssueState struct {
	id, readable, projectID, projectKey string
	archived                            bool
	updated                             int64
}

type linkEntryState struct {
	id, typeID, direction string
	issues                []string
}

// linkFixture is a stateful fake YouTrack: issues in two projects, link types,
// per-issue link entries with server-chosen ids, and a link POST that updates
// both sides like the real server.
type linkFixture struct {
	service *Service
	dir     string
	mu      sync.Mutex
	issues  map[string]*linkIssueState
	types   []map[string]any
	entries map[string][]*linkEntryState
	// requests records every "METHOD path?query" the server sees.
	requests []string
	posts    atomic.Int32
	// postStatus, when set, answers every POST with that status and postBody.
	postStatus int
	postBody   string
	// postEffect false makes a 200 POST that does not change the world.
	postEffect bool
	beforePost func(*linkFixture)
}

func linkEntryID(issueID, typeID, direction string) string {
	return "lnk-" + issueID + "-" + typeID + "-" + strings.ToLower(direction[:1])
}

func newLinkFixture(t *testing.T) *linkFixture {
	t.Helper()
	if runtime.GOOS == "darwin" && !OperatorWriteSupported() {
		t.Skip("Darwin without CGO cannot audit operator-store ACLs; Linux fake-boundary tests remain enabled")
	}
	f := &linkFixture{issues: map[string]*linkIssueState{}, entries: map[string][]*linkEntryState{}, postEffect: true}
	for _, issue := range []*linkIssueState{
		{id: "2-12", readable: "APP-12", projectID: "0-3", projectKey: "APP", updated: 2},
		{id: "2-13", readable: "APP-13", projectID: "0-3", projectKey: "APP", updated: 2},
		{id: "2-19", readable: "OPS-7", projectID: "0-4", projectKey: "OPS", updated: 2},
		{id: "2-20", readable: "OPS-8", projectID: "0-4", projectKey: "OPS", updated: 2},
		{id: "2-30", readable: "ARC-1", projectID: "0-9", projectKey: "ARC", updated: 2},
	} {
		f.issues[issue.id] = issue
	}
	f.types = []map[string]any{
		{"id": "105-0", "name": "Relates", "directed": false, "aggregation": false, "sourceToTarget": "relates to", "targetToSource": "relates to"},
		{"id": "105-1", "name": "Depend", "directed": true, "aggregation": false, "sourceToTarget": "depends on", "targetToSource": "is required for"},
		{"id": "105-2", "name": "Duplicate", "directed": true, "aggregation": false, "sourceToTarget": "duplicates", "targetToSource": "is duplicated by"},
		{"id": "105-3", "name": "Subtask", "directed": true, "aggregation": true, "sourceToTarget": "parent for", "targetToSource": "subtask of"},
	}
	f.resetEntries()
	server := httptest.NewTLSServer(http.HandlerFunc(f.serve(t)))
	t.Cleanup(server.Close)
	f.dir = t.TempDir()
	mcp, err := endpoint.CanonicalMCPURL(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	p := profile.Profile{Name: "work", ServiceURL: server.URL, RESTBaseURL: server.URL + "/api", MCPURL: mcp,
		OAuth:             profile.OAuthConfig{IssuerURL: "https://hub.example.test", AuthorizationURL: "https://hub.example.test" + endpoint.OAuthAuthorizationPath, TokenURL: "https://hub.example.test" + endpoint.OAuthTokenPath, ClientID: "client", Scopes: []string{"YouTrack"}, RedirectURI: "http://127.0.0.1:18987/oauth/callback"},
		ExpectedAccountID: "1-2", ExpectedLogin: "alice", Capabilities: []profile.Capability{profile.CapabilityRead, profile.CapabilityIssueLink}, Executor: profile.ExecutorRESTBestEffort, Assurance: profile.AssuranceBestEffort}
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
	credential, err := auth.BindCredential(auth.Credential{Kind: auth.CredentialPermanentToken, PermanentToken: "perm:" + linkTokenSentinel}, p)
	if err != nil {
		t.Fatal(err)
	}
	f.service = &Service{Profiles: profiles, Policies: policies, Credentials: &fixedCredentials{value: credential}, HTTP: server.Client().Transport,
		OperatorWrites: operatorwrite.New(f.dir), OperatorWriteSupport: func() bool { return true }}
	return f
}

// resetEntries gives every issue one entry per link type and side, with ids
// that are deliberately not derived from the type id.
func (f *linkFixture) resetEntries() {
	f.entries = map[string][]*linkEntryState{}
	for id := range f.issues {
		for _, linkType := range f.types {
			typeID := linkType["id"].(string)
			if linkType["directed"] == false {
				f.entries[id] = append(f.entries[id], &linkEntryState{id: linkEntryID(id, typeID, "BOTH"), typeID: typeID, direction: "BOTH"})
				continue
			}
			f.entries[id] = append(f.entries[id],
				&linkEntryState{id: linkEntryID(id, typeID, "OUTWARD"), typeID: typeID, direction: "OUTWARD"},
				&linkEntryState{id: linkEntryID(id, typeID, "INWARD"), typeID: typeID, direction: "INWARD"})
		}
	}
}

func (f *linkFixture) edit(change func(*linkFixture)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}

func (f *linkFixture) entry(issueID, typeID, direction string) *linkEntryState {
	for _, entry := range f.entries[issueID] {
		if entry.typeID == typeID && entry.direction == direction {
			return entry
		}
	}
	return nil
}

// link adds source -> target on both sides, as the server does. Callers hold no lock.
func (f *linkFixture) link(source, typeID, direction, target string) {
	f.edit(func(f *linkFixture) { f.addLocked(source, typeID, direction, target) })
}

func (f *linkFixture) addLocked(source, typeID, direction, target string) {
	reverse := map[string]string{"OUTWARD": "INWARD", "INWARD": "OUTWARD", "BOTH": "BOTH"}[direction]
	if entry := f.entry(source, typeID, direction); entry != nil && !slices.Contains(entry.issues, target) {
		entry.issues = append(entry.issues, target)
	}
	if entry := f.entry(target, typeID, reverse); entry != nil && !slices.Contains(entry.issues, source) {
		entry.issues = append(entry.issues, source)
	}
}

func (f *linkFixture) findIssue(ref string) *linkIssueState {
	for _, issue := range f.issues {
		if issue.id == ref || issue.readable == ref {
			return issue
		}
	}
	return nil
}

func (f *linkFixture) postCount() int { return int(f.posts.Load()) }

func (f *linkFixture) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func (f *linkFixture) nonGET() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var methods []string
	for _, request := range f.requests {
		if !strings.HasPrefix(request, "GET ") {
			methods = append(methods, request)
		}
	}
	return methods
}

func page(r *http.Request, total int) (int, int) {
	top, _ := strconv.Atoi(r.URL.Query().Get("$top"))
	skip, _ := strconv.Atoi(r.URL.Query().Get("$skip"))
	if top <= 0 {
		top = total
	}
	skip = min(skip, total)
	return skip, min(skip+top, total)
}

func (f *linkFixture) serve(t *testing.T) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		if !strings.HasSuffix(r.Header.Get("Authorization"), linkTokenSentinel) {
			t.Errorf("request carried no credential: %s", r.URL)
		}
		encode := func(value any) {
			if err := json.NewEncoder(w).Encode(value); err != nil {
				t.Error(err)
			}
		}
		path := strings.TrimPrefix(r.URL.Path, "/api")
		parts := strings.Split(strings.Trim(path, "/"), "/")
		switch {
		case r.Method == http.MethodGet && path == "/users/me":
			_, _ = io.WriteString(w, `{"id":"1-2","login":"alice"}`)
		case r.Method == http.MethodGet && path == "/issueLinkTypes":
			from, to := page(r, len(f.types))
			encode(f.types[from:to])
		case r.Method == http.MethodGet && len(parts) == 2 && parts[0] == "issueLinkTypes":
			for _, linkType := range f.types {
				if linkType["id"] == parts[1] {
					encode(linkType)
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodGet && len(parts) == 2 && parts[0] == "issues":
			issue := f.findIssue(parts[1])
			if issue == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			encode(map[string]any{"id": issue.id, "idReadable": issue.readable, "summary": "Summary of " + issue.readable, "description": nil,
				"project":  map[string]any{"id": issue.projectID, "shortName": issue.projectKey, "name": issue.projectKey + " project", "archived": issue.archived},
				"reporter": map[string]any{"id": "1-2", "login": "alice"}, "created": 1, "updated": issue.updated, "commentsCount": 0, "customFields": []any{}})
		case r.Method == http.MethodGet && len(parts) == 3 && parts[0] == "issues" && parts[2] == "links":
			issue := f.findIssue(parts[1])
			if issue == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			var out []map[string]any
			for _, entry := range f.entries[issue.id] {
				out = append(out, map[string]any{"id": entry.id, "direction": entry.direction, "linkType": map[string]any{"id": entry.typeID}})
			}
			from, to := page(r, len(out))
			encode(out[from:to])
		case len(parts) == 5 && parts[0] == "issues" && parts[2] == "links" && parts[4] == "issues":
			issue := f.findIssue(parts[1])
			var entry *linkEntryState
			if issue != nil {
				for _, candidate := range f.entries[issue.id] {
					if candidate.id == parts[3] {
						entry = candidate
					}
				}
			}
			if entry == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if r.Method == http.MethodGet {
				out := []map[string]any{}
				for _, id := range entry.issues {
					out = append(out, map[string]any{"id": id, "idReadable": f.issues[id].readable})
				}
				from, to := page(r, len(out))
				encode(out[from:to])
				return
			}
			f.posts.Add(1)
			if f.beforePost != nil {
				f.beforePost(f)
			}
			if f.postStatus != 0 {
				w.WriteHeader(f.postStatus)
				_, _ = io.WriteString(w, f.postBody)
				return
			}
			var body struct {
				ID string `json:"id"`
			}
			raw, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(raw, &body); err != nil || f.issues[body.ID] == nil || string(raw) != fmt.Sprintf(`{"id":%q}`, body.ID) {
				t.Errorf("unexpected link body %q", raw)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if f.postEffect {
				f.addLocked(issue.id, entry.typeID, entry.direction, body.ID)
			}
			if f.postBody != "" {
				_, _ = io.WriteString(w, f.postBody)
				return
			}
			encode(map[string]any{"id": body.ID, "idReadable": f.issues[body.ID].readable})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func (f *linkFixture) snapshotInput() OperatorSnapshotInput {
	return OperatorSnapshotInput{Profile: "work", Kind: "issue.link", IssueID: "APP-12", TargetID: "OPS-7", LinkType: "Depend", Direction: "depends on"}
}

func (f *linkFixture) snapshot(t *testing.T, change func(*OperatorSnapshotInput)) (OperatorWriteInfo, error) {
	t.Helper()
	input := f.snapshotInput()
	if change != nil {
		change(&input)
	}
	return f.service.SnapshotOperatorWrite(t.Context(), input)
}

func (f *linkFixture) prepare(t *testing.T, change func(*OperatorSnapshotInput)) OperatorWriteInfo {
	t.Helper()
	snapshot, err := f.snapshot(t, change)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(snapshot.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := f.service.PrepareOperatorWrite(t.Context(), OperatorPrepareInput{Profile: "work", SnapshotJSON: raw, RequestJSON: []byte(`{"kind":"issue.link"}`)})
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func (f *linkFixture) apply(t *testing.T, plan OperatorWriteInfo) (OperatorWriteInfo, error) {
	t.Helper()
	return f.service.ApplyOperatorWrite(t.Context(), OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: plan.IntentSHA256, Yes: true})
}

// requireNoSentinel scans the given outputs and every file the run wrote.
func (f *linkFixture) requireNoSentinel(t *testing.T, values ...any) {
	t.Helper()
	for _, value := range values {
		if strings.Contains(fmt.Sprint(value), linkTokenSentinel) {
			t.Fatalf("token sentinel reached an output: %v", value)
		}
		if raw, err := json.Marshal(value); err == nil && strings.Contains(string(raw), linkTokenSentinel) {
			t.Fatalf("token sentinel reached a JSON output: %s", raw)
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
		if strings.Contains(string(raw), linkTokenSentinel) {
			t.Fatalf("token sentinel reached %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
