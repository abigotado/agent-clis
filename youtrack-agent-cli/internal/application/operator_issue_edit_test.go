package application

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/auth"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/operatorwrite"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/profile"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/writepolicy"
)

const (
	oldSummarySentinel     = "OLD_SUMMARY_SENTINEL"
	oldDescriptionSentinel = "OLD_DESCRIPTION_SENTINEL"
)

// editIssue is an issue read with the given text; a nil description encodes JSON null.
func editIssue(summary string, description *string, updated int64) string {
	raw, err := json.Marshal(map[string]any{"id": "2-12", "idReadable": "APP-12", "summary": summary, "description": description,
		"project":  map[string]any{"id": "0-3", "shortName": "APP", "name": "Application", "archived": false},
		"reporter": map[string]any{"id": "1-2", "login": "alice"}, "created": 1, "updated": updated, "commentsCount": 0, "customFields": []any{}})
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func strPtr(value string) *string { return &value }

// enableIssueEdit adds the issue-edit capability and rebinds policy and credential.
func enableIssueEdit(t *testing.T, f *operatorFixture) {
	t.Helper()
	selected, err := f.service.Profiles.Get(t.Context(), "work")
	if err != nil {
		t.Fatal(err)
	}
	selected.Capabilities = append(selected.Capabilities, profile.CapabilityIssueEdit)
	if err := f.service.Profiles.Put(t.Context(), selected); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Policies.Set(t.Context(), selected, []writepolicy.Project{{ID: "0-3", Key: "APP"}}); err != nil {
		t.Fatal(err)
	}
	credential, err := auth.BindCredential(auth.Credential{Kind: auth.CredentialPermanentToken, PermanentToken: "perm:OPERATOR_EDIT_TEST_SENTINEL"}, selected)
	if err != nil {
		t.Fatal(err)
	}
	f.service.Credentials = &fixedCredentials{value: credential}
}

func (f *operatorFixture) setIssue(issue string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issue = issue
}

func (f *operatorFixture) snapshotEdit(t *testing.T) OperatorWriteInfo {
	t.Helper()
	info, err := f.service.SnapshotOperatorWrite(t.Context(), OperatorSnapshotInput{Profile: "work", Kind: "issue.edit", IssueID: "APP-12"})
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func (f *operatorFixture) prepareEditRaw(t *testing.T, snapshot OperatorWriteInfo, request string, dryRun bool) (OperatorWriteInfo, error) {
	t.Helper()
	raw, err := json.Marshal(snapshot.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return f.service.PrepareOperatorWrite(t.Context(), OperatorPrepareInput{Profile: "work", SnapshotJSON: raw, RequestJSON: []byte(request), DryRun: dryRun})
}

func (f *operatorFixture) prepareEdit(t *testing.T, request string) OperatorWriteInfo {
	t.Helper()
	prepared, err := f.prepareEditRaw(t, f.snapshotEdit(t), request, false)
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

// editFixture has issue-edit enabled and the given current text.
func newEditFixture(t *testing.T, summary string, description *string) *operatorFixture {
	t.Helper()
	f := newOperatorFixture(t)
	enableIssueEdit(t, f)
	f.setIssue(editIssue(summary, description, 2))
	return f
}

// methodTransport records the methods it sees and can fail every POST.
type methodTransport struct {
	next     http.RoundTripper
	failPOST bool
	mu       sync.Mutex
	posts    []string
	bodies   []string
	methods  []string
}

func (m *methodTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	m.mu.Lock()
	m.methods = append(m.methods, request.Method)
	m.mu.Unlock()
	if request.Method == http.MethodPost {
		var body []byte
		if request.Body != nil {
			var err error
			if body, err = io.ReadAll(request.Body); err != nil {
				return nil, err
			}
			if err := request.Body.Close(); err != nil {
				return nil, err
			}
			request.Body = io.NopCloser(strings.NewReader(string(body)))
		}
		m.mu.Lock()
		m.posts = append(m.posts, request.URL.Path)
		m.bodies = append(m.bodies, string(body))
		m.mu.Unlock()
		if m.failPOST {
			return nil, errors.New("simulated connection reset")
		}
	}
	return m.next.RoundTrip(request)
}

func TestOperatorIssueEditRequiresItsOwnCapability(t *testing.T) {
	f := newOperatorFixture(t)
	f.setIssue(editIssue("Example", strPtr("body"), 2))
	_, err := f.service.SnapshotOperatorWrite(t.Context(), OperatorSnapshotInput{Profile: "work", Kind: "issue.edit", IssueID: "APP-12"})
	requireRefusal(t, err, "OPERATOR_CAPABILITY_REQUIRED", errx.CodePermission)
}

func TestOperatorIssueEditSnapshotFreezesOnlyHashes(t *testing.T) {
	tests := []struct {
		name        string
		description *string
	}{
		{"null description", nil},
		{"empty description", strPtr("")},
		{"present description", strPtr("body")},
	}
	seen := map[string]string{}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newEditFixture(t, "Example", test.description)
			info := f.snapshotEdit(t)
			text := info.Snapshot.Text
			summary := "Example"
			if info.Kind != "issue.edit" || info.PlanVersion != operatorwrite.PlanVersion4 || text == nil ||
				text.SummarySHA256 != operatorwrite.HashText(&summary) || text.DescriptionSHA256 != operatorwrite.HashText(test.description) {
				t.Fatalf("info=%#v", info)
			}
			seen[test.name] = text.DescriptionSHA256
		})
	}
	if seen["null description"] == seen["empty description"] || seen["empty description"] == seen["present description"] {
		t.Fatalf("hashes do not distinguish null, empty and present: %v", seen)
	}
}

func TestOperatorIssueEditSnapshotRefusesOtherSelectors(t *testing.T) {
	tests := []struct {
		name  string
		input OperatorSnapshotInput
	}{
		{"fields", OperatorSnapshotInput{Fields: []OperatorFieldSelection{{FieldID: "92-1", ValueID: "101-2"}}}},
		{"clear", OperatorSnapshotInput{Fields: []OperatorFieldSelection{{FieldID: "92-1", Clear: true}}}},
		{"project", OperatorSnapshotInput{ProjectID: "APP"}},
		{"comment", OperatorSnapshotInput{CommentID: "4-1"}},
		{"missing id", OperatorSnapshotInput{IssueID: "-"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newEditFixture(t, "Example", strPtr("body"))
			input := test.input
			input.Profile, input.Kind = "work", "issue.edit"
			if input.IssueID == "" {
				input.IssueID = "APP-12"
			}
			if input.IssueID == "-" {
				input.IssueID = ""
			}
			_, err := f.service.SnapshotOperatorWrite(t.Context(), input)
			requireRefusal(t, err, "USAGE", errx.CodeUsage)
		})
	}
}

func TestOperatorIssueEditRefusesNoOp(t *testing.T) {
	tests := []struct {
		name, request string
		refused       bool
	}{
		{"same summary", `{"kind":"issue.edit","summary":"Example"}`, true},
		{"same description", `{"kind":"issue.edit","description":"body"}`, true},
		{"both same", `{"kind":"issue.edit","summary":"Example","description":"body"}`, true},
		{"summary differs", `{"kind":"issue.edit","summary":"Changed"}`, false},
		{"one of two differs", `{"kind":"issue.edit","summary":"Example","description":"changed"}`, false},
	}
	for _, test := range tests {
		for _, dryRun := range []bool{false, true} {
			t.Run(test.name, func(t *testing.T) {
				f := newEditFixture(t, "Example", strPtr("body"))
				_, err := f.prepareEditRaw(t, f.snapshotEdit(t), test.request, dryRun)
				if !test.refused {
					if err != nil {
						t.Fatal(err)
					}
					return
				}
				requireRefusal(t, err, "OPERATOR_TEXT_UNCHANGED", errx.CodeUsage)
			})
		}
	}
}

func TestOperatorIssueEditAppliesExactBody(t *testing.T) {
	tests := []struct {
		name, request, body string
		summary             string
		description         *string
	}{
		{"summary only", `{"kind":"issue.edit","summary":"New summary"}`, `{"summary":"New summary"}`, "New summary", strPtr("body")},
		{"description only", `{"kind":"issue.edit","description":"New\nbody"}`, `{"description":"New\nbody"}`, "Example", strPtr("New\nbody")},
		{"both", `{"kind":"issue.edit","summary":"New summary","description":"New body"}`, `{"summary":"New summary","description":"New body"}`, "New summary", strPtr("New body")},
		{"description from null", `{"kind":"issue.edit","description":"First"}`, `{"description":"First"}`, "Example", strPtr("First")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			current := strPtr("body")
			if test.name == "description from null" {
				current = nil
			}
			f := newEditFixture(t, "Example", current)
			plan := f.prepareEdit(t, test.request)
			if plan.PlanVersion != operatorwrite.PlanVersion4 || plan.Plan.Snapshot.Text == nil {
				t.Fatalf("plan=%#v", plan)
			}
			transport := &methodTransport{next: f.service.HTTP}
			f.service.HTTP = transport
			f.postStatus, f.postBody = http.StatusOK, editIssue(test.summary, test.description, 3)
			applied, err := f.apply(t, plan)
			if err != nil || applied.State != string(operatorwrite.StateApplied) || applied.RemoteID != "2-12" || f.posts.Load() != 1 {
				t.Fatalf("apply=%#v err=%v posts=%d", applied, err, f.posts.Load())
			}
			if len(transport.bodies) != 1 || transport.bodies[0] != test.body || transport.posts[0] != "/api/issues/2-12" {
				t.Fatalf("posts=%q bodies=%q", transport.posts, transport.bodies)
			}
			_, err = f.apply(t, plan)
			requireRefusal(t, err, "OPERATOR_PLAN_CONSUMED", errx.CodeConflict)
			if f.posts.Load() != 1 {
				t.Fatalf("second apply posted: %d", f.posts.Load())
			}
			status, err := f.service.OperatorWriteStatus(t.Context(), plan.PlanID)
			if err != nil || status.State != string(operatorwrite.StateApplied) || !status.NonReplayable {
				t.Fatalf("status=%#v err=%v", status, err)
			}
		})
	}
}

func TestOperatorIssueEditStaleBeforeClaim(t *testing.T) {
	tests := []struct {
		name  string
		issue string
	}{
		{"description changed with same updated", editIssue("Example", strPtr("edited elsewhere"), 2)},
		{"summary changed with same updated", editIssue("Edited elsewhere", strPtr("body"), 2)},
		{"description cleared with same updated", editIssue("Example", nil, 2)},
		{"updated changed with same text", editIssue("Example", strPtr("body"), 3)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newEditFixture(t, "Example", strPtr("body"))
			plan := f.prepareEdit(t, `{"kind":"issue.edit","summary":"New summary"}`)
			f.setIssue(test.issue)
			f.postStatus, f.postBody = http.StatusOK, editIssue("New summary", strPtr("body"), 4)
			_, err := f.apply(t, plan)
			requireRefusal(t, err, "OPERATOR_ISSUE_STALE", errx.CodeConflict)
			if f.posts.Load() != 0 {
				t.Fatalf("stale apply posted %d times", f.posts.Load())
			}
			status, statusErr := f.service.OperatorWriteStatus(t.Context(), plan.PlanID)
			if statusErr != nil || status.State != string(operatorwrite.StatePrepared) || status.NonReplayable {
				t.Fatalf("stale apply consumed the plan: %#v %v", status, statusErr)
			}
		})
	}
}

func TestOperatorIssueEditTransportFailureAfterClaimIsUnknownWithoutReplay(t *testing.T) {
	f := newEditFixture(t, "Example", strPtr("body"))
	plan := f.prepareEdit(t, `{"kind":"issue.edit","summary":"New summary"}`)
	transport := &methodTransport{next: f.service.HTTP, failPOST: true}
	f.service.HTTP = transport
	_, err := f.apply(t, plan)
	if operatorReason(t, err) != "WRITE_OUTCOME_UNKNOWN" {
		t.Fatalf("err=%v", err)
	}
	status, statusErr := f.service.OperatorWriteStatus(t.Context(), plan.PlanID)
	if statusErr != nil || status.State != string(operatorwrite.StateUnknown) || !status.NonReplayable {
		t.Fatalf("status=%#v err=%v", status, statusErr)
	}
	transport.failPOST = false
	_, err = f.apply(t, plan)
	requireRefusal(t, err, "OPERATOR_PLAN_CONSUMED", errx.CodeConflict)
	if len(transport.posts) != 1 || f.posts.Load() != 0 {
		t.Fatalf("posts attempted=%d server posts=%d", len(transport.posts), f.posts.Load())
	}
}

func TestOperatorIssueEditServerNormalisationIsUnknownOutcome(t *testing.T) {
	tests := []struct {
		name, request, response string
	}{
		{"summary normalised", `{"kind":"issue.edit","summary":"New summary"}`, editIssue("New summary (normalised)", strPtr("body"), 3)},
		{"description trimmed", `{"kind":"issue.edit","description":"New body"}`, editIssue("Example", strPtr("New body."), 3)},
		{"description missing", `{"kind":"issue.edit","description":"New body"}`, editIssue("Example", nil, 3)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newEditFixture(t, "Example", strPtr("body"))
			plan := f.prepareEdit(t, test.request)
			f.postStatus, f.postBody = http.StatusOK, test.response
			_, err := f.apply(t, plan)
			if operatorReason(t, err) != "WRITE_OUTCOME_UNKNOWN" || f.posts.Load() != 1 {
				t.Fatalf("err=%v posts=%d", err, f.posts.Load())
			}
			status, statusErr := f.service.OperatorWriteStatus(t.Context(), plan.PlanID)
			if statusErr != nil || status.State != string(operatorwrite.StateUnknown) {
				t.Fatalf("status=%#v err=%v", status, statusErr)
			}
		})
	}
}

func TestOperatorIssueEditReconcileIsGetOnly(t *testing.T) {
	tests := []struct {
		name     string
		observed string
		evidence string
	}{
		{"desired text observed", editIssue("New summary", strPtr("New body"), 3), "desired_value_observed_without_causal_proof"},
		{"old text still present", editIssue("Example", strPtr("body"), 2), "inconclusive"},
		{"only summary applied", editIssue("New summary", strPtr("body"), 3), "inconclusive"},
		{"description absent", editIssue("New summary", nil, 3), "inconclusive"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newEditFixture(t, "Example", strPtr("body"))
			plan := f.prepareEdit(t, `{"kind":"issue.edit","summary":"New summary","description":"New body"}`)
			f.postStatus, f.postBody = http.StatusTooManyRequests, `{"error":"sentinel"}`
			if _, err := f.apply(t, plan); operatorReason(t, err) != "WRITE_OUTCOME_UNKNOWN" {
				t.Fatalf("err=%v", err)
			}
			f.setIssue(test.observed)
			transport := &methodTransport{next: f.service.HTTP}
			f.service.HTTP = transport
			reconciled, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: plan.PlanID, Limit: 2})
			if err != nil || reconciled.State != string(operatorwrite.StateOperatorRequired) || reconciled.Evidence != test.evidence || !reconciled.NonReplayable {
				t.Fatalf("reconcile=%#v err=%v", reconciled, err)
			}
			for _, method := range transport.methods {
				if method != http.MethodGet {
					t.Fatalf("reconcile used %s", method)
				}
			}
			if len(transport.methods) == 0 || f.posts.Load() != 1 {
				t.Fatalf("methods=%v posts=%d", transport.methods, f.posts.Load())
			}
		})
	}
}

// TestOperatorIssueEditNeverStoresOrPrintsOldText runs the whole lifecycle with
// distinctive old text and scans every output and local file for it.
func TestOperatorIssueEditNeverStoresOrPrintsOldText(t *testing.T) {
	const newSummary, newDescription = "NEW_SUMMARY_TEXT", "NEW_DESCRIPTION_TEXT"
	f := newEditFixture(t, oldSummarySentinel, strPtr(oldDescriptionSentinel))
	var outputs []string
	collect := func(label string, value any, err error) {
		t.Helper()
		raw, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		outputs = append(outputs, label+":"+string(raw))
		if err != nil {
			outputs = append(outputs, label+" error:"+err.Error())
			var typed *errx.Error
			if errors.As(err, &typed) {
				outputs = append(outputs, label+" hint:"+typed.Hint)
			}
		}
	}
	snapshot := f.snapshotEdit(t)
	collect("snapshot", snapshot, nil)
	dry, dryErr := f.prepareEditRaw(t, snapshot, `{"kind":"issue.edit","summary":"`+newSummary+`","description":"`+newDescription+`"}`, true)
	collect("dry-run", dry, dryErr)
	if dryErr != nil {
		t.Fatal(dryErr)
	}
	plan := f.prepareEdit(t, `{"kind":"issue.edit","summary":"`+newSummary+`","description":"`+newDescription+`"}`)
	collect("prepare", plan, nil)
	raw, err := json.Marshal(plan.Plan)
	if err != nil || !strings.Contains(string(raw), newSummary) || !strings.Contains(string(raw), newDescription) {
		t.Fatalf("plan does not carry the new text: %s %v", raw, err)
	}

	// A stale apply must not leak the current text either.
	f.setIssue(editIssue(oldSummarySentinel, strPtr("CURRENT_OTHER_SENTINEL"), 2))
	_, staleErr := f.apply(t, plan)
	collect("stale", OperatorWriteInfo{}, staleErr)
	requireRefusal(t, staleErr, "OPERATOR_ISSUE_STALE", errx.CodeConflict)
	f.setIssue(editIssue(oldSummarySentinel, strPtr(oldDescriptionSentinel), 2))

	f.postStatus, f.postBody = http.StatusOK, editIssue(newSummary, strPtr(newDescription), 3)
	applied, err := f.apply(t, plan)
	collect("apply", applied, err)
	if err != nil {
		t.Fatal(err)
	}
	status, err := f.service.OperatorWriteStatus(t.Context(), plan.PlanID)
	collect("status", status, err)
	reconciled, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: plan.PlanID, Limit: 2})
	collect("reconcile", reconciled, err)
	_, replayErr := f.apply(t, plan)
	collect("replay", OperatorWriteInfo{}, replayErr)

	forbidden := []string{oldSummarySentinel, oldDescriptionSentinel, "CURRENT_OTHER_SENTINEL", "OPERATOR_EDIT_TEST_SENTINEL"}
	for _, output := range outputs {
		for _, sentinel := range forbidden {
			if strings.Contains(output, sentinel) {
				t.Fatalf("%q leaked into %.200s", sentinel, output)
			}
		}
	}
	scanned := 0
	err = filepath.WalkDir(f.dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		scanned++
		for _, sentinel := range forbidden {
			if strings.Contains(string(content), sentinel) {
				t.Errorf("%q leaked into local file %s", sentinel, filepath.Base(path))
			}
		}
		return nil
	})
	if err != nil || scanned == 0 {
		t.Fatalf("scanned=%d err=%v", scanned, err)
	}
}
