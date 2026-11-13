package application

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/operatorwrite"
)

const emptyCreateRequestJSON = `{"kind":"issue.create","summary":"New ticket"}`

// nullDescription turns an empty description in a fake issue into JSON null.
func nullDescription(raw string) string {
	return strings.Replace(raw, `"description":""`, `"description":null`, 1)
}

func TestOperatorCreateApplyEmptyDescriptionAcceptsNullEcho(t *testing.T) {
	f := newCreateFixture(t)
	f.set(func() {
		f.postResponse = func([]byte) string {
			issue := matchingIssue("")
			issue.Description = ""
			issue.ValueID = "101-2"
			return nullDescription(issue.json(t))
		}
	})
	p := f.prepare(createStageFields, emptyCreateRequestJSON)
	result, err := f.apply(p)
	if err != nil || result.State != "applied" || f.posts() != 1 {
		t.Fatalf("result=%#v err=%v posts=%d", result, err, f.posts())
	}
}

func TestOperatorCreateApplyEmptyDescriptionRefusesAForeignDescription(t *testing.T) {
	f := newCreateFixture(t)
	f.set(func() {
		f.postResponse = func([]byte) string {
			issue := matchingIssue("")
			issue.Description = "something the server invented"
			return issue.json(t)
		}
	})
	p := f.prepare(createStageFields, emptyCreateRequestJSON)
	_, err := f.apply(p)
	requireFailure(t, err, "WRITE_OUTCOME_UNKNOWN", errx.CodeConflict)
	if record := f.record(p.PlanID); record.State != operatorwrite.StateUnknown || f.posts() != 1 {
		t.Fatalf("record=%#v posts=%d", record, f.posts())
	}
}

func TestOperatorCreateReconcileEmptyDescriptionPlan(t *testing.T) {
	for _, test := range []struct {
		name         string
		description  string
		null         bool
		wantEvidence string
	}{
		{"observed null", "", true, "matching_issue_observed_without_causal_proof"},
		{"observed empty", "", false, "matching_issue_observed_without_causal_proof"},
		{"observed non-empty never matches", "unrelated text", false, "inconclusive"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCreateFixture(t)
			p := f.prepare(createStageFields, emptyCreateRequestJSON)
			f.set(func() { f.postStatus, f.postBody = 500, "boom" })
			_, err := f.apply(p)
			requireFailure(t, err, "WRITE_OUTCOME_UNKNOWN", errx.CodeConflict)
			issue := matchingIssue(p.PlanID)
			issue.Description = test.description
			raw := issue.json(t)
			if test.null {
				raw = nullDescription(raw)
			}
			f.set(func() { f.search, f.issues["2-99"] = "["+raw+"]", raw })
			result, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: p.PlanID, Limit: 5})
			if err != nil || result.Evidence != test.wantEvidence || result.RemoteID != "" {
				t.Fatalf("result=%#v err=%v", result, err)
			}
		})
	}
}

func TestOperatorCreateReconcileNeverLaundersAContentMatch(t *testing.T) {
	f := newCreateFixture(t)
	p := unknownCreate(t, f, false)
	match := matchingIssue(p.PlanID)
	f.set(func() { f.search, f.issues["2-99"] = issueList(t, match), match.json(t) })
	for run := 1; run <= 2; run++ {
		result, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: p.PlanID, Limit: 5})
		if err != nil || result.State != string(operatorwrite.StateOperatorRequired) || result.RemoteID != "" || result.Evidence != "matching_issue_observed_without_causal_proof" {
			t.Fatalf("run %d result=%#v err=%v", run, result, err)
		}
		// The second run must search again: a stored ID would have made it a
		// causal exact read.
		if f.searches() != run || f.count(http.MethodGet, "/api/issues/2-99") != run {
			t.Fatalf("run %d searches=%d exact=%d", run, f.searches(), f.count(http.MethodGet, "/api/issues/2-99"))
		}
		if record := f.record(p.PlanID); record.Result == nil || record.Result.RemoteID != "" || record.Result.RemoteReadableID != "" || record.State != operatorwrite.StateOperatorRequired {
			t.Fatalf("stored record=%#v", record)
		}
	}
	if f.posts() != 1 {
		t.Fatalf("posts=%d", f.posts())
	}
}

func TestOperatorCreateReconcileOversizedSearchPageLeavesTheRecordUnchanged(t *testing.T) {
	f := newCreateFixture(t)
	p := unknownCreate(t, f, false)
	huge := `[{"id":"2-1","summary":"` + strings.Repeat("a", 5<<20) + `"}]`
	f.set(func() { f.search = huge })
	if _, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: p.PlanID, Limit: 5}); err == nil {
		t.Fatal("oversized page was accepted")
	}
	if record := f.record(p.PlanID); record.State != operatorwrite.StateUnknown || f.posts() != 1 {
		t.Fatalf("record=%#v posts=%d", record, f.posts())
	}
}

func TestOperatorCreateReconcileSearchQueryCarriesNoOperatorText(t *testing.T) {
	f := newCreateFixture(t)
	p := f.prepare(createStageFields, `{"kind":"issue.create","summary":"SENTINEL_SUMMARY","description":"SENTINEL_BODY"}`)
	f.set(func() { f.postStatus, f.postBody = 500, "boom" })
	_, _ = f.apply(p)
	if _, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: p.PlanID, Limit: 5}); err != nil {
		t.Fatal(err)
	}
	search, ok := f.last(http.MethodGet, "/api/issues")
	if !ok {
		t.Fatal("no search")
	}
	for _, leaked := range []string{"SENTINEL", p.PlanID, "alice", "OPERATOR_CREATE_SENTINEL"} {
		if strings.Contains(search.query.Get("query"), leaked) {
			t.Fatalf("search query carries %q: %s", leaked, search.query.Get("query"))
		}
	}
}

func TestOperatorCreateReconcileMarkerPlansUnchanged(t *testing.T) {
	f := newCreateFixture(t)
	snapshot, err := f.snapshot(createStageFields)
	if err != nil {
		t.Fatal(err)
	}
	p := storeMarkerPlan(t, f.service, *snapshot.Snapshot, operatorwrite.Request{Kind: operatorwrite.KindIssueCreate, Summary: "New ticket", Description: "Line one"}, operatorwrite.PlanVersion4)
	f.set(func() { f.postStatus, f.postBody = 500, "boom" })
	if _, err := f.apply(p); err == nil || f.posts() != 1 {
		t.Fatalf("apply err=%v posts=%d", err, f.posts())
	}
	match := matchingIssue(p.PlanID)
	match.Description = "Line one\n\n" + operatorwrite.Marker(p.PlanID)
	f.set(func() { f.search, f.issues["2-99"] = issueList(t, match), match.json(t) })
	result, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: p.PlanID, Limit: 5})
	if err != nil || result.State != string(operatorwrite.StateReconciled) || result.Evidence != "matching_issue_observed" || result.RemoteID != "2-99" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	search, _ := f.last(http.MethodGet, "/api/issues")
	if search.query.Get("query") != `project: APP "`+p.PlanID+`"` {
		t.Fatalf("marker plan query=%q", search.query.Get("query"))
	}
	// The marker was posted exactly as frozen.
	post, _ := f.last(http.MethodPost, "/api/issues")
	if !strings.Contains(string(post.body), operatorwrite.Marker(p.PlanID)) {
		t.Fatalf("marker plan body lost its marker: %s", post.body)
	}
}

func TestOperatorApplyCommentV5SendsTextVerbatim(t *testing.T) {
	f := newOperatorFixture(t)
	p := f.prepare(t, "comment.add")
	if p.Plan.Version != operatorwrite.PlanVersion5 || p.Plan.Request.CommentText != "Full body\n\nUNTRUSTED content" {
		t.Fatalf("plan=%#v", p.Plan)
	}
	if _, err := f.service.ApplyOperatorWrite(t.Context(), OperatorApplyInput{Profile: "work", PlanID: p.PlanID, ConfirmIntent: p.IntentSHA256, Yes: true}); err != nil {
		t.Fatal(err)
	}
	if f.commentText != "Full body\n\nUNTRUSTED content" || strings.Contains(f.commentText, "operator-write") {
		t.Fatalf("posted text=%q", f.commentText)
	}
}

func TestOperatorReconcileCommentV5ByContent(t *testing.T) {
	claim := time.Date(2026, time.November, 13, 12, 0, 0, 0, time.UTC)
	after, before := claim.UnixMilli()+1000, claim.UnixMilli()-1000
	const text = "Full body\n\nUNTRUSTED content"
	comment := func(id, author string, created int64, mutate func(map[string]any)) map[string]any {
		c := operatorComment(text, id, author)
		c["created"] = created
		if mutate != nil {
			mutate(c)
		}
		return c
	}
	for _, test := range []struct {
		name         string
		comments     []map[string]any
		exactDeleted bool
		wantEvidence string
		wantExact    int32
	}{
		{"one match", []map[string]any{comment("4-1", "1-2", after, nil)}, false, "matching_comment_observed_without_causal_proof", 1},
		{"zero", []map[string]any{}, false, "inconclusive", 0},
		{"two identical", []map[string]any{comment("4-1", "1-2", after, nil), comment("4-2", "1-2", after, nil)}, false, "inconclusive", 0},
		{"older identical before the claim", []map[string]any{comment("4-1", "1-2", before, nil)}, false, "inconclusive", 0},
		{"older identical beside a match", []map[string]any{comment("4-3", "1-2", before, nil), comment("4-1", "1-2", after, nil)}, false, "matching_comment_observed_without_causal_proof", 1},
		{"over the limit", []map[string]any{comment("4-1", "1-2", after, nil), operatorComment("other", "4-2", "1-2"), operatorComment("another", "4-3", "1-2")}, false, "inconclusive", 0},
		{"deleted identical twin", []map[string]any{comment("4-1", "1-2", after, nil), comment("4-2", "1-2", after, func(c map[string]any) { c["deleted"] = true })}, false, "inconclusive", 0},
		{"restricted identical twin", []map[string]any{comment("4-1", "1-2", after, nil), comment("4-2", "1-2", after, func(c map[string]any) { c["visibility"] = map[string]string{"$type": "LimitedVisibility"} })}, false, "inconclusive", 0},
		{"other author", []map[string]any{comment("4-1", "1-3", after, nil)}, false, "inconclusive", 0},
		{"exact read reports a deleted comment", []map[string]any{comment("4-1", "1-2", after, nil)}, true, "inconclusive", 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newOperatorFixture(t)
			f.commentSkip = "0"
			f.service.Now = func() time.Time { return claim }
			p := f.prepare(t, "comment.add")
			attempt, err := f.service.OperatorWrites.Claim(t.Context(), p.PlanID, p.IntentSHA256, claim)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.service.OperatorWrites.Finalize(t.Context(), p.PlanID, attempt, operatorwrite.Result{State: operatorwrite.StateUnknown, Code: "WRITE_OUTCOME_UNKNOWN"}, claim); err != nil {
				t.Fatal(err)
			}
			f.comments = test.comments
			exact := comment("4-1", "1-2", after, func(c map[string]any) { c["deleted"] = test.exactDeleted })
			raw, err := json.Marshal(exact)
			if err != nil {
				t.Fatal(err)
			}
			f.exactCommentBody = string(raw)
			for run := 1; run <= 2; run++ {
				result, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: p.PlanID, Limit: 2})
				if err != nil || result.State != string(operatorwrite.StateOperatorRequired) || result.Evidence != test.wantEvidence || result.RemoteID != "" || result.CommentID != "" {
					t.Fatalf("run %d result=%#v err=%v", run, result, err)
				}
				if f.pages.Load() != int32(run) || f.exactComments.Load() != test.wantExact*int32(run) || f.posts.Load() != 0 {
					t.Fatalf("run %d pages=%d exact=%d posts=%d", run, f.pages.Load(), f.exactComments.Load(), f.posts.Load())
				}
			}
			if record, err := f.service.OperatorWrites.Get(t.Context(), p.PlanID); err != nil || record.Result == nil || record.Result.RemoteID != "" {
				t.Fatalf("stored record=%#v err=%v", record, err)
			}
		})
	}
}

func TestOperatorReconcileCommentV5RefusesAnOffsetBeforeAnyRequest(t *testing.T) {
	f := newOperatorFixture(t)
	p := f.prepare(t, "comment.add")
	if _, err := f.service.OperatorWrites.Claim(t.Context(), p.PlanID, p.IntentSHA256, f.service.currentTime()); err != nil {
		t.Fatal(err)
	}
	creds, network := &trapCredentials{}, &trapTransport{}
	f.service.Credentials, f.service.HTTP = creds, network
	_, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: p.PlanID, Limit: 2, Offset: 1})
	if errx.ExitCode(err) != errx.CodeUsage || creds.calls != 0 || network.calls != 0 {
		t.Fatalf("err=%v credentials=%d network=%d", err, creds.calls, network.calls)
	}
}

func TestOperatorCreateOmittedDescriptionMemberIsNotAnEmptyDescription(t *testing.T) {
	omit := func(raw string) string { return strings.Replace(raw, `"description":"",`, ``, 1) }
	t.Run("apply response", func(t *testing.T) {
		f := newCreateFixture(t)
		f.set(func() {
			f.postResponse = func([]byte) string {
				issue := matchingIssue("")
				issue.Description, issue.ValueID = "", "101-2"
				return omit(issue.json(t))
			}
		})
		p := f.prepare(createStageFields, emptyCreateRequestJSON)
		_, err := f.apply(p)
		requireFailure(t, err, "WRITE_OUTCOME_UNKNOWN", errx.CodeConflict)
	})
	t.Run("reconcile search and exact read", func(t *testing.T) {
		f := newCreateFixture(t)
		p := f.prepare(createStageFields, emptyCreateRequestJSON)
		f.set(func() { f.postStatus, f.postBody = 500, "boom" })
		_, err := f.apply(p)
		requireFailure(t, err, "WRITE_OUTCOME_UNKNOWN", errx.CodeConflict)
		issue := matchingIssue(p.PlanID)
		issue.Description = ""
		raw := omit(issue.json(t))
		f.set(func() { f.search, f.issues["2-99"] = "["+raw+"]", raw })
		result, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: p.PlanID, Limit: 5})
		if err != nil || result.Evidence != "inconclusive" {
			t.Fatalf("result=%#v err=%v", result, err)
		}
	})
}

func TestOperatorReconcileCommentV5KeptIDIsCausal(t *testing.T) {
	f := newOperatorFixture(t)
	p := f.prepare(t, "comment.add")
	attempt, err := f.service.OperatorWrites.Claim(t.Context(), p.PlanID, p.IntentSHA256, f.service.currentTime())
	if err != nil {
		t.Fatal(err)
	}
	f.commentText = p.Plan.Request.CommentText
	if _, err := f.service.OperatorWrites.Finalize(t.Context(), p.PlanID, attempt, operatorwrite.Result{State: operatorwrite.StateUnknown, Code: "WRITE_OUTCOME_UNKNOWN", RemoteID: "4-1"}, f.service.currentTime()); err != nil {
		t.Fatal(err)
	}
	result, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: p.PlanID, Limit: 2, Offset: 7})
	if err != nil || result.State != string(operatorwrite.StateReconciled) || result.Evidence != "matching_comment_observed" || result.RemoteID != "4-1" || f.pages.Load() != 0 || f.exactComments.Load() != 1 {
		t.Fatalf("result=%#v err=%v pages=%d exact=%d", result, err, f.pages.Load(), f.exactComments.Load())
	}
}
