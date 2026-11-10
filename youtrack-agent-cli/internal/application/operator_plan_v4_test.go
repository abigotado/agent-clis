package application

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/operatorwrite"
)

// recordingTransport keeps the bodies of mutating requests so a test can pin
// the exact payload the plan dispatched.
type recordingTransport struct {
	next   http.RoundTripper
	mu     sync.Mutex
	bodies []string
}

func (r *recordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method == http.MethodPost && request.Body != nil {
		raw, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		if err := request.Body.Close(); err != nil {
			return nil, err
		}
		r.mu.Lock()
		r.bodies = append(r.bodies, string(raw))
		r.mu.Unlock()
		request.Body = io.NopCloser(strings.NewReader(string(raw)))
	}
	return r.next.RoundTrip(request)
}

const openStageIssueValue = `"value":{"id":"101-1","name":"Open","$type":"StateBundleElement"}`

// prepareClear snapshots a State field that currently holds "Open", turns the
// frozen target into an explicit clear and prepares the plan through the
// normal decode path. The CLI cannot request a clear yet; the data model can.
func (f *operatorFixture) prepareClear(t *testing.T) OperatorWriteInfo {
	t.Helper()
	f.issue = strings.Replace(operatorIssueJSON, `"value":null`, openStageIssueValue, 1)
	snapshot, err := f.service.SnapshotOperatorWrite(t.Context(), OperatorSnapshotInput{Profile: "work", Kind: "issue.update", IssueID: "APP-12",
		Fields: []OperatorFieldSelection{{FieldID: "92-1", ValueID: "101-2"}}})
	if err != nil {
		t.Fatal(err)
	}
	field := *snapshot.Snapshot.Field
	field.TargetValue = nil
	frozen := *snapshot.Snapshot
	frozen.Field = &field
	raw, err := json.Marshal(frozen)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := f.service.PrepareOperatorWrite(t.Context(), OperatorPrepareInput{Profile: "work", SnapshotJSON: raw, RequestJSON: []byte(`{"kind":"issue.update"}`)})
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func TestOperatorIssueUpdateVersion4EndToEnd(t *testing.T) {
	f := newOperatorFixture(t)
	snapshot, err := f.service.SnapshotOperatorWrite(t.Context(), OperatorSnapshotInput{Profile: "work", Kind: "issue.update", IssueID: "APP-12",
		Fields: []OperatorFieldSelection{{FieldID: "92-1", ValueID: "101-2"}}})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.PlanVersion != operatorwrite.PlanVersion4 || snapshot.PlanLifetime != operatorwrite.CurrentPlanLifetime || snapshot.Snapshot.Version != operatorwrite.Version {
		t.Fatalf("snapshot info version=%d lifetime=%q snapshot version=%d", snapshot.PlanVersion, snapshot.PlanLifetime, snapshot.Snapshot.Version)
	}
	plan := f.prepare(t, "issue.update")
	if plan.PlanVersion != operatorwrite.PlanVersion4 || plan.Plan.Version != operatorwrite.PlanVersion4 || plan.Plan.Snapshot.Version != operatorwrite.Version ||
		plan.Plan.Snapshot.Field.TargetValue == nil || plan.Plan.Snapshot.Field.TargetValue.ID != "101-2" {
		t.Fatalf("prepared plan=%#v", plan.Plan)
	}
	transport := &recordingTransport{next: f.service.HTTP}
	f.service.HTTP = transport
	applied, err := f.service.ApplyOperatorWrite(t.Context(), OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: plan.IntentSHA256, Yes: true})
	if err != nil || applied.State != string(operatorwrite.StateApplied) || applied.PlanVersion != operatorwrite.PlanVersion4 || f.posts.Load() != 1 {
		t.Fatalf("apply=%#v err=%v posts=%d", applied, err, f.posts.Load())
	}
	if len(transport.bodies) != 1 || transport.bodies[0] != `{"customFields":[{"id":"issue-field-7","$type":"StateIssueCustomField","value":{"id":"101-2"}}]}` {
		t.Fatalf("dispatched bodies=%q", transport.bodies)
	}
	status, err := f.service.OperatorWriteStatus(t.Context(), plan.PlanID)
	if err != nil || status.State != string(operatorwrite.StateApplied) || status.PlanVersion != operatorwrite.PlanVersion4 || !status.NonReplayable || status.RemoteID != "2-12" {
		t.Fatalf("status=%#v err=%v", status, err)
	}
	reconciled, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: plan.PlanID, Limit: 2})
	if err != nil || reconciled.State != string(operatorwrite.StateApplied) || reconciled.Evidence != "verified_terminal_record_preserved" || reconciled.PlanVersion != operatorwrite.PlanVersion4 || f.posts.Load() != 1 {
		t.Fatalf("reconcile=%#v err=%v posts=%d", reconciled, err, f.posts.Load())
	}
}

func TestOperatorVersion4UnknownOutcomeFinalizesAndReconciles(t *testing.T) {
	f := newOperatorFixture(t)
	plan := f.prepare(t, "issue.update")
	f.postStatus, f.postBody = 429, `{"error":"sentinel"}`
	_, err := f.service.ApplyOperatorWrite(t.Context(), OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: plan.IntentSHA256, Yes: true})
	if operatorReason(t, err) != "WRITE_OUTCOME_UNKNOWN" {
		t.Fatalf("err=%v", err)
	}
	status, err := f.service.OperatorWriteStatus(t.Context(), plan.PlanID)
	if err != nil || status.State != string(operatorwrite.StateUnknown) || status.PlanVersion != operatorwrite.PlanVersion4 {
		t.Fatalf("status=%#v err=%v", status, err)
	}
	f.mu.Lock()
	f.issue = strings.Replace(operatorIssueJSON, `"value":null`, `"value":{"id":"101-2","name":"Done","$type":"StateBundleElement"}`, 1)
	f.mu.Unlock()
	reconciled, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: plan.PlanID, Limit: 2})
	if err != nil || reconciled.State != string(operatorwrite.StateOperatorRequired) || reconciled.Evidence != "desired_value_observed_without_causal_proof" || f.posts.Load() != 1 {
		t.Fatalf("reconcile=%#v err=%v posts=%d", reconciled, err, f.posts.Load())
	}
}

func TestOperatorClearPlanAppliesNullWithoutNilDereference(t *testing.T) {
	f := newOperatorFixture(t)
	plan := f.prepareClear(t)
	if plan.PlanVersion != operatorwrite.PlanVersion4 || plan.Plan.Snapshot.Field.TargetValue != nil || plan.Plan.Snapshot.Field.CurrentValue == nil {
		t.Fatalf("clear plan=%#v", plan.Plan)
	}
	transport := &recordingTransport{next: f.service.HTTP}
	f.service.HTTP = transport
	f.postStatus, f.postBody = http.StatusOK, operatorIssueJSON
	applied, err := f.service.ApplyOperatorWrite(t.Context(), OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: plan.IntentSHA256, Yes: true})
	if err != nil || applied.State != string(operatorwrite.StateApplied) || f.posts.Load() != 1 {
		t.Fatalf("apply=%#v err=%v posts=%d", applied, err, f.posts.Load())
	}
	if len(transport.bodies) != 1 || transport.bodies[0] != `{"customFields":[{"id":"issue-field-7","$type":"StateIssueCustomField","value":null}]}` {
		t.Fatalf("dispatched bodies=%q", transport.bodies)
	}
}

func TestOperatorClearPlanDriftStopsBeforeClaim(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*operatorFixture)
	}{
		{"current value changed", func(f *operatorFixture) {
			f.issue = strings.Replace(operatorIssueJSON, `"value":null`, `"value":{"id":"101-2","name":"Done","$type":"StateBundleElement"}`, 1)
		}},
		{"field became required", func(f *operatorFixture) {
			f.schema = strings.Replace(f.schema, `"canBeEmpty":true`, `"canBeEmpty":false`, 1)
		}},
		{"field already empty", func(f *operatorFixture) { f.issue = operatorIssueJSON }},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newOperatorFixture(t)
			plan := f.prepareClear(t)
			f.mu.Lock()
			test.mutate(f)
			f.mu.Unlock()
			_, err := f.service.ApplyOperatorWrite(t.Context(), OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: plan.IntentSHA256, Yes: true})
			if got := operatorReason(t, err); got != "OPERATOR_FIELD_STALE" && got != "OPERATOR_ISSUE_STALE" || errx.ExitCode(err) != errx.CodeConflict {
				t.Fatalf("reason=%q code=%d err=%v", got, errx.ExitCode(err), err)
			}
			record, getErr := f.service.OperatorWrites.Get(t.Context(), plan.PlanID)
			if getErr != nil || record.NonReplayable() || f.posts.Load() != 0 {
				t.Fatalf("drift consumed or dispatched: %#v %v posts=%d", record, getErr, f.posts.Load())
			}
		})
	}
}

func TestOperatorReconcileClearTargetNeedsExactNull(t *testing.T) {
	for _, test := range []struct {
		name     string
		value    string
		evidence string
	}{
		{"explicit null", `"value":null`, "desired_value_observed_without_causal_proof"},
		{"previous value still set", openStageIssueValue, "inconclusive"},
		{"missing value member", ``, "inconclusive"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newOperatorFixture(t)
			plan := f.prepareClear(t)
			if _, err := f.service.OperatorWrites.Claim(t.Context(), plan.PlanID, plan.IntentSHA256, f.service.currentTime()); err != nil {
				t.Fatal(err)
			}
			observed := strings.Replace(operatorIssueJSON, `"value":null,`, test.value+",", 1)
			if test.value == "" {
				observed = strings.Replace(operatorIssueJSON, `"value":null,`, "", 1)
			}
			f.mu.Lock()
			f.issue = observed
			f.mu.Unlock()
			result, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: plan.PlanID, Limit: 2})
			if err != nil || result.State != string(operatorwrite.StateOperatorRequired) || result.Evidence != test.evidence || !result.NonReplayable || f.posts.Load() != 0 {
				t.Fatalf("result=%#v err=%v posts=%d", result, err, f.posts.Load())
			}
		})
	}
}

func TestOperatorUpdateInputNeverDereferencesNilTarget(t *testing.T) {
	f := newOperatorFixture(t)
	base := *f.prepare(t, "issue.update").Plan
	for _, test := range []struct {
		name    string
		change  func(*operatorwrite.Plan)
		want    string
		wantErr bool
	}{
		{"bundle target is id only", func(*operatorwrite.Plan) {}, `{"id":"101-2"}`, false},
		{"nil target clears with null", func(p *operatorwrite.Plan) { p.Snapshot.Field.TargetValue = nil }, `null`, false},
		{"user target is id only", func(p *operatorwrite.Plan) {
			p.Snapshot.Field.Type = "SingleUserIssueCustomField"
			p.Snapshot.Field.TargetValue = &operatorwrite.Value{ID: "1-6", Name: "bob", Type: "User"}
		}, `{"id":"1-6"}`, false},
		{"missing field", func(p *operatorwrite.Plan) { p.Snapshot.Field = nil }, ``, true},
		{"invalid issue identity", func(p *operatorwrite.Plan) { p.Snapshot.Issue.ID = "" }, ``, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan := base
			field := *base.Snapshot.Field
			plan.Snapshot.Field = &field
			test.change(&plan)
			input, err := operatorUpdateInput(plan)
			if (err != nil) != test.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, test.wantErr)
			}
			if err != nil {
				return
			}
			if len(input.CustomFields) != 1 || string(input.CustomFields[0].Value) != test.want || input.CustomFields[0].ID != "issue-field-7" {
				t.Fatalf("input=%#v", input)
			}
			encoded, err := json.Marshal(input.CustomFields[0])
			if err != nil || !strings.Contains(string(encoded), `"value":`+test.want) {
				t.Fatalf("encoded=%s err=%v", encoded, err)
			}
		})
	}
}

func TestOperatorFieldValueObserved(t *testing.T) {
	state := operatorwrite.Field{Type: "StateIssueCustomField", TargetValue: &operatorwrite.Value{ID: "101-2", Name: "Done", Type: "StateBundleElement"}}
	user := operatorwrite.Field{Type: "SingleUserIssueCustomField", TargetValue: &operatorwrite.Value{ID: "1-6", Name: "bob", Type: "User"}}
	clearing := operatorwrite.Field{Type: "StateIssueCustomField"}
	for _, test := range []struct {
		name     string
		field    operatorwrite.Field
		observed string
		want     bool
	}{
		{"state matches", state, `{"id":"101-2","name":"Done","$type":"StateBundleElement"}`, true},
		{"state other id", state, `{"id":"101-1","$type":"StateBundleElement"}`, false},
		{"state other type", state, `{"id":"101-2","$type":"EnumBundleElement"}`, false},
		{"state null", state, `null`, false},
		{"state malformed", state, `{`, false},
		{"state empty", state, ``, false},
		{"user matches by id", user, `{"id":"1-6","login":"someone-else","$type":"User"}`, true},
		{"user other id", user, `{"id":"1-7","login":"bob","$type":"User"}`, false},
		{"user wrong type", user, `{"id":"1-6","$type":"StateBundleElement"}`, false},
		{"user untyped", user, `{"id":"1-6"}`, false},
		{"clear matches exact null", clearing, `null`, true},
		{"clear matches padded null", clearing, " null\n", true},
		{"clear missing value", clearing, ``, false},
		{"clear empty object", clearing, `{}`, false},
		{"clear still set", clearing, `{"id":"101-1","$type":"StateBundleElement"}`, false},
		{"clear string null", clearing, `"null"`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := operatorFieldValueObserved(test.field, json.RawMessage(test.observed)); got != test.want {
				t.Fatalf("observed=%v, want %v", got, test.want)
			}
		})
	}
}
