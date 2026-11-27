package application

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/operatorwrite"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/profile"
)

// linkedFixture is a link fixture in which APP-12 already depends on OPS-7.
func newUnlinkFixture(t *testing.T) *linkFixture {
	t.Helper()
	f := newLinkFixtureWith(t, profile.CapabilityRead, profile.CapabilityIssueUnlink)
	f.link("2-12", "105-1", "OUTWARD", "2-19")
	return f
}

func (f *linkFixture) unlinkSnapshot(t *testing.T, change func(*OperatorSnapshotInput)) (OperatorWriteInfo, error) {
	t.Helper()
	input := f.snapshotInput()
	input.Kind = "issue.unlink"
	if change != nil {
		change(&input)
	}
	return f.service.SnapshotOperatorWrite(t.Context(), input)
}

func (f *linkFixture) prepareUnlink(t *testing.T, change func(*OperatorSnapshotInput)) OperatorWriteInfo {
	t.Helper()
	snapshot, err := f.unlinkSnapshot(t, change)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(snapshot.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := f.service.PrepareOperatorWrite(t.Context(), OperatorPrepareInput{Profile: "work", SnapshotJSON: raw, RequestJSON: []byte(`{"kind":"issue.unlink"}`)})
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func (f *linkFixture) deleteCount() int { return int(f.deletes.Load()) }

// getStatusTransport answers GETs of one path with a fixed status.
type getStatusTransport struct {
	next   http.RoundTripper
	path   string
	status int
	mu     sync.Mutex
	hits   int
}

func (g *getStatusTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method == http.MethodGet && request.URL.Path == g.path {
		g.mu.Lock()
		g.hits++
		g.mu.Unlock()
		return &http.Response{StatusCode: g.status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{}`)), Request: request}, nil
	}
	return g.next.RoundTrip(request)
}

// deleteLossTransport fails every DELETE as a connection loss.
type deleteLossTransport struct {
	next    http.RoundTripper
	deletes int
}

func (d *deleteLossTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method == http.MethodDelete {
		d.deletes++
		return nil, errors.New("simulated connection reset")
	}
	return d.next.RoundTrip(request)
}

func TestOperatorIssueUnlinkRemovesTheLinkOnceAndRecordsIt(t *testing.T) {
	f := newUnlinkFixture(t)
	plan := f.prepareUnlink(t, nil)
	wantID := linkEntryID("2-12", "105-1", "OUTWARD")
	link := plan.Plan.Snapshot.Link
	if plan.Kind != "issue.unlink" || plan.PlanVersion != operatorwrite.PlanVersion4 || link == nil || link.LinkID != wantID || plan.LinkID != wantID ||
		plan.TargetIssueID != "2-19" || link.Direction != operatorwrite.LinkOutward || len(plan.Disclosures) != 0 {
		t.Fatalf("plan=%#v link=%#v", plan, link)
	}
	if len(f.nonGET()) != 0 {
		t.Fatalf("snapshot and prepare wrote: %v", f.nonGET())
	}
	applied, err := f.apply(t, plan)
	if err != nil || applied.State != string(operatorwrite.StateApplied) || applied.RemoteID != "2-19" || f.deleteCount() != 1 || f.postCount() != 0 {
		t.Fatalf("applied=%#v err=%v deletes=%d", applied, err, f.deleteCount())
	}
	if got := f.nonGET(); len(got) != 1 || !strings.HasPrefix(got[0], "DELETE /api/issues/2-12/links/"+wantID+"/issues/2-19") {
		t.Fatalf("writes=%q", got)
	}
	_, err = f.apply(t, plan)
	requireRefusal(t, err, "OPERATOR_PLAN_CONSUMED", errx.CodeConflict)
	if f.deleteCount() != 1 {
		t.Fatalf("replay deleted: %d", f.deleteCount())
	}
	f.requireNoSentinel(t, applied, err)
}

func TestOperatorIssueUnlinkDisclosuresAreConditional(t *testing.T) {
	tests := []struct {
		name, linkType, phrase, typeID string
		want                           []string
	}{
		{"plain type", "Depend", "depends on", "105-1", nil},
		{"duplicate", "Duplicate", "duplicates", "105-2", []string{"duplicate_link_removed"}},
		{"aggregation", "Subtask", "parent for", "105-3", []string{"aggregation_parent_removed"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newLinkFixtureWith(t, profile.CapabilityRead, profile.CapabilityIssueUnlink)
			f.link("2-12", test.typeID, "OUTWARD", "2-19")
			plan := f.prepareUnlink(t, func(in *OperatorSnapshotInput) { in.LinkType, in.Direction = test.linkType, test.phrase })
			if strings.Join(plan.Disclosures, ",") != strings.Join(test.want, ",") {
				t.Fatalf("disclosures=%v want %v", plan.Disclosures, test.want)
			}
		})
	}
}

func TestOperatorIssueUnlinkLinkAbsentAtSnapshotIsRefused(t *testing.T) {
	f := newLinkFixtureWith(t, profile.CapabilityRead, profile.CapabilityIssueUnlink)
	_, err := f.unlinkSnapshot(t, nil)
	requireRefusal(t, err, "OPERATOR_LINK_ABSENT", errx.CodeUsage)
	var typed *errx.Error
	if !errors.As(err, &typed) || typed.Hint != "nothing to change; do not retry unchanged" {
		t.Fatalf("hint missing: %#v", err)
	}
	if len(f.nonGET()) != 0 {
		t.Fatalf("snapshot wrote: %v", f.nonGET())
	}
}

func TestOperatorIssueUnlinkPrepareIsOfflineAndDigestMismatchPrecedesCredentials(t *testing.T) {
	f := newUnlinkFixture(t)
	snapshot, err := f.unlinkSnapshot(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(snapshot.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	creds, network := &trapCredentials{}, &trapTransport{}
	f.service.Credentials, f.service.HTTP = creds, network
	plan, err := f.service.PrepareOperatorWrite(t.Context(), OperatorPrepareInput{Profile: "work", SnapshotJSON: raw, RequestJSON: []byte(`{"kind":"issue.unlink"}`)})
	if err != nil || plan.PlanID == "" || creds.calls != 0 || network.calls != 0 {
		t.Fatalf("prepare=%#v err=%v credentials=%d network=%d", plan, err, creds.calls, network.calls)
	}
	for _, mode := range []string{"missing yes", "wrong digest", "missing digest"} {
		input := OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: plan.IntentSHA256, Yes: true}
		switch mode {
		case "missing yes":
			input.Yes = false
		case "wrong digest":
			input.ConfirmIntent = strings.Repeat("a", 64)
		case "missing digest":
			input.ConfirmIntent = ""
		}
		_, err := f.service.ApplyOperatorWrite(t.Context(), input)
		requireRefusal(t, err, "OPERATOR_CONFIRMATION_REQUIRED", errx.CodeConfirm)
		if creds.calls != 0 || network.calls != 0 {
			t.Fatalf("%s reached credentials=%d network=%d", mode, creds.calls, network.calls)
		}
	}
	record, err := f.service.OperatorWrites.Get(t.Context(), plan.PlanID)
	if err != nil || record.NonReplayable() {
		t.Fatalf("refusals consumed the plan: %#v %v", record, err)
	}
}

func TestOperatorIssueUnlinkApplyDriftIsConflictWithZeroDeleteAndPlanUnconsumed(t *testing.T) {
	tests := []struct {
		name   string
		drift  func(*linkFixture)
		reason string
	}{
		{name: "link already removed", drift: func(f *linkFixture) { f.removeLocked("2-12", "105-1", "OUTWARD", "2-19") }, reason: "OPERATOR_LINK_STALE"},
		{name: "link removed from the target side only", drift: func(f *linkFixture) { f.entry("2-12", "105-1", "OUTWARD").issues = nil }, reason: "OPERATOR_LINK_STALE"},
		{name: "link entry id changed", drift: func(f *linkFixture) { f.entry("2-12", "105-1", "OUTWARD").id = "renumbered" }, reason: "OPERATOR_LINK_STALE"},
		{name: "link entry vanished", drift: func(f *linkFixture) { f.entries["2-12"] = f.entries["2-12"][:1] }, reason: "OPERATOR_LINK_STALE"},
		{name: "link type renamed", drift: func(f *linkFixture) { f.types[1]["name"] = "Renamed" }, reason: "OPERATOR_LINK_STALE"},
		{name: "link type deleted (404)", drift: func(f *linkFixture) { f.types = append(f.types[:1:1], f.types[2:]...) }, reason: "OPERATOR_LINK_STALE"},
		{name: "target moved to another project", drift: func(f *linkFixture) { f.issues["2-19"].projectID, f.issues["2-19"].projectKey = "0-3", "APP" }, reason: "OPERATOR_ISSUE_STALE"},
		{name: "source readable id changed", drift: func(f *linkFixture) { f.issues["2-12"].readable = "APP-120" }, reason: "OPERATOR_ISSUE_STALE"},
		{name: "target issue deleted (404)", drift: func(f *linkFixture) { delete(f.issues, "2-19") }, reason: "OPERATOR_LINK_STALE"},
		{name: "source issue deleted (404)", drift: func(f *linkFixture) { delete(f.issues, "2-12") }, reason: "OPERATOR_LINK_STALE"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newUnlinkFixture(t)
			plan := f.prepareUnlink(t, nil)
			f.edit(test.drift)
			_, err := f.apply(t, plan)
			requireRefusal(t, err, test.reason, errx.CodeConflict)
			status, statusErr := f.service.OperatorWriteStatus(t.Context(), plan.PlanID)
			if f.deleteCount() != 0 || statusErr != nil || status.State != string(operatorwrite.StatePrepared) || status.NonReplayable {
				t.Fatalf("drift deleted=%d or consumed the plan: %#v %v", f.deleteCount(), status, statusErr)
			}
			f.requireNoSentinel(t, err)
		})
	}
}

func TestOperatorIssueUnlinkAuthFailuresInLockKeepTheirClassAndDeleteNothing(t *testing.T) {
	tests := []struct {
		name   string
		status int
		reason string
		code   errx.Code
	}{
		{name: "forbidden", status: 403, reason: "PERMISSION_DENIED", code: errx.CodePermission},
		{name: "rate limited", status: 429, reason: "RATE_LIMITED", code: errx.CodeRetryable},
		{name: "unauthorized", status: 401, reason: "AUTHENTICATION_FAILED", code: errx.CodeAuth},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newUnlinkFixture(t)
			plan := f.prepareUnlink(t, nil)
			f.service.HTTP = &getStatusTransport{next: f.service.HTTP, path: "/api/issues/2-19", status: test.status}
			_, err := f.apply(t, plan)
			requireRefusal(t, err, test.reason, test.code)
			status, statusErr := f.service.OperatorWriteStatus(t.Context(), plan.PlanID)
			if f.deleteCount() != 0 || statusErr != nil || status.State != string(operatorwrite.StatePrepared) || status.NonReplayable {
				t.Fatalf("deleted=%d or consumed: %#v %v", f.deleteCount(), status, statusErr)
			}
		})
	}
}

func TestOperatorIssueUnlinkConcurrentApplyDeletesOnce(t *testing.T) {
	f := newUnlinkFixture(t)
	plan := f.prepareUnlink(t, nil)
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
		} else if reason := operatorReason(t, err); reason != "OPERATOR_PLAN_CONSUMED" && reason != "OPERATOR_LINK_STALE" {
			t.Fatalf("loser err=%v", err)
		}
	}
	if succeeded != 1 || f.deleteCount() != 1 {
		t.Fatalf("succeeded=%d deletes=%d errs=%v", succeeded, f.deleteCount(), errs)
	}
}

func TestOperatorIssueUnlinkTransportLossIsUnknownWithoutReplay(t *testing.T) {
	f := newUnlinkFixture(t)
	plan := f.prepareUnlink(t, nil)
	transport := &deleteLossTransport{next: f.service.HTTP}
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
	if transport.deletes != 1 || f.deleteCount() != 0 {
		t.Fatalf("replay attempted: client deletes=%d server deletes=%d", transport.deletes, f.deleteCount())
	}
	f.requireNoSentinel(t, err, status)
}

func TestOperatorIssueUnlinkDeleteOutcomesAreSingleAndClassified(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		noEffect   bool
		setup      func(*linkFixture)
		wantState  operatorwrite.State
		wantReason string
		wantCode   errx.Code
	}{
		{name: "rate limited", status: 429, wantState: operatorwrite.StateUnknown, wantReason: "WRITE_OUTCOME_UNKNOWN", wantCode: errx.CodeConflict},
		{name: "server error", status: 503, wantState: operatorwrite.StateUnknown, wantReason: "WRITE_OUTCOME_UNKNOWN", wantCode: errx.CodeConflict},
		{name: "success that left the link", noEffect: true, wantState: operatorwrite.StateUnknown, wantReason: "WRITE_OUTCOME_UNKNOWN", wantCode: errx.CodeConflict},
		{name: "entry vanished after delete", setup: func(f *linkFixture) { f.deleteDropsEntry = true }, wantState: operatorwrite.StateApplied},
		{name: "entry duplicated after delete", setup: func(f *linkFixture) { f.deleteDuplicatesEntry = true }, wantState: operatorwrite.StateUnknown, wantReason: "WRITE_OUTCOME_UNKNOWN", wantCode: errx.CodeConflict},
		{name: "entry id changed after delete", setup: func(f *linkFixture) { f.deleteRenumbersEntry = true }, wantState: operatorwrite.StateUnknown, wantReason: "WRITE_OUTCOME_UNKNOWN", wantCode: errx.CodeConflict},
		{name: "forbidden", status: 403, wantState: operatorwrite.StateRejected, wantReason: "PERMISSION_DENIED", wantCode: errx.CodePermission},
		{name: "not found", status: 404, wantState: operatorwrite.StateRejected, wantReason: "TARGET_CHANGED", wantCode: errx.CodeConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newUnlinkFixture(t)
			plan := f.prepareUnlink(t, nil)
			f.deleteStatus, f.deleteEffect = test.status, !test.noEffect
			if test.setup != nil {
				test.setup(f)
			}
			_, err := f.apply(t, plan)
			if test.wantReason == "" {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
			} else {
				requireRefusal(t, err, test.wantReason, test.wantCode)
			}
			status, statusErr := f.service.OperatorWriteStatus(t.Context(), plan.PlanID)
			if statusErr != nil || status.State != string(test.wantState) || !status.NonReplayable || f.deleteCount() != 1 {
				t.Fatalf("status=%#v err=%v deletes=%d", status, statusErr, f.deleteCount())
			}
			_, err = f.apply(t, plan)
			requireRefusal(t, err, "OPERATOR_PLAN_CONSUMED", errx.CodeConflict)
			if f.deleteCount() != 1 {
				t.Fatalf("replay deleted: %d", f.deleteCount())
			}
		})
	}
}

// A 2xx whose read-back cannot be made is unknown, never rejected or applied.
func TestOperatorIssueUnlinkReadBackFailureAfterSuccessIsUnknown(t *testing.T) {
	f := newUnlinkFixture(t)
	plan := f.prepareUnlink(t, nil)
	// The first GET of the target after the DELETE fails; the in-lock verify
	// has already read it by then.
	f.service.HTTP = &afterDeleteFailTransport{next: f.service.HTTP}
	_, err := f.apply(t, plan)
	requireRefusal(t, err, "WRITE_OUTCOME_UNKNOWN", errx.CodeConflict)
	status, statusErr := f.service.OperatorWriteStatus(t.Context(), plan.PlanID)
	if statusErr != nil || status.State != string(operatorwrite.StateUnknown) || f.deleteCount() != 1 {
		t.Fatalf("status=%#v err=%v deletes=%d", status, statusErr, f.deleteCount())
	}
}

// afterDeleteFailTransport lets requests through, then fails every GET once a
// DELETE has gone out.
type afterDeleteFailTransport struct {
	next    http.RoundTripper
	mu      sync.Mutex
	deleted bool
}

func (a *afterDeleteFailTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	a.mu.Lock()
	deleted := a.deleted
	if request.Method == http.MethodDelete {
		a.deleted = true
	}
	a.mu.Unlock()
	if deleted && request.Method == http.MethodGet {
		return nil, errors.New("simulated read failure")
	}
	return a.next.RoundTrip(request)
}

func TestOperatorIssueUnlinkReconcileIsGETOnlyAndNeverProvesCausation(t *testing.T) {
	tests := []struct {
		name         string
		setup        func(*linkFixture)
		wantEvidence string
	}{
		{name: "link absent", setup: func(f *linkFixture) { f.removeLocked("2-12", "105-1", "OUTWARD", "2-19") }, wantEvidence: "desired_link_absence_observed_without_causal_proof"},
		{name: "link still present", wantEvidence: "link_still_present"},
		{name: "entry vanished", setup: func(f *linkFixture) { f.entries["2-12"] = nil }, wantEvidence: "inconclusive"},
		{name: "target deleted", setup: func(f *linkFixture) { delete(f.issues, "2-19") }, wantEvidence: "linked_issue_unavailable"},
		{name: "source deleted", setup: func(f *linkFixture) { delete(f.issues, "2-12") }, wantEvidence: "linked_issue_unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newUnlinkFixture(t)
			plan := f.prepareUnlink(t, nil)
			if _, err := f.service.OperatorWrites.Claim(t.Context(), plan.PlanID, plan.IntentSHA256, f.service.currentTime()); err != nil {
				t.Fatal(err)
			}
			if test.setup != nil {
				f.edit(test.setup)
			}
			result, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: plan.PlanID, Limit: 20})
			if err != nil || result.State != string(operatorwrite.StateOperatorRequired) || result.Evidence != test.wantEvidence || !result.NonReplayable {
				t.Fatalf("result=%#v err=%v", result, err)
			}
			if len(f.nonGET()) != 0 || f.deleteCount() != 0 || f.postCount() != 0 {
				t.Fatalf("reconcile wrote: %v", f.nonGET())
			}
			again, err := f.apply(t, plan)
			requireRefusal(t, err, "OPERATOR_PLAN_CONSUMED", errx.CodeConflict)
			f.requireNoSentinel(t, result, again)
		})
	}
}

func TestOperatorIssueUnlinkRequiresItsOwnCapabilityAndSurfacesInCapabilities(t *testing.T) {
	linkOnly := newLinkFixture(t)
	_, err := linkOnly.unlinkSnapshot(t, nil)
	requireRefusal(t, err, "OPERATOR_CAPABILITY_REQUIRED", errx.CodePermission)
	f := newUnlinkFixture(t)
	info, err := f.service.Capabilities(t.Context(), "work")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, kind := range info.Kinds {
		found = found || kind == "issue.unlink"
	}
	if !found {
		t.Fatalf("kinds=%v", info.Kinds)
	}
}
