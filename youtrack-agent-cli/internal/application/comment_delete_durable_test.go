package application

import (
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/operatorwrite"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/profile"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/writepolicy"
)

type commentDeleteExactNotFoundTransport struct {
	base http.RoundTripper
	gets atomic.Int32
}

func (transport *commentDeleteExactNotFoundTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method == http.MethodGet && request.URL.Path == "/api/issues/2-12/comments/4-1" {
		transport.gets.Add(1)
		return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("not found")), Request: request}, nil
	}
	return transport.base.RoundTrip(request)
}

func TestCommentDeleteRestartedUnknownWithMissingTargetRequiresResolution(t *testing.T) {
	fixture := newOperatorFixture(t)
	enableCommentDelete(t, fixture)
	plan := prepareCommentDelete(t, fixture)
	base := fixture.service.HTTP
	delete := &deleteTransport{base: base, status: http.StatusTooManyRequests}
	fixture.service.HTTP = delete
	if _, err := fixture.service.ApplyOperatorWrite(t.Context(), OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: plan.IntentSHA256, Yes: true}); operatorReason(t, err) != "WRITE_OUTCOME_UNKNOWN" {
		t.Fatalf("ApplyOperatorWrite() error=%v", err)
	}

	// Reopen the durable ledger as a new process would, then provide only an
	// absent exact comment observation. Neither absence nor unrelated comments
	// can prove a hard delete applied.
	fixture.service.OperatorWrites = operatorwrite.New(filepath.Dir(fixture.service.OperatorWrites.Root()))
	fixture.mu.Lock()
	fixture.comments = []map[string]any{operatorComment("unrelated", "4-2", "1-9")}
	fixture.mu.Unlock()
	notFound := &commentDeleteExactNotFoundTransport{base: base}
	fixture.service.HTTP = notFound
	result, err := fixture.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: plan.PlanID, Limit: 3, Offset: 7})
	if err != nil || result.State != string(operatorwrite.StateOperatorRequired) || result.Evidence != "hard_delete_not_proven" ||
		delete.calls.Load() != 1 || notFound.gets.Load() != 1 || fixture.pages.Load() != 0 {
		t.Fatalf("reconcile=%#v err=%v delete=%d exact_get=%d pages=%d", result, err, delete.calls.Load(), notFound.gets.Load(), fixture.pages.Load())
	}
	if _, err := fixture.service.ApplyOperatorWrite(t.Context(), OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: plan.IntentSHA256, Yes: true}); operatorReason(t, err) != "OPERATOR_PLAN_CONSUMED" || delete.calls.Load() != 1 {
		t.Fatalf("replay error=%v delete=%d", err, delete.calls.Load())
	}
}

func TestCommentDeleteStaleRemoteTargetDoesNotDispatch(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*operatorFixture)
	}{
		{
			name: "issue update timestamp changed",
			mutate: func(fixture *operatorFixture) {
				fixture.issue = strings.Replace(fixture.issue, `"updated":2`, `"updated":3`, 1)
			},
		},
		{
			name: "comment became pinned",
			mutate: func(fixture *operatorFixture) {
				fixture.exactCommentBody = strings.Replace(deleteCommentFixture, `"pinned":false`, `"pinned":true`, 1)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOperatorFixture(t)
			enableCommentDelete(t, fixture)
			plan := prepareCommentDelete(t, fixture)
			fixture.mu.Lock()
			test.mutate(fixture)
			fixture.mu.Unlock()
			transport := &deleteTransport{base: fixture.service.HTTP}
			fixture.service.HTTP = transport

			if _, err := fixture.service.ApplyOperatorWrite(t.Context(), OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: plan.IntentSHA256, Yes: true}); err == nil {
				t.Fatal("ApplyOperatorWrite() accepted a stale deletion target")
			}
			record, err := fixture.service.OperatorWrites.Get(t.Context(), plan.PlanID)
			if err != nil || record.NonReplayable() || transport.calls.Load() != 0 {
				t.Fatalf("record=%#v err=%v delete=%d", record, err, transport.calls.Load())
			}
		})
	}
}

func prepareCommentDeleteWithPermission(t *testing.T, fixture *operatorFixture, wantPermission string) OperatorWriteInfo {
	t.Helper()
	snapshot, err := fixture.service.SnapshotOperatorWrite(t.Context(), OperatorSnapshotInput{Profile: "work", Kind: "comment.delete", IssueID: "APP-12", CommentID: "4-1"})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Snapshot.Comment == nil || snapshot.Snapshot.Comment.RequiredServerPermission != wantPermission {
		t.Fatalf("snapshot=%#v", snapshot)
	}
	raw, err := json.Marshal(snapshot.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := fixture.service.PrepareOperatorWrite(t.Context(), OperatorPrepareInput{Profile: "work", SnapshotJSON: raw, RequestJSON: []byte(`{"kind":"comment.delete"}`)})
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func TestCommentDeleteFreezesOwnAndOtherPermissionBeforeExactDispatch(t *testing.T) {
	tests := []struct {
		name           string
		commentBody    string
		wantPermission string
	}{
		{name: "own comment requires delete comment", commentBody: deleteCommentFixture, wantPermission: "Delete Comment"},
		{name: "other comment requires delete not own comment", commentBody: strings.Replace(deleteCommentFixture, `"id":"1-2"`, `"id":"1-3"`, 1), wantPermission: "Delete Not Own Comment"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOperatorFixture(t)
			enableCommentDelete(t, fixture)
			fixture.exactCommentBody = test.commentBody
			plan := prepareCommentDeleteWithPermission(t, fixture, test.wantPermission)
			if plan.Plan.Snapshot.Comment.RequiredServerPermission != test.wantPermission {
				t.Fatalf("frozen permission=%q, want %q", plan.Plan.Snapshot.Comment.RequiredServerPermission, test.wantPermission)
			}
			transport := &deleteTransport{base: fixture.service.HTTP}
			fixture.service.HTTP = transport
			result, err := fixture.service.ApplyOperatorWrite(t.Context(), OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: plan.IntentSHA256, Yes: true})
			if err != nil || result.State != string(operatorwrite.StateApplied) || result.RemoteID != "4-1" || transport.calls.Load() != 1 {
				t.Fatalf("result=%#v err=%v delete=%d", result, err, transport.calls.Load())
			}
		})
	}
}

func TestCommentDeleteLocalDenialsDoNotDispatch(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *operatorFixture)
		input  func(OperatorWriteInfo) OperatorApplyInput
	}{
		{
			name:   "missing consent",
			mutate: func(*testing.T, *operatorFixture) {},
			input: func(plan OperatorWriteInfo) OperatorApplyInput {
				return OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: plan.IntentSHA256}
			},
		},
		{
			name: "policy revision makes binding stale",
			mutate: func(t *testing.T, fixture *operatorFixture) {
				selected, err := fixture.service.Profiles.Get(t.Context(), "work")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := fixture.service.Policies.Set(t.Context(), selected, []writepolicy.Project{{ID: "0-3", Key: "APP"}}); err != nil {
					t.Fatal(err)
				}
			},
			input: func(plan OperatorWriteInfo) OperatorApplyInput {
				return OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: plan.IntentSHA256, Yes: true}
			},
		},
		{
			name: "capability removed",
			mutate: func(t *testing.T, fixture *operatorFixture) {
				selected, err := fixture.service.Profiles.Get(t.Context(), "work")
				if err != nil {
					t.Fatal(err)
				}
				selected.Capabilities = []profile.Capability{profile.CapabilityRead}
				if err := fixture.service.Profiles.Put(t.Context(), selected); err != nil {
					t.Fatal(err)
				}
			},
			input: func(plan OperatorWriteInfo) OperatorApplyInput {
				return OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: plan.IntentSHA256, Yes: true}
			},
		},
		{
			name: "project policy removed",
			mutate: func(t *testing.T, fixture *operatorFixture) {
				if err := fixture.service.Policies.Clear(t.Context(), "work"); err != nil {
					t.Fatal(err)
				}
			},
			input: func(plan OperatorWriteInfo) OperatorApplyInput {
				return OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: plan.IntentSHA256, Yes: true}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOperatorFixture(t)
			enableCommentDelete(t, fixture)
			plan := prepareCommentDelete(t, fixture)
			test.mutate(t, fixture)
			transport := &deleteTransport{base: fixture.service.HTTP}
			fixture.service.HTTP = transport

			if _, err := fixture.service.ApplyOperatorWrite(t.Context(), test.input(plan)); err == nil {
				t.Fatal("ApplyOperatorWrite() accepted a locally denied deletion")
			}
			record, err := fixture.service.OperatorWrites.Get(t.Context(), plan.PlanID)
			if err != nil || record.NonReplayable() || transport.calls.Load() != 0 {
				t.Fatalf("record=%#v err=%v delete=%d", record, err, transport.calls.Load())
			}
		})
	}
}
