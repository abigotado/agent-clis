package application

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/auth"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/operatorwrite"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/profile"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/writepolicy"
)

const deleteCommentFixture = `{"id":"4-1","issue":{"id":"2-12"},"author":{"id":"1-2","login":"alice"},"created":10,"updated":null,"deleted":false,"pinned":false,"text":"Delete this complete comment","visibility":{"$type":"UnlimitedVisibility","permittedGroups":[],"permittedUsers":[]},"attachments":[]}`

type deleteTransport struct {
	base       http.RoundTripper
	status     int
	body       string
	calls      atomic.Int32
	replayable atomic.Bool
}

func (transport *deleteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method != http.MethodDelete {
		return transport.base.RoundTrip(request)
	}
	transport.calls.Add(1)
	if request.GetBody != nil {
		transport.replayable.Store(true)
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	if len(body) != 0 || request.URL.Path != "/api/issues/2-12/comments/4-1" {
		return nil, io.ErrUnexpectedEOF
	}
	status := transport.status
	if status == 0 {
		status = http.StatusNoContent
	}
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(transport.body)), Request: request}, nil
}

func enableCommentDelete(t *testing.T, fixture *operatorFixture) {
	t.Helper()
	selected, err := fixture.service.Profiles.Get(t.Context(), "work")
	if err != nil {
		t.Fatal(err)
	}
	selected.Capabilities = append(selected.Capabilities, profile.CapabilityCommentDelete)
	if err := fixture.service.Profiles.Put(t.Context(), selected); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Policies.Set(t.Context(), selected, []writepolicy.Project{{ID: "0-3", Key: "APP"}}); err != nil {
		t.Fatal(err)
	}
	credential, err := auth.BindCredential(auth.Credential{Kind: auth.CredentialPermanentToken, PermanentToken: "perm:OPERATOR_DELETE_TEST_SENTINEL"}, selected)
	if err != nil {
		t.Fatal(err)
	}
	fixture.service.Credentials = &fixedCredentials{value: credential}
	fixture.exactCommentBody = deleteCommentFixture
}

func prepareCommentDelete(t *testing.T, fixture *operatorFixture) OperatorWriteInfo {
	t.Helper()
	snapshot, err := fixture.service.SnapshotOperatorWrite(t.Context(), OperatorSnapshotInput{Profile: "work", Kind: "comment.delete", IssueID: "APP-12", CommentID: "4-1"})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.PlanVersion != operatorwrite.PlanVersion3 || snapshot.CommentID != "4-1" || snapshot.Snapshot.Comment == nil ||
		snapshot.Snapshot.Comment.RequiredServerPermission != "Delete Comment" {
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

func TestCommentDeleteSnapshotAndOfflinePrepareBindExactTarget(t *testing.T) {
	tests := []struct {
		name      string
		commentID string
		wantCode  errx.Code
	}{
		{"exact issue and comment target is frozen", "4-1", errx.CodeOK},
		{"invalid comment identifier is refused before credentials", "../other", errx.CodeUsage},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOperatorFixture(t)
			enableCommentDelete(t, fixture)
			result, err := fixture.service.SnapshotOperatorWrite(t.Context(), OperatorSnapshotInput{Profile: "work", Kind: "comment.delete", IssueID: "APP-12", CommentID: test.commentID})
			if errx.ExitCode(err) != test.wantCode {
				t.Fatalf("SnapshotOperatorWrite() result=%#v err=%v", result, err)
			}
			if test.wantCode != errx.CodeOK {
				return
			}
			raw, err := json.Marshal(result.Snapshot)
			if err != nil {
				t.Fatal(err)
			}
			credentials, network := &trapCredentials{}, &trapTransport{}
			fixture.service.Credentials, fixture.service.HTTP = credentials, network
			prepared, err := fixture.service.PrepareOperatorWrite(context.Background(), OperatorPrepareInput{Profile: "work", SnapshotJSON: raw, RequestJSON: []byte(`{"kind":"comment.delete"}`), DryRun: true})
			if err != nil || prepared.PlanVersion != operatorwrite.PlanVersion3 || prepared.Plan.Request != (operatorwrite.Request{Kind: operatorwrite.KindCommentDelete}) || credentials.calls != 0 || network.calls != 0 {
				t.Fatalf("prepared=%#v err=%v credentials=%d network=%d", prepared, err, credentials.calls, network.calls)
			}
		})
	}
}

func TestCommentDeleteStaleFrozenFieldsRefuseBeforeDispatch(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(string) string
	}{
		{"text", func(raw string) string { return strings.Replace(raw, "Delete this complete comment", "changed", 1) }},
		{"updated", func(raw string) string { return strings.Replace(raw, `"updated":null`, `"updated":11`, 1) }},
		{"author", func(raw string) string { return strings.Replace(raw, `"id":"1-2"`, `"id":"1-3"`, 1) }},
		{"visibility", func(raw string) string { return strings.Replace(raw, "UnlimitedVisibility", "LimitedVisibility", 1) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOperatorFixture(t)
			enableCommentDelete(t, fixture)
			plan := prepareCommentDelete(t, fixture)
			fixture.exactCommentBody = test.mutate(deleteCommentFixture)
			transport := &deleteTransport{base: fixture.service.HTTP}
			fixture.service.HTTP = transport
			_, err := fixture.service.ApplyOperatorWrite(t.Context(), OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: plan.IntentSHA256, Yes: true})
			if operatorReason(t, err) != "OPERATOR_COMMENT_STALE" || transport.calls.Load() != 0 {
				t.Fatalf("ApplyOperatorWrite() error=%v delete calls=%d", err, transport.calls.Load())
			}
			record, recordErr := fixture.service.OperatorWrites.Get(t.Context(), plan.PlanID)
			if recordErr != nil || record.NonReplayable() {
				t.Fatalf("stale preflight consumed plan=%#v err=%v", record, recordErr)
			}
		})
	}
}

func TestCommentDeleteConsumesExactlyOneAttempt(t *testing.T) {
	tests := []struct {
		name, wantState, wantReason string
		status                      int
	}{
		{"204 applies exact comment id", string(operatorwrite.StateApplied), "", http.StatusNoContent},
		{"403 is rejected and consumed", string(operatorwrite.StateRejected), "PERMISSION_DENIED", http.StatusForbidden},
		{"429 is unknown and consumed", string(operatorwrite.StateUnknown), "WRITE_OUTCOME_UNKNOWN", http.StatusTooManyRequests},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOperatorFixture(t)
			enableCommentDelete(t, fixture)
			plan := prepareCommentDelete(t, fixture)
			transport := &deleteTransport{base: fixture.service.HTTP, status: test.status}
			fixture.service.HTTP = transport
			result, err := fixture.service.ApplyOperatorWrite(t.Context(), OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: plan.IntentSHA256, Yes: true})
			if test.wantReason == "" {
				if err != nil || result.RemoteID != "4-1" {
					t.Fatalf("ApplyOperatorWrite() result=%#v err=%v", result, err)
				}
			} else if operatorReason(t, err) != test.wantReason {
				t.Fatalf("ApplyOperatorWrite() error=%v", err)
			}
			status, statusErr := fixture.service.OperatorWriteStatus(t.Context(), plan.PlanID)
			if statusErr != nil || status.State != test.wantState || !status.NonReplayable || transport.calls.Load() != 1 || transport.replayable.Load() {
				t.Fatalf("status=%#v err=%v calls=%d replayable=%t", status, statusErr, transport.calls.Load(), transport.replayable.Load())
			}
			_, replayErr := fixture.service.ApplyOperatorWrite(t.Context(), OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: plan.IntentSHA256, Yes: true})
			if operatorReason(t, replayErr) != "OPERATOR_PLAN_CONSUMED" || transport.calls.Load() != 1 {
				t.Fatalf("replay error=%v calls=%d", replayErr, transport.calls.Load())
			}
		})
	}
}

func TestCommentDeleteReconcileNeverProvesHardDeleteOrReplays(t *testing.T) {
	fixture := newOperatorFixture(t)
	enableCommentDelete(t, fixture)
	plan := prepareCommentDelete(t, fixture)
	transport := &deleteTransport{base: fixture.service.HTTP, status: http.StatusTooManyRequests}
	fixture.service.HTTP = transport
	_, _ = fixture.service.ApplyOperatorWrite(t.Context(), OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: plan.IntentSHA256, Yes: true})
	result, err := fixture.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: plan.PlanID, Limit: 3, Offset: 7})
	if err != nil || result.State != string(operatorwrite.StateOperatorRequired) || result.Evidence != "hard_delete_not_proven" || transport.calls.Load() != 1 {
		t.Fatalf("reconcile=%#v err=%v delete calls=%d", result, err, transport.calls.Load())
	}
}
