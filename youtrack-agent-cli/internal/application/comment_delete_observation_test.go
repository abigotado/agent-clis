package application

import (
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
)

type commentDeleteObservationTransport struct {
	base        http.RoundTripper
	path        string
	status      int
	body        string
	issueGets   atomic.Int32
	commentGets atomic.Int32
	deletes     atomic.Int32
}

func (transport *commentDeleteObservationTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method == http.MethodDelete {
		transport.deletes.Add(1)
	}
	if request.Method == http.MethodGet && request.URL.Path == "/api/issues/2-12" {
		transport.issueGets.Add(1)
	}
	if request.Method == http.MethodGet && request.URL.Path == "/api/issues/2-12/comments/4-1" {
		transport.commentGets.Add(1)
	}
	if request.Method == http.MethodGet && request.URL.Path == transport.path {
		return &http.Response{StatusCode: transport.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(transport.body)), Request: request}, nil
	}
	return transport.base.RoundTrip(request)
}

func TestCommentDeleteSnapshotRejectsMalformedIdentifiersBeforeCredentialsOrNetwork(t *testing.T) {
	for _, test := range []struct {
		name, issueID, commentID string
	}{
		{name: "issue traversal", issueID: "../other", commentID: "4-1"},
		{name: "comment traversal", issueID: "APP-12", commentID: "../other"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOperatorFixture(t)
			enableCommentDelete(t, fixture)
			credentials, network := &trapCredentials{}, &trapTransport{}
			fixture.service.Credentials, fixture.service.HTTP = credentials, network

			_, err := fixture.service.SnapshotOperatorWrite(t.Context(), OperatorSnapshotInput{Profile: "work", Kind: "comment.delete", IssueID: test.issueID, CommentID: test.commentID})
			if errx.ExitCode(err) != errx.CodeUsage || credentials.calls != 0 || network.calls != 0 {
				t.Fatalf("SnapshotOperatorWrite() err=%v credentials=%d network=%d", err, credentials.calls, network.calls)
			}
		})
	}
}

func TestCommentDeleteReconcileAccessLossAndProjectMoveRequireOperator(t *testing.T) {
	tests := []struct {
		name, path, body string
		status           int
		moveIssue        bool
		wantComments     int32
	}{
		{name: "issue unauthorized", path: "/api/issues/2-12", status: http.StatusUnauthorized},
		{name: "issue forbidden", path: "/api/issues/2-12", status: http.StatusForbidden},
		{name: "issue missing", path: "/api/issues/2-12", status: http.StatusNotFound},
		{name: "issue moved", moveIssue: true},
		{name: "comment unauthorized", path: "/api/issues/2-12/comments/4-1", status: http.StatusUnauthorized, wantComments: 1},
		{name: "comment forbidden", path: "/api/issues/2-12/comments/4-1", status: http.StatusForbidden, wantComments: 1},
		{name: "comment missing", path: "/api/issues/2-12/comments/4-1", status: http.StatusNotFound, wantComments: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOperatorFixture(t)
			enableCommentDelete(t, fixture)
			plan := prepareCommentDelete(t, fixture)
			delete := &deleteTransport{base: fixture.service.HTTP, status: http.StatusTooManyRequests}
			fixture.service.HTTP = delete
			if _, err := fixture.service.ApplyOperatorWrite(t.Context(), OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: plan.IntentSHA256, Yes: true}); operatorReason(t, err) != "WRITE_OUTCOME_UNKNOWN" {
				t.Fatalf("ApplyOperatorWrite() error=%v", err)
			}

			if test.moveIssue {
				fixture.issue = strings.Replace(fixture.issue, `"id":"0-3","shortName":"APP"`, `"id":"0-4","shortName":"OTHER"`, 1)
			}
			observation := &commentDeleteObservationTransport{base: fixture.service.HTTP, path: test.path, status: test.status, body: test.body}
			fixture.service.HTTP = observation
			result, err := fixture.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: plan.PlanID, Limit: 3, Offset: 7})
			if err != nil || result.State != "operator_resolution_required" || result.Evidence != "hard_delete_not_proven" || result.NonReplayable != true {
				t.Fatalf("ReconcileOperatorWrite() result=%#v err=%v", result, err)
			}
			if got := observation.commentGets.Load(); got != test.wantComments || observation.deletes.Load() != 0 || delete.calls.Load() != 1 {
				t.Fatalf("comment_gets=%d want=%d reconcile_deletes=%d original_deletes=%d", got, test.wantComments, observation.deletes.Load(), delete.calls.Load())
			}
		})
	}
}
