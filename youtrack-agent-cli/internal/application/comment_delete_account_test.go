package application

import (
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
)

type commentDeleteAccountSwapTransport struct {
	base        http.RoundTripper
	accountGets atomic.Int32
	targetGets  atomic.Int32
	deletes     atomic.Int32
}

func (transport *commentDeleteAccountSwapTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	switch {
	case request.Method == http.MethodGet && request.URL.Path == "/api/users/me":
		if transport.accountGets.Add(1) == 1 {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"id":"1-2","login":"alice"}`)), Request: request}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"id":"1-9","login":"other"}`)), Request: request}, nil
	case request.Method == http.MethodGet && (request.URL.Path == "/api/issues/2-12" || request.URL.Path == "/api/issues/2-12/comments/4-1"):
		transport.targetGets.Add(1)
		return transport.base.RoundTrip(request)
	case request.Method == http.MethodDelete:
		transport.deletes.Add(1)
		return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	default:
		return transport.base.RoundTrip(request)
	}
}

func TestCommentDeleteRejectsAccountSwapInsideFinalLockBeforeClaim(t *testing.T) {
	fixture := newOperatorFixture(t)
	enableCommentDelete(t, fixture)
	plan := prepareCommentDelete(t, fixture)
	transport := &commentDeleteAccountSwapTransport{base: fixture.service.HTTP}
	fixture.service.HTTP = transport

	_, err := fixture.service.ApplyOperatorWrite(t.Context(), OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: plan.IntentSHA256, Yes: true})
	if errx.ExitCode(err) != errx.CodeAuth || operatorReason(t, err) != "ACCOUNT_IDENTITY_MISMATCH" {
		t.Fatalf("ApplyOperatorWrite() error=%v", err)
	}
	record, recordErr := fixture.service.OperatorWrites.Get(t.Context(), plan.PlanID)
	if recordErr != nil || record.NonReplayable() || transport.accountGets.Load() != 2 || transport.targetGets.Load() != 0 || transport.deletes.Load() != 0 {
		t.Fatalf("record=%#v recordErr=%v account_gets=%d target_gets=%d deletes=%d", record, recordErr, transport.accountGets.Load(), transport.targetGets.Load(), transport.deletes.Load())
	}
}
