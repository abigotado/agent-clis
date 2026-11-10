package youtrack

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
)

const validCommentDeleteJSON = `{"id":"4-1","issue":{"id":"2-12"},"author":{"id":"1-2","login":"alice"},"created":1,"updated":null,"deleted":false,"pinned":false,"text":"active text","visibility":{"$type":"UnlimitedVisibility","permittedGroups":[],"permittedUsers":[]},"attachments":[]}`

func TestGetCommentForDeletionPinsFixedPathProjectionAndTarget(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/youtrack/api/issues/2-12/comments/4-1" ||
			request.URL.Query().Get("fields") != commentDeleteFields || len(request.URL.Query()) != 1 {
			t.Errorf("unexpected exact request: %s %s", request.Method, request.URL.RequestURI())
		}
		_, _ = io.WriteString(writer, validCommentDeleteJSON)
	}))
	defer server.Close()

	target, err := newTestClient(t, server).GetCommentForDeletion(context.Background(), "2-12", "4-1")
	if err != nil {
		t.Fatal(err)
	}
	if target.ID != "4-1" || target.IssueID != "2-12" || target.Text != "active text" ||
		target.AuthorID != "1-2" || target.AuthorLogin != "alice" || target.Created != 1 ||
		target.Updated != nil || target.Deleted || target.Pinned || target.Visibility.Type != "UnlimitedVisibility" ||
		target.Attachments == nil || len(target.Attachments) != 0 {
		t.Fatalf("target=%#v", target)
	}
}

func TestGetCommentForDeletionRejectsIncompleteOrUnsafeTarget(t *testing.T) {
	tests := []struct {
		name     string
		response string
	}{
		{name: "returned comment id mismatch", response: strings.Replace(validCommentDeleteJSON, `"id":"4-1"`, `"id":"4-9"`, 1)},
		{name: "returned issue id mismatch", response: strings.Replace(validCommentDeleteJSON, `"id":"2-12"`, `"id":"2-99"`, 1)},
		{name: "missing issue", response: strings.Replace(validCommentDeleteJSON, `"issue":{"id":"2-12"},`, "", 1)},
		{name: "missing author", response: strings.Replace(validCommentDeleteJSON, `"author":{"id":"1-2","login":"alice"},`, "", 1)},
		{name: "missing author login", response: strings.Replace(validCommentDeleteJSON, `,"login":"alice"`, "", 1)},
		{name: "missing created", response: strings.Replace(validCommentDeleteJSON, `"created":1,`, "", 1)},
		{name: "missing updated", response: strings.Replace(validCommentDeleteJSON, `"updated":null,`, "", 1)},
		{name: "negative updated", response: strings.Replace(validCommentDeleteJSON, `"updated":null`, `"updated":-1`, 1)},
		{name: "missing deleted", response: strings.Replace(validCommentDeleteJSON, `"deleted":false,`, "", 1)},
		{name: "null deleted", response: strings.Replace(validCommentDeleteJSON, `"deleted":false`, `"deleted":null`, 1)},
		{name: "deleted comment", response: strings.Replace(validCommentDeleteJSON, `"deleted":false`, `"deleted":true`, 1)},
		{name: "missing pinned", response: strings.Replace(validCommentDeleteJSON, `"pinned":false,`, "", 1)},
		{name: "null pinned", response: strings.Replace(validCommentDeleteJSON, `"pinned":false`, `"pinned":null`, 1)},
		{name: "missing text", response: strings.Replace(validCommentDeleteJSON, `"text":"active text",`, "", 1)},
		{name: "null text", response: strings.Replace(validCommentDeleteJSON, `"text":"active text"`, `"text":null`, 1)},
		{name: "missing visibility", response: strings.Replace(validCommentDeleteJSON, `"visibility":{"$type":"UnlimitedVisibility","permittedGroups":[],"permittedUsers":[]},`, "", 1)},
		{name: "null visibility", response: strings.Replace(validCommentDeleteJSON, `"visibility":{"$type":"UnlimitedVisibility","permittedGroups":[],"permittedUsers":[]}`, `"visibility":null`, 1)},
		{name: "missing attachments", response: strings.TrimSuffix(validCommentDeleteJSON, `,"attachments":[]}`) + `}`},
		{name: "null attachments", response: strings.Replace(validCommentDeleteJSON, `"attachments":[]`, `"attachments":null`, 1)},
		{name: "nonempty attachments", response: strings.Replace(validCommentDeleteJSON, `"attachments":[]`, `"attachments":[{"id":"7-1"}]`, 1)},
		{name: "non json response", response: "upstream HTML error"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(writer, test.response)
			}))
			defer server.Close()

			_, err := newTestClient(t, server).GetCommentForDeletion(context.Background(), "2-12", "4-1")
			assertError(t, err, errx.CodeInternal, "INTERNAL")
		})
	}
}

func TestGetCommentForDeletionRejectsUnsafeIdentifiersBeforeTransport(t *testing.T) {
	tests := []struct {
		name, issueID, commentID string
	}{
		{name: "unsafe issue id", issueID: "../other", commentID: "4-1"},
		{name: "unsafe comment id", issueID: "2-12", commentID: "../other"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := &countingTransport{}
			client, err := New(Config{RESTBaseURL: "https://tracker.example.test/api"}, Credential{Token: testToken}, WithHTTPClient(&http.Client{Transport: transport}))
			if err != nil {
				t.Fatal(err)
			}

			_, err = client.GetCommentForDeletion(context.Background(), test.issueID, test.commentID)
			assertError(t, err, errx.CodeUsage, "USAGE")
			if transport.calls.Load() != 0 {
				t.Fatalf("invalid target reached transport %d times", transport.calls.Load())
			}
		})
	}
}

func TestGetCommentForDeletionAcceptsExplicitNullUpdated(t *testing.T) {
	tests := []struct {
		name     string
		response string
		wantNil  bool
		want     int64
	}{
		{name: "explicit null is preserved", response: validCommentDeleteJSON, wantNil: true},
		{name: "timestamp is preserved", response: strings.Replace(validCommentDeleteJSON, `"updated":null`, `"updated":42`, 1), want: 42},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(writer, test.response)
			}))
			defer server.Close()

			target, err := newTestClient(t, server).GetCommentForDeletion(context.Background(), "2-12", "4-1")
			if err != nil {
				t.Fatal(err)
			}
			if test.wantNil && target.Updated != nil {
				t.Fatalf("Updated=%v, want nil", *target.Updated)
			}
			if !test.wantNil && (target.Updated == nil || *target.Updated != test.want) {
				t.Fatalf("Updated=%v, want %d", target.Updated, test.want)
			}
		})
	}
}

func TestGetCommentForDeletionDoesNotTrustReturnedRedirectURL(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.URL.Path != "/youtrack/api/issues/2-12/comments/4-1" {
			t.Errorf("request path = %q", request.URL.Path)
		}
		_, _ = io.WriteString(writer, strings.TrimSuffix(validCommentDeleteJSON, "}")+`,"url":"https://untrusted.example/other"}`)
	}))
	defer server.Close()

	if _, err := newTestClient(t, server).GetCommentForDeletion(context.Background(), "2-12", "4-1"); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls=%d, want 1", calls.Load())
	}
}

func TestDeleteCommentAcceptsOnlyEmptySuccessResponses(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "no content empty", status: http.StatusNoContent},
		{name: "ok empty", status: http.StatusOK},
		{name: "ok whitespace", status: http.StatusOK, body: " \r\n\t"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				calls.Add(1)
				assertDeleteCommentRequest(t, request)
				writer.WriteHeader(test.status)
				_, _ = io.WriteString(writer, test.body)
			}))
			defer server.Close()

			err := newTestClient(t, server).DeleteComment(context.Background(), DeleteCommentInput{IssueID: "2-12", CommentID: "4-1"})
			if err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 1 {
				t.Fatalf("calls=%d, want 1", calls.Load())
			}
		})
	}
}

func TestDeleteCommentClassifiesOneShotHTTPOutcomes(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		gzip       bool
		encoding   string
		retryAfter string
		wantCode   errx.Code
		wantReason string
	}{
		{name: "authentication rejection redacts non json error body", status: http.StatusUnauthorized, body: "UPSTREAM_BODY_SENTINEL " + testToken, wantCode: errx.CodeAuth, wantReason: "AUTHENTICATION_FAILED"},
		{name: "permission rejection", status: http.StatusForbidden, body: "non-json upstream error", wantCode: errx.CodePermission, wantReason: "PERMISSION_DENIED"},
		{name: "missing target rejection", status: http.StatusNotFound, body: "non-json upstream error", wantCode: errx.CodeConflict, wantReason: "TARGET_CHANGED"},
		{name: "conflict rejection", status: http.StatusConflict, body: "non-json upstream error", wantCode: errx.CodeConflict, wantReason: "PRECONDITION_FAILED"},
		{name: "precondition rejection", status: http.StatusPreconditionFailed, body: "non-json upstream error", wantCode: errx.CodeConflict, wantReason: "PRECONDITION_FAILED"},
		{name: "malformed compressed permission rejection remains definitive", status: http.StatusForbidden, body: "not a gzip stream", encoding: "gzip", wantCode: errx.CodePermission, wantReason: "PERMISSION_DENIED"},
		{name: "unsupported encoded missing-target rejection remains definitive", status: http.StatusNotFound, body: "opaque body", encoding: "br", wantCode: errx.CodeConflict, wantReason: "TARGET_CHANGED"},
		{name: "oversized conflict rejection remains definitive", status: http.StatusConflict, body: strings.Repeat("x", maxResponseBodyBytes+1), wantCode: errx.CodeConflict, wantReason: "PRECONDITION_FAILED"},
		{name: "rate limit without retry after is unknown", status: http.StatusTooManyRequests, wantCode: errx.CodeConflict, wantReason: "WRITE_OUTCOME_UNKNOWN"},
		{name: "rate limit with retry after is unknown", status: http.StatusTooManyRequests, retryAfter: "1", wantCode: errx.CodeConflict, wantReason: "WRITE_OUTCOME_UNKNOWN"},
		{name: "server failure is unknown", status: http.StatusServiceUnavailable, wantCode: errx.CodeConflict, wantReason: "WRITE_OUTCOME_UNKNOWN"},
		{name: "accepted is unknown", status: http.StatusAccepted, wantCode: errx.CodeConflict, wantReason: "WRITE_OUTCOME_UNKNOWN"},
		{name: "nonempty ok is unknown", status: http.StatusOK, body: "non-json success", wantCode: errx.CodeConflict, wantReason: "WRITE_OUTCOME_UNKNOWN"},
		{name: "plain oversized response is unknown", status: http.StatusOK, body: strings.Repeat("x", maxResponseBodyBytes+1), wantCode: errx.CodeConflict, wantReason: "WRITE_OUTCOME_UNKNOWN"},
		{name: "compressed oversized response is unknown", status: http.StatusOK, body: strings.Repeat("x", maxResponseBodyBytes+1), gzip: true, wantCode: errx.CodeConflict, wantReason: "WRITE_OUTCOME_UNKNOWN"},
		{name: "malformed compressed response is unknown", status: http.StatusOK, body: "not a gzip stream", gzip: true, wantCode: errx.CodeConflict, wantReason: "WRITE_OUTCOME_UNKNOWN"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				calls.Add(1)
				assertDeleteCommentRequest(t, request)
				if test.retryAfter != "" {
					writer.Header().Set("Retry-After", test.retryAfter)
				}
				if test.encoding != "" {
					writer.Header().Set("Content-Encoding", test.encoding)
				} else if test.gzip {
					writer.Header().Set("Content-Encoding", "gzip")
				}
				writer.WriteHeader(test.status)
				if test.gzip && test.name != "malformed compressed response is unknown" {
					zipper := gzip.NewWriter(writer)
					_, _ = io.WriteString(zipper, test.body)
					_ = zipper.Close()
					return
				}
				_, _ = io.WriteString(writer, test.body)
			}))
			defer server.Close()

			err := newTestClient(t, server).DeleteComment(context.Background(), DeleteCommentInput{IssueID: "2-12", CommentID: "4-1"})
			assertError(t, err, test.wantCode, test.wantReason)
			if calls.Load() != 1 {
				t.Fatalf("calls=%d, want exactly one", calls.Load())
			}
			if strings.Contains(err.Error(), "UPSTREAM_BODY_SENTINEL") || strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), server.URL) {
				t.Fatalf("error leaked upstream detail: %v", err)
			}
		})
	}
}

func TestDeleteCommentRejectsUnexpectedNoContentBody(t *testing.T) {
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("unexpected")),
		}, nil
	})
	client, err := New(Config{RESTBaseURL: "https://tracker.example.test/api"}, Credential{Token: testToken}, WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatal(err)
	}
	err = client.DeleteComment(context.Background(), DeleteCommentInput{IssueID: "2-12", CommentID: "4-1"})
	assertError(t, err, errx.CodeConflict, "WRITE_OUTCOME_UNKNOWN")
}

func TestDeleteCommentRefusesRedirectWithoutReplaying(t *testing.T) {
	var redirected atomic.Int32
	redirectTarget := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Add(1)
	}))
	defer redirectTarget.Close()

	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		assertDeleteCommentRequest(t, request)
		writer.Header().Set("Location", redirectTarget.URL+"/untrusted")
		writer.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	err := newTestClient(t, server).DeleteComment(context.Background(), DeleteCommentInput{IssueID: "2-12", CommentID: "4-1"})
	assertError(t, err, errx.CodeConflict, "WRITE_OUTCOME_UNKNOWN")
	if calls.Load() != 1 || redirected.Load() != 0 {
		t.Fatalf("origin calls=%d redirected calls=%d", calls.Load(), redirected.Load())
	}
}

type deleteCommentFailureTransport struct {
	calls      atomic.Int32
	replayable atomic.Bool
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func (transport *deleteCommentFailureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.calls.Add(1)
	if request.GetBody != nil {
		transport.replayable.Store(true)
	}
	return nil, errors.New("TRANSPORT_SENTINEL " + testToken)
}

func TestDeleteCommentTransportIsNonReplayableAndRedacted(t *testing.T) {
	transport := &deleteCommentFailureTransport{}
	client, err := New(Config{RESTBaseURL: "https://tracker.example.test/api"}, Credential{Token: testToken}, WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatal(err)
	}

	err = client.DeleteComment(context.Background(), DeleteCommentInput{IssueID: "2-12", CommentID: "4-1"})
	assertError(t, err, errx.CodeConflict, "WRITE_OUTCOME_UNKNOWN")
	if transport.calls.Load() != 1 || transport.replayable.Load() || strings.Contains(err.Error(), "SENTINEL") || strings.Contains(err.Error(), testToken) {
		t.Fatalf("err=%v calls=%d replayable=%t", err, transport.calls.Load(), transport.replayable.Load())
	}
}

func TestDeleteCommentRejectsUnsafeIdentifiersBeforeTransport(t *testing.T) {
	tests := []struct {
		name, issueID, commentID string
	}{
		{name: "unsafe issue id", issueID: "../other", commentID: "4-1"},
		{name: "unsafe comment id", issueID: "2-12", commentID: "../other"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := &countingTransport{}
			client, err := New(Config{RESTBaseURL: "https://tracker.example.test/api"}, Credential{Token: testToken}, WithHTTPClient(&http.Client{Transport: transport}))
			if err != nil {
				t.Fatal(err)
			}

			err = client.DeleteComment(context.Background(), DeleteCommentInput{IssueID: test.issueID, CommentID: test.commentID})
			assertError(t, err, errx.CodeUsage, "USAGE")
			if transport.calls.Load() != 0 {
				t.Fatalf("invalid input reached transport %d times", transport.calls.Load())
			}
		})
	}
}

func TestGetCommentForDeletionValidatesVisibilityShape(t *testing.T) {
	limited := `{"$type":"LimitedVisibility","permittedGroups":[{"id":"3-1","$type":"UserGroup"}],"permittedUsers":[{"id":"1-2","$type":"User"}]}`
	unlimitedWithoutPrincipals := `{"$type":"UnlimitedVisibility"}`
	tests := []struct {
		name       string
		visibility string
		wantType   string
		wantGroups int
		wantUsers  int
		wantErr    bool
	}{
		{name: "unlimited omitted principals canonicalize empty", visibility: unlimitedWithoutPrincipals, wantType: "UnlimitedVisibility"},
		{name: "limited explicit principals are retained", visibility: limited, wantType: "LimitedVisibility", wantGroups: 1, wantUsers: 1},
		{name: "unlimited groups are rejected", visibility: `{"$type":"UnlimitedVisibility","permittedGroups":[{"id":"3-1"}],"permittedUsers":[]}`, wantErr: true},
		{name: "unknown visibility type is rejected", visibility: `{"$type":"PrivateVisibility","permittedGroups":[],"permittedUsers":[]}`, wantErr: true},
		{name: "limited missing groups is rejected", visibility: `{"$type":"LimitedVisibility","permittedUsers":[]}`, wantErr: true},
		{name: "limited missing users is rejected", visibility: `{"$type":"LimitedVisibility","permittedGroups":[]}`, wantErr: true},
		{name: "limited null groups is rejected", visibility: `{"$type":"LimitedVisibility","permittedGroups":null,"permittedUsers":[]}`, wantErr: true},
		{name: "limited null users is rejected", visibility: `{"$type":"LimitedVisibility","permittedGroups":[],"permittedUsers":null}`, wantErr: true},
		{name: "invalid principal id is rejected", visibility: `{"$type":"LimitedVisibility","permittedGroups":[{"id":"../bad"}],"permittedUsers":[]}`, wantErr: true},
		{name: "unknown principal field is rejected", visibility: `{"$type":"LimitedVisibility","permittedGroups":[{"id":"3-1","unexpected":true}],"permittedUsers":[]}`, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := strings.Replace(validCommentDeleteJSON, `{"$type":"UnlimitedVisibility","permittedGroups":[],"permittedUsers":[]}`, test.visibility, 1)
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(writer, response)
			}))
			defer server.Close()

			target, err := newTestClient(t, server).GetCommentForDeletion(context.Background(), "2-12", "4-1")
			if test.wantErr {
				assertError(t, err, errx.CodeInternal, "INTERNAL")
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if target.Visibility.Type != test.wantType || len(target.Visibility.PermittedGroups) != test.wantGroups || len(target.Visibility.PermittedUsers) != test.wantUsers {
				t.Fatalf("visibility=%#v", target.Visibility)
			}
		})
	}
}

func assertDeleteCommentRequest(t *testing.T, request *http.Request) {
	t.Helper()
	if request.Method != http.MethodDelete || request.URL.Path != "/youtrack/api/issues/2-12/comments/4-1" || request.URL.RawQuery != "" {
		t.Errorf("unexpected deletion request: %s %s", request.Method, request.URL.RequestURI())
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Errorf("read request body: %v", err)
	}
	if len(body) != 0 {
		t.Errorf("request body = %q, want empty", body)
	}
}
