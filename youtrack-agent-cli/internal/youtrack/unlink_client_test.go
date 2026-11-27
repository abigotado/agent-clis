package youtrack

import (
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
)

const unlinkPath = "/youtrack/api/issues/2-12/links/80-2s/issues/2-19"

func validRemoveLinkInput() RemoveIssueLinkInput {
	return RemoveIssueLinkInput{SourceID: "2-12", LinkID: "80-2s", TargetID: "2-19"}
}

func assertUnlinkRequest(t *testing.T, request *http.Request) {
	t.Helper()
	if request.Method != http.MethodDelete || request.URL.EscapedPath() != unlinkPath || request.URL.RawQuery != "" {
		t.Errorf("unexpected unlink request: %s %s", request.Method, request.URL.RequestURI())
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Errorf("read request body: %v", err)
	}
	if len(body) != 0 {
		t.Errorf("request body = %q, want empty", body)
	}
}

func TestRemoveIssueLinkAcceptsOnlyEmptyOrSingleObjectSuccess(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "no content empty", status: http.StatusNoContent},
		{name: "ok empty", status: http.StatusOK},
		{name: "ok whitespace", status: http.StatusOK, body: " \r\n\t"},
		{name: "ok empty object", status: http.StatusOK, body: `{}`},
		{name: "ok object with trailing whitespace", status: http.StatusOK, body: "{\"id\":\"2-19\"}\n "},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				calls.Add(1)
				assertUnlinkRequest(t, request)
				writer.WriteHeader(test.status)
				_, _ = io.WriteString(writer, test.body)
			}))
			defer server.Close()

			if err := newTestClient(t, server).RemoveIssueLink(context.Background(), validRemoveLinkInput()); err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 1 {
				t.Fatalf("calls=%d, want 1", calls.Load())
			}
		})
	}
}

func TestRemoveIssueLinkClassifiesOneShotHTTPOutcomes(t *testing.T) {
	unknown := "WRITE_OUTCOME_UNKNOWN"
	tests := []struct {
		name       string
		status     int
		body       string
		gzip       bool
		malformed  bool
		encoding   string
		wantCode   errx.Code
		wantReason string
	}{
		{name: "bad request is usage", status: http.StatusBadRequest, body: "UPSTREAM_BODY_SENTINEL " + testToken, wantCode: errx.CodeUsage, wantReason: "USAGE"},
		{name: "unprocessable is usage", status: http.StatusUnprocessableEntity, body: "UPSTREAM_BODY_SENTINEL", wantCode: errx.CodeUsage, wantReason: "USAGE"},
		{name: "unauthorized", status: http.StatusUnauthorized, body: "UPSTREAM_BODY_SENTINEL " + testToken, wantCode: errx.CodeAuth, wantReason: "AUTHENTICATION_FAILED"},
		{name: "forbidden", status: http.StatusForbidden, body: "UPSTREAM_BODY_SENTINEL", wantCode: errx.CodePermission, wantReason: "PERMISSION_DENIED"},
		{name: "not found", status: http.StatusNotFound, body: "UPSTREAM_BODY_SENTINEL", wantCode: errx.CodeConflict, wantReason: "TARGET_CHANGED"},
		{name: "conflict", status: http.StatusConflict, body: "UPSTREAM_BODY_SENTINEL", wantCode: errx.CodeConflict, wantReason: "PRECONDITION_FAILED"},
		{name: "precondition failed", status: http.StatusPreconditionFailed, body: "UPSTREAM_BODY_SENTINEL", wantCode: errx.CodeConflict, wantReason: "PRECONDITION_FAILED"},
		{name: "rate limit is unknown", status: http.StatusTooManyRequests, wantCode: errx.CodeConflict, wantReason: unknown},
		{name: "server failure is unknown", status: http.StatusServiceUnavailable, wantCode: errx.CodeConflict, wantReason: unknown},
		{name: "accepted is unknown", status: http.StatusAccepted, wantCode: errx.CodeConflict, wantReason: unknown},
		{name: "two objects are unknown", status: http.StatusOK, body: `{} {}`, wantCode: errx.CodeConflict, wantReason: unknown},
		{name: "object then garbage is unknown", status: http.StatusOK, body: `{} x`, wantCode: errx.CodeConflict, wantReason: unknown},
		{name: "array is unknown", status: http.StatusOK, body: `[]`, wantCode: errx.CodeConflict, wantReason: unknown},
		{name: "null is unknown", status: http.StatusOK, body: `null`, wantCode: errx.CodeConflict, wantReason: unknown},
		{name: "non json is unknown", status: http.StatusOK, body: "UPSTREAM_BODY_SENTINEL success", wantCode: errx.CodeConflict, wantReason: unknown},
		{name: "plain oversized is unknown", status: http.StatusOK, body: strings.Repeat("x", maxResponseBodyBytes+1), wantCode: errx.CodeConflict, wantReason: unknown},
		{name: "gzip oversized is unknown", status: http.StatusOK, body: strings.Repeat("x", maxResponseBodyBytes+1), gzip: true, wantCode: errx.CodeConflict, wantReason: unknown},
		{name: "malformed gzip is unknown", status: http.StatusOK, body: "not a gzip stream", gzip: true, malformed: true, wantCode: errx.CodeConflict, wantReason: unknown},
		{name: "oversized forbidden stays definitive", status: http.StatusForbidden, body: strings.Repeat("x", maxResponseBodyBytes+1), wantCode: errx.CodePermission, wantReason: "PERMISSION_DENIED"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				calls.Add(1)
				assertUnlinkRequest(t, request)
				if test.gzip {
					writer.Header().Set("Content-Encoding", "gzip")
				}
				writer.WriteHeader(test.status)
				if test.gzip && !test.malformed {
					zipper := gzip.NewWriter(writer)
					_, _ = io.WriteString(zipper, test.body)
					_ = zipper.Close()
					return
				}
				_, _ = io.WriteString(writer, test.body)
			}))
			defer server.Close()

			err := newTestClient(t, server).RemoveIssueLink(context.Background(), validRemoveLinkInput())
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

func TestRemoveIssueLinkPathUsesEachSegmentVerbatim(t *testing.T) {
	var path string
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		path = request.URL.EscapedPath()
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	input := RemoveIssueLinkInput{SourceID: "2.12_a", LinkID: "105-1.s_t", TargetID: "2-19"}
	if err := newTestClient(t, server).RemoveIssueLink(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if want := "/youtrack/api/issues/2.12_a/links/105-1.s_t/issues/2-19"; path != want {
		t.Fatalf("path=%s, want %s", path, want)
	}
}

func TestRemoveIssueLinkRefusesRedirectWithoutReplaying(t *testing.T) {
	var redirected atomic.Int32
	redirectTarget := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Add(1)
	}))
	defer redirectTarget.Close()

	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		assertUnlinkRequest(t, request)
		writer.Header().Set("Location", redirectTarget.URL+"/untrusted")
		writer.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	err := newTestClient(t, server).RemoveIssueLink(context.Background(), validRemoveLinkInput())
	assertError(t, err, errx.CodeConflict, "WRITE_OUTCOME_UNKNOWN")
	if calls.Load() != 1 || redirected.Load() != 0 {
		t.Fatalf("origin calls=%d redirected calls=%d", calls.Load(), redirected.Load())
	}
	if strings.Contains(err.Error(), redirectTarget.URL) || strings.Contains(err.Error(), server.URL) {
		t.Fatalf("error leaked a URL: %v", err)
	}
}

func TestRemoveIssueLinkTransportLossIsUnknownSingleAndRedacted(t *testing.T) {
	transport := &deleteCommentFailureTransport{}
	client, err := New(Config{RESTBaseURL: "https://tracker.example.test/api"}, Credential{Token: testToken}, WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatal(err)
	}
	err = client.RemoveIssueLink(context.Background(), validRemoveLinkInput())
	assertError(t, err, errx.CodeConflict, "WRITE_OUTCOME_UNKNOWN")
	if transport.calls.Load() != 1 || transport.replayable.Load() || strings.Contains(err.Error(), "SENTINEL") || strings.Contains(err.Error(), testToken) {
		t.Fatalf("err=%v calls=%d replayable=%t", err, transport.calls.Load(), transport.replayable.Load())
	}
}

func TestRemoveIssueLinkRejectsInvalidInputBeforeNetwork(t *testing.T) {
	mutate := map[string]func(*RemoveIssueLinkInput){
		"source path traversal": func(i *RemoveIssueLinkInput) { i.SourceID = "../x" },
		"empty source":          func(i *RemoveIssueLinkInput) { i.SourceID = "" },
		"link id separator":     func(i *RemoveIssueLinkInput) { i.LinkID = "80-2/s" },
		"link id query":         func(i *RemoveIssueLinkInput) { i.LinkID = "80-2s?x=1" },
		"empty link id":         func(i *RemoveIssueLinkInput) { i.LinkID = "" },
		"empty target":          func(i *RemoveIssueLinkInput) { i.TargetID = "" },
		"target path traversal": func(i *RemoveIssueLinkInput) { i.TargetID = "../x" },
		"target needs quoting":  func(i *RemoveIssueLinkInput) { i.TargetID = `2-19"}` },
		"self unlink":           func(i *RemoveIssueLinkInput) { i.TargetID = i.SourceID },
	}
	for name, change := range mutate {
		t.Run(name, func(t *testing.T) {
			transport := &countingTransport{}
			client, err := New(Config{RESTBaseURL: "https://tracker.example.test/api"}, Credential{Token: testToken}, WithHTTPClient(&http.Client{Transport: transport}))
			if err != nil {
				t.Fatal(err)
			}
			input := validRemoveLinkInput()
			change(&input)
			assertError(t, client.RemoveIssueLink(context.Background(), input), errx.CodeUsage, "USAGE")
			if err := ValidateRemoveIssueLinkInput(input); err == nil {
				t.Fatal("validator accepted invalid input")
			}
			if transport.calls.Load() != 0 {
				t.Fatalf("invalid input reached transport %d times", transport.calls.Load())
			}
		})
	}
}
