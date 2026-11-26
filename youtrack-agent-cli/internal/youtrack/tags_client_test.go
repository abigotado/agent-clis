package youtrack

import (
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
)

const wantTagFields = "id,name,$type,owner(id,login),untagOnResolve,visibleFor(id),updateableBy(id)"

type tagWrite struct {
	name    string
	method  string
	path    string
	body    string
	success []int
	call    func(*Client) error
}

func tagWrites() []tagWrite {
	return []tagWrite{
		{"issue.tag", http.MethodPost, "/youtrack/api/issues/2-12/tags", `{"id":"6-3"}`, []int{200, 201, 204},
			func(c *Client) error { return c.AddIssueTag(context.Background(), "2-12", "6-3") }},
		{"issue.untag", http.MethodDelete, "/youtrack/api/issues/2-12/tags/6-3", ``, []int{200, 204},
			func(c *Client) error { return c.RemoveIssueTag(context.Background(), "2-12", "6-3") }},
	}
}

func assertTagWriteRequest(t *testing.T, write tagWrite, request *http.Request) {
	t.Helper()
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Errorf("read request body: %v", err)
	}
	if request.Method != write.method || request.URL.EscapedPath() != write.path || request.URL.RawQuery != "" || string(body) != write.body {
		t.Errorf("unexpected %s request: %s %s body=%q", write.name, request.Method, request.URL.RequestURI(), body)
	}
}

func TestTagWritesAcceptOnlyEmptyOrSingleObjectSuccess(t *testing.T) {
	for _, write := range tagWrites() {
		for _, status := range write.success {
			for name, body := range map[string]string{"empty": "", "whitespace": " \r\n\t", "object": `{"id":"6-3"}` + "\n ", "empty object": `{}`} {
				t.Run(write.name+"/"+name+"/"+http.StatusText(status), func(t *testing.T) {
					var calls atomic.Int32
					server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
						calls.Add(1)
						assertTagWriteRequest(t, write, request)
						writer.WriteHeader(status)
						if status != http.StatusNoContent {
							_, _ = io.WriteString(writer, body)
						}
					}))
					defer server.Close()
					if err := write.call(newTestClient(t, server)); err != nil {
						t.Fatal(err)
					}
					if calls.Load() != 1 {
						t.Fatalf("calls=%d, want 1", calls.Load())
					}
				})
			}
		}
	}
}

func TestTagWritesClassifyOneShotHTTPOutcomes(t *testing.T) {
	unknown := "WRITE_OUTCOME_UNKNOWN"
	tests := []struct {
		name       string
		status     int
		body       string
		gzip       bool
		malformed  bool
		wantCode   errx.Code
		wantReason string
	}{
		{name: "bad request is usage", status: 400, body: "UPSTREAM_BODY_SENTINEL " + testToken, wantCode: errx.CodeUsage, wantReason: "USAGE"},
		{name: "unprocessable is usage", status: 422, body: "UPSTREAM_BODY_SENTINEL", wantCode: errx.CodeUsage, wantReason: "USAGE"},
		{name: "unauthorized", status: 401, body: "UPSTREAM_BODY_SENTINEL " + testToken, wantCode: errx.CodeAuth, wantReason: "AUTHENTICATION_FAILED"},
		{name: "forbidden", status: 403, body: "UPSTREAM_BODY_SENTINEL", wantCode: errx.CodePermission, wantReason: "PERMISSION_DENIED"},
		{name: "not found", status: 404, body: "UPSTREAM_BODY_SENTINEL", wantCode: errx.CodeConflict, wantReason: "TARGET_CHANGED"},
		{name: "conflict", status: 409, body: "UPSTREAM_BODY_SENTINEL", wantCode: errx.CodeConflict, wantReason: "PRECONDITION_FAILED"},
		{name: "precondition failed", status: 412, body: "UPSTREAM_BODY_SENTINEL", wantCode: errx.CodeConflict, wantReason: "PRECONDITION_FAILED"},
		{name: "rate limit is unknown", status: 429, wantCode: errx.CodeConflict, wantReason: unknown},
		{name: "server failure is unknown", status: 503, wantCode: errx.CodeConflict, wantReason: unknown},
		{name: "accepted is unknown", status: 202, wantCode: errx.CodeConflict, wantReason: unknown},
		{name: "created is unknown for delete", status: 201, wantCode: errx.CodeConflict, wantReason: unknown},
		{name: "two objects are unknown", status: 200, body: `{} {}`, wantCode: errx.CodeConflict, wantReason: unknown},
		{name: "array is unknown", status: 200, body: `[]`, wantCode: errx.CodeConflict, wantReason: unknown},
		{name: "null is unknown", status: 200, body: `null`, wantCode: errx.CodeConflict, wantReason: unknown},
		{name: "non json is unknown", status: 200, body: "UPSTREAM_BODY_SENTINEL success", wantCode: errx.CodeConflict, wantReason: unknown},
		{name: "plain oversized is unknown", status: 200, body: strings.Repeat("x", maxResponseBodyBytes+1), wantCode: errx.CodeConflict, wantReason: unknown},
		{name: "gzip oversized is unknown", status: 200, body: strings.Repeat("x", maxResponseBodyBytes+1), gzip: true, wantCode: errx.CodeConflict, wantReason: unknown},
		{name: "malformed gzip is unknown", status: 200, body: "not a gzip stream", gzip: true, malformed: true, wantCode: errx.CodeConflict, wantReason: unknown},
		{name: "oversized forbidden stays definitive", status: 403, body: strings.Repeat("x", maxResponseBodyBytes+1), wantCode: errx.CodePermission, wantReason: "PERMISSION_DENIED"},
	}
	for _, write := range tagWrites() {
		for _, test := range tests {
			if test.status == 201 && write.method == http.MethodPost {
				continue // 201 is a documented success of the POST
			}
			t.Run(write.name+"/"+test.name, func(t *testing.T) {
				var calls atomic.Int32
				server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					calls.Add(1)
					assertTagWriteRequest(t, write, request)
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

				err := write.call(newTestClient(t, server))
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
}

func TestTagWritesRefuseRedirectWithoutReplaying(t *testing.T) {
	for _, write := range tagWrites() {
		t.Run(write.name, func(t *testing.T) {
			var redirected atomic.Int32
			redirectTarget := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
			defer redirectTarget.Close()
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				calls.Add(1)
				writer.Header().Set("Location", redirectTarget.URL+"/untrusted")
				writer.WriteHeader(http.StatusTemporaryRedirect)
			}))
			defer server.Close()
			err := write.call(newTestClient(t, server))
			assertError(t, err, errx.CodeConflict, "WRITE_OUTCOME_UNKNOWN")
			if calls.Load() != 1 || redirected.Load() != 0 {
				t.Fatalf("origin calls=%d redirected calls=%d", calls.Load(), redirected.Load())
			}
			if strings.Contains(err.Error(), redirectTarget.URL) || strings.Contains(err.Error(), server.URL) {
				t.Fatalf("error leaked a URL: %v", err)
			}
		})
	}
}

func TestTagWritesTransportLossIsUnknownSingleAndRedacted(t *testing.T) {
	for _, write := range tagWrites() {
		t.Run(write.name, func(t *testing.T) {
			transport := &deleteCommentFailureTransport{}
			client, err := New(Config{RESTBaseURL: "https://tracker.example.test/api"}, Credential{Token: testToken}, WithHTTPClient(&http.Client{Transport: transport}))
			if err != nil {
				t.Fatal(err)
			}
			err = write.call(client)
			assertError(t, err, errx.CodeConflict, "WRITE_OUTCOME_UNKNOWN")
			if transport.calls.Load() != 1 || transport.replayable.Load() || strings.Contains(err.Error(), "SENTINEL") || strings.Contains(err.Error(), testToken) {
				t.Fatalf("err=%v calls=%d replayable=%t", err, transport.calls.Load(), transport.replayable.Load())
			}
		})
	}
}

func TestTagCallsRejectInvalidIdentifiersBeforeNetwork(t *testing.T) {
	bad := []string{"", "../x", "6-3/x", "6-3?x=1", `6-3"}`, "%2e%2e", "-6"}
	for _, value := range bad {
		t.Run(value, func(t *testing.T) {
			transport := &countingTransport{}
			client, err := New(Config{RESTBaseURL: "https://tracker.example.test/api"}, Credential{Token: testToken}, WithHTTPClient(&http.Client{Transport: transport}))
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			calls := map[string]func() error{
				"add issue":    func() error { return client.AddIssueTag(ctx, value, "6-3") },
				"add tag":      func() error { return client.AddIssueTag(ctx, "2-12", value) },
				"remove issue": func() error { return client.RemoveIssueTag(ctx, value, "6-3") },
				"remove tag":   func() error { return client.RemoveIssueTag(ctx, "2-12", value) },
				"get tag":      func() error { _, err := client.GetTag(ctx, value); return err },
				"issue tags":   func() error { _, err := client.ListIssueTags(ctx, value, PageOptions{}); return err },
				"issue tag a":  func() error { _, _, err := client.GetIssueTag(ctx, value, "6-3"); return err },
				"issue tag b":  func() error { _, _, err := client.GetIssueTag(ctx, "2-12", value); return err },
			}
			for name, call := range calls {
				assertError(t, call(), errx.CodeUsage, "USAGE")
				if transport.calls.Load() != 0 {
					t.Fatalf("%s reached the transport", name)
				}
			}
		})
	}
	t.Run("list query and top", func(t *testing.T) {
		transport := &countingTransport{}
		client, err := New(Config{RESTBaseURL: "https://tracker.example.test/api"}, Credential{Token: testToken}, WithHTTPClient(&http.Client{Transport: transport}))
		if err != nil {
			t.Fatal(err)
		}
		for name, call := range map[string]func() error{
			"newline": func() error { _, err := client.ListTags(context.Background(), "a\nb", 5); return err },
			"too long": func() error {
				_, err := client.ListTags(context.Background(), strings.Repeat("a", maxTagQueryLen+1), 5)
				return err
			},
			"top too large": func() error { _, err := client.ListTags(context.Background(), "", 102); return err },
			"negative top":  func() error { _, err := client.ListTags(context.Background(), "", -1); return err },
		} {
			assertError(t, call(), errx.CodeUsage, "USAGE")
			if transport.calls.Load() != 0 {
				t.Fatalf("%s reached the transport", name)
			}
		}
	})
}

const tagJSON = `{"id":"6-3","name":"release","$type":"IssueTag","owner":{"id":"1-1","login":"operator"},"untagOnResolve":true,"visibleFor":{"id":"3-1"},"updateableBy":null}`

func TestTagReadsRequestExactPathsAndDecodeTheType(t *testing.T) {
	var got []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		got = append(got, request.Method+" "+request.URL.EscapedPath()+"?"+request.URL.RawQuery)
		switch request.URL.EscapedPath() {
		case "/youtrack/api/tags":
			_, _ = io.WriteString(writer, "["+tagJSON+"]")
		case "/youtrack/api/issues/2-12/tags":
			_, _ = io.WriteString(writer, "[]")
		default:
			_, _ = io.WriteString(writer, tagJSON)
		}
	}))
	defer server.Close()
	client := newTestClient(t, server)
	ctx := context.Background()

	tags, err := client.ListTags(ctx, `tag: {my release} #x&y`, 101)
	if err != nil || len(tags) != 1 {
		t.Fatalf("ListTags = %+v, %v", tags, err)
	}
	want := Tag{ID: "6-3", Name: "release", Type: "IssueTag", OwnerID: "1-1", OwnerLogin: "operator", UntagOnResolve: true, Shared: true}
	if tags[0] != want {
		t.Fatalf("tag = %+v, want %+v", tags[0], want)
	}
	if tag, err := client.GetTag(ctx, "6-3"); err != nil || tag != want {
		t.Fatalf("GetTag = %+v, %v", tag, err)
	}
	if issueTags, err := client.ListIssueTags(ctx, "2-12", PageOptions{Top: 7, Skip: 14}); err != nil || issueTags == nil || len(issueTags) != 0 {
		t.Fatalf("ListIssueTags = %+v, %v", issueTags, err)
	}
	if tag, ok, err := client.GetIssueTag(ctx, "2-12", "6-3"); err != nil || !ok || tag != want {
		t.Fatalf("GetIssueTag = %+v, %v, %v", tag, ok, err)
	}
	if len(got) != 4 {
		t.Fatalf("requests = %v", got)
	}
	listQuery := url.Values{"fields": {wantTagFields}, "$top": {"101"}, "query": {`tag: {my release} #x&y`}}.Encode()
	wantRequests := []string{
		"GET /youtrack/api/tags?" + listQuery,
		"GET /youtrack/api/tags/6-3?" + url.Values{"fields": {wantTagFields}}.Encode(),
		"GET /youtrack/api/issues/2-12/tags?" + url.Values{"fields": {wantTagFields}, "$top": {"7"}, "$skip": {"14"}}.Encode(),
		"GET /youtrack/api/issues/2-12/tags/6-3?" + url.Values{"fields": {wantTagFields}}.Encode(),
	}
	for index := range wantRequests {
		if got[index] != wantRequests[index] {
			t.Errorf("request %d = %s, want %s", index, got[index], wantRequests[index])
		}
	}
}

func TestTagSharedAndOwnerProjection(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantShared bool
		wantOwner  string
		wantErr    bool
	}{
		{"private", `{"id":"6-3","name":"a","$type":"Tag","owner":{"id":"1-1","login":"u"},"untagOnResolve":false}`, false, "1-1", false},
		{"updateable only", `{"id":"6-3","name":"a","$type":"Tag","owner":{"id":"1-1","login":"u"},"untagOnResolve":false,"visibleFor":null,"updateableBy":{"id":"3-1"}}`, true, "1-1", false},
		{"ownerless is decoded for the caller to refuse", `{"id":"6-3","name":"a","$type":"Tag","untagOnResolve":false}`, false, "", false},
		{"missing type", `{"id":"6-3","name":"a","owner":{"id":"1-1","login":"u"},"untagOnResolve":false}`, false, "", true},
		{"missing untagOnResolve", `{"id":"6-3","name":"a","$type":"Tag","owner":{"id":"1-1","login":"u"}}`, false, "", true},
		{"other id", `{"id":"6-4","name":"a","$type":"Tag","owner":{"id":"1-1","login":"u"},"untagOnResolve":false}`, false, "", true},
		{"control char in name", `{"id":"6-3","name":"a\nb","$type":"Tag","owner":{"id":"1-1","login":"u"},"untagOnResolve":false}`, false, "", true},
		{"empty owner login", `{"id":"6-3","name":"a","$type":"Tag","owner":{"id":"1-1","login":""},"untagOnResolve":false}`, false, "", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(writer, test.body) }))
			defer server.Close()
			tag, err := newTestClient(t, server).GetTag(context.Background(), "6-3")
			if (err != nil) != test.wantErr {
				t.Fatalf("GetTag error = %v, wantErr %v", err, test.wantErr)
			}
			if err == nil && (tag.Shared != test.wantShared || tag.OwnerID != test.wantOwner) {
				t.Fatalf("tag = %+v", tag)
			}
		})
	}
}

func TestGetIssueTagReportsAbsenceOnlyOnNotFound(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		wantAbsent bool
		wantCode   errx.Code
	}{
		{"not found is absent", http.StatusNotFound, true, 0},
		{"forbidden stays an error", http.StatusForbidden, false, errx.CodePermission},
		{"unauthorized stays an error", http.StatusUnauthorized, false, errx.CodeAuth},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				writer.WriteHeader(test.status)
				_, _ = io.WriteString(writer, "UPSTREAM_BODY_SENTINEL")
			}))
			defer server.Close()
			tag, ok, err := newTestClient(t, server).GetIssueTag(context.Background(), "2-12", "6-3")
			if ok || tag != (Tag{}) {
				t.Fatalf("tag = %+v ok=%v", tag, ok)
			}
			if test.wantAbsent {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
			} else if err == nil || strings.Contains(err.Error(), "SENTINEL") {
				t.Fatalf("err = %v", err)
			}
			if calls.Load() != 1 {
				t.Fatalf("calls = %d", calls.Load())
			}
		})
	}
}
