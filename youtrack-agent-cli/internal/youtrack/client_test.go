package youtrack

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
)

const testToken = "perm:TEST_TOKEN_SENTINEL"

func TestReadSurfacePinsServicePathFieldsAndBounds(t *testing.T) {
	issueJSON := validIssueJSON("APP-12", "New summary")
	tests := []struct {
		name     string
		wantPath string
		wantTop  string
		wantSkip string
		response string
		invoke   func(context.Context, *Client) error
	}{
		{
			name: "current user", wantPath: "/youtrack/api/users/me", response: `{"id":"1-2","login":"alice"}`,
			invoke: func(ctx context.Context, client *Client) error { _, err := client.CurrentUser(ctx); return err },
		},
		{
			name: "exact project", wantPath: "/youtrack/api/admin/projects/APP", response: `{"id":"0-3","shortName":"APP","name":"Application","archived":false}`,
			invoke: func(ctx context.Context, client *Client) error { _, err := client.GetProject(ctx, "APP"); return err },
		},
		{
			name: "exact issue", wantPath: "/youtrack/api/issues/APP-12", response: issueJSON,
			invoke: func(ctx context.Context, client *Client) error { _, err := client.GetIssue(ctx, "APP-12"); return err },
		},
		{
			name: "project fields", wantPath: "/youtrack/api/admin/projects/0-3/customFields", wantTop: "7", wantSkip: "2",
			response: `[{"id":"92-1","$type":"EnumProjectCustomField","field":{"id":"42-1","name":"Priority","fieldType":{"id":"enum[1]","valueType":"enum","isMultiValue":false,"$type":"FieldType"}},"canBeEmpty":false,"isPublic":true}]`,
			invoke: func(ctx context.Context, client *Client) error {
				_, err := client.ListProjectFields(ctx, "0-3", PageOptions{Top: 7, Skip: 2})
				return err
			},
		},
		{
			name: "comments", wantPath: "/youtrack/api/issues/APP-12/comments", wantTop: "5", wantSkip: "1",
			response: `[{"id":"4-1","author":{"id":"1-2","login":"alice"},"created":1,"updated":null,"deleted":false,"text":"untrusted"}]`,
			invoke: func(ctx context.Context, client *Client) error {
				_, err := client.ListComments(ctx, "APP-12", PageOptions{Top: 5, Skip: 1})
				return err
			},
		},
		{
			name: "bounded search", wantPath: "/youtrack/api/issues", wantTop: "3", wantSkip: "4", response: "[" + issueJSON + "]",
			invoke: func(ctx context.Context, client *Client) error {
				_, err := client.SearchIssues(ctx, "project: APP plan-marker", PageOptions{Top: 3, Skip: 4})
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.Method != http.MethodGet || request.URL.Path != test.wantPath {
					t.Errorf("request = %s %s", request.Method, request.URL.Path)
				}
				if request.URL.Query().Get("fields") == "" {
					t.Error("fields was not explicit")
				}
				if request.URL.Query().Get("$top") != test.wantTop || request.URL.Query().Get("$skip") != test.wantSkip {
					t.Errorf("pagination = top %q skip %q", request.URL.Query().Get("$top"), request.URL.Query().Get("$skip"))
				}
				if got := request.Header.Get("Authorization"); got != "Bearer "+testToken {
					t.Error("request did not use the expected Bearer credential")
				}
				writer.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(writer, test.response)
			}))
			defer server.Close()
			client := newTestClient(t, server)
			if err := test.invoke(context.Background(), client); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type countingTransport struct{ calls atomic.Int32 }

func (transport *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	transport.calls.Add(1)
	return nil, errors.New("unexpected transport call")
}

func TestPathIdentifiersRejectDotSegmentsAndDelimitersBeforeTransport(t *testing.T) {
	invalid := []string{".", "..", "../APP", "APP/../OTHER", "%2e%2e", "-APP", "_APP"}
	for _, value := range invalid {
		t.Run(value, func(t *testing.T) {
			transport := &countingTransport{}
			client, err := New(
				Config{RESTBaseURL: "https://tracker.example.test/api"},
				Credential{Token: testToken},
				WithHTTPClient(&http.Client{Transport: transport}),
			)
			if err != nil {
				t.Fatal(err)
			}
			operations := []func() error{
				func() error { _, err := client.GetProject(context.Background(), value); return err },
				func() error { _, err := client.GetIssue(context.Background(), value); return err },
				func() error {
					_, err := client.ListProjectFields(context.Background(), value, PageOptions{Top: 1})
					return err
				},
				func() error {
					_, err := client.ListComments(context.Background(), value, PageOptions{Top: 1})
					return err
				},
				func() error {
					_, err := client.CreateIssue(context.Background(), CreateIssueInput{ProjectID: value, Summary: "S"})
					return err
				},
				func() error {
					_, err := client.UpdateIssue(context.Background(), UpdateIssueInput{IssueID: value, ProjectID: "0-1", ProjectKey: "APP", Summary: stringPointer("S")})
					return err
				},
				func() error {
					_, err := client.UpdateIssue(context.Background(), UpdateIssueInput{IssueID: "APP-1", ProjectID: value, ProjectKey: "APP", Summary: stringPointer("S")})
					return err
				},
				func() error {
					_, err := client.UpdateIssue(context.Background(), UpdateIssueInput{IssueID: "APP-1", ProjectID: "0-1", ProjectKey: value, Summary: stringPointer("S")})
					return err
				},
			}
			for index, operation := range operations {
				if err := operation(); errx.ExitCode(err) != errx.CodeUsage {
					t.Fatalf("operation %d error=%v", index, err)
				}
			}
			if transport.calls.Load() != 0 {
				t.Fatalf("invalid path reached transport %d times", transport.calls.Load())
			}
		})
	}
}

func TestReadRetriesAreBoundedAndWriteIsOneShot(t *testing.T) {
	t.Run("read retries transient status", func(t *testing.T) {
		var calls atomic.Int32
		server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			if calls.Add(1) < maxReadAttempts {
				writer.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = io.WriteString(writer, `{"id":"1-2","login":"alice"}`)
		}))
		defer server.Close()
		client := newTestClient(t, server)
		if _, err := client.CurrentUser(context.Background()); err != nil {
			t.Fatal(err)
		}
		if calls.Load() != maxReadAttempts {
			t.Fatalf("calls=%d", calls.Load())
		}
	})

	t.Run("write never retries transient status", func(t *testing.T) {
		var calls atomic.Int32
		server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			calls.Add(1)
			if request.GetBody != nil {
				t.Error("mutation request is replayable")
			}
			writer.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()
		client := newTestClient(t, server)
		_, err := client.UpdateIssue(context.Background(), UpdateIssueInput{
			IssueID: "APP-12", ProjectID: "0-3", ProjectKey: "APP", Summary: stringPointer("Changed"),
		})
		assertError(t, err, errx.CodeConflict, "WRITE_OUTCOME_UNKNOWN")
		if calls.Load() != 1 {
			t.Fatalf("calls=%d", calls.Load())
		}
	})

	t.Run("write rate limit is non-replayable unknown outcome", func(t *testing.T) {
		var calls atomic.Int32
		server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			writer.Header().Set("Retry-After", "10")
			writer.WriteHeader(http.StatusTooManyRequests)
		}))
		defer server.Close()
		client := newTestClient(t, server)
		_, err := client.UpdateIssue(context.Background(), UpdateIssueInput{
			IssueID: "APP-12", ProjectID: "0-3", ProjectKey: "APP", Summary: stringPointer("Changed"),
		})
		assertError(t, err, errx.CodeConflict, "WRITE_OUTCOME_UNKNOWN")
		if calls.Load() != 1 {
			t.Fatalf("calls=%d", calls.Load())
		}
	})
}

func TestRedirectIsRefusedBeforeCredentialCanReachAnotherOrigin(t *testing.T) {
	var destinationCalls atomic.Int32
	destination := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		destinationCalls.Add(1)
	}))
	defer destination.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, destination.URL+"/stolen", http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	client := newTestClient(t, source)
	_, err := client.CurrentUser(context.Background())
	if err == nil || destinationCalls.Load() != 0 {
		t.Fatalf("err=%v destination calls=%d", err, destinationCalls.Load())
	}
}

func TestCompressedAndDecompressedBodiesAreIndependentlyBounded(t *testing.T) {
	tests := []struct {
		name string
		body func() []byte
	}{
		{
			name: "compressed body", body: func() []byte { return bytes.Repeat([]byte("x"), maxCompressedBodyBytes+1) },
		},
		{
			name: "decompressed body", body: func() []byte {
				var compressed bytes.Buffer
				zipper := gzip.NewWriter(&compressed)
				_, _ = zipper.Write(bytes.Repeat([]byte("x"), maxResponseBodyBytes+1))
				_ = zipper.Close()
				return compressed.Bytes()
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Encoding", "gzip")
				_, _ = writer.Write(test.body())
			}))
			defer server.Close()
			client := newTestClient(t, server)
			_, err := client.CurrentUser(context.Background())
			if err == nil || strings.Contains(err.Error(), strings.Repeat("x", 16)) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestOversizedReadResponseHasRecoverableOperationSpecificContract(t *testing.T) {
	tests := []struct {
		name     string
		gzip     bool
		paged    bool
		wantCode errx.Code
		wantHint string
	}{
		{name: "identity exact", wantCode: errx.CodeInternal, wantHint: "do not retry unchanged"},
		{name: "gzip exact", gzip: true, wantCode: errx.CodeInternal, wantHint: "do not retry unchanged"},
		{name: "identity paged", paged: true, wantCode: errx.CodeUsage, wantHint: "--limit"},
		{name: "gzip paged", gzip: true, paged: true, wantCode: errx.CodeUsage, wantHint: "--limit"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				body := bytes.Repeat([]byte("x"), maxResponseBodyBytes+1)
				if !test.gzip {
					_, _ = writer.Write(body)
					return
				}
				writer.Header().Set("Content-Encoding", "gzip")
				zipper := gzip.NewWriter(writer)
				_, _ = zipper.Write(body)
				_ = zipper.Close()
			}))
			defer server.Close()
			client := newTestClient(t, server)
			var err error
			if test.paged {
				_, err = client.SearchIssues(t.Context(), "project: APP", PageOptions{Top: 100, CanReduce: true})
			} else {
				_, err = client.CurrentUser(t.Context())
			}
			var typed *errx.Error
			if !errors.As(err, &typed) || typed.Code != test.wantCode || typed.Reason != "RESPONSE_TOO_LARGE" {
				t.Fatalf("error = %#v", err)
			}
			if !strings.Contains(typed.Hint, test.wantHint) || typed.RetryAfter != 0 {
				t.Fatalf("hint=%q retry_after=%s", typed.Hint, typed.RetryAfter)
			}
		})
	}
}

func TestOversizedMinimumPageIsNotReportedAsReducible(t *testing.T) {
	tests := []struct {
		name   string
		invoke func(context.Context, *Client) error
	}{
		{
			name: "project fields",
			invoke: func(ctx context.Context, client *Client) error {
				_, err := client.ListProjectFields(ctx, "APP", PageOptions{Top: 1})
				return err
			},
		},
		{
			name: "comments",
			invoke: func(ctx context.Context, client *Client) error {
				_, err := client.ListComments(ctx, "APP-1", PageOptions{Top: 1})
				return err
			},
		},
		{
			name: "issue search",
			invoke: func(ctx context.Context, client *Client) error {
				_, err := client.SearchIssues(ctx, "project: APP", PageOptions{Top: 1})
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write(bytes.Repeat([]byte("x"), maxResponseBodyBytes+1))
			}))
			defer server.Close()
			err := test.invoke(t.Context(), newTestClient(t, server))
			var typed *errx.Error
			if !errors.As(err, &typed) || typed.Code != errx.CodeInternal || typed.Reason != "RESPONSE_TOO_LARGE" {
				t.Fatalf("error = %#v", err)
			}
			if !strings.Contains(typed.Hint, "do not retry unchanged") || strings.Contains(typed.Hint, "--limit") {
				t.Fatalf("hint = %q", typed.Hint)
			}
		})
	}
}

func TestRetryAfterIsBoundedBeforeAutomaticRetry(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	tests := []struct {
		name         string
		retryAfter   string
		deadline     time.Duration
		wantCalls    int32
		wantSleeps   []time.Duration
		wantRetryFor time.Duration
		wantStop     bool
	}{
		{name: "numeric", retryAfter: "2", wantCalls: 2, wantSleeps: []time.Duration{2 * time.Second}},
		{name: "HTTP date", retryAfter: now.Add(3 * time.Second).Format(http.TimeFormat), wantCalls: 2, wantSleeps: []time.Duration{3 * time.Second}},
		{name: "numeric cap", retryAfter: "31", wantCalls: 1, wantStop: true},
		{name: "date cap", retryAfter: now.Add(maxRetryAfterDelay + time.Second).Format(http.TimeFormat), wantCalls: 1, wantStop: true},
		{name: "numeric overflow", retryAfter: strings.Repeat("9", 100), wantCalls: 1, wantStop: true},
		{name: "deadline budget", retryAfter: "10", deadline: time.Second, wantCalls: 1, wantRetryFor: 10 * time.Second},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				if calls.Add(1) == 1 || test.wantCalls == 1 {
					writer.Header().Set("Retry-After", test.retryAfter)
					writer.WriteHeader(http.StatusTooManyRequests)
					return
				}
				_, _ = io.WriteString(writer, `{"id":"1-2","login":"alice"}`)
			}))
			defer server.Close()
			var sleeps []time.Duration
			client, err := New(
				Config{RESTBaseURL: server.URL + "/youtrack/api"},
				Credential{Token: testToken},
				WithHTTPClient(server.Client()),
				WithSleep(func(_ context.Context, delay time.Duration) error {
					sleeps = append(sleeps, delay)
					return nil
				}),
			)
			if err != nil {
				t.Fatal(err)
			}
			client.now = func() time.Time { return now }
			ctx := context.Background()
			if test.deadline > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, test.deadline)
				defer cancel()
			}
			_, readErr := client.CurrentUser(ctx)
			if test.wantCalls == 2 {
				if readErr != nil {
					t.Fatal(readErr)
				}
			} else {
				var typed *errx.Error
				if !errors.As(readErr, &typed) || typed.Reason != "RATE_LIMITED" || typed.RetryAfter != test.wantRetryFor {
					t.Fatalf("error = %#v", readErr)
				}
				if test.wantStop && !strings.Contains(typed.Hint, "stop automatic retries") {
					t.Fatalf("over-cap hint = %q", typed.Hint)
				}
			}
			if calls.Load() != test.wantCalls {
				t.Fatalf("calls=%d want=%d", calls.Load(), test.wantCalls)
			}
			if len(sleeps) != len(test.wantSleeps) {
				t.Fatalf("sleeps=%v want=%v", sleeps, test.wantSleeps)
			}
			for index := range sleeps {
				if sleeps[index] != test.wantSleeps[index] {
					t.Fatalf("sleeps=%v want=%v", sleeps, test.wantSleeps)
				}
			}
		})
	}
}

func TestCreateAndUpdateIssueUseTypedPayloads(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		response string
		invoke   func(context.Context, *Client) error
		assert   func(*testing.T, map[string]any)
	}{
		{
			name: "create", path: "/youtrack/api/issues", response: validIssueJSON("APP-12", "Created"),
			invoke: func(ctx context.Context, client *Client) error {
				_, err := client.CreateIssue(ctx, CreateIssueInput{ProjectID: "0-3", ProjectKey: "APP", Summary: "Created", Description: stringPointer("body"), ExpectedReporterID: "1-2", ExpectedReporterLogin: "alice"})
				return err
			},
			assert: func(t *testing.T, payload map[string]any) {
				project, ok := payload["project"].(map[string]any)
				if !ok || project["id"] != "0-3" || payload["summary"] != "Created" {
					t.Fatalf("payload=%#v", payload)
				}
			},
		},
		{
			name: "update", path: "/youtrack/api/issues/APP-12", response: validIssueJSON("APP-12", "Changed"),
			invoke: func(ctx context.Context, client *Client) error {
				_, err := client.UpdateIssue(ctx, UpdateIssueInput{IssueID: "APP-12", ProjectID: "0-3", ProjectKey: "APP", Summary: stringPointer("Changed")})
				return err
			},
			assert: func(t *testing.T, payload map[string]any) {
				if _, found := payload["project"]; found {
					t.Fatal("update payload can move the issue")
				}
				if payload["summary"] != "Changed" {
					t.Fatalf("payload=%#v", payload)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.Method != http.MethodPost || request.URL.Path != test.path || request.URL.Query().Get("fields") == "" {
					t.Errorf("request=%s %s?%s", request.Method, request.URL.Path, request.URL.RawQuery)
				}
				if request.GetBody != nil || request.ContentLength <= 0 {
					t.Error("write body is replayable or lengthless")
				}
				var payload map[string]any
				if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
					t.Fatal(err)
				}
				test.assert(t, payload)
				_, _ = io.WriteString(writer, test.response)
			}))
			defer server.Close()
			client := newTestClient(t, server)
			if err := test.invoke(context.Background(), client); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestErrorsRedactCredentialURLAndUpstreamBody(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(writer, "UPSTREAM_SECRET_BODY "+testToken)
	}))
	defer server.Close()
	client := newTestClient(t, server)
	_, err := client.CurrentUser(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	for _, forbidden := range []string{testToken, "UPSTREAM_SECRET_BODY", server.URL, "/youtrack/api"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("error leaks %q: %v", forbidden, err)
		}
	}
}

func TestRESTBaseValidationAndLocalValidationPrecedeNetwork(t *testing.T) {
	invalid := []string{
		"", "http://example.com/api", "https://user@example.com/api", "https://example.com/api/",
		"https://example.com/api?x=1", "https://example.com/not-api", "https://example.com/../api",
	}
	for _, value := range invalid {
		t.Run(value, func(t *testing.T) {
			if _, err := New(Config{RESTBaseURL: value}, Credential{Token: testToken}); err == nil {
				t.Fatal("expected invalid REST base")
			}
		})
	}

	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	client := newTestClient(t, server)
	_, err := client.SearchIssues(context.Background(), strings.Repeat("x", maxQueryBytes+1), PageOptions{Top: 1})
	if errx.ExitCode(err) != errx.CodeUsage || calls.Load() != 0 {
		t.Fatalf("code=%d calls=%d", errx.ExitCode(err), calls.Load())
	}
}

func newTestClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	client, err := New(
		Config{RESTBaseURL: server.URL + "/youtrack/api"},
		Credential{Token: testToken},
		WithHTTPClient(server.Client()),
		WithSleep(func(context.Context, time.Duration) error { return nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func validIssueJSON(idReadable, summary string) string {
	return fmt.Sprintf(`{"id":"2-12","idReadable":%q,"summary":%q,"description":"body","project":{"id":"0-3","shortName":"APP","name":"Application","archived":false},"reporter":{"id":"1-2","login":"alice"},"created":1,"updated":2,"commentsCount":0,"customFields":[]}`, idReadable, summary)
}

func stringPointer(value string) *string { return &value }

func assertError(t *testing.T, err error, code errx.Code, reason string) {
	t.Helper()
	var typed *errx.Error
	if !errors.As(err, &typed) || typed.Code != code || typed.Reason != reason {
		t.Fatalf("err=%#v", err)
	}
}
