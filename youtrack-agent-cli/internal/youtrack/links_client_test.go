package youtrack

import (
	"bytes"
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

const (
	linkTypeJSON       = `{"id":"105-1","name":"Depend","directed":true,"aggregation":false,"sourceToTarget":"depends on","targetToSource":"is required for"}`
	undirectedTypeJSON = `{"id":"105-0","name":"Relates","directed":false,"aggregation":false,"sourceToTarget":"relates to","targetToSource":"relates to"}`
)

func validAddLinkInput() AddIssueLinkInput {
	return AddIssueLinkInput{SourceID: "2-12", LinkID: "105-1s", TargetID: "2-19", TargetReadableID: "OPS-7"}
}

func TestLinkReadsPinPathEscapingFieldsAndPaging(t *testing.T) {
	tests := []struct {
		name      string
		call      func(*Client) error
		path      string
		rawPath   string
		wantQuery map[string]string
		response  string
	}{
		{
			name: "link types page", path: "/youtrack/api/issueLinkTypes",
			call:      func(c *Client) error { _, err := c.ListIssueLinkTypes(t.Context(), PageOptions{Top: 101}); return err },
			wantQuery: map[string]string{"fields": issueLinkTypeFields, "$top": "101", "$skip": "0"}, response: `[` + linkTypeJSON + `]`,
		},
		{
			name: "link type by id", path: "/youtrack/api/issueLinkTypes/105-1",
			call:      func(c *Client) error { _, err := c.GetIssueLinkType(t.Context(), "105-1"); return err },
			wantQuery: map[string]string{"fields": issueLinkTypeFields}, response: linkTypeJSON,
		},
		{
			name: "issue links page", path: "/youtrack/api/issues/2-12/links",
			call: func(c *Client) error {
				_, err := c.ListIssueLinks(t.Context(), "2-12", PageOptions{Top: 101})
				return err
			},
			wantQuery: map[string]string{"fields": "id,direction,linkType(id)", "$top": "101", "$skip": "0"},
			response:  `[{"id":"105-1s","direction":"OUTWARD","linkType":{"id":"105-1"}}]`,
		},
		{
			name: "linked issues page", path: "/youtrack/api/issues/2-12/links/105-1s/issues",
			call: func(c *Client) error {
				_, err := c.ListLinkedIssues(t.Context(), "2-12", "105-1s", PageOptions{Top: 101, Skip: 5})
				return err
			},
			wantQuery: map[string]string{"fields": "id,idReadable", "$top": "101", "$skip": "5"}, response: `[{"id":"2-19","idReadable":"OPS-7"}]`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				calls.Add(1)
				query := request.URL.Query()
				if request.Method != http.MethodGet || request.URL.Path != test.path || len(query) != len(test.wantQuery) {
					t.Errorf("unexpected request %s %s", request.Method, request.URL.RequestURI())
				}
				for key, want := range test.wantQuery {
					if query.Get(key) != want {
						t.Errorf("query %s = %q, want %q", key, query.Get(key), want)
					}
				}
				if request.Header.Get("Authorization") != "Bearer "+testToken {
					t.Error("missing bearer token")
				}
				_, _ = io.WriteString(writer, test.response)
			}))
			defer server.Close()
			if err := test.call(newTestClient(t, server)); err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 1 {
				t.Fatalf("calls=%d, want exactly one bounded request", calls.Load())
			}
		})
	}
}

func TestLinkReadsRejectUnsafeIdentifiersBeforeTransport(t *testing.T) {
	calls := map[string]func(*Client) error{
		"issue in links": func(c *Client) error {
			_, err := c.ListIssueLinks(t.Context(), "../x", PageOptions{Top: 5})
			return err
		},
		"issue in linked": func(c *Client) error {
			_, err := c.ListLinkedIssues(t.Context(), "../x", "1-1s", PageOptions{Top: 5})
			return err
		},
		"link id in linked": func(c *Client) error {
			_, err := c.ListLinkedIssues(t.Context(), "2-1", "1-1s/../x", PageOptions{Top: 5})
			return err
		},
		"link id with query": func(c *Client) error {
			_, err := c.ListLinkedIssues(t.Context(), "2-1", "1-1s?x=1", PageOptions{Top: 5})
			return err
		},
		"type id with segment": func(c *Client) error { _, err := c.GetIssueLinkType(t.Context(), "1-1/x"); return err },
		"page too large":       func(c *Client) error { _, err := c.ListIssueLinkTypes(t.Context(), PageOptions{Top: 102}); return err },
		"negative skip": func(c *Client) error {
			_, err := c.ListIssueLinks(t.Context(), "2-1", PageOptions{Top: 5, Skip: -1})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			transport := &countingTransport{}
			client, err := New(Config{RESTBaseURL: "https://tracker.example.test/api"}, Credential{Token: testToken}, WithHTTPClient(&http.Client{Transport: transport}))
			if err != nil {
				t.Fatal(err)
			}
			assertError(t, call(client), errx.CodeUsage, "USAGE")
			if transport.calls.Load() != 0 {
				t.Fatalf("invalid input reached transport %d times", transport.calls.Load())
			}
		})
	}
}

func TestLinkReadsRejectMissingOrMalformedMembers(t *testing.T) {
	typeCall := func(c *Client) error { _, err := c.GetIssueLinkType(t.Context(), "105-1"); return err }
	listTypes := func(c *Client) error { _, err := c.ListIssueLinkTypes(t.Context(), PageOptions{Top: 101}); return err }
	links := func(c *Client) error {
		_, err := c.ListIssueLinks(t.Context(), "2-12", PageOptions{Top: 101})
		return err
	}
	linked := func(c *Client) error {
		_, err := c.ListLinkedIssues(t.Context(), "2-12", "105-1s", PageOptions{Top: 101})
		return err
	}
	entry := `{"id":"105-1s","direction":"OUTWARD","linkType":{"id":"105-1"}}`
	tests := []struct {
		name     string
		call     func(*Client) error
		response string
	}{
		{"type missing directed", typeCall, strings.Replace(linkTypeJSON, `"directed":true,`, "", 1)},
		{"type null directed", typeCall, strings.Replace(linkTypeJSON, `"directed":true`, `"directed":null`, 1)},
		{"type missing aggregation", typeCall, strings.Replace(linkTypeJSON, `"aggregation":false,`, "", 1)},
		{"type missing name", typeCall, strings.Replace(linkTypeJSON, `"name":"Depend",`, "", 1)},
		{"type blank name", typeCall, strings.Replace(linkTypeJSON, `"Depend"`, `"  "`, 1)},
		{"type missing outward phrase", typeCall, strings.Replace(linkTypeJSON, `"sourceToTarget":"depends on",`, "", 1)},
		{"directed type missing inward phrase", typeCall, strings.Replace(linkTypeJSON, `,"targetToSource":"is required for"`, "", 1)},
		{"directed type blank inward phrase", typeCall, strings.Replace(linkTypeJSON, `"is required for"`, `""`, 1)},
		{"type id mismatch", typeCall, strings.Replace(linkTypeJSON, `"id":"105-1"`, `"id":"105-2"`, 1)},
		{"type bad id", typeCall, strings.Replace(linkTypeJSON, `"id":"105-1"`, `"id":"../x"`, 1)},
		{"types not an array", listTypes, linkTypeJSON},
		{"types null", listTypes, `null`},
		{"types element missing directed", listTypes, `[` + strings.Replace(linkTypeJSON, `"directed":true,`, "", 1) + `]`},
		{"links null", links, `null`},
		{"link missing id", links, `[` + strings.Replace(entry, `"id":"105-1s",`, "", 1) + `]`},
		{"link missing direction", links, `[` + strings.Replace(entry, `"direction":"OUTWARD",`, "", 1) + `]`},
		{"link null direction", links, `[` + strings.Replace(entry, `"OUTWARD"`, `null`, 1) + `]`},
		{"link lowercase direction", links, `[` + strings.Replace(entry, `OUTWARD`, `outward`, 1) + `]`},
		{"link unknown direction", links, `[` + strings.Replace(entry, `OUTWARD`, `SIDEWAYS`, 1) + `]`},
		{"link missing type", links, `[` + strings.Replace(entry, `,"linkType":{"id":"105-1"}`, "", 1) + `]`},
		{"link type without id", links, `[` + strings.Replace(entry, `{"id":"105-1"}`, `{}`, 1) + `]`},
		{"linked null", linked, `null`},
		{"linked missing id", linked, `[{"idReadable":"OPS-7"}]`},
		{"linked missing readable id", linked, `[{"id":"2-19"}]`},
		{"linked bad id", linked, `[{"id":"2/19","idReadable":"OPS-7"}]`},
		{"non json", links, `<html>upstream</html>`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(writer, test.response)
			}))
			defer server.Close()
			assertError(t, test.call(newTestClient(t, server)), errx.CodeInternal, "INTERNAL")
		})
	}
}

func TestUndirectedLinkTypeReadsTheSamePhraseOnBothSides(t *testing.T) {
	tests := map[string]string{
		"both phrases":     undirectedTypeJSON,
		"inward omitted":   strings.Replace(undirectedTypeJSON, `,"targetToSource":"relates to"`, "", 1),
		"inward null":      strings.Replace(undirectedTypeJSON, `"targetToSource":"relates to"`, `"targetToSource":null`, 1),
		"inward blank too": strings.Replace(undirectedTypeJSON, `"targetToSource":"relates to"`, `"targetToSource":""`, 1),
	}
	for name, response := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(writer, response)
			}))
			defer server.Close()
			got, err := newTestClient(t, server).GetIssueLinkType(t.Context(), "105-0")
			if err != nil {
				t.Fatal(err)
			}
			if got.Directed || got.SourceToTarget != "relates to" || got.TargetToSource != "relates to" {
				t.Fatalf("type = %+v", got)
			}
		})
	}
}

func TestLinkReadsRefuseRedirectAndBoundBodies(t *testing.T) {
	t.Run("redirect", func(t *testing.T) {
		var destinationCalls atomic.Int32
		destination := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { destinationCalls.Add(1) }))
		defer destination.Close()
		source := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			http.Redirect(writer, request, destination.URL+"/stolen", http.StatusTemporaryRedirect)
		}))
		defer source.Close()
		_, err := newTestClient(t, source).ListIssueLinks(t.Context(), "2-12", PageOptions{Top: 101})
		if err == nil || destinationCalls.Load() != 0 {
			t.Fatalf("err=%v destination calls=%d", err, destinationCalls.Load())
		}
	})
	for _, name := range []string{"compressed", "decompressed"} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Encoding", "gzip")
				if name == "compressed" {
					_, _ = writer.Write(bytes.Repeat([]byte("x"), maxCompressedBodyBytes+1))
					return
				}
				zipper := gzip.NewWriter(writer)
				_, _ = zipper.Write(bytes.Repeat([]byte("x"), maxResponseBodyBytes+1))
				_ = zipper.Close()
			}))
			defer server.Close()
			_, err := newTestClient(t, server).ListLinkedIssues(t.Context(), "2-12", "105-1s", PageOptions{Top: 101})
			if err == nil || strings.Contains(err.Error(), strings.Repeat("x", 16)) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestAddIssueLinkSendsExactlyOneTypedPost(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(request.Body)
		query := request.URL.Query()
		if request.Method != http.MethodPost || request.URL.Path != "/youtrack/api/issues/2-12/links/105-1s/issues" ||
			len(query) != 1 || query.Get("fields") != "id,idReadable" ||
			string(body) != `{"id":"2-19"}` || request.Header.Get("Content-Type") != "application/json" || request.GetBody != nil {
			t.Errorf("unexpected request %s %s body=%q", request.Method, request.URL.RequestURI(), body)
		}
		_, _ = io.WriteString(writer, `{"id":"2-19","idReadable":"OPS-7"}`)
	}))
	defer server.Close()
	if err := newTestClient(t, server).AddIssueLink(t.Context(), validAddLinkInput()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls=%d", calls.Load())
	}
}

func TestAddIssueLinkEscapesTheServerProvidedLinkID(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/youtrack/api/issues/2-12/links/105-1.s_t/issues" {
			t.Errorf("path = %s", request.URL.EscapedPath())
		}
		_, _ = io.WriteString(writer, `{"id":"2-19","idReadable":"OPS-7"}`)
	}))
	defer server.Close()
	input := validAddLinkInput()
	input.LinkID = "105-1.s_t"
	if err := newTestClient(t, server).AddIssueLink(t.Context(), input); err != nil {
		t.Fatal(err)
	}
}

func TestAddIssueLinkUnverifiedResponsesAreUnknownWithoutReplay(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		gzip       bool
		wantCode   errx.Code
		wantReason string
	}{
		{name: "response names another issue", body: `{"id":"2-20","idReadable":"OPS-7"}`},
		{name: "response names another readable id", body: `{"id":"2-19","idReadable":"OPS-8"}`},
		{name: "response without readable id", body: `{"id":"2-19"}`},
		{name: "empty object", body: `{}`},
		{name: "empty body"},
		{name: "array body", body: `[{"id":"2-19","idReadable":"OPS-7"}]`},
		{name: "non json", body: "BAD_BODY_SENTINEL " + testToken},
		{name: "oversize", body: strings.Repeat("x", maxResponseBodyBytes+1)},
		{name: "gzip oversize", body: strings.Repeat("x", maxResponseBodyBytes+1), gzip: true},
		{name: "rate limited", status: 429},
		{name: "server error", status: 503},
		{name: "bad gateway", status: 502},
		{name: "redirect", status: 307},
		{name: "created without a verifiable body", status: 201, body: `{"id":"2-19","idReadable":"OPS-7"}`},
		{name: "bad request", status: 400, body: "UPSTREAM_SENTINEL " + testToken, wantCode: errx.CodeUsage, wantReason: "USAGE"},
		{name: "auth rejection", status: 401, body: "UPSTREAM_SENTINEL " + testToken, wantCode: errx.CodeAuth, wantReason: "AUTHENTICATION_FAILED"},
		{name: "permission rejection", status: 403, body: "UPSTREAM_SENTINEL " + testToken, wantCode: errx.CodePermission, wantReason: "PERMISSION_DENIED"},
		{name: "not found", status: 404, wantCode: errx.CodeConflict, wantReason: "TARGET_CHANGED"},
		{name: "conflict", status: 409, wantCode: errx.CodeConflict, wantReason: "PRECONDITION_FAILED"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				calls.Add(1)
				if request.GetBody != nil {
					t.Error("mutation request is replayable")
				}
				if test.gzip {
					writer.Header().Set("Content-Encoding", "gzip")
				}
				if test.status != 0 {
					writer.Header().Set("Location", "/another-endpoint")
					writer.WriteHeader(test.status)
				}
				if test.gzip {
					zipper := gzip.NewWriter(writer)
					_, _ = io.WriteString(zipper, test.body)
					_ = zipper.Close()
				} else {
					_, _ = io.WriteString(writer, test.body)
				}
			}))
			defer server.Close()
			err := newTestClient(t, server).AddIssueLink(t.Context(), validAddLinkInput())
			if test.wantReason == "" {
				assertError(t, err, errx.CodeConflict, "WRITE_OUTCOME_UNKNOWN")
			} else {
				assertError(t, err, test.wantCode, test.wantReason)
			}
			if calls.Load() != 1 || strings.Contains(err.Error(), "SENTINEL") || strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), server.URL) {
				t.Fatalf("err=%v calls=%d", err, calls.Load())
			}
		})
	}
}

type linkFailureTransport struct {
	calls      atomic.Int32
	replayable atomic.Bool
}

func (transport *linkFailureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.calls.Add(1)
	if request.GetBody != nil {
		transport.replayable.Store(true)
		return nil, errors.New("replayable request")
	}
	return nil, errors.New("TRANSPORT_SENTINEL " + testToken)
}

func TestAddIssueLinkTransportLossIsUnknownSingleAndRedacted(t *testing.T) {
	transport := &linkFailureTransport{}
	client, err := New(Config{RESTBaseURL: "https://tracker.example.test/api"}, Credential{Token: testToken}, WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatal(err)
	}
	err = client.AddIssueLink(context.Background(), validAddLinkInput())
	assertError(t, err, errx.CodeConflict, "WRITE_OUTCOME_UNKNOWN")
	if transport.calls.Load() != 1 || transport.replayable.Load() || strings.Contains(err.Error(), "SENTINEL") || strings.Contains(err.Error(), testToken) {
		t.Fatalf("err=%v calls=%d", err, transport.calls.Load())
	}
}

func TestAddIssueLinkRejectsInvalidInputBeforeNetwork(t *testing.T) {
	mutate := map[string]func(*AddIssueLinkInput){
		"source path traversal": func(i *AddIssueLinkInput) { i.SourceID = "../x" },
		"link id separator":     func(i *AddIssueLinkInput) { i.LinkID = "105-1/s" },
		"link id query":         func(i *AddIssueLinkInput) { i.LinkID = "105-1s?x=1" },
		"empty link id":         func(i *AddIssueLinkInput) { i.LinkID = "" },
		"empty target":          func(i *AddIssueLinkInput) { i.TargetID = "" },
		"target needs quoting":  func(i *AddIssueLinkInput) { i.TargetID = `2-19"}` },
		"empty readable id":     func(i *AddIssueLinkInput) { i.TargetReadableID = "" },
		"self link":             func(i *AddIssueLinkInput) { i.TargetID = i.SourceID },
	}
	for name, change := range mutate {
		t.Run(name, func(t *testing.T) {
			transport := &countingTransport{}
			client, err := New(Config{RESTBaseURL: "https://tracker.example.test/api"}, Credential{Token: testToken}, WithHTTPClient(&http.Client{Transport: transport}))
			if err != nil {
				t.Fatal(err)
			}
			input := validAddLinkInput()
			change(&input)
			assertError(t, client.AddIssueLink(context.Background(), input), errx.CodeUsage, "USAGE")
			if transport.calls.Load() != 0 {
				t.Fatalf("invalid input reached transport %d times", transport.calls.Load())
			}
		})
	}
}
