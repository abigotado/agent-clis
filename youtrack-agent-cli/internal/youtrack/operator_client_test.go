package youtrack

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
)

const publicCommentJSON = `{"id":"4-1","author":{"id":"1-2","login":"alice"},"text":"Final text [plan-marker]","deleted":false,"visibility":{"$type":"UnlimitedVisibility"}}`
const exactProjectFieldJSON = `{"id":"92-1","$type":"StateProjectCustomField","project":{"id":"0-3"},"field":{"id":"42-1","name":"Stage","fieldType":{"id":"state[1]","valueType":"state","isMultiValue":false,"$type":"FieldType"}},"canBeEmpty":true,"isPublic":true,"bundle":{"id":"100-1","$type":"StateBundle","values":[{"id":"101-1","name":"Open","archived":false,"$type":"StateBundleElement"}]}}`

func validAddCommentInput() AddCommentInput {
	return AddCommentInput{IssueID: "2-12", ExpectedAuthorID: "1-2", ExpectedAuthorLogin: "alice", Text: "Final text [plan-marker]"}
}

func TestOperatorExactReadsPinPathProjectionAndIdentity(t *testing.T) {
	tests := []struct {
		name, path, fields, response string
		invoke                       func(*Client) error
	}{
		{name: "project field", path: "/youtrack/api/admin/projects/0-3/customFields/92-1", fields: projectFieldFields + ",project(id)", response: exactProjectFieldJSON,
			invoke: func(client *Client) error {
				_, err := client.GetProjectField(context.Background(), "0-3", "92-1")
				return err
			}},
		{name: "comment", path: "/youtrack/api/issues/2-12/comments/4-1", fields: commentFields, response: publicCommentJSON,
			invoke: func(client *Client) error {
				_, err := client.GetComment(context.Background(), "2-12", "4-1")
				return err
			}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				calls.Add(1)
				if request.Method != http.MethodGet || request.URL.Path != test.path || request.URL.Query().Get("fields") != test.fields || len(request.URL.Query()) != 1 {
					t.Errorf("unexpected exact request: %s %s", request.Method, request.URL.RequestURI())
				}
				// Returned URLs are inert and cannot redirect the next operation.
				_, _ = io.WriteString(writer, strings.TrimSuffix(test.response, "}")+`,"url":"https://untrusted.example/api"}`)
			}))
			defer server.Close()
			if err := test.invoke(newTestClient(t, server)); err != nil || calls.Load() != 1 {
				t.Fatalf("err=%v calls=%d", err, calls.Load())
			}
		})
	}
}

func TestOperatorExactReadsRejectInvalidReturnedShape(t *testing.T) {
	tests := []struct {
		name, response string
		comment        bool
	}{
		{name: "field identity", response: strings.Replace(exactProjectFieldJSON, `"id":"92-1"`, `"id":"92-9"`, 1)},
		{name: "project identity", response: strings.Replace(exactProjectFieldJSON, `"id":"0-3"`, `"id":"0-9"`, 1)},
		{name: "missing project", response: strings.Replace(exactProjectFieldJSON, `"project":{"id":"0-3"},`, "", 1)},
		{name: "global identity", response: strings.Replace(exactProjectFieldJSON, `"id":"42-1"`, `"id":"../bad"`, 1)},
		{name: "missing field type", response: strings.Replace(exactProjectFieldJSON, `"valueType":"state"`, `"valueType":""`, 1)},
		{name: "missing cardinality", response: strings.Replace(exactProjectFieldJSON, `"isMultiValue":false,`, "", 1)},
		{name: "null emptiness", response: strings.Replace(exactProjectFieldJSON, `"canBeEmpty":true`, `"canBeEmpty":null`, 1)},
		{name: "missing public", response: strings.Replace(exactProjectFieldJSON, `"isPublic":true,`, "", 1)},
		{name: "malformed bundle", response: strings.Replace(exactProjectFieldJSON, `"id":"100-1"`, `"id":""`, 1)},
		{name: "malformed value", response: strings.Replace(exactProjectFieldJSON, `"id":"101-1"`, `"id":""`, 1)},
		{name: "missing archived", response: strings.Replace(exactProjectFieldJSON, `"archived":false,`, "", 1)},
		{name: "null archived", response: strings.Replace(exactProjectFieldJSON, `"archived":false`, `"archived":null`, 1)},
		{name: "comment identity", comment: true, response: strings.Replace(publicCommentJSON, `"id":"4-1"`, `"id":"4-9"`, 1)},
		{name: "null comment", comment: true, response: "null"},
		{name: "missing deleted", comment: true, response: strings.Replace(publicCommentJSON, `"deleted":false,`, "", 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(writer, test.response) }))
			defer server.Close()
			client := newTestClient(t, server)
			var err error
			if test.comment {
				_, err = client.GetComment(context.Background(), "2-12", "4-1")
			} else {
				_, err = client.GetProjectField(context.Background(), "0-3", "92-1")
			}
			if err == nil {
				t.Fatal("unverified exact read succeeded")
			}
		})
	}
}

func TestIssueFieldCrosswalkProjection(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !strings.Contains(request.URL.Query().Get("fields"), "projectCustomField(id,field(id))") {
			t.Error("issue projection omitted the schema crosswalk")
		}
		response := strings.Replace(validIssueJSON("APP-12", "Summary"), `"customFields":[]`, `"customFields":[{"id":"issue-field-1","name":"Stage","$type":"StateIssueCustomField","value":null,"projectCustomField":{"id":"92-1","field":{"id":"42-1"}}}]`, 1)
		_, _ = io.WriteString(writer, response)
	}))
	defer server.Close()
	issue, err := newTestClient(t, server).GetIssue(context.Background(), "APP-12")
	if err != nil || len(issue.CustomFields) != 1 || issue.CustomFields[0].ProjectCustomField == nil || issue.CustomFields[0].ProjectCustomField.Field.ID != "42-1" {
		t.Fatalf("issue=%#v err=%v", issue, err)
	}
}

func TestExactProjectFieldPreservesArchivedValue(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, strings.Replace(exactProjectFieldJSON, `"archived":false`, `"archived":true`, 1))
	}))
	defer server.Close()
	field, err := newTestClient(t, server).GetProjectField(context.Background(), "0-3", "92-1")
	if err != nil || field.Bundle == nil || len(field.Bundle.Values) != 1 || !field.Bundle.Values[0].Archived {
		t.Fatalf("field=%#v err=%v", field, err)
	}
}

func TestAddCommentPinsTypedPayloadAndVerifiesPublicResult(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.Method != http.MethodPost || request.URL.Path != "/youtrack/api/issues/2-12/comments" || request.URL.Query().Get("fields") != commentFields || len(request.URL.Query()) != 1 {
			t.Errorf("unexpected mutation: %s %s", request.Method, request.URL.RequestURI())
		}
		var payload map[string]json.RawMessage
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		if len(payload) != 2 || string(payload["text"]) != `"Final text [plan-marker]"` || string(payload["visibility"]) != `{"$type":"UnlimitedVisibility"}` {
			t.Errorf("unexpected payload: %s", payload)
		}
		_, _ = io.WriteString(writer, publicCommentJSON)
	}))
	defer server.Close()
	result, err := newTestClient(t, server).AddComment(context.Background(), validAddCommentInput())
	if err != nil || result.ID != "4-1" || result.Deleted || calls.Load() != 1 {
		t.Fatalf("result=%#v err=%v calls=%d", result, err, calls.Load())
	}
}

func TestAddCommentRejectsUnverifiedSuccessWithoutReplay(t *testing.T) {
	tests := []struct{ name, response string }{
		{"null", "null"},
		{"invalid id", strings.Replace(publicCommentJSON, `"id":"4-1"`, `"id":"../bad"`, 1)},
		{"text mismatch", strings.Replace(publicCommentJSON, "Final text", "Other text", 1)},
		{"null text", strings.Replace(publicCommentJSON, `"text":"Final text [plan-marker]"`, `"text":null`, 1)},
		{"author mismatch", strings.Replace(publicCommentJSON, `"id":"1-2"`, `"id":"1-9"`, 1)},
		{"login mismatch", strings.Replace(publicCommentJSON, "alice", "other", 1)},
		{"null author", strings.Replace(publicCommentJSON, `"author":{"id":"1-2","login":"alice"}`, `"author":null`, 1)},
		{"deleted", strings.Replace(publicCommentJSON, `"deleted":false`, `"deleted":true`, 1)},
		{"null deleted", strings.Replace(publicCommentJSON, `"deleted":false`, `"deleted":null`, 1)},
		{"missing deleted", strings.Replace(publicCommentJSON, `"deleted":false,`, "", 1)},
		{"limited visibility", strings.Replace(publicCommentJSON, "UnlimitedVisibility", "LimitedVisibility", 1)},
		{"null visibility", strings.Replace(publicCommentJSON, `{"$type":"UnlimitedVisibility"}`, "null", 1)},
		{"permitted group", strings.Replace(publicCommentJSON, `"UnlimitedVisibility"`, `"UnlimitedVisibility","permittedGroups":[{"id":"3-1"}]`, 1)},
		{"permitted user", strings.Replace(publicCommentJSON, `"UnlimitedVisibility"`, `"UnlimitedVisibility","permittedUsers":[{"id":"1-2"}]`, 1)},
		{"malformed visibility", strings.Replace(publicCommentJSON, `"UnlimitedVisibility"`, `"UnlimitedVisibility","permittedUsers":{}`, 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				_, _ = io.WriteString(writer, test.response)
			}))
			defer server.Close()
			_, err := newTestClient(t, server).AddComment(context.Background(), validAddCommentInput())
			assertError(t, err, errx.CodeConflict, "WRITE_OUTCOME_UNKNOWN")
			if calls.Load() != 1 {
				t.Fatalf("calls=%d", calls.Load())
			}
		})
	}
}

func TestOperatorInputValidationPrecedesTransport(t *testing.T) {
	transport := &countingTransport{}
	client, err := New(Config{RESTBaseURL: "https://tracker.example.test/api"}, Credential{Token: testToken}, WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		edit func(*AddCommentInput)
	}{
		{"issue", func(input *AddCommentInput) { input.IssueID = "../other" }},
		{"author", func(input *AddCommentInput) { input.ExpectedAuthorID = "" }},
		{"login", func(input *AddCommentInput) { input.ExpectedAuthorLogin = " " }},
		{"empty", func(input *AddCommentInput) { input.Text = "\n " }},
		{"oversize including marker", func(input *AddCommentInput) { input.Text = strings.Repeat("x", maxCommentBytes) + " [marker]" }},
		{"invalid utf8", func(input *AddCommentInput) { input.Text = "\xff" }},
		{"nul", func(input *AddCommentInput) { input.Text = "text\x00" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validAddCommentInput()
			test.edit(&input)
			_, err := client.AddComment(context.Background(), input)
			if errx.ExitCode(err) != errx.CodeUsage {
				t.Fatalf("err=%v", err)
			}
		})
	}
	for _, identifiers := range [][2]string{{"../project", "92-1"}, {"0-3", "../field"}} {
		if _, err := client.GetProjectField(context.Background(), identifiers[0], identifiers[1]); errx.ExitCode(err) != errx.CodeUsage {
			t.Fatalf("err=%v", err)
		}
	}
	for _, identifiers := range [][2]string{{"../issue", "4-1"}, {"2-12", "../comment"}} {
		if _, err := client.GetComment(context.Background(), identifiers[0], identifiers[1]); errx.ExitCode(err) != errx.CodeUsage {
			t.Fatalf("err=%v", err)
		}
	}
	if transport.calls.Load() != 0 {
		t.Fatalf("invalid input reached transport %d times", transport.calls.Load())
	}
}

func TestUpdateIssueVerifiesTouchedFieldIdentityTypeAndValue(t *testing.T) {
	tests := []struct {
		name, expected, returned string
		wantUnknown              bool
	}{
		{"entity accepts names", `{"id":"101-1"}`, `[{"id":"issue-field-1","name":"Stage","$type":"StateIssueCustomField","value":{"id":"101-1","name":"Open","$type":"StateBundleElement"}}]`, false},
		{"missing", `{"id":"101-1"}`, `[]`, true},
		{"id mismatch", `{"id":"101-1"}`, `[{"id":"other","name":"Stage","$type":"StateIssueCustomField","value":{"id":"101-1"}}]`, true},
		{"type mismatch", `{"id":"101-1"}`, `[{"id":"issue-field-1","name":"Stage","$type":"SingleEnumIssueCustomField","value":{"id":"101-1"}}]`, true},
		{"value mismatch", `{"id":"101-1"}`, `[{"id":"issue-field-1","name":"Stage","$type":"StateIssueCustomField","value":{"id":"101-9"}}]`, true},
		{"null mismatch", `{"id":"101-1"}`, `[{"id":"issue-field-1","name":"Stage","$type":"StateIssueCustomField","value":null}]`, true},
		{"duplicate", `{"id":"101-1"}`, `[{"id":"issue-field-1","name":"Stage","$type":"StateIssueCustomField","value":{"id":"101-1"}},{"id":"issue-field-1","name":"Stage","$type":"StateIssueCustomField","value":{"id":"101-1"}}]`, true},
		{"generic string", `"value"`, `[{"id":"issue-field-1","name":"Text","$type":"StateIssueCustomField","value":"value"}]`, false},
		{"generic null", `null`, `[{"id":"issue-field-1","name":"Text","$type":"StateIssueCustomField","value":null}]`, false},
		{"generic number", `7`, `[{"id":"issue-field-1","name":"Number","$type":"StateIssueCustomField","value":7}]`, false},
		{"entity list", `[{"id":"101-1"}]`, `[{"id":"issue-field-1","name":"Multi","$type":"StateIssueCustomField","value":[{"id":"101-1","name":"Open"}]}]`, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				calls.Add(1)
				if request.Method != http.MethodPost || request.URL.Path != "/youtrack/api/issues/2-12" || request.URL.Query().Get("fields") != issueFields {
					t.Error("update endpoint or projection changed")
				}
				var payload struct {
					CustomFields []CustomFieldUpdate `json:"customFields"`
				}
				if err := json.NewDecoder(request.Body).Decode(&payload); err != nil || len(payload.CustomFields) != 1 || string(payload.CustomFields[0].Value) != test.expected {
					t.Errorf("payload=%#v err=%v", payload, err)
				}
				_, _ = io.WriteString(writer, strings.Replace(validIssueJSON("APP-12", "Summary"), `"customFields":[]`, `"customFields":`+test.returned, 1))
			}))
			defer server.Close()
			_, err := newTestClient(t, server).UpdateIssue(context.Background(), UpdateIssueInput{IssueID: "2-12", ProjectID: "0-3", ProjectKey: "APP", CustomFields: []CustomFieldUpdate{{ID: "issue-field-1", Type: "StateIssueCustomField", Value: json.RawMessage(test.expected)}}})
			if test.wantUnknown {
				assertError(t, err, errx.CodeConflict, "WRITE_OUTCOME_UNKNOWN")
			} else if err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 1 {
				t.Fatalf("calls=%d", calls.Load())
			}
		})
	}
}

type commentFailureTransport struct {
	calls      atomic.Int32
	replayable atomic.Bool
}

func (transport *commentFailureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.calls.Add(1)
	if request.GetBody != nil {
		transport.replayable.Store(true)
		return nil, errors.New("replayable request")
	}
	return nil, errors.New("TRANSPORT_SENTINEL " + testToken)
}

func TestAddCommentTransportIsNonReplayableAndRedacted(t *testing.T) {
	transport := &commentFailureTransport{}
	client, err := New(Config{RESTBaseURL: "https://tracker.example.test/api"}, Credential{Token: testToken}, WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.AddComment(context.Background(), validAddCommentInput())
	assertError(t, err, errx.CodeConflict, "WRITE_OUTCOME_UNKNOWN")
	if transport.calls.Load() != 1 || transport.replayable.Load() || strings.Contains(err.Error(), "SENTINEL") || strings.Contains(err.Error(), testToken) {
		t.Fatalf("err=%v calls=%d", err, transport.calls.Load())
	}
}

func TestAddCommentHTTPFailuresAreOneShotAndRedacted(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		gzip       bool
		wantCode   errx.Code
		wantReason string
	}{
		{name: "rate limited", status: 429},
		{name: "redirect", status: 307},
		{name: "server error", status: 503},
		{name: "bad body", body: "BAD_BODY_SENTINEL " + testToken},
		{name: "empty body"},
		{name: "oversize", body: strings.Repeat("x", maxResponseBodyBytes+1)},
		{name: "gzip oversize", body: strings.Repeat("x", maxResponseBodyBytes+1), gzip: true},
		{name: "bad gzip", body: "BAD_GZIP_SENTINEL", gzip: true},
		{name: "auth rejection", status: 401, body: "UPSTREAM_SENTINEL " + testToken, wantCode: errx.CodeAuth, wantReason: "AUTHENTICATION_FAILED"},
		{name: "permission rejection", status: 403, body: "UPSTREAM_SENTINEL " + testToken, wantCode: errx.CodePermission, wantReason: "PERMISSION_DENIED"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				if test.gzip {
					writer.Header().Set("Content-Encoding", "gzip")
				}
				if test.status != 0 {
					writer.Header().Set("Location", "/another-endpoint")
					writer.WriteHeader(test.status)
				}
				if test.gzip && test.name != "bad gzip" {
					zipper := gzip.NewWriter(writer)
					_, _ = io.WriteString(zipper, test.body)
					_ = zipper.Close()
				} else {
					_, _ = io.WriteString(writer, test.body)
				}
			}))
			defer server.Close()
			_, err := newTestClient(t, server).AddComment(context.Background(), validAddCommentInput())
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
