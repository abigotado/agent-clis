package youtrack

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
)

const createdIssueJSON = `{"id":"2-40","idReadable":"TAC-7","summary":"Harness MR","description":"Body\n\n[marker]","project":{"id":"0-1","shortName":"TAC","name":"Tackroom","archived":false},"reporter":{"id":"2-1","login":"admin"},"created":1,"updated":1,"commentsCount":0,"customFields":[{"id":"189-8","name":"Stage","$type":"StateIssueCustomField","value":{"id":"20-2","name":"In Progress","$type":"StateBundleElement"},"projectCustomField":{"id":"189-8","field":{"id":"58-1"}}}]}`

func createInput() CreateIssueInput {
	return CreateIssueInput{ProjectID: "0-1", ProjectKey: "TAC", Summary: "Harness MR", Description: stringPointer("Body\n\n[marker]"),
		ExpectedReporterID: "2-1", ExpectedReporterLogin: "admin",
		CustomFields: []CreateCustomField{{ProjectFieldID: "189-8", Name: "Stage", Type: "StateIssueCustomField", ValueID: "20-2"}}}
}

func TestCreateIssueSendsNameAddressedFieldsOnce(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		posts.Add(1)
		if request.Method != http.MethodPost || request.URL.Path != "/youtrack/api/issues" || request.URL.Query().Get("fields") != issueFields {
			t.Errorf("request=%s %s", request.Method, request.URL)
		}
		raw, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
		}
		const want = `{"project":{"id":"0-1"},"summary":"Harness MR","description":"Body\n\n[marker]","customFields":[{"name":"Stage","$type":"StateIssueCustomField","value":{"id":"20-2"}}]}`
		if string(raw) != want {
			t.Errorf("payload=%s\nwant   =%s", raw, want)
		}
		_, _ = io.WriteString(writer, createdIssueJSON)
	}))
	defer server.Close()
	issue, err := newTestClient(t, server).CreateIssue(context.Background(), createInput())
	if err != nil || issue.ID != "2-40" || issue.IDReadable != "TAC-7" || posts.Load() != 1 {
		t.Fatalf("issue=%#v err=%v posts=%d", issue, err, posts.Load())
	}
}

func TestCreateIssueUnverifiedResponseIsUnknownAndKeepsIdentity(t *testing.T) {
	tests := []struct {
		name, from, to string
		keepsIdentity  bool
	}{
		{"project", `"id":"0-1","shortName":"TAC"`, `"id":"0-2","shortName":"TAC"`, true},
		{"project key", `"shortName":"TAC"`, `"shortName":"CVF"`, true},
		{"summary", `"summary":"Harness MR"`, `"summary":"Harness MR (edited)"`, true},
		{"description", `"description":"Body\n\n[marker]"`, `"description":"Body"`, true},
		{"null description", `"description":"Body\n\n[marker]"`, `"description":null`, true},
		{"reporter", `"reporter":{"id":"2-1","login":"admin"}`, `"reporter":{"id":"2-9","login":"admin"}`, true},
		{"missing reporter", `"reporter":{"id":"2-1","login":"admin"},`, ``, true},
		{"field value", `"value":{"id":"20-2"`, `"value":{"id":"20-1"`, true},
		{"field type", `"$type":"StateIssueCustomField"`, `"$type":"SingleEnumIssueCustomField"`, true},
		{"field mapping", `"projectCustomField":{"id":"189-8"`, `"projectCustomField":{"id":"189-9"`, true},
		{"missing readable id", `"idReadable":"TAC-7",`, ``, true},
		{"missing id", `"id":"2-40",`, ``, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := strings.Replace(createdIssueJSON, test.from, test.to, 1)
			if body == createdIssueJSON {
				t.Fatalf("replacement %q did not apply", test.from)
			}
			var posts atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				posts.Add(1)
				_, _ = io.WriteString(writer, body)
			}))
			defer server.Close()
			issue, err := newTestClient(t, server).CreateIssue(context.Background(), createInput())
			assertError(t, err, errx.CodeConflict, "WRITE_OUTCOME_UNKNOWN")
			if posts.Load() != 1 {
				t.Fatalf("posts=%d", posts.Load())
			}
			wantReadable := "TAC-7"
			if strings.Contains(test.from, "idReadable") {
				wantReadable = ""
			}
			if test.keepsIdentity && (issue.ID != "2-40" || issue.IDReadable != wantReadable) || !test.keepsIdentity && (issue.ID != "" || issue.IDReadable != "") {
				t.Fatalf("identity=%#v", issue)
			}
		})
	}
}

func TestCreatedIssueMatchesRequiresExactlyOneMappedField(t *testing.T) {
	var issue Issue
	if err := json.Unmarshal([]byte(createdIssueJSON), &issue); err != nil {
		t.Fatal(err)
	}
	if !CreatedIssueMatches(issue, createInput()) {
		t.Fatal("exact created issue refused")
	}
	issue.CustomFields = append(issue.CustomFields, issue.CustomFields[0])
	if CreatedIssueMatches(issue, createInput()) {
		t.Fatal("duplicated mapped field accepted")
	}
	issue.CustomFields = nil
	if CreatedIssueMatches(issue, createInput()) {
		t.Fatal("missing mapped field accepted")
	}
}

func TestCreateIssueRejectsInvalidInputBeforeNetwork(t *testing.T) {
	tests := []struct {
		name   string
		change func(*CreateIssueInput)
	}{
		{"project key", func(input *CreateIssueInput) { input.ProjectKey = "" }},
		{"reporter", func(input *CreateIssueInput) { input.ExpectedReporterID = "" }},
		{"reporter login", func(input *CreateIssueInput) { input.ExpectedReporterLogin = " " }},
		{"field value", func(input *CreateIssueInput) { input.CustomFields[0].ValueID = "bad value" }},
		{"field type", func(input *CreateIssueInput) { input.CustomFields[0].Type = "State-Field" }},
		{"field name", func(input *CreateIssueInput) { input.CustomFields[0].Name = "" }},
		{"duplicate field", func(input *CreateIssueInput) {
			input.CustomFields = append(input.CustomFields, input.CustomFields[0])
		}},
		{"duplicate name", func(input *CreateIssueInput) {
			duplicate := input.CustomFields[0]
			duplicate.ProjectFieldID = "189-9"
			input.CustomFields = append(input.CustomFields, duplicate)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("invalid create input reached the network")
			}))
			defer server.Close()
			input := createInput()
			test.change(&input)
			_, err := newTestClient(t, server).CreateIssue(context.Background(), input)
			assertError(t, err, errx.CodeUsage, "USAGE")
		})
	}
}
