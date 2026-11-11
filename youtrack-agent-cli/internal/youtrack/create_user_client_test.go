package youtrack

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
)

func createWithUserFields() CreateIssueInput {
	input := createInput()
	input.CustomFields = append(input.CustomFields,
		CreateCustomField{ProjectFieldID: "190-3", Name: "Assignee", Type: "SingleUserIssueCustomField", ValueID: "1-7"},
		CreateCustomField{ProjectFieldID: "189-5", Name: "Subsystem", Type: "SingleEnumIssueCustomField", Clear: true})
	return input
}

// createdUserIssueJSON answers createWithUserFields; assignee and subsystem
// are the raw ,"value":... members (or nothing) of the two added fields.
func createdUserIssueJSON(assignee, subsystem string) string {
	return `{"id":"2-40","idReadable":"TAC-7","summary":"Harness MR","description":"Body\n\n[marker]","project":{"id":"0-1","shortName":"TAC","name":"Tackroom","archived":false},"reporter":{"id":"2-1","login":"admin"},"created":1,"updated":1,"commentsCount":0,"customFields":[` +
		`{"id":"189-8","name":"Stage","$type":"StateIssueCustomField","value":{"id":"20-2","name":"In Progress","$type":"StateBundleElement"},"projectCustomField":{"id":"189-8","field":{"id":"58-1"}}},` +
		`{"id":"190-3","name":"Assignee","$type":"SingleUserIssueCustomField"` + assignee + `,"projectCustomField":{"id":"190-3","field":{"id":"58-2"}}},` +
		`{"id":"189-5","name":"Subsystem","$type":"SingleEnumIssueCustomField"` + subsystem + `,"projectCustomField":{"id":"189-5","field":{"id":"58-3"}}}]}`
}

const (
	assigneeSet   = `,"value":{"id":"1-7","login":"jdoe","$type":"User"}`
	subsystemNull = `,"value":null`
)

func TestCreateIssueSendsUserSetAndClearOnce(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		posts.Add(1)
		raw, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
		}
		const want = `{"project":{"id":"0-1"},"summary":"Harness MR","description":"Body\n\n[marker]","customFields":[` +
			`{"name":"Stage","$type":"StateIssueCustomField","value":{"id":"20-2"}},` +
			`{"name":"Assignee","$type":"SingleUserIssueCustomField","value":{"id":"1-7"}},` +
			`{"name":"Subsystem","$type":"SingleEnumIssueCustomField","value":null}]}`
		if string(raw) != want {
			t.Errorf("payload=%s\nwant   =%s", raw, want)
		}
		_, _ = io.WriteString(writer, createdUserIssueJSON(assigneeSet, subsystemNull))
	}))
	defer server.Close()
	issue, err := newTestClient(t, server).CreateIssue(context.Background(), createWithUserFields())
	if err != nil || issue.ID != "2-40" || posts.Load() != 1 {
		t.Fatalf("issue=%#v err=%v posts=%d", issue, err, posts.Load())
	}
}

func TestCreateIssueUserAndClearResponsesAreVerifiedExactly(t *testing.T) {
	tests := []struct {
		name                string
		assignee, subsystem string
		verified            bool
	}{
		{"set and cleared", assigneeSet, subsystemNull, true},
		{"set user without a type", `,"value":{"id":"1-7","login":"jdoe"}`, subsystemNull, false},
		{"set user with another type", `,"value":{"id":"1-7","$type":"UserGroup"}`, subsystemNull, false},
		{"set user with another id", `,"value":{"id":"1-8","$type":"User"}`, subsystemNull, false},
		{"set user refilled to null", subsystemNull, subsystemNull, false},
		{"set user value missing", ``, subsystemNull, false},
		{"cleared field refilled", assigneeSet, `,"value":{"id":"9-1","$type":"EnumBundleElement"}`, false},
		{"cleared field empty object", assigneeSet, `,"value":{}`, false},
		{"cleared field empty id", assigneeSet, `,"value":{"id":""}`, false},
		{"cleared field value missing", assigneeSet, ``, false},
		{"cleared field empty array", assigneeSet, `,"value":[]`, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var posts atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				posts.Add(1)
				_, _ = io.WriteString(writer, createdUserIssueJSON(test.assignee, test.subsystem))
			}))
			defer server.Close()
			issue, err := newTestClient(t, server).CreateIssue(context.Background(), createWithUserFields())
			if posts.Load() != 1 {
				t.Fatalf("posts=%d", posts.Load())
			}
			if test.verified {
				if err != nil || issue.ID != "2-40" {
					t.Fatalf("issue=%#v err=%v", issue, err)
				}
				return
			}
			assertError(t, err, errx.CodeConflict, "WRITE_OUTCOME_UNKNOWN")
			if issue.ID != "2-40" || issue.IDReadable != "TAC-7" {
				t.Fatalf("identity=%#v", issue)
			}
		})
	}
}

func TestCreateIssueWithUserFieldsIsOneShotOnTransientFailure(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var posts atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				posts.Add(1)
				writer.WriteHeader(status)
			}))
			defer server.Close()
			_, err := newTestClient(t, server).CreateIssue(context.Background(), createWithUserFields())
			assertError(t, err, errx.CodeConflict, "WRITE_OUTCOME_UNKNOWN")
			if posts.Load() != 1 {
				t.Fatalf("posts=%d", posts.Load())
			}
		})
	}
	t.Run("connection loss", func(t *testing.T) {
		var posts atomic.Int32
		server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			posts.Add(1)
			connection, _, err := writer.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			// Closing models transport loss after the request was sent.
			if err := connection.Close(); err != nil {
				t.Error(err)
			}
		}))
		defer server.Close()
		_, err := newTestClient(t, server).CreateIssue(context.Background(), createWithUserFields())
		assertError(t, err, errx.CodeConflict, "WRITE_OUTCOME_UNKNOWN")
		if posts.Load() != 1 {
			t.Fatalf("posts=%d", posts.Load())
		}
	})
}

func TestCreateIssueRefusesInvalidClearBeforeNetwork(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("invalid create input reached the network")
	}))
	defer server.Close()
	tests := []struct {
		name  string
		field CreateCustomField
		valid bool
	}{
		{"clear with a value", CreateCustomField{ProjectFieldID: "190-3", Name: "Assignee", Type: "SingleUserIssueCustomField", ValueID: "1-7", Clear: true}, false},
		{"neither value nor clear", CreateCustomField{ProjectFieldID: "190-3", Name: "Assignee", Type: "SingleUserIssueCustomField"}, false},
		{"clear alone", CreateCustomField{ProjectFieldID: "190-3", Name: "Assignee", Type: "SingleUserIssueCustomField", Clear: true}, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := createInput()
			input.CustomFields = append(input.CustomFields, test.field)
			err := ValidateCreateIssueInput(input)
			if test.valid != (err == nil) {
				t.Fatalf("valid=%v err=%v", test.valid, err)
			}
			if !test.valid {
				assertError(t, err, errx.CodeUsage, "USAGE")
				_, err = newTestClient(t, server).CreateIssue(context.Background(), input)
				assertError(t, err, errx.CodeUsage, "USAGE")
			}
		})
	}
}

func TestCreatedIssueMatchesUserAndClearEvidence(t *testing.T) {
	var issue Issue
	if err := json.Unmarshal([]byte(createdUserIssueJSON(assigneeSet, subsystemNull)), &issue); err != nil {
		t.Fatal(err)
	}
	if !CreatedIssueMatches(issue, createWithUserFields()) {
		t.Fatal("exact created issue refused")
	}
	var refilled Issue
	if err := json.Unmarshal([]byte(createdUserIssueJSON(assigneeSet, `,"value":{"id":"9-1"}`)), &refilled); err != nil {
		t.Fatal(err)
	}
	if CreatedIssueMatches(refilled, createWithUserFields()) {
		t.Fatal("a refilled cleared field matched")
	}
	identity := createWithUserFields()
	identity.CustomFields = nil
	if !CreatedIssueMatches(refilled, identity) {
		t.Fatal("identity-only evidence refused")
	}
}
