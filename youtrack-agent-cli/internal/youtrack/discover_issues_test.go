package youtrack

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
)

const issueSummaryJSON = `{"id":"2-12","idReadable":"APP-12","summary":"New summary","project":{"id":"0-3","shortName":"APP","name":"Application","archived":false},"updated":2}`

func TestDiscoverIssuesPinsCompactFieldsAndBounds(t *testing.T) {
	for _, test := range []struct {
		name, query, top, skip string
	}{
		{"bounded page", "project: APP", "3", "4"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/youtrack/api/issues" {
					t.Errorf("request=%s %s", r.Method, r.URL.Path)
				}
				if r.URL.Query().Get("query") != test.query || r.URL.Query().Get("$top") != test.top || r.URL.Query().Get("$skip") != test.skip {
					t.Errorf("query=%s", r.URL.RawQuery)
				}
				if got, want := r.URL.Query().Get("fields"), "id,idReadable,summary,project(id,shortName,name,archived),updated,customFields(name,$type,value(name,login))"; got != want {
					t.Errorf("fields=%q want %q", got, want)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, "["+strings.Replace(issueSummaryJSON, `"archived":false`, `"archived":true`, 1)+"]")
			}))
			defer server.Close()

			values, err := newTestClient(t, server).DiscoverIssues(context.Background(), test.query, PageOptions{Top: 3, Skip: 4})
			if err != nil || len(values) != 1 || values[0].Summary != "New summary" || !values[0].Project.Archived {
				t.Fatalf("values=%#v error=%v", values, err)
			}
		})
	}
}

func TestDiscoverIssuesRejectsMalformedResults(t *testing.T) {
	for _, test := range []struct {
		name, response string
	}{
		{"missing project name", `[{"id":"2-12","idReadable":"APP-12","summary":"New summary","project":{"id":"0-3","shortName":"APP"},"updated":2}]`},
		{"missing project archived", `[{"id":"2-12","idReadable":"APP-12","summary":"New summary","project":{"id":"0-3","shortName":"APP","name":"Application"},"updated":2}]`},
		{"null project archived", `[{"id":"2-12","idReadable":"APP-12","summary":"New summary","project":{"id":"0-3","shortName":"APP","name":"Application","archived":null},"updated":2}]`},
		{"missing updated timestamp", `[{"id":"2-12","idReadable":"APP-12","summary":"New summary","project":{"id":"0-3","shortName":"APP","name":"Application","archived":false}}]`},
		{"negative updated", `[{"id":"2-12","idReadable":"APP-12","summary":"New summary","project":{"id":"0-3","shortName":"APP","name":"Application","archived":false},"updated":-1}]`},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, test.response)
			}))
			defer server.Close()

			_, err := newTestClient(t, server).DiscoverIssues(context.Background(), "project: APP", PageOptions{Top: 1})
			if errx.ExitCode(err) != errx.CodeInternal {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestDiscoverIssuesKeepsOnlyRequestedCustomFieldProperties(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[{"id":"2-12","idReadable":"APP-12","summary":"S","project":{"id":"0-3","shortName":"APP","name":"Application","archived":false},"updated":2,
			"customFields":[{"id":"c-1","name":"Stage","$type":"StateIssueCustomField","projectCustomField":{"id":"p-1","field":{"id":"f-1"}},"value":{"name":"Open"}}]}]`)
	}))
	defer server.Close()

	values, err := newTestClient(t, server).DiscoverIssues(context.Background(), "project: APP", PageOptions{Top: 1})

	if err != nil || len(values) != 1 || len(values[0].CustomFields) != 1 {
		t.Fatalf("values=%#v error=%v", values, err)
	}
	field := values[0].CustomFields[0]
	if field.ID != "" || field.ProjectCustomField != nil || field.Name != "Stage" || field.Type != "StateIssueCustomField" || string(field.Value) != `{"name":"Open"}` {
		t.Fatalf("field=%#v", field)
	}
}

func TestDiscoverIssuesToleratesOddCustomFields(t *testing.T) {
	huge := strings.Repeat("x", maxCustomFieldValueSize)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[{"id":"2-12","idReadable":"APP-12","summary":"S","project":{"id":"0-3","shortName":"APP","name":"Application","archived":false},"updated":2,
			"customFields":[{"$type":"StateIssueCustomField","value":{"name":"Open"}},{"name":"NoType","value":null},
				{"name":"Notes","$type":"SimpleIssueCustomField","value":"`+huge+`"},{"name":"Stage","$type":"StateIssueCustomField","value":{"name":"Open"}}]}]`)
	}))
	defer server.Close()

	values, err := newTestClient(t, server).DiscoverIssues(context.Background(), "project: APP", PageOptions{Top: 1})

	if err != nil || len(values) != 1 || len(values[0].CustomFields) != 2 {
		t.Fatalf("values=%#v error=%v", values, err)
	}
	if notes := values[0].CustomFields[0]; notes.Name != "Notes" || notes.Value != nil {
		t.Errorf("oversized value was kept: name=%q len=%d", notes.Name, len(notes.Value))
	}
	if stage := values[0].CustomFields[1]; stage.Name != "Stage" || string(stage.Value) != `{"name":"Open"}` {
		t.Errorf("stage=%#v", stage)
	}
}

// YouTrack answers an unparseable query with 400 invalid_query. Its body is
// untrusted server text, so the sentinel must never reach the error.
const invalidQueryBody = `{"error":"invalid_query","error_description":"Can't parse search query SENTINEL-QUERY-TEXT","error_field":"query"}`

func TestIssueQueriesMapABadRequestByWhoWroteTheQuery(t *testing.T) {
	for _, test := range []struct {
		name       string
		search     func(*Client) error
		wantCode   errx.Code
		wantReason string
	}{
		{"caller-written discovery query is a usage error", func(client *Client) error {
			_, err := client.DiscoverIssues(context.Background(), "project: Application", PageOptions{Top: 2})
			return err
		}, errx.CodeUsage, "QUERY_REJECTED"},
		{"CLI-built reconciliation query stays internal", func(client *Client) error {
			_, err := client.SearchIssues(context.Background(), "project: APP", PageOptions{Top: 2})
			return err
		}, errx.CodeInternal, "INTERNAL"},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, invalidQueryBody)
			}))
			defer server.Close()

			err := test.search(newTestClient(t, server))

			var typed *errx.Error
			if !errors.As(err, &typed) || typed.Code != test.wantCode || typed.Reason != test.wantReason {
				t.Fatalf("error=%#v", err)
			}
			if requests != 1 {
				t.Errorf("requests=%d, a rejected query must not be retried", requests)
			}
			if strings.Contains(typed.Message+typed.Hint, "SENTINEL") {
				t.Errorf("server text leaked: %q %q", typed.Message, typed.Hint)
			}
		})
	}
}
