package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
)

const cliIssueSummaryJSON = `{"id":"2-12","idReadable":"APP-12","summary":"New summary","project":{"id":"0-3","shortName":"APP","name":"Application","archived":false},"updated":2}`

func TestInspectIssuesRejectsInvalidInvocationBeforeNetwork(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
	}{
		{"missing query", []string{"--profile", "work"}},
		{"zero limit", []string{"--profile", "work", "--query", "project: APP", "--limit", "0"}},
		{"unknown field", []string{"--profile", "work", "--query", "project: APP", "--fields", "nonexistent"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				_, _ = io.WriteString(w, `[]`)
			}))
			defer server.Close()
			app, _, _, _, stdout, stderr := testApp(t)
			service, store := commentsTestService(t, server)
			app.service = service
			code := runApp(app, append([]string{"inspect", "issues", "-o", "json"}, test.args...)...)
			if code != errx.CodeUsage || requests != 0 || store.loads != 0 || decode(t, stdout)["error"].(map[string]any)["code"] != "USAGE" {
				t.Fatalf("code=%d requests=%d loads=%d stdout=%s stderr=%s", code, requests, store.loads, stdout, stderr)
			}
		})
	}
}

func TestInspectIssuesUsesSavedDefaultAndReturnsBoundedEnvelope(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/users/me":
			_, _ = io.WriteString(w, `{"id":"1-2","login":"alice"}`)
		case "/api/issues":
			requests++
			if r.URL.Query().Get("query") != "project: APP" || r.URL.Query().Get("$top") != "11" || r.URL.Query().Get("$skip") != "0" {
				t.Errorf("query=%s", r.URL.RawQuery)
			}
			_, _ = io.WriteString(w, "["+cliIssueSummaryJSON+"]")
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
		}
	}))
	defer server.Close()
	app, _, _, _, stdout, stderr := testApp(t)
	service, store := commentsTestService(t, server)
	if _, err := service.ChangeProfileDefaults(t.Context(), funcName("work"), nil, false); err != nil {
		t.Fatal(err)
	}
	app.service = service
	if code := runApp(app, "inspect", "issues", "--query", "project: APP", "-o", "json"); code != errx.CodeOK {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	envelope := decode(t, stdout)
	meta := envelope["meta"].(map[string]any)
	if requests != 1 || store.loads != 1 || envelope["ok"] != true || meta["count"] != float64(1) || meta["truncated"] != false || meta["profile"] != "work" || meta["instance"] != server.URL || meta["account_id"] != "1-2" || meta["account_login"] != "alice" {
		t.Fatalf("requests=%d loads=%d envelope=%#v", requests, store.loads, envelope)
	}
}

func TestInspectIssuesRendersCompactTrustAndProjection(t *testing.T) {
	for _, test := range []struct {
		name, fields string
		empty        bool
	}{
		{"default compact fields", "", false},
		{"requested fields", "id,project_name", false},
		{"empty requested fields", "id,project_name", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/api/users/me":
					_, _ = io.WriteString(w, `{"id":"1-2","login":"alice"}`)
				case "/api/issues":
					if test.empty {
						_, _ = io.WriteString(w, `[]`)
					} else {
						_, _ = io.WriteString(w, "["+cliIssueSummaryJSON+"]")
					}
				default:
					t.Errorf("unexpected request %s", r.URL.Path)
				}
			}))
			defer server.Close()

			app, _, _, _, stdout, stderr := testApp(t)
			app.service, _ = commentsTestService(t, server)
			args := []string{"inspect", "issues", "--profile", "work", "--query", "project: APP", "-o", "json"}
			if test.fields != "" {
				args = append(args, "--fields", test.fields)
			}
			if code := runApp(app, args...); code != errx.CodeOK || stderr.Len() != 0 {
				t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			encoded, err := json.Marshal(decode(t, stdout)["data"])
			if err != nil {
				t.Fatal(err)
			}
			var rows []map[string]any
			if err := json.Unmarshal(encoded, &rows); err != nil {
				t.Fatal(err)
			}
			if test.empty {
				if rows == nil || len(rows) != 0 {
					t.Fatalf("empty rows=%#v", rows)
				}
				return
			}
			if len(rows) != 1 || rows[0]["trust"] != untrustedYouTrackContent {
				t.Fatalf("rows=%#v", rows)
			}
			if test.fields == "" {
				for _, field := range []string{"id", "readable_id", "summary", "project_id", "project_key", "updated"} {
					if _, ok := rows[0][field]; !ok {
						t.Errorf("default output misses %s: %#v", field, rows[0])
					}
				}
				for _, field := range []string{"description", "project_name", "project_archived"} {
					if _, ok := rows[0][field]; ok {
						t.Errorf("default output leaks %s: %#v", field, rows[0])
					}
				}
				return
			}
			if len(rows[0]) != 3 || rows[0]["id"] != "2-12" || rows[0]["project_name"] != "Application" {
				t.Fatalf("projected rows=%#v", rows)
			}
		})
	}
}

func TestInspectIssuesReportsStageAndAssigneeFromTheServerResponse(t *testing.T) {
	var requestedFields string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/users/me" {
			_, _ = io.WriteString(w, `{"id":"1-2","login":"alice"}`)
			return
		}
		requestedFields = r.URL.Query().Get("fields")
		_, _ = io.WriteString(w, `[
			{"id":"2-1","idReadable":"APP-1","summary":"S","project":{"id":"0-1","shortName":"APP","name":"App","archived":false},"updated":2,
			 "customFields":[
				{"name":"Stage","$type":"StateIssueCustomField","value":{"name":"In Progress","$type":"StateBundleElement"}},
				{"name":"Assignee","$type":"SingleUserIssueCustomField","value":{"login":"alice","name":"Alice","$type":"User"}},
				{"name":"Priority","$type":"SingleEnumIssueCustomField","value":{"name":"Normal","$type":"EnumBundleElement"}}]},
			{"id":"2-2","idReadable":"APP-2","summary":"T","project":{"id":"0-1","shortName":"APP","name":"App","archived":false},"updated":3,
			 "customFields":[
				{"name":"State","$type":"StateMachineIssueCustomField","value":{"name":"Open","$type":"StateMachineEventElement"}},
				{"name":"Reviewers","$type":"MultiUserIssueCustomField","value":[{"login":"bob","$type":"User"},{"login":"carol","$type":"User"}]},
				{"name":"Owner","$type":"SingleUserIssueCustomField","value":null}]},
			{"id":"2-3","idReadable":"APP-3","summary":"U","project":{"id":"0-1","shortName":"APP","name":"App","archived":false},"updated":4}]`)
	}))
	defer server.Close()
	app, _, _, _, stdout, stderr := testApp(t)
	service, _ := commentsTestService(t, server)
	app.service = service

	code := runApp(app, "inspect", "issues", "--profile", "work", "--query", "project: APP", "-o", "json")

	if code != errx.CodeOK {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	// Scoped because these property names also occur elsewhere in the query.
	_, customFields, _ := strings.Cut(requestedFields, "customFields(")
	fieldProperties, valueProperties, _ := strings.Cut(customFields, "value(")
	valueProperties, _, _ = strings.Cut(valueProperties, ")")
	if !strings.Contains(fieldProperties, "$type") || !strings.Contains(fieldProperties, "name") {
		t.Errorf("custom field properties %q omit $type or name", fieldProperties)
	}
	for _, property := range strings.Fields("login name") {
		if !strings.Contains(valueProperties, property) {
			t.Errorf("custom field value properties %q omit %q", valueProperties, property)
		}
	}
	encoded, err := json.Marshal(decode(t, stdout)["data"])
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &rows); err != nil || len(rows) != 3 {
		t.Fatalf("rows=%s error=%v", encoded, err)
	}
	for index, want := range []map[string]string{
		{"state_fields": `[{"name":"Stage","values":["In Progress"]}]`, "user_fields": `[{"name":"Assignee","values":["alice"]}]`},
		{"state_fields": `[{"name":"State","values":["Open"]}]`, "user_fields": `[{"name":"Reviewers","values":["bob","carol"]},{"name":"Owner","values":[]}]`},
		{"state_fields": `[]`, "user_fields": `[]`},
	} {
		for field, value := range want {
			if got := string(rows[index][field]); got != value {
				t.Errorf("row %d %s=%s, want %s", index, field, got, value)
			}
		}
		if _, ok := rows[index]["custom_fields"]; ok {
			t.Errorf("row %d leaks custom_fields: %s", index, encoded)
		}
	}
}

func TestInspectIssuesTextShowsQuotedStageAndAssignee(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/users/me" {
			_, _ = io.WriteString(w, `{"id":"1-2","login":"alice"}`)
			return
		}
		_, _ = io.WriteString(w, `[{"id":"2-1","idReadable":"APP-1","summary":"S","project":{"id":"0-1","shortName":"APP","name":"App","archived":false},"updated":2,
			"customFields":[{"name":"Stage","$type":"StateIssueCustomField","value":{"name":"A\"; user_fields=\"x","$type":"StateBundleElement"}},
				{"name":"Assignee","$type":"SingleUserIssueCustomField","value":{"login":"alice","$type":"User"}}]}]`)
	}))
	defer server.Close()
	app, _, _, _, stdout, stderr := testApp(t)
	app.service, _ = commentsTestService(t, server)

	code := runApp(app, "inspect", "issues", "--profile", "work", "--query", "project: APP", "-o", "text")

	if code != errx.CodeOK {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, want := range []string{`"Stage"="A\"; user_fields=\"x"`, `"Assignee"="alice"`} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("text output %q omits %s", stdout.String(), want)
		}
	}
}

func TestInspectIssuesSelectsAndRendersStageAndAssigneeFields(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want []string
		not  []string
	}{
		{"selected alone", []string{"-o", "json", "--fields", "state_fields,user_fields"}, []string{`"state_fields":[{"name":"Stage","values":["Open"]}]`, `"user_fields":[{"name":"Assignee","values":["alice"]}]`}, []string{"summary", "custom_fields"}},
		{"raw carries them", []string{"-o", "raw"}, []string{`"state_fields":[{"name":"Stage","values":["Open"]}]`}, []string{`"ok"`, "custom_fields"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/api/users/me" {
					_, _ = io.WriteString(w, `{"id":"1-2","login":"alice"}`)
					return
				}
				_, _ = io.WriteString(w, `[{"id":"2-1","idReadable":"APP-1","summary":"S","project":{"id":"0-1","shortName":"APP","name":"App","archived":false},"updated":2,
					"customFields":[{"name":"Stage","$type":"StateIssueCustomField","value":{"name":"Open"}},
						{"name":"Assignee","$type":"SingleUserIssueCustomField","value":{"login":"alice","name":"Alice"}}]}]`)
			}))
			defer server.Close()
			app, _, _, _, stdout, stderr := testApp(t)
			app.service, _ = commentsTestService(t, server)

			code := runApp(app, append([]string{"inspect", "issues", "--profile", "work", "--query", "project: APP"}, test.args...)...)

			if code != errx.CodeOK {
				t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			for _, want := range test.want {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("output omits %q: %s", want, stdout)
				}
			}
			for _, unwanted := range test.not {
				if strings.Contains(stdout.String(), unwanted) {
					t.Errorf("output contains %q: %s", unwanted, stdout)
				}
			}
		})
	}
}

func TestInspectIssuesReportsARejectedQueryAsUsage(t *testing.T) {
	searches := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/users/me":
			_, _ = io.WriteString(w, `{"id":"1-2","login":"alice"}`)
		case "/api/issues":
			searches++
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"invalid_query","error_description":"Can't parse search query SENTINEL-QUERY-TEXT"}`)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
		}
	}))
	defer server.Close()
	app, _, _, _, stdout, stderr := testApp(t)
	service, _ := commentsTestService(t, server)
	app.service = service

	code := runApp(app, "inspect", "issues", "--profile", "work", "--query", "project: Application", "-o", "json")

	envelope := decode(t, stdout)
	failure, _ := envelope["error"].(map[string]any)
	if code != errx.CodeUsage || searches != 1 || envelope["ok"] != false || failure["code"] != "QUERY_REJECTED" || !strings.Contains(envelope["hint"].(string), "--query") {
		t.Fatalf("code=%d searches=%d stdout=%s stderr=%s", code, searches, stdout, stderr)
	}
	if strings.Contains(stdout.String()+stderr.String(), "SENTINEL") {
		t.Fatalf("server text leaked: stdout=%s stderr=%s", stdout, stderr)
	}
}
