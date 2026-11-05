package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
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
