package application

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
)

const inspectIssueSummaryJSON = `{"id":"2-12","idReadable":"APP-12","summary":"New summary","project":{"id":"0-3","shortName":"APP","name":"Application","archived":false},"updated":2}`

func TestInspectIssuesRejectsInvalidInputBeforeCredentials(t *testing.T) {
	for _, test := range []struct {
		name, query   string
		limit, offset int
	}{
		{"empty query", "", 10, 0},
		{"whitespace query", " \t", 10, 0},
		{"newline query", "project: APP\n", 10, 0},
		{"NUL query", "project: APP\x00", 10, 0},
		{"long query", strings.Repeat("a", 4097), 10, 0},
		{"zero limit", "project: APP", 0, 0},
		{"limit above public maximum", "project: APP", 51, 0},
		{"negative offset", "project: APP", 10, -1},
	} {
		t.Run(test.name, func(t *testing.T) {
			credentials := &trapCredentials{}
			service := &Service{Credentials: credentials}
			_, _, _, err := service.InspectIssues(t.Context(), "work", test.query, test.limit, test.offset)
			if errx.ExitCode(err) != errx.CodeUsage || credentials.calls != 0 {
				t.Fatalf("error=%v credential calls=%d", err, credentials.calls)
			}
		})
	}
}

func TestInspectIssuesVerifiesAccountAndBoundsOnePage(t *testing.T) {
	for _, test := range []struct {
		name                 string
		limit, offset, count int
		truncated            bool
	}{
		{"empty", 10, 0, 0, false},
		{"exact limit", 2, 0, 2, false},
		{"sentinel", 2, 7, 3, true},
		{"maximum", 50, 19, 51, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := make([]string, 0, 2)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/api/users/me":
					requests = append(requests, "account")
					_, _ = io.WriteString(w, `{"id":"1-2","login":"alice"}`)
				case "/api/issues":
					requests = append(requests, "issues")
					if r.URL.Query().Get("query") != "project: APP" || r.URL.Query().Get("$top") != strconv.Itoa(test.limit+1) || r.URL.Query().Get("$skip") != strconv.Itoa(test.offset) {
						t.Errorf("query=%s", r.URL.RawQuery)
					}
					body := strings.TrimSuffix(strings.Repeat(inspectIssueSummaryJSON+",", test.count), ",")
					_, _ = io.WriteString(w, "["+body+"]")
				default:
					t.Errorf("unexpected request %s", r.URL.Path)
				}
			}))
			defer server.Close()

			values, truncated, selected, err := inspectTestService(t, server).InspectIssues(t.Context(), "work", "project: APP", test.limit, test.offset)
			wantCount := min(test.count, test.limit)
			if err != nil || len(values) != wantCount || truncated != test.truncated || selected.ExpectedAccountID != "1-2" || strings.Join(requests, ",") != "account,issues" {
				t.Fatalf("values=%#v truncated=%v selected=%#v requests=%v error=%v", values, truncated, selected, requests, err)
			}
			if values == nil {
				t.Fatal("empty response must be a typed empty slice")
			}
		})
	}
}
