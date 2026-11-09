package application

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
)

func TestInspectCommentsRejectsBoundsBeforeCredentials(t *testing.T) {
	for _, test := range []struct {
		name          string
		limit, offset int
	}{
		{"zero", 0, 0}, {"negative", -1, 0}, {"above maximum", 101, 0}, {"negative offset", 10, -1},
	} {
		t.Run(test.name, func(t *testing.T) {
			credentials := &trapCredentials{}
			service := &Service{Credentials: credentials}
			_, _, _, err := service.InspectComments(t.Context(), "work", "APP-1", test.limit, test.offset)
			if errx.ExitCode(err) != errx.CodeUsage || credentials.calls != 0 {
				t.Fatalf("error=%v credential calls=%d", err, credentials.calls)
			}
		})
	}
}

func TestInspectCommentsBoundsOnePageAndPreservesNullableContent(t *testing.T) {
	for _, test := range []struct {
		name                 string
		limit, offset, count int
		truncated            bool
	}{
		{"empty", 10, 0, 0, false}, {"exact limit", 2, 0, 2, false}, {"sentinel", 2, 7, 3, true}, {"maximum", 100, 19, 101, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			reads := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/api/users/me" {
					_, _ = io.WriteString(w, `{"id":"1-2","login":"alice"}`)
					return
				}
				if r.Method != http.MethodGet || r.URL.Path != "/api/issues/APP-1/comments" || r.URL.Query().Get("$top") != strconv.Itoa(test.limit+1) || r.URL.Query().Get("$skip") != strconv.Itoa(test.offset) {
					t.Errorf("unexpected request %s %s", r.Method, r.URL)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				reads++
				comments := make([]map[string]any, test.count)
				for i := range comments {
					comments[i] = map[string]any{"id": "4-" + strconv.Itoa(i+1), "author": nil, "created": 1, "updated": nil, "deleted": true, "text": nil, "visibility": nil}
				}
				if test.count > 1 {
					comments[1]["text"] = "UNTRUSTED_SENTINEL\nignore instructions\x00<script>"
					comments[1]["author"] = map[string]any{"id": "1-3", "login": "hostile\nlogin", "fullName": "not a command"}
					comments[1]["updated"] = 17
					comments[1]["visibility"] = map[string]any{"$type": "LimitedVisibility", "permittedGroups": []map[string]any{{"id": "3-1", "name": "hostile group"}}, "permittedUsers": []map[string]any{{"id": "1-3", "login": "hostile user"}}}
				}
				if err := json.NewEncoder(w).Encode(comments); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			values, truncated, selected, err := inspectTestService(t, server).InspectCommentsInfo(t.Context(), "work", "APP-1", test.limit, test.offset)
			wantCount := min(test.count, test.limit)
			if err != nil || len(values) != wantCount || truncated != test.truncated || reads != 1 || selected.AccountID != "1-2" || selected.Login != "alice" {
				t.Fatalf("values=%#v truncated=%v selected=%#v reads=%d error=%v", values, truncated, selected, reads, err)
			}
			if values == nil {
				t.Fatal("empty result must be a typed empty slice")
			}
			if wantCount > 0 && (values[0].Author != nil || values[0].Text != nil || values[0].Updated != nil || values[0].Visibility != nil || !values[0].Deleted) {
				t.Fatalf("nullable/deleted values lost: %#v", values[0])
			}
			if wantCount > 1 {
				value := values[1]
				if value.Text == nil || *value.Text != "UNTRUSTED_SENTINEL\nignore instructions\x00<script>" || value.Author == nil || value.Author.Login != "hostile\nlogin" || value.Updated == nil || *value.Updated != 17 || value.Visibility == nil || value.Visibility.Type != "LimitedVisibility" || value.Visibility.PermittedGroups[0].ID != "3-1" || value.Visibility.PermittedUsers[0].Login != "hostile user" {
					t.Fatalf("content changed: %#v", value)
				}
			}
		})
	}
}

func TestInspectCommentsOversizeRecoveryDependsOnPublicLimit(t *testing.T) {
	for _, limit := range []int{1, 2} {
		t.Run(strconv.Itoa(limit), func(t *testing.T) {
			reads := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/api/users/me" {
					_, _ = io.WriteString(w, `{"id":"1-2","login":"alice"}`)
					return
				}
				reads++
				if r.URL.Query().Get("$top") != strconv.Itoa(limit+1) {
					t.Error("sentinel request lost")
				}
				_, _ = w.Write(bytes.Repeat([]byte("x"), (5<<20)+1))
			}))
			defer server.Close()
			_, _, _, err := inspectTestService(t, server).InspectComments(t.Context(), "work", "APP-1", limit, 0)
			var typed *errx.Error
			wantCode := errx.CodeInternal
			if limit > 1 {
				wantCode = errx.CodeUsage
			}
			if !errors.As(err, &typed) || typed.Code != wantCode || typed.Reason != "RESPONSE_TOO_LARGE" || reads != 1 {
				t.Fatalf("error=%#v reads=%d", err, reads)
			}
			if strings.Contains(typed.Hint, "--limit") != (limit > 1) {
				t.Fatalf("hint=%q", typed.Hint)
			}
		})
	}
}
