package release

import (
	"strings"
	"testing"
)

func TestParseReleasePages(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		want   int // releases read
		reason string
		anyErr bool
	}{
		{name: "pages printed back to back", in: `[{"id":1,"tag_name":"a","draft":true}][{"id":2,"tag_name":"b","draft":false}]`, want: 2},
		{name: "pages separated by newlines", in: "[{\"id\":1,\"tag_name\":\"a\"}]\n[{\"id\":2,\"tag_name\":\"b\"}]\n", want: 2},
		{name: "empty page", in: `[]`, want: 0},
		{name: "unknown members are tolerated", in: `[{"id":1,"tag_name":"a","body":"x","author":{"login":"y"}}]`, want: 1},
		{name: "no output", in: ``, reason: "empty"},
		{name: "an object instead of an array", in: `{"message":"Not Found"}`, reason: "want arrays of releases"},
		{name: "a page that is null", in: `null`, reason: "want arrays of releases"},
		{name: "second page is not an array", in: `[][{"id":1}] 5`, reason: "want arrays of releases"},
		{name: "truncated page", in: `[{"id":1,"tag_name":"a"}`, anyErr: true},
		{name: "duplicate member", in: `[{"id":1,"id":2,"tag_name":"a"}]`, anyErr: true},
		{name: "wrong member type", in: `[{"id":"one"}]`, anyErr: true},
		{name: "too many pages", in: strings.Repeat("[]", maxPages+1), reason: "pages"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseReleasePages([]byte(tc.in))
			switch {
			case tc.anyErr:
				if err == nil {
					t.Fatal("parseReleasePages() error = nil, want an error")
				}
			case tc.reason != "":
				if err == nil {
					t.Fatalf("parseReleasePages() error = nil, want a refusal containing %q", tc.reason)
				}
				wantRefusal(t, err, StepResolve, tc.reason)
			default:
				if err != nil {
					t.Fatalf("parseReleasePages() error = %v", err)
				}
				if len(got) != tc.want {
					t.Fatalf("read %d releases, want %d", len(got), tc.want)
				}
			}
		})
	}
}
