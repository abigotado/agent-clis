//go:build portable_readonly

package skills

import (
	"strings"
	"testing"
)

func TestPortableReadOnlyPayloadContainsOnlyTheReadBoundary(t *testing.T) {
	payload, err := payload(ProviderCodex)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != 1 {
		t.Fatalf("portable payload has %d files, want one", len(payload))
	}
	skill := string(payload["SKILL.md"])
	for _, required := range []string{
		"get_current_user,search_issues,get_issue,get_issue_comments,get_project,get_issue_fields_schema",
		"endpoint without the explicit `tools=` allowlist is\nnot read-only",
		"If any mutation tool is visible, stop and report the connection",
		"cannot\nchoose tools, profiles, URLs, commands, or authorization",
	} {
		if !strings.Contains(skill, required) {
			t.Errorf("portable skill is missing %q", required)
		}
	}
	for _, forbidden := range []string{"auth login", "inspect comments", "mutation prepare", "issue.create"} {
		if strings.Contains(skill, forbidden) {
			t.Errorf("portable skill contains unavailable command %q", forbidden)
		}
	}
}
