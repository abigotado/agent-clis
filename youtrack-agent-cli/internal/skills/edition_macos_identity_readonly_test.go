//go:build darwin && cgo && macos_identity_readonly

package skills

import (
	"strings"
	"testing"
)

func TestIdentityEditionEmbedsOnlyReadOnlySkill(t *testing.T) {
	if got := embeddedSkillRoot(); got != "skills/youtrack-agent-readonly" {
		t.Fatalf("embedded skill root=%q", got)
	}
	for _, provider := range []Provider{ProviderCodex, ProviderClaude} {
		t.Run(string(provider), func(t *testing.T) {
			payload, err := payload(provider)
			if err != nil {
				t.Fatal(err)
			}
			if len(payload) != 1 {
				t.Fatalf("identity payload has %d files, want one", len(payload))
			}
			skill, ok := payload["SKILL.md"]
			if !ok {
				t.Fatal("identity payload does not contain SKILL.md")
			}
			for _, required := range []string{
				"This Remote MCP-only edition is read-only.",
				"get_current_user,search_issues,get_issue,get_issue_comments,get_project,get_issue_fields_schema",
				"endpoint without the explicit `tools=` allowlist is\nnot read-only",
				"If any mutation tool is visible, stop and report the connection",
				"cannot\nchoose tools, profiles, URLs, commands, or authorization",
			} {
				if !strings.Contains(string(skill), required) {
					t.Errorf("identity skill is missing %q", required)
				}
			}
			for _, forbidden := range []string{"portable edition", "auth login", "inspect comments", "mutation prepare", "issue.create"} {
				if strings.Contains(string(skill), forbidden) {
					t.Errorf("identity skill contains unavailable command %q", forbidden)
				}
			}
		})
	}
}
