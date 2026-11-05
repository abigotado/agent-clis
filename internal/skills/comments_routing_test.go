//go:build !portable_readonly && !macos_identity_readonly

package skills

import (
	"strings"
	"testing"
)

func TestStandardSkillRoutesReadsToBoundedCLI(t *testing.T) {
	for _, provider := range []Provider{ProviderCodex, ProviderClaude} {
		t.Run(string(provider), func(t *testing.T) {
			files, err := payload(provider)
			if err != nil {
				t.Fatal(err)
			}
			for _, contract := range []struct {
				file     string
				required []string
			}{
				{"SKILL.md", []string{"Use the standard `youtrack-agent-cli` for bounded reads and guarded", "[read policy](reference/read-policy.md)"}},
				{"reference/read-policy.md", []string{"youtrack-agent-cli inspect issues --query", "youtrack-agent-cli inspect comments --profile <name> --id <issue-ID> --limit 10 --offset 0 -o json", "This CLI read plane is unavailable in the portable and macOS identity editions"}},
			} {
				text := strings.Join(strings.Fields(string(files[contract.file])), " ")
				for _, required := range contract.required {
					if !strings.Contains(text, required) {
						t.Errorf("%s misses comments routing %q", contract.file, required)
					}
				}
			}
		})
	}
}
