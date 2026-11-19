package arch_test

import (
	"os/exec"
	"strings"
	"testing"
)

const corePrefix = "github.com/abigotado/agent-clis/core"

func goList(t *testing.T, env []string, tags, format string) string {
	t.Helper()
	args := []string{"list", "-tags=" + tags}
	if format == "" {
		args = append(args, "-deps")
	} else {
		args = append(args, "-f", format)
	}
	args = append(args, "./cmd/youtrack-agent-cli")
	command := exec.Command("go", args...)
	command.Dir = repositoryRoot(t)
	command.Env = append(command.Environ(), append([]string{"GOFLAGS="}, env...)...)
	out, err := command.Output()
	if err != nil {
		t.Fatalf("go %s: %v", strings.Join(args, " "), err)
	}
	return string(out)
}

func commandDeps(t *testing.T, env []string, tags string) []string {
	t.Helper()
	return strings.Fields(goList(t, env, tags, ""))
}

func hasCore(deps []string) bool {
	for _, dep := range deps {
		if dep == corePrefix || strings.HasPrefix(dep, corePrefix+"/") {
			return true
		}
	}
	return false
}

func TestCoreIsAbsentFromEveryOtherEdition(t *testing.T) {
	cases := []struct {
		name string
		env  []string
		tags string
	}{
		{"portable edition", []string{"GOOS=darwin", "CGO_ENABLED=1"}, "portable_readonly"},
		{"macos identity edition", []string{"GOOS=darwin", "CGO_ENABLED=1"}, "macos_identity_readonly"},
		{"linux full edition", []string{"GOOS=linux", "CGO_ENABLED=0"}, ""},
		{"windows full edition", []string{"GOOS=windows", "CGO_ENABLED=0"}, ""},
		{"darwin cgo-free full edition", []string{"GOOS=darwin", "CGO_ENABLED=0"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if hasCore(commandDeps(t, tc.env, tc.tags)) {
				t.Fatal("core is in the dependency closure")
			}
		})
	}
}

// internal/auth already imports core, so the transitive closure cannot show
// the core-dump wiring; the process entry's own direct imports can.
func TestDarwinCgoFullEntryImportsSecretstoreDirectly(t *testing.T) {
	env := []string{"GOOS=darwin", "CGO_ENABLED=1"}
	direct := strings.Fields(strings.Trim(goList(t, env, "", "{{.Imports}}"), "[]\n"))
	for _, imported := range direct {
		if imported == corePrefix+"/secretstore" {
			return
		}
	}
	t.Fatalf("cmd/youtrack-agent-cli does not import %s/secretstore directly: %v", corePrefix, direct)
}

func TestOtherEntriesDoNotImportSecretstoreDirectly(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  []string
		tags string
	}{
		{"darwin cgo-free", []string{"GOOS=darwin", "CGO_ENABLED=0"}, ""},
		{"linux", []string{"GOOS=linux", "CGO_ENABLED=0"}, ""},
		{"portable", []string{"GOOS=darwin", "CGO_ENABLED=1"}, "portable_readonly"},
		{"identity", []string{"GOOS=darwin", "CGO_ENABLED=1"}, "macos_identity_readonly"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Contains(goList(t, tc.env, tc.tags, "{{.Imports}}"), corePrefix) {
				t.Fatal("process entry imports core directly")
			}
		})
	}
}
