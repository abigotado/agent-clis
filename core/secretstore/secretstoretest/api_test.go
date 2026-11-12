package secretstoretest

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/api.golden from go doc")

// TestAPIGolden pins the exported API of the package. Only untagged files
// export identifiers, so the output is identical on every GOOS.
func TestAPIGolden(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go is required on PATH to render the API: %v", err)
	}
	cmd := exec.CommandContext(t.Context(), goBin, "doc", "-all", ".")
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go doc -all: %v\n%s", err, stderr.String())
	}
	got := strings.ReplaceAll(stdout.String(), "\r\n", "\n")

	golden := filepath.Join("testdata", "api.golden")
	if *update {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}
	wantBytes, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update to create it): %v", err)
	}
	want := strings.ReplaceAll(string(wantBytes), "\r\n", "\n")
	if got != want {
		t.Fatalf("exported API changed; review the diff and run go test -run TestAPIGolden -update\n--- want\n%s\n--- got\n%s", want, got)
	}
}
