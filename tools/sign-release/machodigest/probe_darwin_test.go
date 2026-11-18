//go:build darwin

package machodigest

import (
	"bytes"
	"debug/macho"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const probeSource = `package main

/*
static int answer(void) { return 42; }
*/
import "C"

func main() { println(C.answer()) }
`

// run executes a command and fails the test with its combined output.
func run(t *testing.T, dir string, env []string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

// TestProbeLinkerSignedBinariesSurviveAReSign proves on real toolchain output
// that a re-sign changes nothing the digest covers and a __TEXT change does.
// It signs only ad hoc and never touches a keychain or a signing identity.
func TestProbeLinkerSignedBinariesSurviveAReSign(t *testing.T) {
	for _, tool := range []string{"clang", "codesign", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			// CI must run the probe: a missing tool there is a broken runner, not a skip.
			if os.Getenv("CI") == "true" {
				t.Fatalf("%s not found on a CI runner: %v", tool, err)
			}
			t.Skipf("%s not found: %v", tool, err)
		}
	}

	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "go.mod"), []byte("module probe\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "main.go"), []byte(probeSource), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "probe")
			run(t, src, []string{"GOWORK=off", "GOOS=darwin", "GOARCH=" + arch, "CGO_ENABLED=1", "GOTOOLCHAIN=local"},
				"go", "build", "-o", bin, "-ldflags=-extldflags=-Wl,-adhoc_codesign", ".")

			if info := run(t, dir, nil, "codesign", "-dv", bin); !strings.Contains(info, "linker-signed") {
				t.Fatalf("codesign -dv does not show linker-signed:\n%s", info)
			}

			original, err := os.ReadFile(bin)
			if err != nil {
				t.Fatal(err)
			}
			copyPath := filepath.Join(dir, "resigned")
			if err := os.WriteFile(copyPath, original, 0o700); err != nil {
				t.Fatal(err)
			}
			run(t, dir, nil, "codesign", "--force", "--sign", "-", "--options", "runtime",
				"--identifier", "dev.example.probe", "--timestamp=none", copyPath)
			resigned, err := os.ReadFile(copyPath)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(original, resigned) {
				t.Fatal("the re-signed copy is byte-identical, so the probe proved nothing")
			}

			want, err := Sum(original)
			if err != nil {
				t.Fatalf("Sum(original) error = %v", err)
			}
			got, err := Sum(resigned)
			if err != nil {
				t.Fatalf("Sum(resigned) error = %v", err)
			}
			if got != want {
				t.Fatalf("digest of the re-signed copy %x != original %x", got, want)
			}

			f, err := macho.Open(bin)
			if err != nil {
				t.Fatal(err)
			}
			text := f.Section("__text")
			if cerr := f.Close(); cerr != nil {
				t.Fatal(cerr)
			}
			if text == nil || text.Size == 0 {
				t.Fatal("binary has no __text section")
			}
			tampered := bytes.Clone(original)
			tampered[text.Offset+uint32(text.Size/2)] ^= 1
			changed, err := Sum(tampered)
			if err != nil {
				t.Fatalf("Sum(tampered) error = %v", err)
			}
			if changed == want {
				t.Fatal("a one-byte __TEXT change left the digest equal")
			}
		})
	}
}
