package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abigotado/agent-clis/tools/sign-release/internal/machofixture"
)

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestRunUsageErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
	}{
		{name: "no arguments"},
		{name: "missing -o", args: []string{"binary"}},
		{name: "missing binary", args: []string{"-o", "stream"}},
		{name: "two binaries", args: []string{"-o", "stream", "a", "b"}},
		{name: "flag after the binary", args: []string{"binary", "-o", "stream"}},
		{name: "unknown flag", args: []string{"-x", "-o", "stream", "binary"}},
		{name: "empty -o value", args: []string{"-o", "", "binary"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if code := run(tt.args, &stdout, &stderr); code != 2 {
				t.Fatalf("exit = %d, want 2 (stderr %q)", code, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want empty", stdout.String())
			}
			if !strings.Contains(stderr.String(), "usage: machodigest -o <stream-file> <binary>") {
				t.Fatalf("stderr = %q, want the usage line", stderr.String())
			}
		})
	}
}

func TestRunHelpExitsZero(t *testing.T) {
	t.Parallel()

	for _, flagName := range []string{"-h", "-help"} {
		t.Run(flagName, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if code := run([]string{flagName}, &stdout, &stderr); code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr %q)", code, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want empty", stdout.String())
			}
			if !strings.Contains(stderr.String(), "usage: machodigest -o <stream-file> <binary>") {
				t.Fatalf("stderr = %q, want the usage line", stderr.String())
			}
		})
	}
}

func TestRunWritesStreamAndPrintsDigest(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	f := machofixture.Build(machofixture.Spec{})
	binary := writeFile(t, dir, "bin", f.Bytes)
	output := filepath.Join(dir, "bin.machostream")

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-o", output, binary}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr %q)", code, stderr.String())
	}

	stream, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read stream: %v", err)
	}
	if len(stream) != f.SignatureOff {
		t.Fatalf("stream is %d bytes, want %d", len(stream), f.SignatureOff)
	}
	want := fmt.Sprintf("sha256:%x  %s\n", sha256.Sum256(stream), binary)
	if stdout.String() != want {
		t.Fatalf("stdout = %q, want %q", stdout.String(), want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}

	t.Run("a re-signed copy prints the same digest", func(t *testing.T) {
		t.Parallel()
		resigned := writeFile(t, dir, "resigned", machofixture.Build(machofixture.Spec{Signature: bytes.Repeat([]byte{9}, 4096)}).Bytes)
		var out2, err2 bytes.Buffer
		if code := run([]string{"-o", filepath.Join(dir, "resigned.machostream"), resigned}, &out2, &err2); code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr %q)", code, err2.String())
		}
		first, _, _ := strings.Cut(stdout.String(), "  ")
		second, _, _ := strings.Cut(out2.String(), "  ")
		if first != second {
			t.Fatalf("digests differ: %s vs %s", first, second)
		}
	})
}

func TestRunFailuresExitOne(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	valid := writeFile(t, dir, "valid", machofixture.Build(machofixture.Spec{}).Bytes)
	fat := machofixture.Build(machofixture.Spec{}).Bytes
	copy(fat, []byte{0xca, 0xfe, 0xba, 0xbe})
	refused := writeFile(t, dir, "fat", fat)
	existing := writeFile(t, dir, "existing", []byte("keep me"))

	tests := []struct {
		name       string
		binary     string
		output     string
		stderrWant string
		wantNoFile bool
	}{
		{name: "refused input", binary: refused, output: filepath.Join(dir, "out-refused"), stderrWant: "thin-file", wantNoFile: true},
		{name: "missing input", binary: filepath.Join(dir, "absent"), output: filepath.Join(dir, "out-missing"), stderrWant: "open binary", wantNoFile: true},
		{name: "input is a directory", binary: dir, output: filepath.Join(dir, "out-dir"), stderrWant: "not a regular file", wantNoFile: true},
		{name: "output already exists", binary: valid, output: existing, stderrWant: "create stream file"},
		{name: "output directory is missing", binary: valid, output: filepath.Join(dir, "no", "such", "out"), stderrWant: "create stream file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if code := run([]string{"-o", tt.output, tt.binary}, &stdout, &stderr); code != 1 {
				t.Fatalf("exit = %d, want 1 (stderr %q)", code, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want empty", stdout.String())
			}
			if !strings.Contains(stderr.String(), tt.stderrWant) {
				t.Fatalf("stderr = %q, want it to contain %q", stderr.String(), tt.stderrWant)
			}
			if tt.wantNoFile {
				if _, err := os.Stat(tt.output); !os.IsNotExist(err) {
					t.Fatalf("output %s exists after a refusal (stat error %v)", tt.output, err)
				}
			}
		})
	}

	got, err := os.ReadFile(existing)
	if err != nil || string(got) != "keep me" {
		t.Fatalf("existing output = %q, %v, want it untouched", got, err)
	}
}

// TestRunMapsAPanicToExitOne shows a panic is exit 1 and never the exit 2 a Go
// panic gives on its own, which means usage here.
func TestRunMapsAPanicToExitOne(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code := runWith([]string{"-o", "stream", "binary"}, &stdout, &stderr, func(string, string) ([32]byte, error) {
		panic("boom")
	})
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "internal error: boom") {
		t.Fatalf("stdout = %q, stderr = %q, want an empty stdout and the internal error", stdout.String(), stderr.String())
	}
}
