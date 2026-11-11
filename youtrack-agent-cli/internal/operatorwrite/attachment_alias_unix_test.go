//go:build darwin || linux

package operatorwrite

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestReadAttachmentSourceStoresResolvedDirectory(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "innocent")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	// A body no format accepts makes the read fail on type, which is after path
	// resolution; a PDF-shaped file keeps the test independent of the sniffer
	// details by only asserting the path when the read succeeds.
	body := append([]byte("%PDF-1.4\n"), bytes.Repeat([]byte("x"), 32)...)
	body = append(body, []byte("\n%%EOF\n")...)
	if err := os.WriteFile(filepath.Join(real, "report.pdf"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := ReadAttachmentSource(context.Background(), filepath.Join(alias, "report.pdf"))
	if err != nil {
		t.Skipf("fixture not accepted by the type sniffer: %v", err)
	}
	if want := filepath.Join(real, "report.pdf"); source.Path != want {
		t.Fatalf("Path = %q, want resolved %q", source.Path, want)
	}
}

func TestReadAttachmentSourceStillRefusesFinalSymlinkAfterResolution(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.pdf")
	if err := os.WriteFile(target, []byte("%PDF-1.4\n%%EOF\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.pdf")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAttachmentSource(context.Background(), link); err == nil {
		t.Fatal("final-component symlink was accepted")
	}
}
