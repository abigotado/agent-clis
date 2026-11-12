//go:build darwin || linux

package operatorwrite

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/protocolvalue"
)

func TestReadAttachmentSource(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	regular := write("shot.png", pngBytes)
	atCap := write("cap.png", minimalPNGOfSize(MaxAttachmentBytes))
	overCap := write("big.png", minimalPNGOfSize(MaxAttachmentBytes+1))
	empty := write("empty.png", nil)
	text := write("note.txt", []byte("plain text"))
	link := filepath.Join(dir, "link.png")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	subdir := filepath.Join(dir, "sub")
	if err := os.Mkdir(subdir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subdir, "inner.png"), pngBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	dirLink := filepath.Join(dir, "dirlink")
	if err := os.Symlink(subdir, dirLink); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "pipe.png")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	unreadable := write("locked.png", pngBytes)
	if err := os.Chmod(unreadable, 0); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name, path, reason string
	}{
		{"regular", regular, ""},
		{"exactly at cap", atCap, ""},
		{"intermediate symlinked directory", filepath.Join(dirLink, "inner.png"), ""},
		{"symlink final component", link, "OPERATOR_ATTACHMENT_SOURCE_INVALID"},
		{"directory", subdir, "OPERATOR_ATTACHMENT_SOURCE_INVALID"},
		{"fifo", fifo, "OPERATOR_ATTACHMENT_SOURCE_INVALID"},
		{"dev null", "/dev/null", "OPERATOR_ATTACHMENT_SOURCE_INVALID"},
		{"missing", filepath.Join(dir, "missing.png"), "OPERATOR_ATTACHMENT_SOURCE_INVALID"},
		{"empty file", empty, "OPERATOR_ATTACHMENT_SOURCE_INVALID"},
		{"empty path", "", "OPERATOR_ATTACHMENT_SOURCE_INVALID"},
		{"over cap by one byte", overCap, "OPERATOR_ATTACHMENT_TOO_LARGE"},
		{"unsupported type", text, "OPERATOR_ATTACHMENT_TYPE_UNSUPPORTED"},
	}
	if os.Geteuid() != 0 {
		tests = append(tests, struct{ name, path, reason string }{"unreadable", unreadable, "OPERATOR_ATTACHMENT_SOURCE_INVALID"})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			done := make(chan struct{})
			var (
				got AttachmentSource
				err error
			)
			go func() {
				defer close(done)
				got, err = ReadAttachmentSource(context.Background(), test.path)
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("ReadAttachmentSource hung")
			}
			if test.reason == "" {
				if err != nil {
					t.Fatalf("ReadAttachmentSource: %v", err)
				}
				if got.Size != int64(len(got.Bytes)) || got.SHA256 != protocolvalue.SHA256Hex(got.Bytes) || got.ContentType != "image/png" || !filepath.IsAbs(got.Path) {
					t.Fatalf("source = %+v", got)
				}
				return
			}
			var typed *errx.Error
			if !errors.As(err, &typed) || typed.Reason != test.reason || errx.ExitCode(err) != 2 {
				t.Fatalf("error = %#v, want reason %s exit 2", err, test.reason)
			}
			for _, text := range []string{typed.Message, typed.Hint, err.Error()} {
				if test.path != "" && strings.Contains(text, test.path) || strings.Contains(text, dir) {
					t.Fatalf("error text carries the path: %q", text)
				}
			}
			if typed.Unwrap() != nil {
				t.Fatalf("error wraps an underlying cause: %v", typed.Unwrap())
			}
		})
	}

	t.Run("returns the exact bytes", func(t *testing.T) {
		got, err := ReadAttachmentSource(context.Background(), regular)
		if err != nil || !bytes.Equal(got.Bytes, pngBytes) || got.Path != regular && got.Path != mustEval(t, regular) {
			t.Fatalf("got %+v, %v", got, err)
		}
	})
	t.Run("relative path becomes absolute", func(t *testing.T) {
		t.Chdir(dir)
		got, err := ReadAttachmentSource(context.Background(), "shot.png")
		if err != nil || !filepath.IsAbs(got.Path) || filepath.Base(got.Path) != "shot.png" {
			t.Fatalf("got %+v, %v", got, err)
		}
	})
	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := ReadAttachmentSource(ctx, regular); !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("attachment freeze", func(t *testing.T) {
		src, err := ReadAttachmentSource(context.Background(), regular)
		if err != nil {
			t.Fatal(err)
		}
		a, err := src.Attachment("shot.png")
		if err != nil || a.SHA256 != src.SHA256 || a.Size != src.Size || a.ContentType != "image/png" || a.SourcePath != src.Path {
			t.Fatalf("attachment = %+v, %v", a, err)
		}
		if _, err := src.Attachment("shot.pdf"); err == nil {
			t.Fatal("mismatched name accepted")
		}
	})
}

func mustEval(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}
