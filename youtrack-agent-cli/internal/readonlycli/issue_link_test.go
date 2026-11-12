package readonlycli

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/profile"
)

func TestReadonlyEditionNeverMentionsTheIssueLinkLane(t *testing.T) {
	stdout := &bytes.Buffer{}
	app := NewApp()
	app.stdout, app.stderr = stdout, &bytes.Buffer{}
	app.profiles = profile.NewRegistry(filepath.Join(t.TempDir(), "profiles.json"))
	if code := app.Run(t.Context(), app.NewRootCommand(), []string{"capabilities", "-o", "json"}); code != errx.CodeOK {
		t.Fatalf("code=%d stdout=%s", code, stdout)
	}
	for _, forbidden := range []string{"issue.link", "issue-link"} {
		if bytes.Contains(stdout.Bytes(), []byte(forbidden)) {
			t.Fatalf("read-only capabilities mention %q: %s", forbidden, stdout)
		}
	}
	root := filepath.Join("..", "..", "assets", "skills", "youtrack-agent-readonly")
	scanned := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		scanned++
		for _, forbidden := range []string{"issue.link", "issue-link"} {
			if bytes.Contains(raw, []byte(forbidden)) {
				t.Errorf("read-only skill file %s mentions %q", path, forbidden)
			}
		}
		return nil
	})
	if err != nil || scanned == 0 {
		t.Fatalf("scanned=%d err=%v", scanned, err)
	}
}
