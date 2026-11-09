package readonlycli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/profile"
)

func TestReadonlyCapabilitiesAdvertiseNoWriteLane(t *testing.T) {
	for _, format := range []string{"json", "raw"} {
		t.Run(format, func(t *testing.T) {
			stdout := &bytes.Buffer{}
			app := NewApp()
			app.stdout, app.stderr = stdout, &bytes.Buffer{}
			app.profiles = profile.NewRegistry(filepath.Join(t.TempDir(), "profiles.json"))
			root := app.NewRootCommand()
			for _, command := range root.Commands() {
				if command.Name() == "operator-write" {
					t.Fatal("readonly edition exposes an operator-write command")
				}
			}
			if code := app.Run(t.Context(), root, []string{"capabilities", "-o", format}); code != errx.CodeOK {
				t.Fatalf("code=%d stdout=%s", code, stdout)
			}
			var decoded map[string]json.RawMessage
			if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
				t.Fatal(err)
			}
			if format == "json" {
				if err := json.Unmarshal(decoded["data"], &decoded); err != nil {
					t.Fatal(err)
				}
			}
			for _, field := range []string{"operator_write_supported", "native_user_presence_supported", "locally_ready"} {
				if string(decoded[field]) != "false" {
					t.Fatalf("%s=%s", field, decoded[field])
				}
			}
			if string(decoded["kinds"]) != "[]" || string(decoded["readiness_scope"]) != `"local_configuration_only"` {
				t.Fatalf("capabilities=%s", stdout)
			}
		})
	}
}
