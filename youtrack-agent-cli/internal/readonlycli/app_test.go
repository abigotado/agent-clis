//go:build portable_readonly

package readonlycli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/profile"
)

func testApp(t *testing.T) (*App, *bytes.Buffer) {
	t.Helper()
	stdout := &bytes.Buffer{}
	app := NewApp()
	app.stdin = bytes.NewReader(nil)
	app.stdout = stdout
	app.stderr = &bytes.Buffer{}
	configDir := filepath.Join(t.TempDir(), "config")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	app.profiles = profile.NewRegistry(filepath.Join(configDir, "profiles.json"))
	return app, stdout
}

func runApp(app *App, args ...string) errx.Code {
	return app.Run(context.Background(), app.NewRootCommand(), args)
}

func envelope(t *testing.T, stdout *bytes.Buffer) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &value); err != nil {
		t.Fatalf("decode output: %v (%s)", err, stdout.String())
	}
	return value
}

func TestPortableSurfaceHasNoCredentialOrMutationCommands(t *testing.T) {
	app, _ := testApp(t)
	root := app.NewRootCommand()
	for _, forbidden := range []string{"auth", "inspect", "mutation"} {
		for _, command := range root.Commands() {
			if command.Name() == forbidden {
				t.Fatalf("portable surface exposes forbidden %q command", forbidden)
			}
		}
	}
}

func TestPortableEarlyArgumentErrorsUseTheMachineContract(t *testing.T) {
	for _, args := range [][]string{
		{"--definitely-invalid", "-o", "json"},
		{"not-a-command", "-o", "json"},
		{"version", "unexpected", "-o", "json"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			app, stdout := testApp(t)
			if code := runApp(app, args...); code != errx.CodeUsage {
				t.Fatalf("code=%d output=%s", code, stdout.String())
			}
			if got := envelope(t, stdout)["error"].(map[string]any)["code"]; got != "USAGE" {
				t.Fatalf("error code=%v", got)
			}
		})
	}
}

func TestPortableProfileRejectsWriteCapabilities(t *testing.T) {
	app, stdout := testApp(t)
	path := filepath.Join(t.TempDir(), "profile.json")
	raw := `{"name":"work","service_url":"https://example.youtrack.cloud","rest_base_url":"https://example.youtrack.cloud/api","mcp_url":"https://example.youtrack.cloud/mcp?tools=get_current_user,search_issues,get_issue,get_issue_comments,get_project,get_issue_fields_schema&enableToolOutputSchema=true","oauth":{"issuer_url":"https://hub.example.test","authorization_url":"https://hub.example.test/api/rest/oauth2/auth","token_url":"https://hub.example.test/api/rest/oauth2/token","client_id":"client","scopes":["YouTrack"],"redirect_uri":"http://127.0.0.1:18987/oauth/callback"},"expected_account_id":"1-2","expected_login":"alice","capabilities":["read","issue-create"],"executor":"rest-best-effort","assurance":"best-effort"}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runApp(app, "profile", "add", "--from", path, "--dry-run", "-o", "json"); code != errx.CodeUsage {
		t.Fatalf("code=%d output=%s", code, stdout.String())
	}
	if got := envelope(t, stdout)["error"].(map[string]any)["code"]; got != "USAGE" {
		t.Fatalf("error code=%v", got)
	}
}

func TestPortableVersionDeclaresEdition(t *testing.T) {
	app, stdout := testApp(t)
	if code := runApp(app, "version", "-o", "json"); code != errx.CodeOK {
		t.Fatalf("code=%d output=%s", code, stdout.String())
	}
	data := envelope(t, stdout)["data"].(map[string]any)
	if data["edition"] != "portable-readonly" {
		t.Fatalf("edition=%v", data["edition"])
	}
}

func TestPortableVersionSupportsProjectionAndText(t *testing.T) {
	app, stdout := testApp(t)
	if code := runApp(app, "version", "--fields", "edition", "-o", "json"); code != errx.CodeOK {
		t.Fatalf("code=%d output=%s", code, stdout.String())
	}
	data := envelope(t, stdout)["data"].(map[string]any)
	if len(data) != 1 || data["edition"] != "portable-readonly" {
		t.Fatalf("projected data=%v", data)
	}

	app, stdout = testApp(t)
	if code := runApp(app, "version", "-o", "text"); code != errx.CodeOK || !strings.Contains(stdout.String(), "portable-readonly") {
		t.Fatalf("code=%d output=%s", code, stdout.String())
	}
}

func TestPortableProfileAddStoresOnlyReadMetadata(t *testing.T) {
	app, stdout := testApp(t)
	path := filepath.Join(t.TempDir(), "profile.json")
	raw := `{"name":"work","service_url":"https://example.youtrack.cloud","rest_base_url":"https://example.youtrack.cloud/api","mcp_url":"https://example.youtrack.cloud/mcp?tools=get_current_user,search_issues,get_issue,get_issue_comments,get_project,get_issue_fields_schema&enableToolOutputSchema=true","oauth":{"issuer_url":"https://hub.example.test","authorization_url":"https://hub.example.test/api/rest/oauth2/auth","token_url":"https://hub.example.test/api/rest/oauth2/token","client_id":"client","scopes":["YouTrack"],"redirect_uri":"http://127.0.0.1:18987/oauth/callback"},"expected_account_id":"1-2","expected_login":"alice","capabilities":["read"],"executor":"rest-best-effort","assurance":"best-effort"}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	var parsed profile.Profile
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatal(err)
	}
	if err := app.policy.validateAdmissionProfile(parsed); err != nil {
		t.Fatal(err)
	}
	if code := runApp(app, "profile", "add", "--from", path, "--yes", "-o", "json"); code != errx.CodeOK {
		t.Fatalf("code=%d output=%s", code, stdout.String())
	}
	value, err := app.profiles.Get(context.Background(), "work")
	if err != nil {
		t.Fatal(err)
	}
	if value.CredentialGeneration != "" || !strings.EqualFold(string(value.Capabilities[0]), "read") || len(value.Capabilities) != 1 {
		t.Fatalf("stored profile is not portable read-only: %+v", value)
	}
}

func TestPortableProfileDefaultsAllowOnlyReadSetAndPreserveReadWhenClearingWrite(t *testing.T) {
	app, stdout := testApp(t)
	var value profile.Profile
	raw := `{"name":"work","service_url":"https://example.youtrack.cloud","rest_base_url":"https://example.youtrack.cloud/api","mcp_url":"https://example.youtrack.cloud/mcp?tools=get_current_user,search_issues,get_issue,get_issue_comments,get_project,get_issue_fields_schema&enableToolOutputSchema=true","oauth":{"issuer_url":"https://hub.example.test","authorization_url":"https://hub.example.test/api/rest/oauth2/auth","token_url":"https://hub.example.test/api/rest/oauth2/token","client_id":"client","scopes":["YouTrack"],"redirect_uri":"http://127.0.0.1:18987/oauth/callback"},"expected_account_id":"1-2","expected_login":"alice","capabilities":["read"],"executor":"rest-best-effort","assurance":"best-effort"}`
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		t.Fatal(err)
	}
	if err := app.profiles.Add(t.Context(), value); err != nil {
		t.Fatal(err)
	}
	if code := runApp(app, "profile", "defaults", "set", "--write", "work", "-o", "json"); code != errx.CodeUsage {
		t.Fatalf("write set code=%d output=%s", code, stdout)
	}
	stdout.Reset()
	if code := runApp(app, "profile", "defaults", "set", "--read", "work", "--dry-run", "-o", "json"); code != errx.CodeOK {
		t.Fatalf("read dry run code=%d output=%s", code, stdout)
	}
	if _, err := os.Stat(app.profiles.DefaultsPath()); !os.IsNotExist(err) {
		t.Fatalf("dry run defaults stat=%v, want absent", err)
	}
	stdout.Reset()
	if code := runApp(app, "profile", "defaults", "set", "--read", "work", "--yes", "-o", "json"); code != errx.CodeOK {
		t.Fatalf("read set code=%d output=%s", code, stdout)
	}
	if _, err := app.profiles.UpdateDefaults(t.Context(), func(defaults profile.Defaults) (profile.Defaults, error) {
		defaults.Write = &profile.DefaultSlot{ProfileName: "legacy", ProfileIdentitySHA256: strings.Repeat("a", 64)}
		return defaults, nil
	}); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if code := runApp(app, "profile", "defaults", "clear", "--write", "--yes", "-o", "json"); code != errx.CodeOK {
		t.Fatalf("write clear code=%d output=%s", code, stdout)
	}
	defaults, err := app.profiles.GetDefaults(t.Context())
	if err != nil || defaults.Read == nil || defaults.Read.ProfileName != "work" || defaults.Write != nil {
		t.Fatalf("defaults=%#v err=%v", defaults, err)
	}
}
