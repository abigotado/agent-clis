//go:build darwin && cgo && macos_identity_readonly

package readonlycli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/profile"
)

const identityProfileJSON = `{"name":"work","service_url":"https://example.youtrack.cloud","rest_base_url":"https://example.youtrack.cloud/api","mcp_url":"https://example.youtrack.cloud/mcp?tools=get_current_user,search_issues,get_issue,get_issue_comments,get_project,get_issue_fields_schema&enableToolOutputSchema=true","oauth":{"issuer_url":"https://hub.example.test","authorization_url":"https://hub.example.test/api/rest/oauth2/auth","token_url":"https://hub.example.test/api/rest/oauth2/token","client_id":"client","scopes":["YouTrack"],"redirect_uri":"http://127.0.0.1:18987/oauth/callback"},"expected_account_id":"1-2","expected_login":"alice","capabilities":["read"],"executor":"rest-best-effort","assurance":"best-effort"}`

func testIdentityApp(t *testing.T) (*App, *bytes.Buffer) {
	t.Helper()
	stdout := &bytes.Buffer{}
	app := NewApp()
	app.stdin = bytes.NewReader(nil)
	app.stdout = stdout
	app.stderr = &bytes.Buffer{}
	configDirectory := filepath.Join(t.TempDir(), "config")
	if err := os.Mkdir(configDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	app.profiles = profile.NewRegistry(filepath.Join(configDirectory, "identity-profiles.json"))
	return app, stdout
}

func runIdentityApp(app *App, args ...string) errx.Code {
	return app.Run(context.Background(), app.NewRootCommand(), args)
}

func identityEnvelope(t *testing.T, stdout *bytes.Buffer) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &value); err != nil {
		t.Fatalf("decode output: %v (%s)", err, stdout.String())
	}
	return value
}

func identityProfile(t *testing.T) profile.Profile {
	t.Helper()
	var value profile.Profile
	if err := json.Unmarshal([]byte(identityProfileJSON), &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestIdentitySurfaceAndVersionAreExact(t *testing.T) {
	app, stdout := testIdentityApp(t)
	root := app.NewRootCommand()
	gotCommands := make([]string, 0, len(root.Commands()))
	for _, command := range root.Commands() {
		gotCommands = append(gotCommands, command.Name())
	}
	sort.Strings(gotCommands)
	wantCommands := []string{"capabilities", "contract", "profile", "skills", "version"}
	if !reflect.DeepEqual(gotCommands, wantCommands) {
		t.Fatalf("commands=%v, want %v", gotCommands, wantCommands)
	}
	if code := runIdentityApp(app, "version", "-o", "json"); code != errx.CodeOK {
		t.Fatalf("version code=%d output=%s", code, stdout.String())
	}
	if got := identityEnvelope(t, stdout)["data"].(map[string]any)["edition"]; got != "macos-identity-readonly" {
		t.Fatalf("edition=%v", got)
	}

	app, stdout = testIdentityApp(t)
	if code := runIdentityApp(app, "--help"); code != errx.CodeOK {
		t.Fatalf("help code=%d output=%s", code, stdout.String())
	}
	help := stdout.String()
	for _, command := range append([]string{"completion", "help"}, wantCommands...) {
		if !strings.Contains(help, "  "+command+" ") {
			t.Errorf("identity help omits command %q: %s", command, help)
		}
	}
	for _, forbidden := range []string{"auth", "inspect", "mutation", "journal", "writepolicy"} {
		if strings.Contains(strings.ToLower(help), forbidden) {
			t.Errorf("identity help exposes forbidden surface %q: %s", forbidden, help)
		}
	}
}

func TestIdentityRegistryUsesDedicatedMetadataPath(t *testing.T) {
	directory, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := editionPolicy().newRegistry()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(directory, "youtrack-agent-cli-identity-readonly", "profiles.json")
	if got := registry.Path(); got != want {
		t.Fatalf("identity registry path=%q, want %q", got, want)
	}
}

func TestIdentityRefusesEveryOperationOnLoadedNonReadOnlyProfiles(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, value profile.Profile) profile.Profile
	}{
		{
			name: "write capability",
			mutate: func(_ *testing.T, value profile.Profile) profile.Profile {
				value.Capabilities = []profile.Capability{profile.CapabilityRead, profile.CapabilityIssueCreate}
				return value
			},
		},
		{
			name: "credential generation",
			mutate: func(t *testing.T, value profile.Profile) profile.Profile {
				bound, err := value.WithNewCredentialGeneration()
				if err != nil {
					t.Fatal(err)
				}
				return bound
			},
		},
	}
	operations := []struct {
		name string
		args []string
	}{
		{name: "list", args: []string{"profile", "list", "-o", "json"}},
		{name: "show", args: []string{"--profile", "work", "profile", "show", "-o", "json"}},
		{name: "validate", args: []string{"--profile", "work", "profile", "validate", "--offline", "-o", "json"}},
		{name: "remove", args: []string{"--profile", "work", "profile", "remove", "--yes", "-o", "json"}},
		{name: "replace", args: []string{"--profile", "work", "profile", "add", "--from", "PROFILE_FILE", "--yes", "-o", "json"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, operation := range operations {
				t.Run(operation.name, func(t *testing.T) {
					app, stdout := testIdentityApp(t)
					stored := test.mutate(t, identityProfile(t))
					if err := app.profiles.Add(context.Background(), stored); err != nil {
						t.Fatal(err)
					}
					args := append([]string(nil), operation.args...)
					for index, value := range args {
						if value != "PROFILE_FILE" {
							continue
						}
						path := filepath.Join(t.TempDir(), "profile.json")
						if err := os.WriteFile(path, []byte(identityProfileJSON), 0o600); err != nil {
							t.Fatal(err)
						}
						args[index] = path
					}
					if code := runIdentityApp(app, args...); code != errx.CodeUsage {
						t.Fatalf("code=%d output=%s", code, stdout.String())
					}
					errorData := identityEnvelope(t, stdout)["error"].(map[string]any)
					if got := errorData["code"]; got != "USAGE" {
						t.Fatalf("error code=%v output=%s", got, stdout.String())
					}
					remaining, err := app.profiles.Get(context.Background(), "work")
					if err != nil {
						t.Fatalf("operation changed invalid registry entry: %v", err)
					}
					got, err := json.Marshal(remaining)
					if err != nil {
						t.Fatal(err)
					}
					want, err := json.Marshal(stored)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(got, want) {
						t.Fatalf("operation changed invalid registry entry: got=%s want=%s", got, want)
					}
				})
			}
		})
	}
}

func TestIdentityRejectsSelectedProfileOperationsWhenAnyNeighborIsDisallowed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, value profile.Profile) profile.Profile
	}{
		{
			name: "write capability",
			mutate: func(_ *testing.T, value profile.Profile) profile.Profile {
				value.Capabilities = []profile.Capability{profile.CapabilityRead, profile.CapabilityIssueUpdate}
				return value
			},
		},
		{
			name: "credential generation",
			mutate: func(t *testing.T, value profile.Profile) profile.Profile {
				bound, err := value.WithNewCredentialGeneration()
				if err != nil {
					t.Fatal(err)
				}
				return bound
			},
		},
	}
	operations := []struct {
		name        string
		profileName string
		args        []string
	}{
		{name: "show", profileName: "work", args: []string{"--profile", "work", "profile", "show", "-o", "json"}},
		{name: "validate", profileName: "work", args: []string{"--profile", "work", "profile", "validate", "--offline", "-o", "json"}},
		{name: "add new", profileName: "new", args: []string{"--profile", "new", "profile", "add", "--from", "PROFILE_FILE", "--yes", "-o", "json"}},
		{name: "replace", profileName: "work", args: []string{"--profile", "work", "profile", "add", "--from", "PROFILE_FILE", "--yes", "-o", "json"}},
		{name: "remove", profileName: "work", args: []string{"--profile", "work", "profile", "remove", "--yes", "-o", "json"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, operation := range operations {
				t.Run(operation.name, func(t *testing.T) {
					app, stdout := testIdentityApp(t)
					valid := identityProfile(t)
					neighbor := test.mutate(t, identityProfile(t))
					neighbor.Name = "neighbor"
					if err := app.profiles.Add(context.Background(), valid); err != nil {
						t.Fatal(err)
					}
					if err := app.profiles.Add(context.Background(), neighbor); err != nil {
						t.Fatal(err)
					}
					before, err := os.ReadFile(app.profiles.Path())
					if err != nil {
						t.Fatal(err)
					}

					candidate := identityProfile(t)
					candidate.Name = operation.profileName
					raw, err := json.Marshal(candidate)
					if err != nil {
						t.Fatal(err)
					}
					path := filepath.Join(t.TempDir(), "profile.json")
					if err := os.WriteFile(path, raw, 0o600); err != nil {
						t.Fatal(err)
					}
					args := append([]string(nil), operation.args...)
					for index, value := range args {
						if value == "PROFILE_FILE" {
							args[index] = path
						}
					}

					if code := runIdentityApp(app, args...); code != errx.CodeUsage {
						t.Fatalf("code=%d output=%s", code, stdout.String())
					}
					if got := identityEnvelope(t, stdout)["error"].(map[string]any)["code"]; got != "USAGE" {
						t.Fatalf("error code=%v output=%s", got, stdout.String())
					}
					after, err := os.ReadFile(app.profiles.Path())
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(after, before) {
						t.Fatalf("operation rewrote identity registry: got=%s want=%s", after, before)
					}
					values, err := app.profiles.List(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					if len(values) != 2 || values[0].Name != "neighbor" || values[1].Name != "work" {
						t.Fatalf("operation changed registry records: %+v", values)
					}
				})
			}
		})
	}
}
