package config

import (
	"errors"
	"os"
	"strings"
	"testing"
)

const validSHA1 = "0123456789abcdef0123456789abcdef01234567"

const validConfig = `{
  "repository": "abigotado/agent-clis",
  "signer_workflow": ".github/workflows/release.yaml",
  "clis": {
    "youtrack-agent-cli": {
      "identifier": "dev.abigotado.youtrack-agent-cli",
      "team": "5XCS9FFW5Z",
      "cert_sha1": "",
      "formula": "youtrack-agent-cli",
      "tag_prefix": "youtrack-agent-cli/v",
      "assets": {
        "darwin_archives": {
          "amd64": "youtrack-agent-cli_{version}_darwin_amd64.tar.gz",
          "arm64": "youtrack-agent-cli_{version}_darwin_arm64.tar.gz"
        },
        "darwin_checksums": "checksums-darwin.txt",
        "linux_archives": {
          "amd64": "youtrack-agent-cli_{version}_linux_amd64.tar.gz",
          "arm64": "youtrack-agent-cli_{version}_linux_arm64.tar.gz"
        },
        "linux_checksums": "checksums.txt",
        "archive_entries": ["LICENSE", "README.md", "youtrack-agent-cli"]
      }
    }
  }
}`

// mutate returns validConfig with one substring replaced, failing the test if
// the substring is not there so a stale edit cannot pass silently.
func mutate(t *testing.T, old, replacement string) string {
	t.Helper()
	if !strings.Contains(validConfig, old) {
		t.Fatalf("test fixture does not contain %q", old)
	}
	return strings.Replace(validConfig, old, replacement, 1)
}

func TestParseAcceptsTheShippedConfig(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../config.json")
	if err != nil {
		t.Fatalf("read config.json: %v", err)
	}
	c, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse(config.json) error = %v", err)
	}
	cli, err := c.CLI("youtrack-agent-cli")
	if err != nil {
		t.Fatalf("CLI() error = %v", err)
	}
	if cli.Identifier != "dev.abigotado.youtrack-agent-cli" || cli.Team != "5XCS9FFW5Z" {
		t.Errorf("identity = %q / %q", cli.Identifier, cli.Team)
	}
	if cli.CertSHA1 != "" {
		// The operator supplies it; once they do, it must still be well formed,
		// which Parse above has already checked.
		if err := cli.ReadyToSign("youtrack-agent-cli"); err != nil {
			t.Errorf("a supplied cert_sha1 must be ready to sign: %v", err)
		}
	}
}

func TestParseValid(t *testing.T) {
	t.Parallel()

	c, err := Parse([]byte(validConfig))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	cli, err := c.CLI("youtrack-agent-cli")
	if err != nil {
		t.Fatalf("CLI() error = %v", err)
	}
	if c.Repository != "abigotado/agent-clis" || c.SignerWorkflow != ".github/workflows/release.yaml" {
		t.Errorf("repository/workflow = %q / %q", c.Repository, c.SignerWorkflow)
	}
	if cli.TagPrefix != "youtrack-agent-cli/v" || cli.Formula != "youtrack-agent-cli" {
		t.Errorf("tag prefix/formula = %q / %q", cli.TagPrefix, cli.Formula)
	}
	if got := cli.Assets.ArchiveEntries; len(got) != 3 || got[2] != "youtrack-agent-cli" {
		t.Errorf("ArchiveEntries = %v", got)
	}
	if _, err := c.CLI("missing"); err == nil {
		t.Error("CLI(missing) error = nil")
	}
}

func TestParseRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  string
		field  string // substring of the FieldError field; empty means any error
		reason string
	}{
		{name: "unknown top-level field", input: mutate(t, `"repository"`, `"extra": 1, "repository"`)},
		{name: "unknown CLI field", input: mutate(t, `"formula"`, `"extra": 1, "formula"`)},
		{name: "unknown asset field", input: mutate(t, `"linux_checksums"`, `"extra": "x", "linux_checksums"`)},
		{name: "unknown nested archive field", input: mutate(t, `"arm64": "youtrack-agent-cli_{version}_darwin_arm64.tar.gz"`, `"arm64": "youtrack-agent-cli_{version}_darwin_arm64.tar.gz", "riscv": "x"`)},
		{name: "duplicate top-level key", input: mutate(t, `"repository": "abigotado/agent-clis",`, `"repository": "abigotado/agent-clis", "repository": "other/repo",`)},
		{name: "duplicate team", input: mutate(t, `"team": "5XCS9FFW5Z",`, `"team": "5XCS9FFW5Z", "team": "AAAAAAAAAA",`)},
		{name: "duplicate CLI name", input: mutate(t, `"clis": {`, `"clis": {"youtrack-agent-cli": {}, `)},
		{name: "duplicate assets key", input: mutate(t, `"linux_checksums": "checksums.txt",`, `"linux_checksums": "checksums.txt", "linux_checksums": "x.txt",`)},
		{name: "duplicate nested archive key", input: mutate(t, `"amd64": "youtrack-agent-cli_{version}_darwin_amd64.tar.gz",`, `"amd64": "youtrack-agent-cli_{version}_darwin_amd64.tar.gz", "amd64": "x_{version}.tar.gz",`)},
		{name: "key differing only in case: TEAM", input: mutate(t, `"team"`, `"TEAM"`)},
		{name: "key differing only in case: Cert_SHA1", input: mutate(t, `"cert_sha1"`, `"Cert_SHA1"`)},
		{name: "key differing only in case: top level", input: mutate(t, `"repository"`, `"Repository"`)},
		{name: "key differing only in case: assets", input: mutate(t, `"darwin_checksums"`, `"Darwin_Checksums"`)},
		{name: "key differing only in case: nested archive", input: mutate(t, `"arm64": "youtrack-agent-cli_{version}_linux_arm64.tar.gz"`, `"ARM64": "youtrack-agent-cli_{version}_linux_arm64.tar.gz"`)},
		{name: "case variant beside the exact key", input: mutate(t, `"team": "5XCS9FFW5Z",`, `"team": "5XCS9FFW5Z", "Team": "AAAAAAAAAA",`)},
		{name: "trailing data", input: validConfig + ` {}`},
		{name: "not json", input: `team: x`},
		{name: "wrong type", input: mutate(t, `"team": "5XCS9FFW5Z"`, `"team": 5`)},
		{name: "wrong identifier: not reverse-DNS", input: mutate(t, `dev.abigotado.youtrack-agent-cli`, `youtrack-agent-cli`), field: "identifier"},
		{name: "wrong identifier: uppercase", input: mutate(t, `dev.abigotado.youtrack-agent-cli`, `Dev.abigotado.youtrack-agent-cli`), field: "identifier"},
		{name: "wrong identifier: quote", input: mutate(t, `dev.abigotado.youtrack-agent-cli`, `dev.abigotado.x\" or true`), field: "identifier"},
		{name: "wrong identifier: empty label", input: mutate(t, `dev.abigotado.youtrack-agent-cli`, `dev..youtrack`), field: "identifier"},
		{name: "empty identifier", input: mutate(t, `dev.abigotado.youtrack-agent-cli`, ``), field: "identifier"},
		{name: "team too short", input: mutate(t, `5XCS9FFW5Z`, `5XCS9FFW5`), field: "team"},
		{name: "team lowercase", input: mutate(t, `5XCS9FFW5Z`, `5xcs9ffw5z`), field: "team"},
		{name: "team too long", input: mutate(t, `5XCS9FFW5Z`, `5XCS9FFW5ZA`), field: "team"},
		{name: "cert_sha1 too short", input: mutate(t, `"cert_sha1": ""`, `"cert_sha1": "0123"`), field: "cert_sha1"},
		{name: "cert_sha1 not hex", input: mutate(t, `"cert_sha1": ""`, `"cert_sha1": "`+strings.Repeat("g", 40)+`"`), field: "cert_sha1"},
		{name: "cert_sha1 with colons", input: mutate(t, `"cert_sha1": ""`, `"cert_sha1": "01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67"`), field: "cert_sha1"},
		{name: "cert_sha1 too long", input: mutate(t, `"cert_sha1": ""`, `"cert_sha1": "`+validSHA1+`0"`), field: "cert_sha1"},
		{name: "tag prefix differs from the CLI", input: mutate(t, `"youtrack-agent-cli/v"`, `"other/v"`), field: "tag_prefix"},
		{name: "archive without placeholder", input: mutate(t, `youtrack-agent-cli_{version}_darwin_amd64.tar.gz`, `youtrack-agent-cli_darwin_amd64.tar.gz`), field: "darwin_archives.amd64"},
		{name: "archive with a path", input: mutate(t, `youtrack-agent-cli_{version}_darwin_amd64.tar.gz`, `../youtrack-agent-cli_{version}_darwin_amd64.tar.gz`), field: "darwin_archives.amd64"},
		{name: "archive not tar.gz", input: mutate(t, `youtrack-agent-cli_{version}_darwin_amd64.tar.gz`, `youtrack-agent-cli_{version}_darwin_amd64.zip`), field: "darwin_archives.amd64"},
		{name: "duplicate archive name", input: mutate(t, `youtrack-agent-cli_{version}_darwin_arm64.tar.gz`, `youtrack-agent-cli_{version}_darwin_amd64.tar.gz`), field: "darwin_archives.arm64"},
		{name: "checksums repeat", input: mutate(t, `"checksums-darwin.txt"`, `"checksums.txt"`), field: "linux_checksums"},
		{name: "empty entry list", input: mutate(t, `["LICENSE", "README.md", "youtrack-agent-cli"]`, `[]`), field: "archive_entries"},
		{name: "entry with a path", input: mutate(t, `"LICENSE"`, `"dir/LICENSE"`), field: "archive_entries"},
		{name: "duplicate entry", input: mutate(t, `"README.md"`, `"LICENSE"`), field: "archive_entries"},
		{name: "bad repository", input: mutate(t, `abigotado/agent-clis`, `agent-clis`), field: "repository"},
		{name: "workflow path escapes", input: mutate(t, `.github/workflows/release.yaml`, `../release.yaml`), field: "signer_workflow"},
		{name: "no CLIs", input: `{"repository":"a/b","signer_workflow":"w.yaml","clis":{}}`, field: "clis"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse([]byte(tt.input))
			if err == nil {
				t.Fatal("Parse() error = nil")
			}
			if tt.field == "" {
				return
			}
			var fe *FieldError
			if !errors.As(err, &fe) {
				t.Fatalf("error = %v, want a *FieldError", err)
			}
			if !strings.Contains(fe.Field, tt.field) {
				t.Errorf("field = %q, want it to contain %q (%v)", fe.Field, tt.field, err)
			}
		})
	}
}

func TestParseAcceptsHexInEitherCase(t *testing.T) {
	t.Parallel()

	for _, sum := range []string{validSHA1, strings.ToUpper(validSHA1)} {
		c, err := Parse([]byte(mutate(t, `"cert_sha1": ""`, `"cert_sha1": "`+sum+`"`)))
		if err != nil {
			t.Fatalf("Parse(%s) error = %v", sum, err)
		}
		cli, err := c.CLI("youtrack-agent-cli")
		if err != nil {
			t.Fatalf("CLI() error = %v", err)
		}
		if err := cli.ReadyToSign("youtrack-agent-cli"); err != nil {
			t.Errorf("ReadyToSign(%s) error = %v", sum, err)
		}
	}
}

func TestReadyToSign(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		sha1    string
		wantErr bool
		want    string
	}{
		{name: "empty", sha1: "", wantErr: true, want: "operator must supply"},
		{name: "malformed", sha1: "abc", wantErr: true, want: "operator must supply"},
		{name: "valid", sha1: validSHA1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := CLI{CertSHA1: tt.sha1}.ReadyToSign("youtrack-agent-cli")
			if (err != nil) != tt.wantErr {
				t.Fatalf("ReadyToSign() error = %v, wantErr %t", err, tt.wantErr)
			}
			if err == nil {
				return
			}
			var nre *NotReadyError
			if !errors.As(err, &nre) {
				t.Fatalf("error = %v, want a *NotReadyError", err)
			}
			if !strings.Contains(err.Error(), tt.want) || !strings.Contains(err.Error(), "cert_sha1") {
				t.Errorf("message %q does not tell the operator what to supply", err)
			}
		})
	}
}

func TestExpandName(t *testing.T) {
	t.Parallel()

	const tmpl = "youtrack-agent-cli_{version}_darwin_arm64.tar.gz"
	tests := []struct {
		name     string
		template string
		version  string
		want     string
		wantErr  bool
	}{
		{name: "release", template: tmpl, version: "0.13.0", want: "youtrack-agent-cli_0.13.0_darwin_arm64.tar.gz"},
		{name: "prerelease", template: tmpl, version: "0.13.0-rc.1", want: "youtrack-agent-cli_0.13.0-rc.1_darwin_arm64.tar.gz"},
		{name: "leading v", template: tmpl, version: "v0.13.0", wantErr: true},
		{name: "path in version", template: tmpl, version: "0.13.0/../x", wantErr: true},
		{name: "empty version", template: tmpl, version: "", wantErr: true},
		{name: "no placeholder", template: "checksums.txt", version: "0.13.0", wantErr: true},
		{name: "two placeholders", template: "{version}{version}", version: "0.13.0", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ExpandName(tt.template, tt.version)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ExpandName() error = %v, wantErr %t", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ExpandName() = %q, want %q", got, tt.want)
			}
		})
	}
}
