// Package config loads and validates the sign-release configuration.
//
// config.json is the single source for the signing identity and the release
// asset names. The tap workflow and the formula renderer read the same file, so
// the format is plain JSON and stays stable. Parse refuses unknown, duplicate and
// differently cased fields and malformed values; a certificate hash that is still empty loads, so tests and
// the tap workflow can read the rest, and CLI.ReadyToSign is the separate check
// the signing tool runs before it does anything.
package config

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// VersionPlaceholder marks where an asset name template takes the version.
const VersionPlaceholder = "{version}"

// Config is the whole file.
type Config struct {
	// Repository is the GitHub repository, owner/name.
	Repository string `json:"repository"`
	// SignerWorkflow is the workflow path the attestations must name, relative
	// to the repository root.
	SignerWorkflow string         `json:"signer_workflow"`
	CLIs           map[string]CLI `json:"clis"`
}

// CLI is the signing identity and asset layout of one CLI.
type CLI struct {
	// Identifier is the code signing identifier, in reverse-DNS form.
	Identifier string `json:"identifier"`
	// Team is the Apple team identifier.
	Team string `json:"team"`
	// CertSHA1 is the SHA-1 of the Developer ID leaf certificate: 40 hex
	// characters, or empty until the operator supplies it.
	CertSHA1 string `json:"cert_sha1"`
	// Formula is the Homebrew formula name.
	Formula string `json:"formula"`
	// TagPrefix precedes the version in a release tag.
	TagPrefix string `json:"tag_prefix"`
	Assets    Assets `json:"assets"`
}

// Assets names the files of a release. Archive names are templates that carry
// VersionPlaceholder exactly once.
type Assets struct {
	DarwinArchives  Archives `json:"darwin_archives"`
	DarwinChecksums string   `json:"darwin_checksums"`
	LinuxArchives   Archives `json:"linux_archives"`
	LinuxChecksums  string   `json:"linux_checksums"`
	// ArchiveEntries are the exact member names of every archive.
	ArchiveEntries []string `json:"archive_entries"`
}

// Archives holds one archive name template per architecture.
type Archives struct {
	AMD64 string `json:"amd64"`
	ARM64 string `json:"arm64"`
}

// FieldError reports a value that failed validation.
type FieldError struct {
	Field  string
	Reason string
}

// Error names the field and the reason.
func (e *FieldError) Error() string {
	return fmt.Sprintf("invalid config: %s: %s", e.Field, e.Reason)
}

func invalid(field, format string, args ...any) error {
	return &FieldError{Field: field, Reason: fmt.Sprintf(format, args...)}
}

// NotReadyError reports a CLI that cannot be signed yet.
type NotReadyError struct {
	CLI    string
	Reason string
}

// Error tells the operator what to supply.
func (e *NotReadyError) Error() string {
	return fmt.Sprintf("%s is not ready to sign: %s", e.CLI, e.Reason)
}

var (
	identifierPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	teamPattern       = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	sha1Pattern       = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	namePattern       = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	repoPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+$`)
	versionPattern    = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$`)
)

const maxIdentifierLen = 128

// ValidateIdentifier checks a code signing identifier: at least two
// dot-separated lowercase labels of letters, digits and inner hyphens.
func ValidateIdentifier(id string) error {
	switch {
	case id == "":
		return invalid("identifier", "is empty")
	case len(id) > maxIdentifierLen:
		return invalid("identifier", "is longer than %d bytes", maxIdentifierLen)
	case !identifierPattern.MatchString(id):
		return invalid("identifier", "%q is not reverse-DNS (lowercase dot-separated labels, at least two)", id)
	}
	return nil
}

// ValidateTeam checks an Apple team identifier: 10 uppercase alphanumerics.
func ValidateTeam(team string) error {
	if !teamPattern.MatchString(team) {
		return invalid("team", "%q is not 10 uppercase alphanumeric characters", team)
	}
	return nil
}

// ValidateCertSHA1 checks a certificate SHA-1: exactly 40 hex characters.
func ValidateCertSHA1(sum string) error {
	if !sha1Pattern.MatchString(sum) {
		return invalid("cert_sha1", "%q is not exactly 40 hex characters", sum)
	}
	return nil
}

// Parse decodes and validates a configuration. Unknown fields, keys that
// differ from a field name in case, duplicate keys at any level, trailing data
// and malformed values are refused. jq and Ruby read the same file, so Go must
// not accept a document they would read differently; encoding/json v2 matches
// names case-sensitively and rejects duplicates by default. An empty cert_sha1
// is accepted; use CLI.ReadyToSign before signing.
func Parse(data []byte) (Config, error) {
	var c Config
	if err := json.Unmarshal(data, &c, json.RejectUnknownMembers(true), json.MatchCaseInsensitiveNames(false)); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := c.validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// CLI returns the named CLI.
func (c Config) CLI(name string) (CLI, error) {
	cli, ok := c.CLIs[name]
	if !ok {
		return CLI{}, invalid("clis", "no CLI named %q", name)
	}
	return cli, nil
}

func (c Config) validate() error {
	if !repoPattern.MatchString(c.Repository) {
		return invalid("repository", "%q is not owner/name", c.Repository)
	}
	if err := validateRelativePath("signer_workflow", c.SignerWorkflow); err != nil {
		return err
	}
	if len(c.CLIs) == 0 {
		return invalid("clis", "has no CLI")
	}
	for name, cli := range c.CLIs {
		if !namePattern.MatchString(name) {
			return invalid("clis", "name %q is not lowercase letters, digits and hyphens", name)
		}
		if err := cli.validate(name); err != nil {
			return err
		}
	}
	return nil
}

func validateRelativePath(field, p string) error {
	switch {
	case p == "":
		return invalid(field, "is empty")
	case strings.HasPrefix(p, "/"), strings.Contains(p, ".."), strings.Contains(p, `\`), strings.ContainsAny(p, " \t\r\n"):
		return invalid(field, "%q is not a plain relative path", p)
	}
	return nil
}

func (c CLI) validate(name string) error {
	scope := func(field string) string { return "clis." + name + "." + field }
	if err := ValidateIdentifier(c.Identifier); err != nil {
		return invalid(scope("identifier"), "%s", reasonOf(err))
	}
	if err := ValidateTeam(c.Team); err != nil {
		return invalid(scope("team"), "%s", reasonOf(err))
	}
	if c.CertSHA1 != "" {
		if err := ValidateCertSHA1(c.CertSHA1); err != nil {
			return invalid(scope("cert_sha1"), "%s", reasonOf(err))
		}
	}
	if !namePattern.MatchString(c.Formula) {
		return invalid(scope("formula"), "%q is not lowercase letters, digits and hyphens", c.Formula)
	}
	if want := name + "/v"; c.TagPrefix != want {
		return invalid(scope("tag_prefix"), "is %q, want %q", c.TagPrefix, want)
	}
	return c.Assets.validate(scope("assets"))
}

func reasonOf(err error) string {
	var fe *FieldError
	if errors.As(err, &fe) {
		return fe.Reason
	}
	return err.Error()
}

func (a Assets) validate(scope string) error {
	templates := []struct{ field, value string }{
		{"darwin_archives.amd64", a.DarwinArchives.AMD64},
		{"darwin_archives.arm64", a.DarwinArchives.ARM64},
		{"linux_archives.amd64", a.LinuxArchives.AMD64},
		{"linux_archives.arm64", a.LinuxArchives.ARM64},
	}
	seen := map[string]string{}
	for _, t := range templates {
		field := scope + "." + t.field
		if err := validateFileName(field, t.value); err != nil {
			return err
		}
		if n := strings.Count(t.value, VersionPlaceholder); n != 1 {
			return invalid(field, "%q has %d %s placeholders, want 1", t.value, n, VersionPlaceholder)
		}
		if !strings.HasSuffix(t.value, ".tar.gz") {
			return invalid(field, "%q is not a .tar.gz name", t.value)
		}
		if prev, dup := seen[t.value]; dup {
			return invalid(field, "%q repeats %s", t.value, prev)
		}
		seen[t.value] = t.field
	}
	for _, t := range []struct{ field, value string }{
		{"darwin_checksums", a.DarwinChecksums},
		{"linux_checksums", a.LinuxChecksums},
	} {
		field := scope + "." + t.field
		if err := validateFileName(field, t.value); err != nil {
			return err
		}
		if strings.Contains(t.value, "{") {
			return invalid(field, "%q must not be a template", t.value)
		}
		if prev, dup := seen[t.value]; dup {
			return invalid(field, "%q repeats %s", t.value, prev)
		}
		seen[t.value] = t.field
	}
	if len(a.ArchiveEntries) == 0 {
		return invalid(scope+".archive_entries", "is empty")
	}
	entries := map[string]bool{}
	for _, e := range a.ArchiveEntries {
		field := scope + ".archive_entries"
		if err := validateFileName(field, e); err != nil {
			return err
		}
		if strings.Contains(e, "{") {
			return invalid(field, "%q must not be a template", e)
		}
		if entries[e] {
			return invalid(field, "%q is listed twice", e)
		}
		entries[e] = true
	}
	return nil
}

func validateFileName(field, name string) error {
	switch {
	case name == "":
		return invalid(field, "is empty")
	case name == "." || name == "..", strings.ContainsAny(name, "/\\ \t\r\n\x00"):
		return invalid(field, "%q is not a plain file name", name)
	}
	return nil
}

// ReadyToSign reports whether the CLI carries everything signing needs. It
// refuses while cert_sha1 is empty or malformed, telling the operator to supply
// the Developer ID certificate SHA-1.
func (c CLI) ReadyToSign(name string) error {
	if c.CertSHA1 == "" {
		return &NotReadyError{CLI: name, Reason: "cert_sha1 is empty; the operator must supply the 40-hex SHA-1 of the Developer ID Application certificate in tools/sign-release/config.json"}
	}
	if err := ValidateCertSHA1(c.CertSHA1); err != nil {
		return &NotReadyError{CLI: name, Reason: "cert_sha1 is malformed; the operator must supply the 40-hex SHA-1 of the Developer ID Application certificate in tools/sign-release/config.json"}
	}
	return nil
}

// ExpandName renders an archive name template for version, which must be a
// plain semantic version without a leading v.
func ExpandName(template, version string) (string, error) {
	if !versionPattern.MatchString(version) {
		return "", invalid("version", "%q is not a semantic version without a leading v", version)
	}
	if strings.Count(template, VersionPlaceholder) != 1 {
		return "", invalid("template", "%q does not carry exactly one %s", template, VersionPlaceholder)
	}
	return strings.Replace(template, VersionPlaceholder, version, 1), nil
}
