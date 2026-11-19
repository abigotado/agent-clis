// Package codesign builds the designated requirement sign-release signs with
// and checks the text codesign prints about a signed binary against it.
//
// Nothing here runs a program. The parsers take the output as a string, so the
// runner that executes /usr/bin/codesign stays a separate seam and every check
// is testable on any platform. codesign writes -dvv to stderr and -d -r- and
// -d --entitlements - to stdout; the caller passes whichever stream carries the
// text, and a first line of the form "Executable=/...", which codesign prints
// to stderr, is ignored in all three.
//
// These parsers authenticate nothing. They read text a program printed, and
// text can be forged or replayed. Verify therefore adds to
// `codesign --verify --strict -R=<Requirement()>` and never replaces it: only
// that cryptographic check proves the signature is intact and that the leaf
// certificate pin in the designated requirement holds.
package codesign

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/abigotado/agent-clis/tools/sign-release/internal/config"
)

// Check names one verification a binary must pass.
type Check string

// The checks Verify runs.
const (
	CheckOutput       Check = "codesign-output"
	CheckIdentifier   Check = "identifier"
	CheckRuntime      Check = "hardened-runtime-flag"
	CheckTeam         Check = "team-identifier"
	CheckTimestamp    Check = "secure-timestamp"
	CheckDesignated   Check = "designated-requirement"
	CheckEntitlements Check = "entitlements-empty"
)

// CheckError reports a failed check.
type CheckError struct {
	Check  Check
	Detail string
}

// Error names the failed check.
func (e *CheckError) Error() string {
	return fmt.Sprintf("codesign check %s failed: %s", e.Check, e.Detail)
}

func fail(check Check, format string, args ...any) error {
	return &CheckError{Check: check, Detail: fmt.Sprintf(format, args...)}
}

// Expectation is what a signed binary must show.
type Expectation struct {
	Identifier string
	Team       string
	CertSHA1   string
}

// Validate refuses an expectation that could not be rendered into a
// requirement.
func (e Expectation) Validate() error {
	if err := config.ValidateIdentifier(e.Identifier); err != nil {
		return fmt.Errorf("expectation: %w", err)
	}
	if err := config.ValidateTeam(e.Team); err != nil {
		return fmt.Errorf("expectation: %w", err)
	}
	if err := config.ValidateCertSHA1(e.CertSHA1); err != nil {
		return fmt.Errorf("expectation: %w", err)
	}
	return nil
}

// ExpectationFor builds the expectation of a CLI, refusing one that is not
// ready to sign.
func ExpectationFor(name string, cli config.CLI) (Expectation, error) {
	if err := cli.ReadyToSign(name); err != nil {
		return Expectation{}, fmt.Errorf("build expectation: %w", err)
	}
	e := Expectation{Identifier: cli.Identifier, Team: cli.Team, CertSHA1: cli.CertSHA1}
	if err := e.Validate(); err != nil {
		return Expectation{}, err
	}
	return e, nil
}

// Requirement returns the requirement argument for `codesign --requirements`
// and `-R`, with its leading "=":
//
//	=designated => identifier "<id>" and anchor apple generic and certificate leaf = H"<sha1>"
//
// The hex is lowercase.
func (e Expectation) Requirement() (string, error) {
	expr, err := e.designated()
	if err != nil {
		return "", err
	}
	return "=" + expr, nil
}

// designated returns the requirement as `codesign -d -r-` prints it: the same
// text without the leading "=".
func (e Expectation) designated() (string, error) {
	if err := e.Validate(); err != nil {
		return "", err
	}
	return fmt.Sprintf(`designated => identifier "%s" and anchor apple generic and certificate leaf = H"%s"`,
		e.Identifier, strings.ToLower(e.CertSHA1)), nil
}

// Details is what `codesign -dvv` reports.
type Details struct {
	Identifier string
	// Flags is the raw flags= value of the CodeDirectory line, such as
	// "0x10000(runtime)".
	Flags string
	// FlagNames are the names inside the parentheses of Flags.
	FlagNames []string
	// Runtime reports whether FlagNames contains "runtime" and the flags value
	// has the hardened runtime bit, 0x10000, set. Either alone is not enough.
	Runtime        bool
	TeamIdentifier string
	// HasTimestamp reports a secure "Timestamp=" line. "Signed Time=" is the
	// signer's own clock and does not count.
	HasTimestamp bool
	// CDHash is the CDHash= value. codesign prints it only at -dvvv on some
	// releases, so it may be empty.
	CDHash string
}

// runtimeFlag is CS_RUNTIME, the hardened runtime bit of the CodeDirectory
// flags.
const runtimeFlag = 0x10000

var flagsPattern = regexp.MustCompile(`(?:^|\s)flags=(0x[0-9a-fA-F]+)\(([^)]*)\)`)

// ParseDetails reads the output of `codesign -dvv`. Each field it extracts may
// appear once; a repeated one is refused because the output would be ambiguous.
// A field that is absent stays empty and Verify reports it.
func ParseDetails(output string) (Details, error) {
	var d Details
	counts := map[string]int{}
	once := func(key string) error {
		counts[key]++
		if counts[key] > 1 {
			return fail(CheckOutput, "%s appears more than once", key)
		}
		return nil
	}
	ls, err := lines(output)
	if err != nil {
		return Details{}, fail(CheckOutput, "%v", err)
	}
	for _, line := range ls {
		switch {
		case strings.HasPrefix(line, "Identifier="):
			if err := once("Identifier="); err != nil {
				return Details{}, err
			}
			d.Identifier = strings.TrimPrefix(line, "Identifier=")
		case strings.HasPrefix(line, "TeamIdentifier="):
			if err := once("TeamIdentifier="); err != nil {
				return Details{}, err
			}
			d.TeamIdentifier = strings.TrimPrefix(line, "TeamIdentifier=")
		case strings.HasPrefix(line, "Timestamp="):
			if err := once("Timestamp="); err != nil {
				return Details{}, err
			}
			d.HasTimestamp = strings.TrimSpace(strings.TrimPrefix(line, "Timestamp=")) != ""
		case strings.HasPrefix(line, "CDHash="):
			if err := once("CDHash="); err != nil {
				return Details{}, err
			}
			d.CDHash = strings.TrimPrefix(line, "CDHash=")
		case strings.HasPrefix(line, "CodeDirectory "):
			if err := once("CodeDirectory"); err != nil {
				return Details{}, err
			}
			if m := flagsPattern.FindStringSubmatch(line); m != nil {
				d.Flags = m[1] + "(" + m[2] + ")"
				value, perr := strconv.ParseUint(m[1][2:], 16, 64)
				named := false
				for name := range strings.SplitSeq(m[2], ",") {
					name = strings.TrimSpace(name)
					if name == "" {
						continue
					}
					d.FlagNames = append(d.FlagNames, name)
					if name == "runtime" {
						named = true
					}
				}
				d.Runtime = named && perr == nil && value&runtimeFlag != 0
			}
		}
	}
	return d, nil
}

// body normalizes output for parsing. CRLF becomes LF; a carriage return that
// is not part of a CRLF is refused, since a reader that treats it as a line
// break would see different lines. Only a first line that starts with
// "Executable=/", the header codesign prints to stderr, is dropped.
func body(output string) (string, error) {
	s := strings.ReplaceAll(output, "\r\n", "\n")
	if strings.Contains(s, "\r") {
		return "", errors.New("the output contains a carriage return that is not part of a CRLF")
	}
	first, rest, _ := strings.Cut(s, "\n")
	if strings.HasPrefix(first, "Executable=/") {
		return rest, nil
	}
	return s, nil
}

// lines splits the normalized output into lines and drops blank ones.
func lines(output string) ([]string, error) {
	b, err := body(output)
	if err != nil {
		return nil, err
	}
	var out []string
	for line := range strings.SplitSeq(b, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}

var hashLiteral = regexp.MustCompile(`H"([0-9A-Fa-f]+)"`)

// normalizeHex lowercases only the hex inside H"..." literals; the H, the
// quotes and everything else stay as printed.
func normalizeHex(s string) string {
	return hashLiteral.ReplaceAllStringFunc(s, func(m string) string {
		return `H"` + strings.ToLower(m[2:len(m)-1]) + `"`
	})
}

// VerifyDesignated verifies the output of `codesign -d -r-`. It must hold
// exactly one line, `designated => ...`, equal to the requirement e builds;
// only the hex inside H"..." is compared case-insensitively. An implicit
// `# designated =>` line, extra clauses and any other requirement type are
// refused.
func VerifyDesignated(output string, e Expectation) error {
	want, err := e.designated()
	if err != nil {
		return fail(CheckDesignated, "cannot build the expected requirement: %v", err)
	}
	got, err := lines(output)
	if err != nil {
		return fail(CheckDesignated, "%v", err)
	}
	switch len(got) {
	case 0:
		return fail(CheckDesignated, "no requirement in the output")
	case 1:
	default:
		return fail(CheckDesignated, "the output has %d requirement lines, want exactly 1", len(got))
	}
	line := got[0]
	switch {
	case strings.HasPrefix(line, "#"):
		return fail(CheckDesignated, "the requirement is implicit (%q), not the explicit one signing sets", line)
	case !strings.HasPrefix(line, "designated => "):
		return fail(CheckDesignated, "the line %q is not a designated requirement", line)
	case normalizeHex(line) != normalizeHex(want):
		return fail(CheckDesignated, "got %q, want %q", line, want)
	}
	return nil
}

// emptyPlist is the one XML document accepted as an empty entitlement set,
// compared after all whitespace is removed.
const emptyPlist = `<?xmlversion="1.0"encoding="UTF-8"?><!DOCTYPEplistPUBLIC"-//Apple//DTDPLIST1.0//EN""https://www.apple.com/DTDs/PropertyList-1.0.dtd"><plistversion="1.0"><dict/></plist>`

// VerifyEntitlements verifies the output of `codesign -d --entitlements -`. It
// accepts only three shapes, after the optional "Executable=/" header line and
// surrounding blank space: nothing at all, the exact text "[Dict]", or the one
// canonical empty plist document (Apple's XML header and DOCTYPE around
// "<dict/>"), compared with whitespace removed. Anything else, including any
// other XML, is refused, so an unknown format fails closed.
func VerifyEntitlements(output string) error {
	b, err := body(output)
	if err != nil {
		return fail(CheckEntitlements, "%v", err)
	}
	trimmed := strings.TrimSpace(b)
	switch {
	case trimmed == "":
		return nil
	case strings.Contains(trimmed, "[Key]"), strings.Contains(trimmed, "<key>"):
		return fail(CheckEntitlements, "the binary carries entitlements")
	case strings.TrimRight(b, "\n") == "[Dict]":
		return nil
	case strings.Join(strings.Fields(trimmed), "") == emptyPlist:
		return nil
	}
	return fail(CheckEntitlements, "the output is not empty and not a recognized empty entitlement set (%d bytes)", len(trimmed))
}

// Outputs are the texts of the three codesign inspections of one binary.
type Outputs struct {
	// Details is `codesign -dvv`, from stderr.
	Details string
	// Requirements is `codesign -d -r-`.
	Requirements string
	// Entitlements is `codesign -d --entitlements -`.
	Entitlements string
}

// Verify checks a full set of outputs against the expectation. It runs every
// check and returns the failures joined; each is a *CheckError, so errors.As
// finds the first and the message names every failed check. It returns nil
// only when all checks pass.
func Verify(e Expectation, out Outputs) error {
	if err := e.Validate(); err != nil {
		return err
	}
	var errs []error
	d, err := ParseDetails(out.Details)
	if err != nil {
		errs = append(errs, err)
	} else {
		errs = append(errs, checkDetails(e, d)...)
	}
	if err := VerifyDesignated(out.Requirements, e); err != nil {
		errs = append(errs, err)
	}
	if err := VerifyEntitlements(out.Entitlements); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func checkDetails(e Expectation, d Details) []error {
	var errs []error
	switch {
	case d.Identifier == "":
		errs = append(errs, fail(CheckIdentifier, "no Identifier= line"))
	case d.Identifier != e.Identifier:
		errs = append(errs, fail(CheckIdentifier, "got %s, want %s", strconv.Quote(d.Identifier), strconv.Quote(e.Identifier)))
	}
	switch {
	case d.Flags == "":
		errs = append(errs, fail(CheckRuntime, "no flags= value on the CodeDirectory line"))
	case !d.Runtime:
		errs = append(errs, fail(CheckRuntime, "flags %s do not include runtime", strconv.Quote(d.Flags)))
	}
	switch {
	case d.TeamIdentifier == "":
		errs = append(errs, fail(CheckTeam, "no TeamIdentifier= line"))
	case d.TeamIdentifier != e.Team:
		errs = append(errs, fail(CheckTeam, "got %s, want %s", strconv.Quote(d.TeamIdentifier), strconv.Quote(e.Team)))
	}
	if !d.HasTimestamp {
		errs = append(errs, fail(CheckTimestamp, "no Timestamp= line (a secure timestamp); a Signed Time= line does not count"))
	}
	return errs
}
