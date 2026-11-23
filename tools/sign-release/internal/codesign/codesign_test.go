package codesign

import (
	"errors"
	"strings"
	"testing"

	"github.com/abigotado/agent-clis/tools/sign-release/internal/config"
)

// The fixtures follow the shapes `codesign` prints on macOS 26. The ad hoc and
// Apple-signed texts were captured from a throwaway binary and /usr/bin/true;
// the Developer ID text is the same format with the identity lines of a
// leaf-pinned signature. The certificate hash is a placeholder, never a real
// one.
const (
	testSHA1  = "0123456789abcdef0123456789abcdef01234567"
	testID    = "dev.abigotado.youtrack-agent-cli"
	testTeam  = "5XCS9FFW5Z"
	goldenReq = `=designated => identifier "dev.abigotado.youtrack-agent-cli" and anchor apple generic and certificate leaf = H"0123456789abcdef0123456789abcdef01234567"`
	goodDR    = `designated => identifier "dev.abigotado.youtrack-agent-cli" and anchor apple generic and certificate leaf = H"0123456789abcdef0123456789abcdef01234567"` + "\n"

	execLine = "Executable=/private/tmp/sign/youtrack-agent-cli\n"

	goodDetails = execLine + `Identifier=dev.abigotado.youtrack-agent-cli
Format=Mach-O thin (arm64)
CodeDirectory v=20500 size=3730 flags=0x10000(runtime) hashes=111+2 location=embedded
Hash type=sha256 size=32
CandidateCDHash sha256=484ac453247fd10c40e068ecc97754c1cab9137f
CandidateCDHashFull sha256=484ac453247fd10c40e068ecc97754c1cab9137f94a86ce475939db981026c69
Hash choices=sha256
CMSDigest=94a86ce475939db981026c69484ac453247fd10c40e068ecc97754c1cab9137f
CMSDigestType=2
CDHash=484ac453247fd10c40e068ecc97754c1cab9137f
Signature size=9013
Authority=Developer ID Application: Example Person (5XCS9FFW5Z)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
Timestamp=19 Nov 2026 at 10:15:42
Info.plist=not bound
TeamIdentifier=5XCS9FFW5Z
Runtime Version=26.2.0
Sealed Resources=none
Internal requirements count=1 size=172
`
)

func expectation() Expectation {
	return Expectation{Identifier: testID, Team: testTeam, CertSHA1: testSHA1}
}

func TestRequirementGolden(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		sha1 string
	}{
		{name: "lowercase input", sha1: testSHA1},
		{name: "uppercase input is lowered", sha1: strings.ToUpper(testSHA1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := Expectation{Identifier: testID, Team: testTeam, CertSHA1: tt.sha1}
			got, err := e.Requirement()
			if err != nil {
				t.Fatalf("Requirement() error = %v", err)
			}
			if got != goldenReq {
				t.Errorf("Requirement() =\n%s\nwant\n%s", got, goldenReq)
			}
		})
	}
}

func TestRequirementRefusesUnsafeInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		e    Expectation
	}{
		{name: "quote in identifier", e: Expectation{Identifier: `dev.x" or anchor apple`, Team: testTeam, CertSHA1: testSHA1}},
		{name: "empty cert hash", e: Expectation{Identifier: testID, Team: testTeam}},
		{name: "short cert hash", e: Expectation{Identifier: testID, Team: testTeam, CertSHA1: "abc"}},
		{name: "bad team", e: Expectation{Identifier: testID, Team: "team", CertSHA1: testSHA1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, err := tt.e.Requirement(); err == nil {
				t.Errorf("Requirement() = %q, error = nil", got)
			}
		})
	}
}

func TestExpectationFor(t *testing.T) {
	t.Parallel()

	cli := config.CLI{Identifier: testID, Team: testTeam, CertSHA1: testSHA1}
	got, err := ExpectationFor("youtrack-agent-cli", cli)
	if err != nil {
		t.Fatalf("ExpectationFor() error = %v", err)
	}
	if got != expectation() {
		t.Errorf("ExpectationFor() = %+v", got)
	}

	cli.CertSHA1 = ""
	_, err = ExpectationFor("youtrack-agent-cli", cli)
	var nre *config.NotReadyError
	if !errors.As(err, &nre) {
		t.Errorf("ExpectationFor(empty cert_sha1) error = %v, want a *config.NotReadyError", err)
	}
}

func TestParseDetails(t *testing.T) {
	t.Parallel()

	adhoc := execLine + `Identifier=dev.example.probe
Format=Mach-O thin (arm64)
CodeDirectory v=20500 size=3730 flags=0x10002(adhoc,runtime) hashes=111+2 location=embedded
Signature=adhoc
Info.plist=not bound
TeamIdentifier=not set
Runtime Version=26.2.0
Sealed Resources=none
Internal requirements count=0 size=12
`
	apple := `Executable=/usr/bin/true
Identifier=com.apple.true
Format=Mach-O universal (x86_64 arm64e)
CodeDirectory v=20400 size=231 flags=0x0(none) hashes=2+2 location=embedded
Platform identifier=26
Signature size=4567
Authority=macOS Software Signing
Authority=Apple Code Signing Certification Authority
Authority=Apple Root CA
Signed Time=31 Jul 2026 at 22:52:35
Info.plist=not bound
TeamIdentifier=not set
Sealed Resources=none
Internal requirements count=1 size=64
`
	tests := []struct {
		name   string
		output string
		want   Details
	}{
		{
			name:   "developer id with runtime and timestamp",
			output: goodDetails,
			want: Details{
				Identifier: testID, Flags: "0x10000(runtime)", FlagNames: []string{"runtime"}, Runtime: true,
				TeamIdentifier: testTeam, HasTimestamp: true, CDHash: "484ac453247fd10c40e068ecc97754c1cab9137f",
			},
		},
		{
			name:   "ad hoc with runtime, no timestamp",
			output: adhoc,
			want: Details{
				Identifier: "dev.example.probe", Flags: "0x10002(adhoc,runtime)", FlagNames: []string{"adhoc", "runtime"}, Runtime: true,
				TeamIdentifier: "not set",
			},
		},
		{
			name:   "apple binary has Signed Time and no timestamp",
			output: apple,
			want: Details{
				Identifier: "com.apple.true", Flags: "0x0(none)", FlagNames: []string{"none"}, TeamIdentifier: "not set",
			},
		},
		{
			name:   "windows line endings",
			output: strings.ReplaceAll(goodDetails, "\n", "\r\n"),
			want: Details{
				Identifier: testID, Flags: "0x10000(runtime)", FlagNames: []string{"runtime"}, Runtime: true,
				TeamIdentifier: testTeam, HasTimestamp: true, CDHash: "484ac453247fd10c40e068ecc97754c1cab9137f",
			},
		},
		{
			name:   "Timestamp and Signed Time together",
			output: goodDetails + "Signed Time=19 Nov 2026 at 10:15:40\n",
			want: Details{
				Identifier: testID, TeamIdentifier: testTeam, HasTimestamp: true, CDHash: "484ac453247fd10c40e068ecc97754c1cab9137f", Flags: "0x10000(runtime)", FlagNames: []string{"runtime"}, Runtime: true,
			},
		},
		{
			name:   "runtime name without the runtime bit",
			output: strings.Replace(goodDetails, "flags=0x10000(runtime)", "flags=0x0(runtime)", 1),
			want: Details{
				Identifier: testID, TeamIdentifier: testTeam, HasTimestamp: true, CDHash: "484ac453247fd10c40e068ecc97754c1cab9137f", Flags: "0x0(runtime)", FlagNames: []string{"runtime"},
			},
		},
		{
			name:   "runtime bit without the runtime name",
			output: strings.Replace(goodDetails, "flags=0x10000(runtime)", "flags=0x10000(none)", 1),
			want: Details{
				Identifier: testID, TeamIdentifier: testTeam, HasTimestamp: true, CDHash: "484ac453247fd10c40e068ecc97754c1cab9137f", Flags: "0x10000(none)", FlagNames: []string{"none"},
			},
		},
		{
			name:   "runtime is matched as a whole name",
			output: strings.Replace(goodDetails, "flags=0x10000(runtime)", "flags=0x10000(noruntime,runtime-x)", 1),
			want: Details{
				Identifier: testID, TeamIdentifier: testTeam, HasTimestamp: true, CDHash: "484ac453247fd10c40e068ecc97754c1cab9137f", Flags: "0x10000(noruntime,runtime-x)", FlagNames: []string{"noruntime", "runtime-x"},
			},
		},
		{name: "empty", output: "", want: Details{}},
		{
			name:   "an empty Timestamp= value is not a timestamp",
			output: "Timestamp=\n",
			want:   Details{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseDetails(tt.output)
			if err != nil {
				t.Fatalf("ParseDetails() error = %v", err)
			}
			if got.Identifier != tt.want.Identifier || got.Flags != tt.want.Flags || got.Runtime != tt.want.Runtime ||
				got.TeamIdentifier != tt.want.TeamIdentifier || got.HasTimestamp != tt.want.HasTimestamp || got.CDHash != tt.want.CDHash ||
				strings.Join(got.FlagNames, ",") != strings.Join(tt.want.FlagNames, ",") {
				t.Errorf("ParseDetails() =\n%+v\nwant\n%+v", got, tt.want)
			}
		})
	}
}

func TestParseDetailsRefusesBareCarriageReturn(t *testing.T) {
	t.Parallel()

	_, err := ParseDetails(strings.ReplaceAll(goodDetails, "\n", "\r"))
	assertCheck(t, err, CheckOutput)
}

func TestParseDetailsRefusesRepeatedFields(t *testing.T) {
	t.Parallel()

	for _, line := range []string{
		"Identifier=other.id",
		"TeamIdentifier=AAAAAAAAAA",
		"Timestamp=1 Jan 2026 at 00:00:00",
		"CDHash=00",
		"CodeDirectory v=20500 size=1 flags=0x0(none) hashes=1+1 location=embedded",
	} {
		t.Run(line[:strings.IndexAny(line, "= ")], func(t *testing.T) {
			t.Parallel()
			_, err := ParseDetails(goodDetails + line + "\n")
			assertCheck(t, err, CheckOutput)
		})
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()

	good := Outputs{Details: goodDetails, Requirements: execLine + goodDR, Entitlements: execLine}
	with := func(edit func(*Outputs)) Outputs {
		o := good
		edit(&o)
		return o
	}
	tests := []struct {
		name string
		out  Outputs
		want []Check // empty means the outputs pass
	}{
		{name: "everything correct", out: good},
		{name: "plain empty entitlements output", out: with(func(o *Outputs) { o.Entitlements = "" })},
		{
			name: "missing runtime flag",
			out: with(func(o *Outputs) {
				o.Details = strings.Replace(goodDetails, "flags=0x10000(runtime)", "flags=0x0(none)", 1)
			}),
			want: []Check{CheckRuntime},
		},
		{
			name: "runtime only in the hex, not named",
			out: with(func(o *Outputs) {
				o.Details = strings.Replace(goodDetails, "flags=0x10000(runtime)", "flags=0x10000()", 1)
			}),
			want: []Check{CheckRuntime},
		},
		{
			name: "no flags value",
			out: with(func(o *Outputs) {
				o.Details = strings.Replace(goodDetails, "flags=0x10000(runtime) ", "", 1)
			}),
			want: []Check{CheckRuntime},
		},
		{
			name: "wrong team",
			out: with(func(o *Outputs) {
				o.Details = strings.Replace(goodDetails, "TeamIdentifier=5XCS9FFW5Z", "TeamIdentifier=AAAAAAAAAA", 1)
			}),
			want: []Check{CheckTeam},
		},
		{
			name: "team not set",
			out: with(func(o *Outputs) {
				o.Details = strings.Replace(goodDetails, "TeamIdentifier=5XCS9FFW5Z", "TeamIdentifier=not set", 1)
			}),
			want: []Check{CheckTeam},
		},
		{
			name: "no timestamp",
			out: with(func(o *Outputs) {
				o.Details = strings.Replace(goodDetails, "Timestamp=19 Nov 2026 at 10:15:42\n", "", 1)
			}),
			want: []Check{CheckTimestamp},
		},
		{
			name: "Signed Time instead of Timestamp",
			out: with(func(o *Outputs) {
				o.Details = strings.Replace(goodDetails, "Timestamp=19 Nov 2026 at 10:15:42", "Signed Time=19 Nov 2026 at 10:15:42", 1)
			}),
			want: []Check{CheckTimestamp},
		},
		{
			name: "wrong identifier",
			out: with(func(o *Outputs) {
				o.Details = strings.Replace(goodDetails, "Identifier=dev.abigotado.youtrack-agent-cli", "Identifier=dev.abigotado.other", 1)
			}),
			want: []Check{CheckIdentifier},
		},
		{
			name: "no identifier",
			out: with(func(o *Outputs) {
				o.Details = strings.Replace(goodDetails, "Identifier=dev.abigotado.youtrack-agent-cli\n", "", 1)
			}),
			want: []Check{CheckIdentifier},
		},
		{
			name: "identifier with a trailing space",
			out: with(func(o *Outputs) {
				o.Details = strings.Replace(goodDetails, "Identifier=dev.abigotado.youtrack-agent-cli", "Identifier=dev.abigotado.youtrack-agent-cli ", 1)
			}),
			want: []Check{CheckIdentifier},
		},
		{
			name: "entitlements present",
			out: with(func(o *Outputs) {
				o.Entitlements = execLine + "[Dict]\n\t[Key] com.apple.security.cs.allow-jit\n\t[Value]\n\t\t[Bool] true\n"
			}),
			want: []Check{CheckEntitlements},
		},
		{
			name: "implicit designated requirement",
			out: with(func(o *Outputs) {
				o.Requirements = `# designated => cdhash H"484ac453247fd10c40e068ecc97754c1cab9137f"` + "\n"
			}),
			want: []Check{CheckDesignated},
		},
		{
			name: "several failures are all named",
			out: Outputs{
				Details:      strings.Replace(strings.Replace(goodDetails, "flags=0x10000(runtime)", "flags=0x0(none)", 1), "TeamIdentifier=5XCS9FFW5Z", "TeamIdentifier=AAAAAAAAAA", 1),
				Requirements: "",
				Entitlements: "[Dict]\n[Key] x\n",
			},
			want: []Check{CheckRuntime, CheckTeam, CheckDesignated, CheckEntitlements},
		},
		{
			name: "repeated identifier in the details",
			out:  with(func(o *Outputs) { o.Details = goodDetails + "Identifier=dev.abigotado.youtrack-agent-cli\n" }),
			want: []Check{CheckOutput},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := Verify(expectation(), tt.out)
			if len(tt.want) == 0 {
				if err != nil {
					t.Fatalf("Verify() error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("Verify() error = nil")
			}
			for _, c := range tt.want {
				if !strings.Contains(err.Error(), "codesign check "+string(c)+" failed") {
					t.Errorf("error does not name check %s: %v", c, err)
				}
			}
			if got := strings.Count(err.Error(), "codesign check "); got != len(tt.want) {
				t.Errorf("error names %d checks, want %d: %v", got, len(tt.want), err)
			}
			assertCheck(t, err, tt.want[0])
		})
	}
}

func TestVerifyRefusesAnUnusableExpectation(t *testing.T) {
	t.Parallel()

	e := expectation()
	e.CertSHA1 = ""
	err := Verify(e, Outputs{Details: goodDetails, Requirements: goodDR})
	if err == nil {
		t.Fatal("Verify() error = nil")
	}
	var ce *CheckError
	if errors.As(err, &ce) {
		t.Errorf("an unusable expectation is not a failed check: %v", err)
	}
}

func TestVerifyDesignated(t *testing.T) {
	t.Parallel()

	upperHex := strings.ToUpper(testSHA1)
	tests := []struct {
		name    string
		output  string
		wantErr bool
	}{
		{name: "exact", output: goodDR},
		{name: "with the stderr header", output: execLine + goodDR},
		{name: "no trailing newline", output: strings.TrimSuffix(goodDR, "\n")},
		{name: "windows line endings", output: strings.TrimSuffix(goodDR, "\n") + "\r\n"},
		{
			name:   "uppercase hex",
			output: strings.Replace(goodDR, testSHA1, upperHex, 1),
		},
		{
			name:   "mixed-case hex",
			output: strings.Replace(goodDR, testSHA1, "0123456789ABCDEF0123456789abcdef01234567", 1),
		},
		{
			name:    "lowercase h in the hash literal",
			output:  strings.Replace(goodDR, `H"`, `h"`, 1),
			wantErr: true,
		},
		{
			name:    "39-character hex",
			output:  strings.Replace(goodDR, testSHA1, testSHA1[:39], 1),
			wantErr: true,
		},
		{
			name:    "bare carriage return between lines",
			output:  strings.TrimSuffix(goodDR, "\n") + "\r" + goodDR,
			wantErr: true,
		},
		{
			name:    "a second Executable= line is not a header",
			output:  execLine + execLine + goodDR,
			wantErr: true,
		},
		{
			name:    "a header without an absolute path is not dropped",
			output:  "Executable=relative\n" + goodDR,
			wantErr: true,
		},
		{name: "empty", output: "", wantErr: true},
		{name: "header only", output: execLine, wantErr: true},
		{
			name:    "implicit designated line",
			output:  `# designated => cdhash H"484ac453247fd10c40e068ecc97754c1cab9137f"` + "\n",
			wantErr: true,
		},
		{
			name:    "implicit line after the explicit one",
			output:  goodDR + `# designated => cdhash H"484ac453247fd10c40e068ecc97754c1cab9137f"` + "\n",
			wantErr: true,
		},
		{
			name:    "implicit line before the explicit one",
			output:  `# designated => cdhash H"484ac453247fd10c40e068ecc97754c1cab9137f"` + "\n" + goodDR,
			wantErr: true,
		},
		{
			name:    "the same line twice",
			output:  goodDR + goodDR,
			wantErr: true,
		},
		{
			name:    "extra clause",
			output:  strings.TrimSuffix(goodDR, "\n") + ` and certificate 1[field.1.2.840.113635.100.6.2.6] exists` + "\n",
			wantErr: true,
		},
		{
			name:    "or clause",
			output:  strings.TrimSuffix(goodDR, "\n") + ` or cdhash H"484ac453247fd10c40e068ecc97754c1cab9137f"` + "\n",
			wantErr: true,
		},
		{
			name:    "extra requirement type",
			output:  goodDR + `host => anchor apple` + "\n",
			wantErr: true,
		},
		{
			name:    "library requirement alone",
			output:  `library => anchor apple` + "\n",
			wantErr: true,
		},
		{
			name:    "different hash",
			output:  strings.Replace(goodDR, "0123456789abcdef", "fedcba9876543210", 1),
			wantErr: true,
		},
		{
			name:    "different identifier",
			output:  strings.Replace(goodDR, "youtrack-agent-cli", "other", 1),
			wantErr: true,
		},
		{
			name:    "identifier case is exact",
			output:  strings.Replace(goodDR, "dev.abigotado", "dev.Abigotado", 1),
			wantErr: true,
		},
		{
			name:    "anchor apple instead of apple generic",
			output:  strings.Replace(goodDR, "anchor apple generic", "anchor apple", 1),
			wantErr: true,
		},
		{
			name:    "keyword case is exact",
			output:  strings.Replace(goodDR, "anchor apple generic", "ANCHOR APPLE GENERIC", 1),
			wantErr: true,
		},
		{
			name:    "double space",
			output:  strings.Replace(goodDR, "and anchor", "and  anchor", 1),
			wantErr: true,
		},
		{
			name:    "leading space",
			output:  " " + goodDR,
			wantErr: true,
		},
		{
			name:    "leaf pinned by the hash of a longer value",
			output:  strings.Replace(goodDR, testSHA1, testSHA1+"00", 1),
			wantErr: true,
		},
		{
			name:    "the Apple-signed requirement",
			output:  `designated => identifier "com.apple.true" and anchor apple` + "\n",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := VerifyDesignated(tt.output, expectation())
			if (err != nil) != tt.wantErr {
				t.Fatalf("VerifyDesignated() error = %v, wantErr %t", err, tt.wantErr)
			}
			if err != nil {
				assertCheck(t, err, CheckDesignated)
			}
		})
	}
}

func TestVerifyEntitlements(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		output  string
		wantErr bool
	}{
		{name: "empty", output: ""},
		{name: "newline only", output: "\n"},
		{name: "header only", output: execLine},
		{name: "header and blank lines", output: execLine + "\n\n"},
		{name: "empty dictionary", output: "[Dict]\n"},
		{name: "empty xml dictionary", output: `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict/></plist>`},
		{name: "canonical empty plist on separate lines", output: "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"https://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict/>\n</plist>\n"},
		{name: "empty xml dictionary, long form is not canonical", output: `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict></dict></plist>`, wantErr: true},
		{name: "xml with a non-dict root and a comment holding a dict", output: `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><array/><!-- <dict/> --></plist>`, wantErr: true},
		{name: "empty dictionary with text after it", output: "[Dict]\nextra\n", wantErr: true},
		{name: "empty dictionary twice", output: "[Dict]\n[Dict]\n", wantErr: true},
		{name: "output separated by CR alone", output: "[Dict]\r\tx\r", wantErr: true},
		{name: "CR alone after an empty dictionary", output: "[Dict]\r", wantErr: true},
		{name: "CR alone and nothing else", output: "\r", wantErr: true},
		{name: "empty dictionary with CRLF", output: "[Dict]\r\n"},
		{name: "executable header without an absolute path", output: "Executable=relative\n", wantErr: true},
		{name: "second executable header", output: execLine + execLine, wantErr: true},
		{name: "dictionary with a key", output: "[Dict]\n\t[Key] com.apple.security.cs.allow-jit\n\t[Value]\n\t\t[Bool] true\n", wantErr: true},
		{name: "dictionary with a key after the header", output: execLine + "[Dict]\n\t[Key] com.apple.security.get-task-allow\n\t[Value]\n\t\t[Bool] true\n", wantErr: true},
		{
			name:    "xml with a key",
			output:  `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>com.apple.security.cs.allow-jit</key><true/></dict></plist>`,
			wantErr: true,
		},
		{name: "xml key mixed with an empty dict", output: `<?xml version="1.0"?><plist><dict/><dict><key>x</key><true/></dict></plist>`, wantErr: true},
		{name: "unknown format fails closed", output: "\xfa\xde\x71\x72 binary blob", wantErr: true},
		{name: "free text fails closed", output: "none", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := VerifyEntitlements(tt.output)
			if (err != nil) != tt.wantErr {
				t.Fatalf("VerifyEntitlements() error = %v, wantErr %t", err, tt.wantErr)
			}
			if err != nil {
				assertCheck(t, err, CheckEntitlements)
			}
		})
	}
}

func assertCheck(t *testing.T, err error, want Check) {
	t.Helper()
	var ce *CheckError
	if !errors.As(err, &ce) {
		t.Fatalf("error = %v, want a *CheckError", err)
	}
	if ce.Check != want {
		t.Fatalf("check = %s, want %s (%v)", ce.Check, want, err)
	}
}

// TestExpressionIsTheBareRequirement pins the form `codesign --verify -R=` can
// parse, and that Requirement is built from it so the two cannot drift.
func TestExpressionIsTheBareRequirement(t *testing.T) {
	t.Parallel()

	const goldenExpr = `identifier "dev.abigotado.youtrack-agent-cli" and anchor apple generic and certificate leaf = H"0123456789abcdef0123456789abcdef01234567"`
	e := Expectation{Identifier: testID, Team: testTeam, CertSHA1: strings.ToUpper(testSHA1)}
	got, err := e.Expression()
	if err != nil || got != goldenExpr {
		t.Fatalf("Expression() = %q, %v; want %q", got, err, goldenExpr)
	}
	req, err := e.Requirement()
	if err != nil || req != "=designated => "+got {
		t.Fatalf("Requirement() = %q, %v; want it built from the expression", req, err)
	}
	if _, err := (Expectation{Identifier: testID, Team: testTeam}).Expression(); err == nil {
		t.Fatal("Expression() accepted an empty certificate hash")
	}
}
