package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/macho"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/abigotado/agent-clis/tools/sign-release/internal/runner"
)

const goldenRequirement = `=designated => identifier "dev.abigotado.youtrack-agent-cli" and anchor apple generic and certificate leaf = H"7b35c316aa0000000000000000000000000a8531"`

func exitErr(code int) error { return &runner.ExitError{Program: "fake", Code: code} }

// postRun is the commands Finish started, without the ten of Run.
func (p *pub) postRun() [][]string { return p.s.calls[10:] }

func TestFinishHappyPathCommandsAreExact(t *testing.T) {
	p := newPub(t)
	got, err := p.finish(goodAnswers)
	if err != nil {
		t.Fatalf("Finish() error = %v", err)
	}
	work := p.s.params.WorkDir
	bins := [2]string{filepath.Join(work, "amd64", testCLI), filepath.Join(work, "arm64", testCLI)}
	var want [][]string
	want = append(want, []string{testGH, "api", "--hostname", "github.com", "repos/" + testRepo + "/immutable-releases"})
	for _, bin := range bins {
		want = append(want,
			[]string{CodesignPath, "--force", "--sign", testCertSHA, "--options", "runtime", "--timestamp",
				"--identifier", testID, "--requirements", goldenRequirement, bin},
			[]string{CodesignPath, "--verify", "--strict", "-R=" + goldenExpression, bin},
			[]string{CodesignPath, "-dvv", bin},
			[]string{CodesignPath, "-d", "-r-", bin},
			[]string{CodesignPath, "-d", "--entitlements", "-", bin},
		)
	}
	signed := filepath.Join(work, "signed")
	ref := []string{testGH, "api", "--hostname", "github.com", "repos/" + testRepo + "/git/ref/tags/" + testTag}
	rel := []string{testGH, "api", "--hostname", "github.com", "repos/" + testRepo + "/releases/4242"}
	want = append(want,
		[]string{testGH, "api", "--hostname", "github.com", "repos/" + testRepo + "/git/commits/" + testCommit},
		[]string{testGH, "release", "upload", testTag,
			filepath.Join(signed, p.s.darwin[0]), filepath.Join(signed, p.s.darwin[1]), filepath.Join(signed, p.s.checksum),
			"--clobber", "--repo", "github.com/" + testRepo},
		rel, ref, ref,
		[]string{testGH, "api", "--hostname", "github.com", "-X", "PATCH", "repos/" + testRepo + "/releases/4242", "--input", "-"},
		rel, ref,
	)
	if gotCalls := p.postRun(); !slices.EqualFunc(gotCalls, want, slices.Equal[[]string]) {
		t.Fatalf("commands:\n got %q\nwant %q", gotCalls, want)
	}
	if len(p.patches) != 1 || string(p.patches[0]) != `{"draft":false}` {
		t.Fatalf("PATCH bodies = %q, want exactly one `{\"draft\":false}`", p.patches)
	}
	if got.Tag != testTag || got.ReleaseID != testRelID || got.Commit != testCommit || len(got.Assets) != 3 {
		t.Fatalf("Published = %+v", got)
	}
	for _, a := range got.Assets {
		sum := sha256.Sum256(p.s.files[a.Name])
		if a.SHA256 != hex.EncodeToString(sum[:]) {
			t.Fatalf("asset %s reports sha256 %s, uploaded %x", a.Name, a.SHA256, sum)
		}
	}
}

func TestFinishUploadsSignedRepackagedArchives(t *testing.T) {
	p := newPub(t)
	if _, err := p.finish(goodAnswers); err != nil {
		t.Fatalf("Finish() error = %v", err)
	}
	mtime := time.Date(2026, 11, 20, 10, 11, 12, 0, time.UTC)
	for i, cpu := range []macho.Cpu{macho.CpuAmd64, macho.CpuArm64} {
		data := p.s.files[p.s.darwin[i]]
		files, err := extractArchive(data, []string{"LICENSE", "README.md", testCLI}, DefaultLimits())
		if err != nil {
			t.Fatalf("extract uploaded %s: %v", p.s.darwin[i], err)
		}
		if want := resign(thinBinary(cpu)); !bytes.Equal(files[testCLI], want) {
			t.Fatalf("%s holds an unsigned or foreign binary", p.s.darwin[i])
		}
		if string(files["LICENSE"]) != "license\n" || string(files["README.md"]) != "readme\n" {
			t.Fatalf("%s changed a non-binary member", p.s.darwin[i])
		}
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("gzip: %v", err)
		}
		if !zr.ModTime.IsZero() || zr.Name != "" || zr.Comment != "" || zr.OS != 255 {
			t.Fatalf("gzip header = %+v, want zero time, no name, OS 255", zr.Header)
		}
		tr := tar.NewReader(zr)
		var names []string
		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("tar: %v", err)
			}
			names = append(names, hdr.Name)
			wantMode := int64(0o644)
			if hdr.Name == testCLI {
				wantMode = 0o755
			}
			if hdr.Mode != wantMode || hdr.Uid != 0 || hdr.Gid != 0 || hdr.Uname != "" || hdr.Gname != "" ||
				!hdr.ModTime.Equal(mtime) || hdr.Format != tar.FormatUSTAR {
				t.Fatalf("header of %s = %+v, want mode %o, uid/gid 0, no names, mtime %v, USTAR", hdr.Name, hdr, wantMode, mtime)
			}
		}
		if !slices.Equal(names, []string{"LICENSE", "README.md", testCLI}) {
			t.Fatalf("members = %v, want the archive_entries order", names)
		}
	}
	want := sumLine(p.s.darwin[0], p.s.files[p.s.darwin[0]]) + sumLine(p.s.darwin[1], p.s.files[p.s.darwin[1]])
	if got := string(p.s.files[p.s.checksum]); got != want {
		t.Fatalf("checksums-darwin.txt = %q, want %q", got, want)
	}
	if _, err := parseChecksums(p.s.files[p.s.checksum], p.s.darwin[:]); err != nil {
		t.Fatalf("the new checksums file does not parse: %v", err)
	}
}

func TestRepackageIsDeterministicAcrossRuns(t *testing.T) {
	var uploads [2]map[string][]byte
	for i := range uploads {
		p := newPub(t)
		if _, err := p.finish(goodAnswers); err != nil {
			t.Fatalf("Finish() run %d error = %v", i, err)
		}
		uploads[i] = map[string][]byte{}
		for _, name := range []string{p.s.darwin[0], p.s.darwin[1], p.s.checksum} {
			uploads[i][name] = p.s.files[name]
		}
	}
	for name, first := range uploads[0] {
		if !bytes.Equal(first, uploads[1][name]) {
			t.Fatalf("%s differs between two runs of the same release", name)
		}
	}
}

// TestBuildArchiveGolden pins the bytes of one fixed input. The compressed
// stream is that of this Go toolchain's compress/flate: a toolchain that
// changes it moves this digest, and the bump is a deliberate edit that says why.
func TestBuildArchiveGolden(t *testing.T) {
	files := map[string][]byte{"LICENSE": []byte("license\n"), "README.md": []byte("readme\n"), "tool": []byte("binary bytes\n")}
	mtime := time.Date(2026, 11, 20, 10, 11, 12, 0, time.UTC)
	first, err := buildArchive([]string{"LICENSE", "README.md", "tool"}, "tool", files, mtime)
	if err != nil {
		t.Fatalf("buildArchive() error = %v", err)
	}
	second, err := buildArchive([]string{"LICENSE", "README.md", "tool"}, "tool", files, mtime)
	if err != nil {
		t.Fatalf("buildArchive() error = %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("two builds of the same input differ")
	}
	sum := sha256.Sum256(first)
	const golden = "bd7e868bf1c163101390075c8f11869009c6c69ce161a51474121bba2297be17"
	if got := hex.EncodeToString(sum[:]); got != golden {
		t.Fatalf("sha256 of the archive = %s, want %s", got, golden)
	}
	other, err := buildArchive([]string{"LICENSE", "README.md", "tool"}, "tool", files, mtime.Add(time.Second))
	if err != nil {
		t.Fatalf("buildArchive() error = %v", err)
	}
	if bytes.Equal(first, other) {
		t.Fatal("the archive does not depend on the mtime")
	}
}

func TestParseCommitTime(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string // empty means refused
	}{
		{"utc seconds", "2026-11-20T10:11:12Z", "2026-11-20T10:11:12Z"},
		{"offset is not UTC", "2026-11-20T12:11:12+02:00", ""},
		{"zero offset spelled out", "2026-11-20T10:11:12+00:00", ""},
		{"fraction", "2026-11-20T10:11:12.5Z", ""},
		{"lowercase z", "2026-11-20T10:11:12z", ""},
		{"space separator", "2026-11-20 10:11:12Z", ""},
		{"date only", "2026-11-20", ""},
		{"empty", "", ""},
		{"epoch", "1970-01-01T00:00:00Z", ""},
		{"leading space", " 2026-11-20T10:11:12Z", ""},
		{"trailing newline", "2026-11-20T10:11:12Z\n", ""},
		{"impossible date", "2026-13-40T10:11:12Z", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCommitTime(tt.in)
			if tt.want == "" {
				wantRefusal(t, err, StepRepackage, "commit date")
				return
			}
			if err != nil || got.Format(time.RFC3339) != tt.want {
				t.Fatalf("parseCommitTime(%q) = %v, %v; want %s", tt.in, got, err, tt.want)
			}
		})
	}
}

func TestFinishReadsTheCommitDateOfTheTaggedCommit(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(p *pub)
		substr string
	}{
		{"commit answers for another sha", func(p *pub) { p.commitSHA = otherCommit }, "commit read answered"},
		{"non-UTC date", func(p *pub) { p.commitDate = "2026-11-20T12:11:12+02:00" }, "commit date"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newPub(t)
			tt.mutate(p)
			_, err := p.finish(goodAnswers)
			wantRefusal(t, err, StepRepackage, tt.substr)
			wantNothingPublished(t, p)
		})
	}
}

func wantNothingPublished(t *testing.T, p *pub) {
	t.Helper()
	if n := p.uploadCount(); n != 0 {
		t.Fatalf("%d upload commands ran, want none", n)
	}
	wantNoPatch(t, p)
}

func wantNoPatch(t *testing.T, p *pub) {
	t.Helper()
	if n := p.patchCount(); n != 0 {
		t.Fatalf("%d PATCH commands ran, want none", n)
	}
}

func TestFinishVerifyFailsClosed(t *testing.T) {
	good := goodDetailsText("/x")
	tests := []struct {
		name   string
		mutate func(p *pub)
		step   Step
		substr string
	}{
		{"codesign --verify exits non-zero", func(p *pub) { p.verifyErr = exitErr(1) }, StepVerify, "codesign verify"},
		{"wrong team", func(p *pub) {
			p.detailsOut = strings.Replace(good, "TeamIdentifier="+testTeam, "TeamIdentifier=EVILTEAM00", 1)
		}, StepVerify, "team-identifier"},
		{"wrong identifier", func(p *pub) {
			p.detailsOut = strings.Replace(good, "Identifier="+testID, "Identifier=com.evil.tool", 1)
		}, StepVerify, "identifier"},
		{"no hardened runtime", func(p *pub) {
			p.detailsOut = strings.Replace(good, "flags=0x10000(runtime)", "flags=0x0(none)", 1)
		}, StepVerify, "hardened-runtime-flag"},
		{"no secure timestamp", func(p *pub) {
			p.detailsOut = strings.Replace(good, "Timestamp=Nov 23, 2026 at 10:00:00\n", "Signed Time=Nov 23, 2026 at 10:00:00\n", 1)
		}, StepVerify, "secure-timestamp"},
		{"entitlements present", func(p *pub) {
			p.entitlements = "<?xml version=\"1.0\"?><plist><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>"
		}, StepVerify, "entitlements-empty"},
		{"implicit designated requirement", func(p *pub) {
			p.requirements = "# " + p.requirements
		}, StepVerify, "designated-requirement"},
		{"designated requirement pins another leaf", func(p *pub) {
			p.requirements = strings.Replace(p.requirements, "7b35c316", "00000000", 1)
		}, StepVerify, "designated-requirement"},
		{"no designated requirement at all", func(p *pub) { p.requirements = "" }, StepVerify, "designated-requirement"},
		{"codesign sign fails", func(p *pub) { p.signErr = exitErr(1) }, StepSign, "codesign sign"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newPub(t)
			tt.mutate(p)
			_, err := p.finish(goodAnswers)
			wantRefusal(t, err, tt.step, tt.substr)
			wantNothingPublished(t, p)
		})
	}
}

// TestFinishRefusesASwappedBinary is R14: a signing step that changed more than
// the signature leaves a different machodigest stream, and nothing is uploaded.
func TestFinishRefusesASwappedBinary(t *testing.T) {
	p := newPub(t)
	p.signFn = swapText
	_, err := p.finish(goodAnswers)
	wantRefusal(t, err, StepVerify, "differs from the attested stream")
	wantNothingPublished(t, p)
}

func TestFinishRefusesABinaryChangedBeforeSigning(t *testing.T) {
	p := newPub(t)
	res, err := p.s.run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	b, err := os.ReadFile(res.AMD64.BinaryPath)
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	if err := os.WriteFile(res.AMD64.BinaryPath, swapText(b), 0o600); err != nil {
		t.Fatalf("write binary: %v", err)
	}
	c, _ := p.console(goodAnswers)
	_, err = Finish(t.Context(), p.s, p.s.params, res, c)
	wantRefusal(t, err, StepSign, "no longer matches the attested")
	if n := p.codesignCount(); n != 0 {
		t.Fatalf("%d codesign commands ran on a binary that was not the attested one", n)
	}
	wantNothingPublished(t, p)
}

func TestFinishRequiresImmutableReleases(t *testing.T) {
	tests := []struct {
		name string
		out  string
		err  error
	}{
		{"setting disabled", `{"enabled":false}`, nil},
		{"answer without enabled", `{"enforced_by_owner":false}`, nil},
		{"enabled is a string", `{"enabled":"true"}`, nil},
		{"404 not found", `{"message":"Not Found"}`, exitErr(1)},
		{"403 token lacks the permission", `{"message":"Resource not accessible by personal access token"}`, exitErr(1)},
		{"not JSON", `<html>`, nil},
		{"empty answer", ``, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newPub(t)
			p.immutableOut, p.immutableErr = tt.out, tt.err
			_, err := p.finish(goodAnswers)
			wantRefusal(t, err, StepImmutable, "immutable releases")
			var ref *Refusal
			if !errors.As(err, &ref) || !strings.Contains(ref.Reason, "disabled") || !strings.Contains(ref.Reason, "permission") {
				t.Fatalf("refusal %v does not name both causes", err)
			}
			wantNothingPublished(t, p)
			if n := p.codesignCount(); n != 0 {
				t.Fatalf("%d codesign commands ran before the immutable releases check passed", n)
			}
		})
	}
}

func wrongTimes(answer string, n int) string { return strings.Repeat(answer+"\n", n) }

func TestFinishRefusesAWrongTypedTag(t *testing.T) {
	// Each wrong answer is given three times, the bound of one prompt, and the
	// right tag follows on the fourth line to show it is never read.
	tests := []struct {
		name      string
		input     string
		wantFirst bool // refused at the first prompt, before the upload
	}{
		{"empty input", "", true},
		{"wrong tag", wrongTimes("other", 3) + testTag + "\n", true},
		{"upper case", wrongTimes(strings.ToUpper(testTag), 3) + testTag + "\n", true},
		{"trailing space", wrongTimes(testTag+" ", 3) + testTag + "\n", true},
		{"leading space", wrongTimes(" "+testTag, 3) + testTag + "\n", true},
		{"CRLF", wrongTimes(testTag+"\r", 3) + testTag + "\n", true},
		{"prefix of the tag", wrongTimes(testTag[:len(testTag)-1], 3) + testTag + "\n", true},
		{"answer too long", strings.Repeat("a", 5000) + "\n" + testTag + "\n", true},
		{"second answer wrong", testTag + "\n" + wrongTimes("nope", 3) + testTag + "\n", false},
		{"second answer missing", testTag + "\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newPub(t)
			_, err := p.finish(tt.input)
			wantRefusal(t, err, StepConfirm, "")
			wantNoPatch(t, p)
			wantUploads := 1
			if tt.wantFirst {
				wantUploads = 0
			}
			if n := p.uploadCount(); n != wantUploads {
				t.Fatalf("%d uploads ran, want %d", n, wantUploads)
			}
		})
	}
}

// TestPromptIsBounded shows a wrong answer asks again, three answers in all,
// and that the right tag after the third wrong one is never taken.
func TestPromptIsBounded(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		left    string // input left unread
	}{
		{"right at once", testTag + "\nrest", false, "rest"},
		{"right on the second try", "x\n" + testTag + "\nrest", false, "rest"},
		{"right on the third try", "x\ny\n" + testTag + "\nrest", false, "rest"},
		{"three wrong answers", "x\ny\nz\n" + testTag + "\n", true, testTag + "\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			in := strings.NewReader(tt.input)
			pr := newPrompter(in, &out)
			err := pr.confirm("tag? ", testTag)
			if tt.wantErr {
				wantRefusal(t, err, StepConfirm, "answer 3 of 3")
			} else if err != nil {
				t.Fatalf("confirm() error = %v", err)
			}
			rest, rerr := io.ReadAll(pr.in)
			if rerr != nil || string(rest) != tt.left {
				t.Fatalf("unread input = %q (err %v), want %q", rest, rerr, tt.left)
			}
		})
	}
}

func TestFinishPromptsTellCtrlCWaitsForEnter(t *testing.T) {
	p := newPub(t)
	res, err := p.s.run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	c, out := p.console(goodAnswers)
	if _, err := Finish(t.Context(), p.s, p.s.params, res, c); err != nil {
		t.Fatalf("Finish() error = %v", err)
	}
	if n := strings.Count(out.String(), "Ctrl-C takes effect only after Enter"); n != 2 {
		t.Fatalf("%d prompts carry the Ctrl-C note, want 2:\n%s", n, out.String())
	}
}

func TestFinishAcceptsARetypedTag(t *testing.T) {
	p := newPub(t)
	if _, err := p.finish("typo\n" + testTag + "\n" + "typo\ntypo\n" + testTag + "\n"); err != nil {
		t.Fatalf("Finish() error = %v", err)
	}
}

func TestFinishAcceptsAnAnswerWithoutTrailingNewlineAtEOF(t *testing.T) {
	p := newPub(t)
	if _, err := p.finish(testTag + "\n" + testTag); err != nil {
		t.Fatalf("Finish() error = %v", err)
	}
}

func editAssets(rel map[string]any, f func(assets []any) []any) {
	rel["assets"] = f(rel["assets"].([]any))
}

func setAsset(rel map[string]any, name, key string, value any) {
	for _, a := range rel["assets"].([]any) {
		if m := a.(map[string]any); m["name"] == name {
			m[key] = value
		}
	}
}

func TestFinishChecksTheReleaseAfterTheUpload(t *testing.T) {
	zeros := "sha256:" + strings.Repeat("0", 64)
	tests := []struct {
		name   string
		mutate func(p *pub, rel map[string]any)
		substr string
	}{
		{"extra asset", func(p *pub, rel map[string]any) {
			editAssets(rel, func(a []any) []any {
				return append(a, map[string]any{"id": 9, "name": "evil.tar.gz", "size": 1})
			})
		}, "unexpected asset"},
		{"missing asset", func(p *pub, rel map[string]any) {
			editAssets(rel, func(a []any) []any {
				return slices.DeleteFunc(a, func(x any) bool { return x.(map[string]any)["name"] == p.s.checksum })
			})
		}, "lacks the asset"},
		{"duplicate asset", func(p *pub, rel map[string]any) {
			editAssets(rel, func(a []any) []any { return append(a, a[0]) })
		}, "more than once"},
		{"digest mismatch", func(p *pub, rel map[string]any) { setAsset(rel, p.s.darwin[0], "digest", zeros) }, "digest"},
		{"digest of another algorithm", func(p *pub, rel map[string]any) {
			setAsset(rel, p.s.darwin[1], "digest", "sha512:"+strings.Repeat("0", 128))
		}, "digest"},
		{"checksums digest mismatch", func(p *pub, rel map[string]any) { setAsset(rel, p.s.checksum, "digest", zeros) }, "digest"},
		{"size mismatch", func(p *pub, rel map[string]any) { setAsset(rel, p.s.darwin[0], "size", 1) }, "bytes"},
		{"linux asset replaced", func(p *pub, rel map[string]any) {
			for _, a := range p.s.rel.Assets {
				if strings.Contains(a.Name, "linux_amd64") {
					setAsset(rel, a.Name, "id", 777)
				}
			}
		}, "was replaced"},
		{"release no longer a draft", func(p *pub, rel map[string]any) { rel["draft"] = false }, "no longer a draft"},
		{"release has another tag", func(p *pub, rel map[string]any) { rel["tag_name"] = "youtrack-agent-cli/v9.9.9" }, "has the tag"},
		{"read answers for another release", func(p *pub, rel map[string]any) { rel["id"] = 1 }, "answered for id"},
		{"digest missing and the content differs", func(p *pub, rel map[string]any) {
			delete(rel["assets"].([]any)[0].(map[string]any), "digest")
			for _, a := range rel["assets"].([]any) {
				m := a.(map[string]any)
				delete(m, "digest")
				if m["name"] == p.s.darwin[0] {
					data := slices.Clone(p.s.files[p.s.darwin[0]])
					data[len(data)-1] ^= 0xFF
					p.s.files[p.s.darwin[0]] = data
				}
			}
		}, "downloaded back"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newPub(t)
			p.tweak = func(read int, rel map[string]any) {
				if read == 1 {
					tt.mutate(p, rel)
				}
			}
			_, err := p.finish(goodAnswers)
			wantRefusal(t, err, StepUpload, tt.substr)
			if p.uploadCount() != 1 {
				t.Fatalf("%d uploads ran, want 1", p.uploadCount())
			}
			wantNoPatch(t, p)
		})
	}
}

// TestFinishRefusesAFailedUpload covers gh failing after the files were stored:
// the draft then looks right, and only the exit status says the run is unsafe.
func TestFinishRefusesAFailedUpload(t *testing.T) {
	for _, applied := range []bool{false, true} {
		name := "nothing stored"
		if applied {
			name = "files stored but gh exits non-zero"
		}
		t.Run(name, func(t *testing.T) {
			p := newPub(t)
			p.uploadErr, p.uploadApplied = exitErr(1), applied
			_, err := p.finish(goodAnswers)
			wantRefusal(t, err, StepUpload, "gh release upload")
			wantNoPatch(t, p)
		})
	}
}

func TestFinishVerifiesByDownloadWhenTheDigestIsMissing(t *testing.T) {
	p := newPub(t)
	p.noDigest = true
	if _, err := p.finish(goodAnswers); err != nil {
		t.Fatalf("Finish() error = %v", err)
	}
	downloads := 0
	for _, c := range p.postRun() {
		if slices.Contains(c, "Accept: application/octet-stream") {
			downloads++
		}
	}
	// Three darwin assets, read back after the upload and again after the publish.
	if downloads != 6 {
		t.Fatalf("%d downloads after the upload, want 6", downloads)
	}
}

func TestFinishRefusesAMovedTag(t *testing.T) {
	tests := []struct {
		name     string
		moveAt   int
		patched  bool
		wantText string
	}{
		{"moved before the upload check", 2, false, "now points at"},
		{"moved while the operator typed", 3, false, "now points at"},
		{"moved after the publish", 4, true, "published assets cannot be changed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newPub(t)
			p.moveTagAtRead = tt.moveAt
			_, err := p.finish(goodAnswers)
			if err == nil || !strings.Contains(err.Error(), tt.wantText) {
				t.Fatalf("Finish() error = %v, want it to contain %q", err, tt.wantText)
			}
			if got := p.patchCount() == 1; got != tt.patched {
				t.Fatalf("PATCH sent = %v, want %v", got, tt.patched)
			}
			if p.patchCount() > 1 {
				t.Fatalf("%d PATCH commands, want at most one", p.patchCount())
			}
		})
	}
}

func TestFinishRequiresAPublishedImmutableRelease(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(p *pub, rel map[string]any)
		substr string
	}{
		{"immutable false", func(p *pub, rel map[string]any) { rel["immutable"] = false }, "not immutable"},
		{"immutable absent", func(p *pub, rel map[string]any) { delete(rel, "immutable") }, "not immutable"},
		{"immutable is a string", func(p *pub, rel map[string]any) { rel["immutable"] = "true" }, "decode release"},
		{"still a draft", func(p *pub, rel map[string]any) { rel["draft"] = true }, "still a draft"},
		{"tag changed", func(p *pub, rel map[string]any) { rel["tag_name"] = "youtrack-agent-cli/v9.9.9" }, "has the tag"},
		{"asset replaced", func(p *pub, rel map[string]any) {
			setAsset(rel, p.s.darwin[0], "digest", "sha256:"+strings.Repeat("0", 64))
		}, "digest"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newPub(t)
			p.tweak = func(read int, rel map[string]any) {
				if read == 2 {
					tt.mutate(p, rel)
				}
			}
			_, err := p.finish(goodAnswers)
			if err == nil || !strings.Contains(err.Error(), tt.substr) {
				t.Fatalf("Finish() error = %v, want it to contain %q", err, tt.substr)
			}
			if p.patchCount() != 1 {
				t.Fatalf("%d PATCH commands, want exactly one", p.patchCount())
			}
		})
	}
}

func TestFinishPublishFailureDoesNotRetry(t *testing.T) {
	p := newPub(t)
	res, err := p.s.run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	patchAt := 0
	p.s.intercept = func(argv []string, stdin []byte) ([]byte, []byte, error, bool) {
		if isPatch(argv) {
			patchAt++
			return nil, []byte("HTTP 502"), exitErr(1), true
		}
		return p.intercept(argv, stdin)
	}
	c, _ := p.console(goodAnswers)
	_, err = Finish(t.Context(), p.s, p.s.params, res, c)
	wantRefusal(t, err, StepPublish, "may or may not be published")
	if patchAt != 1 {
		t.Fatalf("%d PATCH commands, want exactly one", patchAt)
	}
}

// TestNoPatchFollowsAnyFailure fails each command of the happy path in turn,
// from the first one Finish starts to the last before the PATCH, and requires
// that the PATCH is never sent and that the run reports the failure.
func TestNoPatchFollowsAnyFailure(t *testing.T) {
	ref := newPub(t)
	if _, err := ref.finish(goodAnswers); err != nil {
		t.Fatalf("Finish() error = %v", err)
	}
	patchAt := 0
	for i, c := range ref.s.calls {
		if isPatch(c) {
			patchAt = i + 1 // calls are numbered from 1
		}
	}
	if patchAt <= 11 {
		t.Fatalf("PATCH is command %d, want it after Run's ten and Finish's first", patchAt)
	}
	for n := 11; n < patchAt; n++ {
		p := newPub(t)
		res, err := p.s.run()
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		p.failAt = n
		c, _ := p.console(goodAnswers)
		_, err = Finish(t.Context(), p.s, p.s.params, res, c)
		if err == nil {
			t.Fatalf("command %d (%q) failed and Finish() returned nil", n, p.s.calls[n-1])
		}
		if p.patchCount() != 0 {
			t.Fatalf("command %d (%q) failed and the PATCH was sent", n, p.s.calls[n-1])
		}
	}
}

func TestFinishNeverExecutesABinary(t *testing.T) {
	p := newPub(t)
	if _, err := p.finish(goodAnswers); err != nil {
		t.Fatalf("Finish() error = %v", err)
	}
	work := p.s.params.WorkDir
	codesignVerbs := []string{"--force", "--verify", "-dvv", "-d"}
	for _, argv := range p.s.calls {
		switch argv[0] {
		case testGH:
		case CodesignPath:
			if !slices.Contains(codesignVerbs, argv[1]) {
				t.Fatalf("codesign command %q is not a sign or an inspection", argv)
			}
		default:
			t.Fatalf("command %q starts a program that is neither gh nor codesign", argv)
		}
		if strings.HasPrefix(argv[0], work) {
			t.Fatalf("command %q starts a file of the work directory", argv)
		}
	}
	if p.codesignCount() != 10 {
		t.Fatalf("%d codesign commands, want 5 per binary", p.codesignCount())
	}
}

func TestFinishRefusesAResultNotFromRun(t *testing.T) {
	p := newPub(t)
	c, _ := p.console(goodAnswers)
	_, err := Finish(t.Context(), p.s, p.s.params, Result{}, c)
	wantRefusal(t, err, StepPreflight, "not produced by Run")
	if len(p.s.calls) != 0 {
		t.Fatalf("%d commands ran for a foreign result", len(p.s.calls))
	}
}

func TestFinishPrintsOneLinePerStep(t *testing.T) {
	p := newPub(t)
	res, err := p.s.run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	c, out := p.console(goodAnswers)
	if _, err := Finish(t.Context(), p.s, p.s.params, res, c); err != nil {
		t.Fatalf("Finish() error = %v", err)
	}
	for _, want := range []string{"immutable releases:", "sign amd64:", "sign arm64:", "repackage:", "upload:", "tag:", "publish:", "Type the tag " + testTag} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("console output lacks %q:\n%s", want, out.String())
		}
	}
}

// TestVerifyUsesTheBareExpression pins what real codesign parses: -R takes the
// expression after "=", and "designated =>" or a doubled "=" is a syntax error.
func TestVerifyUsesTheBareExpression(t *testing.T) {
	p := newPub(t)
	if _, err := p.finish(goodAnswers); err != nil {
		t.Fatalf("Finish() error = %v", err)
	}
	seen := 0
	for _, argv := range p.s.calls {
		if argv[0] != CodesignPath || argv[1] != "--verify" {
			continue
		}
		seen++
		var value string
		for _, a := range argv {
			if v, ok := strings.CutPrefix(a, "-R"); ok {
				value = v
			}
		}
		if !strings.HasPrefix(value, "=") || strings.HasPrefix(value, "==") || strings.Contains(value, "designated") {
			t.Fatalf("-R value %q must start with one \"=\" and never contain \"designated\"", value)
		}
		if value != "="+goldenExpression {
			t.Fatalf("-R value = %q, want %q", value, "="+goldenExpression)
		}
	}
	if seen != 2 {
		t.Fatalf("%d --verify commands, want 2", seen)
	}
	for _, argv := range p.s.calls {
		if argv[0] == CodesignPath && argv[1] == "--force" && !slices.Contains(argv, goldenRequirement) {
			t.Fatalf("signing argv %q does not carry the designated requirement set", argv)
		}
	}
}

const restoreNote = "no attestation covers"

func TestFinishNamesTheRecoveryAfterAnUpload(t *testing.T) {
	zeros := "sha256:" + strings.Repeat("0", 64)
	tests := []struct {
		name  string
		setup func(p *pub)
		input string
	}{
		{"gh upload fails after storing files", func(p *pub) { p.uploadErr, p.uploadApplied = exitErr(1), true }, goodAnswers},
		{"digest mismatch", func(p *pub) {
			p.tweak = func(read int, rel map[string]any) {
				if read == 1 {
					setAsset(rel, p.s.darwin[0], "digest", zeros)
				}
			}
		}, goodAnswers},
		{"release read fails", func(p *pub) { p.relReadFail = map[int]string{1: "error"} }, goodAnswers},
		{"tag moved after the upload", func(p *pub) { p.moveTagAtRead = 2 }, goodAnswers},
		{"tag moved while the operator typed", func(p *pub) { p.moveTagAtRead = 3 }, goodAnswers},
		{"second confirmation refused three times", func(p *pub) {}, testTag + "\n" + wrongTimes("no", 3)},
		{"still a draft after the PATCH", func(p *pub) {
			p.tweak = func(read int, rel map[string]any) {
				if read == 2 {
					rel["draft"] = true
				}
			}
		}, goodAnswers},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newPub(t)
			tt.setup(p)
			_, err := p.finish(tt.input)
			if err == nil {
				t.Fatal("Finish() error = nil")
			}
			work := p.s.params.WorkDir
			for _, want := range []string{restoreNote, work, p.s.checksum, "--clobber", "re-run will refuse", "gh release upload " + testTag, "--repo github.com/" + testRepo} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error %q lacks %q", err, want)
				}
			}
		})
	}
}

// TestFinishNamesNoRecoveryOutsideTheUploadWindow shows the restore advice is
// only for the window in which the draft holds signed assets.
func TestFinishNamesNoRecoveryOutsideTheUploadWindow(t *testing.T) {
	tests := []struct {
		name  string
		setup func(p *pub)
		input string
	}{
		{"verify fails before the upload", func(p *pub) { p.verifyErr = exitErr(1) }, goodAnswers},
		{"first confirmation refused", func(p *pub) {}, wrongTimes("no", 3)},
		{"published but not immutable", func(p *pub) { p.immutableAfter = false }, goodAnswers},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newPub(t)
			tt.setup(p)
			_, err := p.finish(tt.input)
			if err == nil {
				t.Fatal("Finish() error = nil")
			}
			if strings.Contains(err.Error(), restoreNote) {
				t.Fatalf("error %q gives restore advice outside the upload window", err)
			}
		})
	}
}

func TestFinishAdviceAfterThePatchDependsOnTheRead(t *testing.T) {
	const nextPatch = "cut the next patch version"
	readFirst := "read release 4242 with gh before doing anything else"
	tests := []struct {
		name     string
		setup    func(p *pub)
		wantRead bool // the read did not complete
	}{
		{"read fails", func(p *pub) { p.relReadFail = map[int]string{2: "error"} }, true},
		{"read answers with garbage", func(p *pub) { p.relReadFail = map[int]string{2: "garbage"} }, true},
		{"read succeeds and a check fails", func(p *pub) { p.immutableAfter = false }, false},
		{"read succeeds and the tag changed", func(p *pub) {
			p.tweak = func(read int, rel map[string]any) {
				if read == 2 {
					rel["tag_name"] = "youtrack-agent-cli/v9.9.9"
				}
			}
		}, false},
		{"tag read fails afterwards", func(p *pub) { p.failTagReadAfterPatch = true }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newPub(t)
			tt.setup(p)
			_, err := p.finish(goodAnswers)
			if err == nil {
				t.Fatal("Finish() error = nil")
			}
			msg := err.Error()
			if got := strings.Contains(msg, readFirst); got != tt.wantRead {
				t.Fatalf("error %q: read-first advice = %v, want %v", msg, got, tt.wantRead)
			}
			if got := strings.Contains(msg, nextPatch); got == tt.wantRead {
				t.Fatalf("error %q: next-patch advice = %v, want %v", msg, got, !tt.wantRead)
			}
			if p.patchCount() != 1 {
				t.Fatalf("%d PATCH commands, want exactly one", p.patchCount())
			}
		})
	}
}

// TestFinishDigestFallbackDownloadFailure covers the digest field missing and
// the download that replaces it exiting non-zero. The run is not a refusal of
// the assets: it could not read them. Before the PATCH that is a plain error
// with the restore note; after it, the advice is to read the release first.
func TestFinishDigestFallbackDownloadFailure(t *testing.T) {
	t.Run("before the PATCH", func(t *testing.T) {
		p := newPub(t)
		p.noDigest, p.failDownload = true, "beforePatch"
		_, err := p.finish(goodAnswers)
		if err == nil || !strings.Contains(err.Error(), "download asset") || !strings.Contains(err.Error(), restoreNote) {
			t.Fatalf("Finish() error = %v, want a download error with the restore note", err)
		}
		var ref *Refusal
		if errors.As(err, &ref) {
			t.Fatalf("error %v is a Refusal, want a plain error", err)
		}
		wantNoPatch(t, p)
	})
	t.Run("after the PATCH", func(t *testing.T) {
		p := newPub(t)
		p.noDigest, p.failDownload = true, "afterPatch"
		_, err := p.finish(goodAnswers)
		if err == nil {
			t.Fatal("Finish() error = nil")
		}
		msg := err.Error()
		if !strings.Contains(msg, "read release 4242 with gh before doing anything else") || strings.Contains(msg, "cut the next patch version") {
			t.Fatalf("error %q, want the read-first advice and no next-patch advice", msg)
		}
		if p.patchCount() != 1 {
			t.Fatalf("%d PATCH commands, want exactly one", p.patchCount())
		}
	})
}

// TestFinishPatchFailureNamesTheRestore shows a failed PATCH keeps its
// "may or may not be published" message and adds how to restore a draft.
func TestFinishPatchFailureNamesTheRestore(t *testing.T) {
	p := newPub(t)
	res, err := p.s.run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	p.s.intercept = func(argv []string, stdin []byte) ([]byte, []byte, error, bool) {
		if isPatch(argv) {
			return nil, []byte("HTTP 502"), exitErr(1), true
		}
		return p.intercept(argv, stdin)
	}
	c, _ := p.console(goodAnswers)
	_, err = Finish(t.Context(), p.s, p.s.params, res, c)
	wantRefusal(t, err, StepPublish, "may or may not be published")
	for _, want := range []string{
		"read it with gh", "if it is still a draft", "restore the originals from " + p.s.params.WorkDir, p.s.checksum,
		"gh release upload " + testTag + " <files> --clobber --repo github.com/" + testRepo, "then run again",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q lacks %q", err, want)
		}
	}
	// The draft-state sentence of the upload-window note is not true here.
	if strings.Contains(err.Error(), restoreNote) {
		t.Fatalf("error %q claims the draft carries unattested assets", err)
	}
}
