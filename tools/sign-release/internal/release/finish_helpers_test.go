package release

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/abigotado/agent-clis/tools/sign-release/internal/codesign"
	"github.com/abigotado/agent-clis/tools/sign-release/internal/machofixture"
	"github.com/abigotado/agent-clis/tools/sign-release/internal/runner"
)

// goldenExpression is the bare requirement expression of the test identity.
const goldenExpression = `identifier "dev.abigotado.youtrack-agent-cli" and anchor apple generic and certificate leaf = H"7b35c316aa0000000000000000000000000a8531"`

const (
	testCommitDate = "2026-11-20T10:11:12Z"
	testID         = "dev.abigotado.youtrack-agent-cli"
	testTeam       = "5XCS9FFW5Z"
)

var errFake = errors.New("fake failure")

var otherCommit = strings.Repeat("b", 40)

// pub extends a scenario with a fake codesign, a fake release that accepts
// uploads and a fake immutable releases setting. It is a runner through the
// scenario's intercept hook, so every command is recorded in scenario.calls.
type pub struct {
	t *testing.T
	s *scenario

	immutableOut string
	immutableErr error
	// immutableAfter is the "immutable" member of the release once published.
	immutableAfter bool

	signErr       error
	verifyErr     error
	detailsOut    string
	requirements  string
	entitlements  string
	signFn        func(b []byte) []byte
	commitDate    string
	commitSHA     string
	uploadErr     error
	uploadApplied bool // the upload takes effect although gh reports the error
	noDigest      bool
	tweak         func(read int, rel map[string]any)
	moveTagAtRead int // the nth read of the tag ref moves the tag; 0 never
	// onList runs on the nth release list (Run's own is the first) before it
	// answers.
	onList func(n int)
	// immutableOutAt replaces the immutable releases answer on the nth read.
	immutableOutAt        map[int]string
	lists, immutableReads int
	// failDownload makes the digest-fallback downloads, those after the upload,
	// exit non-zero: "beforePatch" or "afterPatch".
	failDownload string
	// failTagReadAfterPatch makes tag reads after the PATCH fail.
	failTagReadAfterPatch bool
	failAt                int // the nth command (from 1, counting Run's too) fails; 0 never

	nextID    int64
	published bool
	tagReads  int
	relReads  int
	// relReadFail makes the nth release read fail: "error" for a transport
	// error, "garbage" for an answer that is not JSON.
	relReadFail map[int]string
	patches     [][]byte
	uploads     [][]string
}

func newPub(t *testing.T) *pub {
	t.Helper()
	p := &pub{
		t:              t,
		s:              newScenario(t),
		immutableOut:   `{"enabled":true,"enforced_by_owner":false}`,
		immutableAfter: true,
		commitDate:     testCommitDate,
		commitSHA:      testCommit,
		nextID:         5000,
		signFn:         resign,
	}
	exp := codesign.Expectation{Identifier: testID, Team: testTeam, CertSHA1: testCertSHA}
	req, err := exp.Requirement()
	if err != nil {
		t.Fatalf("Requirement() error = %v", err)
	}
	p.requirements = strings.TrimPrefix(req, "=") + "\n"
	p.detailsOut = goodDetailsText("/work/youtrack-agent-cli")
	p.s.intercept = p.intercept
	return p
}

func goodDetailsText(path string) string {
	return "Executable=" + path + `
Identifier=` + testID + `
Format=Mach-O thin (arm64)
CodeDirectory v=20500 size=3730 flags=0x10000(runtime) hashes=111+2 location=embedded
Signature size=9013
Authority=Developer ID Application: Test (` + testTeam + `)
Timestamp=Nov 23, 2026 at 10:00:00
TeamIdentifier=` + testTeam + `
`
}

// resign replaces the signature blob, the last 64 bytes of the fixture, as a
// signing run would.
func resign(b []byte) []byte {
	out := slices.Clone(b)
	for i := len(out) - 64; i < len(out); i++ {
		out[i] = 0xEE
	}
	return out
}

// swapText changes a __TEXT byte too, as a binary swapped for another would.
func swapText(b []byte) []byte {
	out := resign(b)
	out[machofixture.Build(machofixture.Spec{}).TextByteAt] ^= 0xFF
	return out
}

func (p *pub) isTagRef(argv []string) bool {
	return len(argv) == 5 && argv[1] == "api" && argv[4] == "repos/"+testRepo+"/git/ref/tags/"+testTag
}

func (p *pub) intercept(argv []string, stdin []byte) ([]byte, []byte, error, bool) {
	if p.failAt > 0 && len(p.s.calls) == p.failAt {
		return nil, nil, errFake, true
	}
	if len(p.uploads) > 0 && slices.Contains(argv, "Accept: application/octet-stream") {
		if (p.failDownload == "beforePatch" && !p.published) || (p.failDownload == "afterPatch" && p.published) {
			return nil, []byte("HTTP 502"), exitErr(1), true
		}
	}
	if len(argv) == 6 && argv[1] == "api" && argv[4] == "--paginate" {
		p.lists++
		if p.onList != nil {
			p.onList(p.lists)
		}
		return nil, nil, nil, false
	}
	if p.isTagRef(argv) {
		if p.failTagReadAfterPatch && p.published {
			return nil, nil, errFake, true
		}
		p.tagReads++
		if p.moveTagAtRead == p.tagReads {
			p.s.tagRefOut = fmt.Sprintf(`{"ref":"refs/tags/%s","object":{"sha":%q,"type":"commit"}}`, testTag, otherCommit)
		}
		return nil, nil, nil, false
	}
	switch {
	case argv[0] == CodesignPath:
		return p.codesign(argv)
	case len(argv) == 5 && argv[1] == "api" && argv[4] == "repos/"+testRepo+"/immutable-releases":
		p.immutableReads++
		if out, ok := p.immutableOutAt[p.immutableReads]; ok {
			return []byte(out), nil, p.immutableErr, true
		}
		return []byte(p.immutableOut), nil, p.immutableErr, true
	case len(argv) == 5 && argv[1] == "api" && argv[4] == "repos/"+testRepo+"/git/commits/"+testCommit:
		return []byte(fmt.Sprintf(`{"sha":%q,"committer":{"date":%q}}`, p.commitSHA, p.commitDate)), nil, nil, true
	case len(argv) > 3 && argv[1] == "release" && argv[2] == "upload":
		return p.upload(argv)
	case len(argv) == 9 && argv[1] == "api" && argv[4] == "-X" && argv[5] == "PATCH":
		p.patches = append(p.patches, slices.Clone(stdin))
		p.published = true
		return []byte(`{}`), nil, nil, true
	case len(argv) == 5 && argv[1] == "api" && argv[4] == "repos/"+testRepo+"/releases/"+strconv.Itoa(testRelID):
		p.relReads++
		switch p.relReadFail[p.relReads] {
		case "error":
			return nil, nil, errFake, true
		case "garbage":
			return []byte("<html>"), nil, nil, true
		}
		return []byte(p.releaseJSON()), nil, nil, true
	}
	return nil, nil, nil, false
}

func (p *pub) codesign(argv []string) ([]byte, []byte, error, bool) {
	bin := argv[len(argv)-1]
	switch {
	case argv[1] == "--force":
		if p.signErr != nil {
			return nil, []byte("no identity found"), p.signErr, true
		}
		b, err := os.ReadFile(bin)
		if err != nil {
			p.t.Errorf("fake codesign cannot read %s: %v", bin, err)
			return nil, nil, err, true
		}
		if err := os.WriteFile(bin, p.signFn(b), 0o600); err != nil {
			p.t.Errorf("fake codesign cannot write %s: %v", bin, err)
			return nil, nil, err, true
		}
		return nil, nil, nil, true
	case argv[1] == "--verify":
		// Real codesign rejects a -R it cannot parse, and the only form it
		// parses is the bare expression; any other argv exits 1.
		want := []string{CodesignPath, "--verify", "--strict", "-R=" + goldenExpression, bin}
		if !slices.Equal(argv, want) {
			return nil, []byte("line 1:1: unexpected token"), &runner.ExitError{Program: CodesignPath, Code: 1}, true
		}
		return nil, nil, p.verifyErr, true
	case argv[1] == "-dvv":
		return nil, []byte(p.detailsOut), nil, true
	case slices.Equal(argv[1:3], []string{"-d", "-r-"}):
		return []byte(p.requirements), []byte("Executable=" + bin + "\n"), nil, true
	case slices.Equal(argv[1:4], []string{"-d", "--entitlements", "-"}):
		return []byte(p.entitlements), nil, nil, true
	}
	p.t.Errorf("unexpected codesign command %q", argv)
	return nil, nil, errFake, true
}

func (p *pub) upload(argv []string) ([]byte, []byte, error, bool) {
	p.uploads = append(p.uploads, slices.Clone(argv))
	if p.uploadErr != nil && !p.uploadApplied {
		return nil, []byte("HTTP 422"), p.uploadErr, true
	}
	// gh release upload <tag> <files>... --clobber --repo <repo>
	for _, path := range argv[4 : len(argv)-3] {
		data, err := os.ReadFile(path)
		if err != nil {
			p.t.Errorf("fake upload cannot read %s: %v", path, err)
			return nil, nil, err, true
		}
		name := filepath.Base(path)
		s := p.s
		for i := range s.rel.Assets {
			if s.rel.Assets[i].Name != name {
				continue
			}
			delete(s.byID, s.rel.Assets[i].ID)
			p.nextID++
			s.rel.Assets[i].ID = p.nextID
			s.rel.Assets[i].Size = int64(len(data))
			s.byID[p.nextID] = name
		}
		s.files[name] = data
	}
	return nil, nil, p.uploadErr, true
}

func (p *pub) releaseJSON() string {
	var assets []any
	for _, a := range p.s.rel.Assets {
		m := map[string]any{"id": a.ID, "name": a.Name, "size": a.Size}
		if !p.noDigest {
			sum := sha256.Sum256(p.s.files[a.Name])
			m["digest"] = "sha256:" + hex.EncodeToString(sum[:])
		}
		assets = append(assets, m)
	}
	rel := map[string]any{"id": testRelID, "tag_name": testTag, "draft": !p.published, "assets": assets}
	if p.published {
		rel["immutable"] = p.immutableAfter
	}
	if p.tweak != nil {
		p.tweak(p.relReads, rel)
	}
	data, err := json.Marshal(rel)
	if err != nil {
		p.t.Fatalf("marshal release: %v", err)
	}
	return string(data)
}

func (p *pub) console(input string) (Console, *bytes.Buffer) {
	var out bytes.Buffer
	return Console{In: strings.NewReader(input), Out: &out}, &out
}

const goodAnswers = testTag + "\n" + testTag + "\n"

// finish runs steps 1 to 5 and then 6 to 11 against the fake.
func (p *pub) finish(input string) (Published, error) {
	p.t.Helper()
	res, err := p.s.run()
	if err != nil {
		p.t.Fatalf("Run() error = %v", err)
	}
	c, _ := p.console(input)
	return Finish(p.t.Context(), p.s, p.s.params, res, c)
}

func (p *pub) argvs() [][]string { return p.s.calls }

func (p *pub) patchCount() int {
	n := 0
	for _, c := range p.s.calls {
		if isPatch(c) {
			n++
		}
	}
	return n
}

func isPatch(argv []string) bool {
	return len(argv) > 5 && argv[1] == "api" && slices.Contains(argv, "PATCH")
}

func isUpload(argv []string) bool {
	return len(argv) > 2 && argv[1] == "release" && argv[2] == "upload"
}

func (p *pub) uploadCount() int {
	n := 0
	for _, c := range p.s.calls {
		if isUpload(c) {
			n++
		}
	}
	return n
}

func (p *pub) codesignCount() int {
	n := 0
	for _, c := range p.s.calls {
		if c[0] == CodesignPath {
			n++
		}
	}
	return n
}

var _ runner.Runner = (*scenario)(nil)
