package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/macho"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/abigotado/agent-clis/tools/sign-release/internal/config"
	"github.com/abigotado/agent-clis/tools/sign-release/internal/machofixture"
	"github.com/abigotado/agent-clis/tools/sign-release/internal/runner"
)

const (
	testRepo    = "abigotado/agent-clis"
	testCLI     = "youtrack-agent-cli"
	testVersion = "0.13.0"
	testTag     = "youtrack-agent-cli/v0.13.0"
	testGH      = "/opt/test/bin/gh"
	testCertSHA = "7b35c316aa0000000000000000000000000a8531"
	testRelID   = 4242
)

var testCommit = strings.Repeat("a", 40)

// testConfig parses the real config.json, so the asset names the tests use are
// the ones production uses, and fills in a certificate hash.
func testConfig(t *testing.T) config.Config {
	t.Helper()
	data, err := os.ReadFile("../../config.json")
	if err != nil {
		t.Fatalf("read config.json: %v", err)
	}
	cfg, err := config.Parse(data)
	if err != nil {
		t.Fatalf("config.Parse() error = %v", err)
	}
	cli := cfg.CLIs[testCLI]
	cli.CertSHA1 = testCertSHA
	cfg.CLIs[testCLI] = cli
	return cfg
}

func newWorkDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(t.TempDir(), "work")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	return dir
}

// thinBinary returns a structurally valid thin Mach-O executable for cpu. The
// fixture's symbol table is emptied because debug/macho reads it.
func thinBinary(cpu macho.Cpu) []byte {
	f := machofixture.Build(machofixture.Spec{})
	b := f.Clone()
	binary.LittleEndian.PutUint32(b[4:], uint32(cpu))
	binary.LittleEndian.PutUint32(b[f.Cmds["LC_SYMTAB"]+12:], 0)
	return b
}

type tarEntry struct {
	hdr  tar.Header
	body []byte
}

func regular(name string, body []byte) tarEntry {
	return tarEntry{hdr: tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}, body: body}
}

func makeTarGz(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		hdr := e.hdr
		if err := tw.WriteHeader(&hdr); err != nil {
			t.Fatalf("WriteHeader(%q) error = %v", hdr.Name, err)
		}
		if _, err := tw.Write(e.body); err != nil {
			t.Fatalf("Write(%q) error = %v", hdr.Name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close() error = %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip Close() error = %v", err)
	}
	return buf.Bytes()
}

func goodArchive(t *testing.T, cpu macho.Cpu) []byte {
	return makeTarGz(t,
		regular("LICENSE", []byte("license\n")),
		regular("README.md", []byte("readme\n")),
		regular(testCLI, thinBinary(cpu)),
	)
}

func sumLine(name string, data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]) + "  " + name + "\n"
}

// scenario is a fake GitHub: a release list, assets by ID, a tag and a verify
// reply per file. It is also the runner, and records every argv.
type scenario struct {
	t      *testing.T
	params Params

	rel    releaseJSON
	others []releaseJSON
	files  map[string][]byte
	byID   map[int64]string

	darwin   [2]string // archive names, amd64 then arm64
	checksum string

	tagRefOut  string
	tagObjects map[string]string
	verifyOut  map[string]string // by base name of the verified file
	verifyErr  map[string]error
	listErr    error
	authErr    error
	onVerify   func() // called when a verify command arrives
	calls      [][]string

	// intercept sees every command after it is recorded and before the default
	// answers; handled reports that it answered.
	intercept func(argv []string, stdin []byte) (stdout, stderr []byte, err error, handled bool)
}

// verifyEntry is one entry of gh attestation verify --format json, built
// from the certificate members the tool compares.
func verifyEntry(c certificateJSON) string {
	data, err := json.Marshal(map[string]any{
		"attestation": map[string]any{"bundle": map[string]any{}},
		"verificationResult": map[string]any{
			"mediaType": "x",
			"signature": map[string]any{"certificate": c},
		},
	})
	if err != nil {
		panic(err) // marshalling plain maps and strings cannot fail
	}
	return string(data)
}

func goodCertificate(commit, ref string) certificateJSON {
	return certificateJSON{
		Issuer:                 "https://token.actions.githubusercontent.com",
		BuildSignerURI:         "https://github.com/" + testRepo + "/.github/workflows/release.yaml@refs/tags/" + testTag,
		BuildSignerDigest:      testCommit,
		RunnerEnvironment:      "github-hosted",
		SourceRepositoryURI:    "https://github.com/" + testRepo,
		SourceRepositoryDigest: commit,
		SourceRepositoryRef:    ref,
	}
}

func goodVerifyJSON(commit, ref string) string {
	return "[" + verifyEntry(goodCertificate(commit, ref)) + "]"
}

func newScenario(t *testing.T) *scenario {
	t.Helper()
	cfg := testConfig(t)
	cli := cfg.CLIs[testCLI]
	name := func(tpl string) string {
		n, err := config.ExpandName(tpl, testVersion)
		if err != nil {
			t.Fatalf("ExpandName() error = %v", err)
		}
		return n
	}
	s := &scenario{
		t:          t,
		files:      map[string][]byte{},
		byID:       map[int64]string{},
		tagObjects: map[string]string{},
		verifyOut:  map[string]string{},
		verifyErr:  map[string]error{},
		params: Params{
			Config: cfg, CLI: testCLI, Version: testVersion, GH: testGH, WorkDir: newWorkDir(t),
			Limits: Limits{MaxArchive: 1 << 20, MaxChecksums: 4096, MaxEntry: 1 << 20, MaxExtracted: 4 << 20},
		},
		darwin:   [2]string{name(cli.Assets.DarwinArchives.AMD64), name(cli.Assets.DarwinArchives.ARM64)},
		checksum: cli.Assets.DarwinChecksums,
	}
	amd64 := goodArchive(t, macho.CpuAmd64)
	arm64 := goodArchive(t, macho.CpuArm64)
	s.files[s.darwin[0]] = amd64
	s.files[s.darwin[1]] = arm64
	s.files[name(cli.Assets.LinuxArchives.AMD64)] = []byte("linux amd64")
	s.files[name(cli.Assets.LinuxArchives.ARM64)] = []byte("linux arm64")
	s.files[cli.Assets.LinuxChecksums] = []byte("linux sums\n")
	s.setChecksums()

	s.rel = releaseJSON{ID: testRelID, TagName: testTag, Draft: true}
	names := make([]string, 0, len(s.files))
	for n := range s.files {
		names = append(names, n)
	}
	slices.Sort(names)
	for i, n := range names {
		id := int64(100 + i)
		s.byID[id] = n
		s.rel.Assets = append(s.rel.Assets, assetJSON{ID: id, Name: n, Size: int64(len(s.files[n]))})
	}
	s.others = []releaseJSON{{ID: 1, TagName: "youtrack-agent-cli/v0.12.0", Draft: false}}

	s.tagRefOut = fmt.Sprintf(`{"ref":"refs/tags/%s","node_id":"x","object":{"sha":%q,"type":"commit"}}`, testTag, testCommit)
	return s
}

// setChecksums rewrites checksums-darwin.txt from the current archives and
// refreshes the reported size of the checksums asset.
func (s *scenario) setChecksums() {
	s.files[s.checksum] = []byte(sumLine(s.darwin[0], s.files[s.darwin[0]]) + sumLine(s.darwin[1], s.files[s.darwin[1]]))
	s.syncSize(s.checksum)
}

func (s *scenario) syncSize(name string) {
	for i := range s.rel.Assets {
		if s.rel.Assets[i].Name == name {
			s.rel.Assets[i].Size = int64(len(s.files[name]))
		}
	}
}

// replaceArchive swaps a darwin archive and keeps the checksums honest, so the
// test reaches the check it is about.
func (s *scenario) replaceArchive(idx int, data []byte) {
	s.files[s.darwin[idx]] = data
	s.syncSize(s.darwin[idx])
	s.setChecksums()
}

func (s *scenario) assetID(name string) int64 {
	for id, n := range s.byID {
		if n == name {
			return id
		}
	}
	s.t.Fatalf("no asset %q", name)
	return 0
}

func (s *scenario) dropAsset(name string) {
	s.rel.Assets = slices.DeleteFunc(s.rel.Assets, func(a assetJSON) bool { return a.Name == name })
}

func (s *scenario) setReportedSize(name string, size int64) {
	for i := range s.rel.Assets {
		if s.rel.Assets[i].Name == name {
			s.rel.Assets[i].Size = size
		}
	}
}

func (s *scenario) pages() string {
	all := append(slices.Clone(s.others), s.rel)
	var out strings.Builder
	for _, r := range all {
		data, err := json.Marshal([]releaseJSON{r})
		if err != nil {
			s.t.Fatalf("marshal release page: %v", err)
		}
		out.Write(data) // one array per page, printed back to back as gh does
	}
	return out.String()
}

func (s *scenario) record(argv []string) { s.calls = append(s.calls, slices.Clone(argv)) }

func (s *scenario) Run(_ context.Context, argv []string, stdin []byte) ([]byte, []byte, error) {
	s.record(argv)
	if s.intercept != nil {
		if out, errOut, err, handled := s.intercept(argv, stdin); handled {
			return out, errOut, err
		}
	}
	fail := func() ([]byte, []byte, error) {
		s.t.Errorf("unexpected command %q", argv)
		return nil, nil, fmt.Errorf("unexpected command %q", argv)
	}
	if len(argv) < 2 || argv[0] != testGH {
		return fail()
	}
	switch {
	case slices.Equal(argv[1:], []string{"auth", "status", "--hostname", "github.com"}):
		return nil, nil, s.authErr
	case slices.Equal(argv[1:], []string{"api", "--hostname", "github.com", "--paginate", "repos/" + testRepo + "/releases"}):
		if s.listErr != nil {
			return nil, nil, s.listErr
		}
		return []byte(s.pages()), nil, nil
	case len(argv) == 7 && slices.Equal(argv[1:6], []string{"api", "--hostname", "github.com", "-H", "Accept: application/octet-stream"}):
		prefix := "repos/" + testRepo + "/releases/assets/"
		var id int64
		if _, err := fmt.Sscanf(strings.TrimPrefix(argv[6], prefix), "%d", &id); err != nil || !strings.HasPrefix(argv[6], prefix) {
			return fail()
		}
		name, ok := s.byID[id]
		if !ok {
			return nil, nil, errors.New("asset not found")
		}
		return s.files[name], nil, nil
	case slices.Equal(argv[1:], []string{"api", "--hostname", "github.com", "repos/" + testRepo + "/git/ref/tags/" + testTag}):
		return []byte(s.tagRefOut), nil, nil
	case len(argv) == 5 && slices.Equal(argv[1:4], []string{"api", "--hostname", "github.com"}) && strings.HasPrefix(argv[4], "repos/"+testRepo+"/git/tags/"):
		out, ok := s.tagObjects[strings.TrimPrefix(argv[4], "repos/"+testRepo+"/git/tags/")]
		if !ok {
			return nil, nil, errors.New("tag object not found")
		}
		return []byte(out), nil, nil
	case len(argv) > 3 && argv[1] == "attestation" && argv[2] == "verify":
		if s.onVerify != nil {
			s.onVerify()
		}
		base := filepath.Base(argv[3])
		if err := s.verifyErr[base]; err != nil {
			return nil, []byte("verification failed"), err
		}
		if out, ok := s.verifyOut[base]; ok {
			return []byte(out), nil, nil
		}
		return []byte(goodVerifyJSON(testCommit, "refs/tags/"+testTag)), nil, nil
	}
	return fail()
}

var _ runner.Runner = (*scenario)(nil)

func (s *scenario) run() (Result, error) {
	s.t.Helper()
	return s.runCtx(s.t.Context())
}

func (s *scenario) runCtx(ctx context.Context) (Result, error) {
	s.t.Helper()
	return Run(ctx, s, s.params)
}

func wantRefusal(t *testing.T, err error, step Step, substr string) {
	t.Helper()
	var ref *Refusal
	if !errors.As(err, &ref) {
		t.Fatalf("error = %v, want a *Refusal at step %q", err, step)
	}
	if ref.Step != step || !strings.Contains(ref.Reason, substr) {
		t.Fatalf("refusal = {%s: %q}, want step %q with %q", ref.Step, ref.Reason, step, substr)
	}
}

func makeGzip(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatalf("gzip Write() error = %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip Close() error = %v", err)
	}
	return buf.Bytes()
}
