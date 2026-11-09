package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRepositoryManifestMatchesModuleClosure(t *testing.T) {
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	locked, err := readManifest(filepath.Join(root, "packaging", "homebrew", "modules.json"))
	if err != nil {
		t.Fatal(err)
	}
	required, err := readRequiredModules(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if err := compareClosure(locked.Modules, required); err != nil {
		t.Fatal(err)
	}
	if err := verifyGoSum(filepath.Join(root, "go.sum"), locked.Modules); err != nil {
		t.Fatal(err)
	}
}

func TestReadManifestRejectsInvalidEntries(t *testing.T) {
	validHash := strings.Repeat("a", sha256.Size*2)
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{name: "unknown field", content: `{"schema":1,"modules":[{"path":"example.com/a","version":"v1.0.0","zip_sha256":"` + validHash + `","url":"https://example.com"}]}`, want: "unknown field"},
		{name: "duplicate", content: `{"schema":1,"modules":[{"path":"example.com/a","version":"v1.0.0","zip_sha256":"` + validHash + `"},{"path":"example.com/a","version":"v1.1.0","zip_sha256":"` + validHash + `"}]}`, want: "duplicate module"},
		{name: "unsorted", content: `{"schema":1,"modules":[{"path":"example.com/b","version":"v1.0.0","zip_sha256":"` + validHash + `"},{"path":"example.com/a","version":"v1.0.0","zip_sha256":"` + validHash + `"}]}`, want: "sorted"},
		{name: "uppercase digest", content: `{"schema":1,"modules":[{"path":"example.com/a","version":"v1.0.0","zip_sha256":"` + strings.Repeat("A", sha256.Size*2) + `"}]}`, want: "invalid zip_sha256"},
		{name: "trailing JSON", content: `{"schema":1,"modules":[{"path":"example.com/a","version":"v1.0.0","zip_sha256":"` + validHash + `"}]} {}`, want: "trailing JSON"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "modules.json")
			if err := os.WriteFile(path, []byte(test.content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := readManifest(path)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("readManifest() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestReadRequiredModulesRejectsReplacements(t *testing.T) {
	tests := []struct {
		name    string
		replace string
	}{
		{name: "single", replace: "replace example.com/a => ../a\n"},
		{name: "block", replace: "replace (\nexample.com/a => ../a\n)\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "go.mod")
			content := "module example.com/root\n\ngo 1.25\n\nrequire example.com/a v1.0.0\n\n" + test.replace
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := readRequiredModules(path)
			if err == nil || !strings.Contains(err.Error(), "replacements are not supported") {
				t.Fatalf("readRequiredModules() error = %v", err)
			}
		})
	}
}

func TestBoundedInputsRejectContentAfterLimit(t *testing.T) {
	validHash := strings.Repeat("a", sha256.Size*2)
	tests := []struct {
		name   string
		limit  int
		prefix string
		suffix string
		invoke func(string) error
		want   string
	}{
		{
			name: "manifest", limit: maxManifestBytes,
			prefix: `{"schema":1,"modules":[{"path":"example.com/a","version":"v1.0.0","zip_sha256":"` + validHash + `"}]}`,
			invoke: func(path string) error { _, err := readManifest(path); return err }, want: "dependency manifest exceeds",
		},
		{
			name: "go.mod replacement after limit", limit: maxGoModBytes,
			prefix: "module example.com/root\n\ngo 1.25\n\nrequire example.com/a v1.0.0\n",
			suffix: "\nreplace example.com/a => ../local\n",
			invoke: func(path string) error { _, err := readRequiredModules(path); return err }, want: "go.mod exceeds",
		},
		{
			name: "go.sum duplicate after limit", limit: maxGoSumBytes,
			prefix: "example.com/a v1.0.0 h1:zip\nexample.com/a v1.0.0/go.mod h1:mod\n",
			suffix: "\nexample.com/a v1.0.0 h1:zip\n",
			invoke: func(path string) error {
				return verifyGoSum(path, []module{{Path: "example.com/a", Version: "v1.0.0"}})
			}, want: "go.sum exceeds",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			padding := test.limit + 1 - len(test.prefix) - len(test.suffix)
			if padding < 0 {
				t.Fatal("invalid oversized fixture")
			}
			content := test.prefix + strings.Repeat(" ", padding) + test.suffix
			path := filepath.Join(t.TempDir(), "input")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			err := test.invoke(path)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("bounded reader error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestReadRequiredModulesParsesTheCompleteRequireClosure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "go.mod")
	content := `module example.com/root

go 1.25

require example.com/single v1.0.0

require (
	example.com/direct v1.1.0
	example.com/indirect v1.2.0 // indirect
)
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readRequiredModules(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []module{
		{Path: "example.com/single", Version: "v1.0.0"},
		{Path: "example.com/direct", Version: "v1.1.0"},
		{Path: "example.com/indirect", Version: "v1.2.0"},
	}
	if len(got) != len(want) {
		t.Fatalf("readRequiredModules() = %#v, want %#v", got, want)
	}
	for index := range want {
		if got[index].Path != want[index].Path || got[index].Version != want[index].Version {
			t.Fatalf("readRequiredModules()[%d] = %#v, want %#v", index, got[index], want[index])
		}
	}
}

func TestCompareClosureRejectsDrift(t *testing.T) {
	tests := []struct {
		name     string
		locked   []module
		required []module
		want     string
	}{
		{name: "missing", required: []module{{Path: "example.com/a", Version: "v1.0.0"}}, want: "missing example.com/a@v1.0.0"},
		{name: "extra", locked: []module{{Path: "example.com/a", Version: "v1.0.0"}}, want: "extra example.com/a@v1.0.0"},
		{name: "version", locked: []module{{Path: "example.com/a", Version: "v1.0.0"}}, required: []module{{Path: "example.com/a", Version: "v1.1.0"}}, want: "version mismatch"},
		{name: "duplicate requirement", locked: []module{{Path: "example.com/a", Version: "v1.0.0"}}, required: []module{{Path: "example.com/a", Version: "v1.0.0"}, {Path: "example.com/a", Version: "v1.0.0"}}, want: "more than once"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := compareClosure(test.locked, test.required)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("compareClosure() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestVerifyGoSumRequiresZipAndModuleHashes(t *testing.T) {
	dependency := module{Path: "example.com/a", Version: "v1.0.0"}
	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{name: "both", content: "example.com/a v1.0.0 h1:zip\nexample.com/a v1.0.0/go.mod h1:mod\n"},
		{name: "missing zip", content: "example.com/a v1.0.0/go.mod h1:mod\n", wantErr: true},
		{name: "duplicate", content: "example.com/a v1.0.0 h1:zip\nexample.com/a v1.0.0 h1:zip\nexample.com/a v1.0.0/go.mod h1:mod\n", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "go.sum")
			if err := os.WriteFile(path, []byte(test.content), 0o600); err != nil {
				t.Fatal(err)
			}
			err := verifyGoSum(path, []module{dependency})
			if (err != nil) != test.wantErr {
				t.Fatalf("verifyGoSum() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestVerifyModuleZip(t *testing.T) {
	ctx := context.Background()
	validPath, validHash := writeModuleZip(t, "example.com/a", "v1.0.0", map[string]string{
		"go.mod": "module example.com/a\n\ngo 1.25\n",
		"a.go":   "package a\n",
	})
	tests := []struct {
		name       string
		path       string
		dependency module
		want       string
	}{
		{name: "valid", path: validPath, dependency: module{Path: "example.com/a", Version: "v1.0.0", ZipSHA256: validHash}},
		{name: "digest mismatch", path: validPath, dependency: module{Path: "example.com/a", Version: "v1.0.0", ZipSHA256: strings.Repeat("0", 64)}, want: "digest mismatch"},
	}
	unsafePath, unsafeHash := writeRawZip(t, map[string]string{
		"example.com/a@v1.0.0/go.mod":    "module example.com/a\n",
		"example.com/a@v1.0.0/../bad.go": "package bad\n",
	})
	tests = append(tests, struct {
		name       string
		path       string
		dependency module
		want       string
	}{name: "unsafe entry", path: unsafePath, dependency: module{Path: "example.com/a", Version: "v1.0.0", ZipSHA256: unsafeHash}, want: "unsafe entry"})
	wrongModulePath, wrongModuleHash := writeModuleZip(t, "example.com/a", "v1.0.0", map[string]string{
		"go.mod": "module example.com/b\n",
	})
	tests = append(tests, struct {
		name       string
		path       string
		dependency module
		want       string
	}{name: "wrong module", path: wrongModulePath, dependency: module{Path: "example.com/a", Version: "v1.0.0", ZipSHA256: wrongModuleHash}, want: "declares module"})
	symlinkPath, symlinkHash := writeZipEntries(t, []zipEntry{
		{name: "example.com/a@v1.0.0/go.mod", content: "module example.com/a\n"},
		{name: "example.com/a@v1.0.0/link", content: "../../outside", mode: os.ModeSymlink | 0o777},
	})
	tests = append(tests, struct {
		name       string
		path       string
		dependency module
		want       string
	}{name: "symbolic link entry", path: symlinkPath, dependency: module{Path: "example.com/a", Version: "v1.0.0", ZipSHA256: symlinkHash}, want: "unsafe entry"})
	duplicatePath, duplicateHash := writeZipEntries(t, []zipEntry{
		{name: "example.com/a@v1.0.0/go.mod", content: "module example.com/a\n"},
		{name: "example.com/a@v1.0.0/a.go", content: "package a\n"},
		{name: "example.com/a@v1.0.0/a.go", content: "package different\n"},
	})
	tests = append(tests, struct {
		name       string
		path       string
		dependency module
		want       string
	}{name: "duplicate archive entry", path: duplicatePath, dependency: module{Path: "example.com/a", Version: "v1.0.0", ZipSHA256: duplicateHash}, want: "duplicate archive entry"})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := verifyModuleZip(ctx, test.path, test.dependency)
			if test.want == "" && err != nil {
				t.Fatal(err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("verifyModuleZip() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestVerifyModuleZipRejectsSourceSymlink(t *testing.T) {
	target, digest := writeModuleZip(t, "example.com/a", "v1.0.0", map[string]string{
		"go.mod": "module example.com/a\n",
	})
	link := filepath.Join(t.TempDir(), "module.zip")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	_, err := verifyModuleZip(context.Background(), link, module{Path: "example.com/a", Version: "v1.0.0", ZipSHA256: digest})
	if err == nil || !strings.Contains(err.Error(), "without following symlinks") {
		t.Fatalf("verifyModuleZip() error = %v, want symlink rejection", err)
	}
}

func TestSnapshotModuleZipUsesOpenedDescriptorAfterPathReplacement(t *testing.T) {
	source, digest := writeModuleZip(t, "example.com/a", "v1.0.0", map[string]string{
		"go.mod": "module example.com/a\n",
		"a.go":   "package a\nconst Value = \"original\"\n",
	})
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	replacement, _ := writeModuleZip(t, "example.com/a", "v1.0.0", map[string]string{
		"go.mod": "module example.com/a\n",
		"a.go":   "package a\nconst Value = \"replacement\"\n",
	})
	snapshot := filepath.Join(t.TempDir(), "snapshot.zip")
	_, err = snapshotModuleZip(
		context.Background(), source, snapshot,
		module{Path: "example.com/a", Version: "v1.0.0", ZipSHA256: digest},
		func() {
			if renameErr := os.Rename(replacement, source); renameErr != nil {
				t.Fatalf("replace source path after open: %v", renameErr)
			}
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("snapshot followed the replaced path instead of the opened descriptor")
	}
}

func TestCheckStagesVendorAndUsesOfflineBuildEnvironment(t *testing.T) {
	root := t.TempDir()
	for _, directory := range []string{"cmd/youtrack-agent-cli", "internal/example", "assets"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		"go.mod":                         "module example.com/root\n\ngo 1.25\n\nrequire example.com/a v1.0.0\n",
		"go.sum":                         "example.com/a v1.0.0 h1:zip\nexample.com/a v1.0.0/go.mod h1:mod\n",
		"cmd/youtrack-agent-cli/main.go": "package main\nfunc main() {}\n",
		"internal/example/example.go":    "package example\n",
		"assets/embed.go":                "package assets\n",
	}
	for path, content := range files {
		if err := os.WriteFile(filepath.Join(root, path), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	proxyRoot := t.TempDir()
	zipPath, digest := writeModuleZipAt(t, proxyRoot, "example.com/a", "v1.0.0", map[string]string{
		"go.mod": "module example.com/a\n\ngo 1.25\n",
		"a.go":   "package a\n",
	})
	proxyZip := filepath.Join(proxyRoot, "example.com", "a", "@v", "v1.0.0.zip")
	if err := os.MkdirAll(filepath.Dir(proxyZip), 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proxyZip, data, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "modules.json")
	manifestBytes, err := json.Marshal(manifest{Schema: 1, Modules: []module{{Path: "example.com/a", Version: "v1.0.0", ZipSHA256: digest}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{t: t}
	if err := check(context.Background(), checkOptions{
		Root: root, ManifestPath: manifestPath, ProxyDir: proxyRoot, Build: true,
	}, runner); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("got %d Go calls, want 2", len(runner.calls))
	}
	vendorCall := runner.calls[0]
	for key, want := range map[string]string{
		"CGO_ENABLED": "1",
		"GOAUTH":      "off",
		"GOENV":       "off",
		"GOFLAGS":     "-mod=mod",
		"GONOPROXY":   "",
		"GONOSUMDB":   "",
		"GOPRIVATE":   "",
		"GOSUMDB":     "off",
		"GOTOOLCHAIN": "local",
		"GOVCS":       "*:off",
		"GOWORK":      "off",
	} {
		assertEnv(t, vendorCall.env, key, want)
		assertSingleEnv(t, vendorCall.env, key)
	}
	for _, key := range []string{"GOCACHE", "GOMODCACHE", "GOPATH", "GOTMPDIR"} {
		if got := envValue(vendorCall.env, key); got == "" || !strings.Contains(got, "youtrack-homebrewcheck-") {
			t.Fatalf("vendor %s = %q, want isolated temporary path", key, got)
		}
	}
	if got := envValue(vendorCall.env, "GOPROXY"); !strings.HasPrefix(got, "file://") {
		t.Fatalf("vendor GOPROXY = %q, want file://", got)
	}
	buildCall := runner.calls[1]
	for key, want := range map[string]string{
		"CGO_ENABLED": "1",
		"GOAUTH":      "off",
		"GOENV":       "off",
		"GOFLAGS":     "-mod=vendor -trimpath",
		"GONOPROXY":   "",
		"GONOSUMDB":   "",
		"GOPRIVATE":   "",
		"GOPROXY":     "off",
		"GOSUMDB":     "off",
		"GOTOOLCHAIN": "local",
		"GOVCS":       "*:off",
		"GOWORK":      "off",
	} {
		assertEnv(t, buildCall.env, key, want)
		assertSingleEnv(t, buildCall.env, key)
	}
	if len(buildCall.args) != 6 || buildCall.args[0] != "build" || buildCall.args[1] != "-ldflags" || buildCall.args[3] != "-o" || buildCall.args[5] != "./cmd/youtrack-agent-cli" {
		t.Fatalf("unexpected build arguments: %q", buildCall.args)
	}
	for _, stamp := range []string{rehearsalVersion, rehearsalCommit, rehearsalCommitTime} {
		if !strings.Contains(buildCall.args[2], stamp) {
			t.Fatalf("build ldflags %q do not contain %q", buildCall.args[2], stamp)
		}
	}
	if len(runner.outputCalls) < 2 {
		t.Fatalf("got %d verification calls, want at least version and contract", len(runner.outputCalls))
	}
}

func TestSuccessfulEnvelopeRejectsContractBoundaryViolations(t *testing.T) {
	tests := []struct {
		name   string
		output string
		stderr string
		want   string
	}{
		{name: "invalid json", output: `{`, want: "decode JSON envelope"},
		{name: "trailing json", output: `{"ok":true,"v":1,"data":{}} {}`, want: "trailing JSON"},
		{name: "error envelope", output: `{"ok":false,"v":1,"data":{}}`, want: "invalid success envelope"},
		{name: "wrong envelope version", output: `{"ok":true,"v":2,"data":{}}`, want: "invalid success envelope"},
		{name: "missing data", output: `{"ok":true,"v":1}`, want: "invalid success envelope"},
		{name: "null data", output: `{"ok":true,"v":1,"data":null}`, want: "invalid success envelope"},
		{name: "forbidden error", output: `{"ok":true,"v":1,"data":{},"error":null}`, want: "forbidden error"},
		{name: "forbidden hint", output: `{"ok":true,"v":1,"data":{},"hint":null}`, want: "forbidden hint"},
		{name: "json only on stderr", stderr: `{"ok":true,"v":1,"data":{}}`, want: "wrote to stderr"},
		{name: "nonempty stderr with valid stdout", output: `{"ok":true,"v":1,"data":{}}`, stderr: "warning\n", want: "wrote to stderr"},
		{name: "null meta", output: `{"ok":true,"v":1,"data":{},"meta":null}`, want: "null envelope metadata"},
		{name: "wrong known meta type", output: `{"ok":true,"v":1,"data":{},"meta":{"count":1.0}}`, want: "metadata count"},
		{name: "null known string meta", output: `{"ok":true,"v":1,"data":{},"meta":{"profile":null}}`, want: "metadata profile"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := staticOutputRunner{stdout: []byte(test.output), stderr: []byte(test.stderr)}
			_, err := successfulEnvelope(context.Background(), runner, t.TempDir(), nil, "fixture", "contract", "-o", "json")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("successfulEnvelope() error = %v, want containing %q", err, test.want)
			}
		})
	}
	t.Run("unknown additive fields are allowed by v1", func(t *testing.T) {
		runner := staticOutputRunner{stdout: []byte(`{"ok":true,"v":1,"data":{},"future":true,"meta":{"future":null}}`)}
		if _, err := successfulEnvelope(context.Background(), runner, t.TempDir(), nil, "fixture", "contract", "-o", "json"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestVerifyBuiltBinaryFailsClosedAtVerificationSeams(t *testing.T) {
	validVersion := `{"ok":true,"v":1,"data":{"version":"` + rehearsalVersion + `","commit":"` + rehearsalCommit + `","commit_time":"` + rehearsalCommitTime + `"}}`
	validContract := `{"ok":true,"v":1,"data":{"envelope_version":1,"codes":[{"code":0}]}}`
	tests := []struct {
		name           string
		version        string
		contract       string
		linkage        string
		binaryContents string
		want           string
		darwinOnly     bool
	}{
		{name: "wrong provenance", version: strings.Replace(validVersion, rehearsalCommit, "wrong-commit", 1), contract: validContract, want: "did not preserve injected Homebrew provenance"},
		{name: "empty contract codes", version: validVersion, contract: `{"ok":true,"v":1,"data":{"envelope_version":1,"codes":[]}}`, want: "invalid v1 contract"},
		{name: "missing Security framework", version: validVersion, contract: validContract, linkage: "/usr/lib/libSystem.B.dylib\n", want: "not linked to Security.framework", darwinOnly: true},
		{name: "security subprocess path", version: validVersion, contract: validContract, linkage: "/System/Library/Frameworks/Security.framework/Versions/A/Security\n", binaryContents: "fixture /usr/bin/security fixture", want: "forbidden /usr/bin/security dependency", darwinOnly: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.darwinOnly && runtime.GOOS != "darwin" {
				t.Skip("Darwin linkage verification is platform-specific")
			}
			binary := filepath.Join(t.TempDir(), "youtrack-agent-cli")
			contents := test.binaryContents
			if contents == "" {
				contents = "fixture binary"
			}
			if err := os.WriteFile(binary, []byte(contents), 0o700); err != nil {
				t.Fatal(err)
			}
			runner := verificationRunner{
				version:  []byte(test.version),
				contract: []byte(test.contract),
				linkage:  []byte(test.linkage),
			}
			err := verifyBuiltBinary(context.Background(), runner, binary, nil, t.TempDir())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("verifyBuiltBinary() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

type recordedCall struct {
	dir  string
	env  []string
	name string
	args []string
}

type recordingRunner struct {
	t           *testing.T
	calls       []recordedCall
	outputCalls []recordedCall
}

type staticOutputRunner struct {
	stdout []byte
	stderr []byte
	err    error
}

func (staticOutputRunner) Run(context.Context, string, []string, string, ...string) error {
	return errors.New("unexpected Run call")
}

func (runner staticOutputRunner) Output(context.Context, string, []string, string, ...string) (commandOutput, error) {
	return commandOutput{Stdout: runner.stdout, Stderr: runner.stderr}, runner.err
}

type verificationRunner struct {
	version  []byte
	contract []byte
	linkage  []byte
	stderr   []byte
}

func (verificationRunner) Run(context.Context, string, []string, string, ...string) error {
	return errors.New("unexpected Run call")
}

func (runner verificationRunner) Output(_ context.Context, _ string, _ []string, name string, args ...string) (commandOutput, error) {
	joined := strings.Join(args, " ")
	switch {
	case joined == "version -o json":
		return commandOutput{Stdout: runner.version, Stderr: runner.stderr}, nil
	case joined == "contract -o json":
		return commandOutput{Stdout: runner.contract, Stderr: runner.stderr}, nil
	case name == "/usr/bin/otool" && joined != "":
		return commandOutput{Stdout: runner.linkage, Stderr: runner.stderr}, nil
	default:
		return commandOutput{}, errors.New("unexpected Output call")
	}
}

func (runner *recordingRunner) Run(_ context.Context, dir string, env []string, name string, args ...string) error {
	runner.calls = append(runner.calls, recordedCall{dir: dir, env: append([]string(nil), env...), name: name, args: append([]string(nil), args...)})
	if strings.Join(args, " ") == "mod vendor" {
		vendorDir := filepath.Join(dir, "vendor")
		if err := os.MkdirAll(vendorDir, 0o755); err != nil {
			runner.t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(vendorDir, "modules.txt"), []byte("fixture\n"), 0o600); err != nil {
			runner.t.Fatal(err)
		}
	}
	if len(args) == 6 && args[0] == "build" {
		if err := os.WriteFile(args[4], []byte("fixture binary"), 0o700); err != nil {
			runner.t.Fatal(err)
		}
	}
	return nil
}

func (runner *recordingRunner) Output(_ context.Context, dir string, env []string, name string, args ...string) (commandOutput, error) {
	runner.outputCalls = append(runner.outputCalls, recordedCall{dir: dir, env: append([]string(nil), env...), name: name, args: append([]string(nil), args...)})
	joined := strings.Join(args, " ")
	switch {
	case joined == "version -o json":
		return commandOutput{Stdout: []byte(`{"ok":true,"v":1,"data":{"version":"` + rehearsalVersion + `","commit":"` + rehearsalCommit + `","commit_time":"` + rehearsalCommitTime + `","go":"go-test","os":"darwin","arch":"arm64"}}` + "\n")}, nil
	case joined == "contract -o json":
		return commandOutput{Stdout: []byte(`{"ok":true,"v":1,"data":{"envelope_version":1,"codes":[{"code":0}]}}` + "\n")}, nil
	case len(args) == 2 && args[0] == "-L":
		return commandOutput{Stdout: []byte(name + ":\n\t/System/Library/Frameworks/Security.framework/Versions/A/Security\n")}, nil
	default:
		runner.t.Fatalf("unexpected output call: %s %s", name, joined)
		return commandOutput{}, nil
	}
}

func writeModuleZip(t *testing.T, modulePath, version string, files map[string]string) (string, string) {
	t.Helper()
	return writeModuleZipAt(t, t.TempDir(), modulePath, version, files)
}

func writeModuleZipAt(t *testing.T, directory, modulePath, version string, files map[string]string) (string, string) {
	t.Helper()
	prefixed := make(map[string]string, len(files))
	for path, content := range files {
		prefixed[modulePath+"@"+version+"/"+path] = content
	}
	return writeRawZipAt(t, directory, prefixed)
}

func writeRawZip(t *testing.T, files map[string]string) (string, string) {
	t.Helper()
	return writeRawZipAt(t, t.TempDir(), files)
}

func writeRawZipAt(t *testing.T, directory string, files map[string]string) (string, string) {
	t.Helper()
	path := filepath.Join(directory, "module.zip")
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sortStrings(paths)
	for _, path := range paths {
		writer, err := archive.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(files[path])); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(buffer.Bytes())
	return path, hex.EncodeToString(digest[:])
}

type zipEntry struct {
	name    string
	content string
	mode    os.FileMode
}

func writeZipEntries(t *testing.T, entries []zipEntry) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "module.zip")
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
		if entry.mode != 0 {
			header.SetMode(entry.mode)
		}
		writer, err := archive.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(entry.content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(buffer.Bytes())
	return path, hex.EncodeToString(digest[:])
}

func sortStrings(values []string) {
	for index := 1; index < len(values); index++ {
		for current := index; current > 0 && values[current] < values[current-1]; current-- {
			values[current], values[current-1] = values[current-1], values[current]
		}
	}
}

func assertEnv(t *testing.T, env []string, key, want string) {
	t.Helper()
	if got := envValue(env, key); got != want {
		t.Fatalf("%s = %q, want %q", key, got, want)
	}
}

func assertSingleEnv(t *testing.T, env []string, key string) {
	t.Helper()
	prefix := key + "="
	count := 0
	for _, item := range env {
		if strings.HasPrefix(item, prefix) {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("%s occurs %d times in environment, want exactly once", key, count)
	}
}

func envValue(env []string, key string) string {
	prefix := key + "="
	for _, item := range env {
		if strings.HasPrefix(item, prefix) {
			return strings.TrimPrefix(item, prefix)
		}
	}
	return ""
}
