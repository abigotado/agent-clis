package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const manifestSchema = 1

const maxProxyZipSize = 256 << 20

const (
	maxManifestBytes = 1 << 20
	maxGoModBytes    = 1 << 20
	maxGoSumBytes    = 4 << 20
)

const (
	rehearsalVersion    = "v0.0.0-homebrewcheck"
	rehearsalCommit     = "0000000000000000000000000000000000000000"
	rehearsalCommitTime = "2000-01-01T00:00:00Z"
)

type module struct {
	Path      string `json:"path"`
	Version   string `json:"version"`
	ZipSHA256 string `json:"zip_sha256"`
}

type manifest struct {
	Schema  int      `json:"schema"`
	Modules []module `json:"modules"`
}

type checkOptions struct {
	Root         string
	ManifestPath string
	ProxyDir     string
	Build        bool
}

type runner interface {
	Run(ctx context.Context, dir string, env []string, name string, args ...string) error
	Output(ctx context.Context, dir string, env []string, name string, args ...string) (commandOutput, error)
}

type commandOutput struct {
	Stdout []byte
	Stderr []byte
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, dir string, env []string, name string, args ...string) error {
	command := exec.CommandContext(ctx, name, args...)
	command.Dir = dir
	command.Env = env
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("run %s: %w", strings.Join(append([]string{name}, args...), " "), err)
	}
	return nil
}

func (execRunner) Output(ctx context.Context, dir string, env []string, name string, args ...string) (commandOutput, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Dir = dir
	command.Env = env
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if err != nil {
		diagnostic := strings.TrimSpace(stderr.String())
		if diagnostic == "" {
			diagnostic = strings.TrimSpace(stdout.String())
		}
		return commandOutput{}, fmt.Errorf("run %s: %w: %s", strings.Join(append([]string{name}, args...), " "), err, diagnostic)
	}
	return commandOutput{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, nil
}

func check(ctx context.Context, options checkOptions, commandRunner runner) error {
	root := options.Root
	if root == "" {
		var err error
		root, err = repositoryRoot()
		if err != nil {
			return err
		}
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve repository root: %w", err)
	}
	manifestPath := options.ManifestPath
	if manifestPath == "" {
		manifestPath = filepath.Join(root, "packaging", "homebrew", "modules.json")
	}
	locked, err := readManifest(manifestPath)
	if err != nil {
		return err
	}
	required, err := readRequiredModules(filepath.Join(root, "go.mod"))
	if err != nil {
		return err
	}
	if err := compareClosure(locked.Modules, required); err != nil {
		return err
	}
	if err := verifyGoSum(filepath.Join(root, "go.sum"), locked.Modules); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	proxyDir, err := filepath.Abs(options.ProxyDir)
	if err != nil {
		return fmt.Errorf("resolve proxy directory: %w", err)
	}
	tempDir, err := os.MkdirTemp("", "youtrack-homebrewcheck-")
	if err != nil {
		return fmt.Errorf("create temporary workspace: %w", err)
	}
	defer func() {
		// The workspace contains only public source and dependency archives.
		_ = os.RemoveAll(tempDir)
	}()
	syntheticProxy := filepath.Join(tempDir, "proxy")
	if err := stageProxy(ctx, proxyDir, syntheticProxy, locked.Modules); err != nil {
		return err
	}
	buildRoot := filepath.Join(tempDir, "source")
	if err := stageSource(ctx, root, buildRoot); err != nil {
		return err
	}
	if err := deriveVendor(ctx, commandRunner, buildRoot, syntheticProxy, tempDir); err != nil {
		return err
	}
	if options.Build {
		if err := rehearseBuild(ctx, commandRunner, buildRoot, tempDir); err != nil {
			return err
		}
	}
	return nil
}

func readManifest(path string) (manifest, error) {
	content, err := readBoundedFile(path, maxManifestBytes, "dependency manifest")
	if err != nil {
		return manifest{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var result manifest
	if err := decoder.Decode(&result); err != nil {
		return manifest{}, fmt.Errorf("decode dependency manifest: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return manifest{}, err
	}
	if result.Schema != manifestSchema {
		return manifest{}, fmt.Errorf("unsupported dependency manifest schema %d", result.Schema)
	}
	if len(result.Modules) == 0 {
		return manifest{}, fmt.Errorf("dependency manifest has no modules")
	}
	seen := make(map[string]struct{}, len(result.Modules))
	previous := ""
	for index, dependency := range result.Modules {
		key := dependency.Path + "@" + dependency.Version
		if dependency.Path == "" || dependency.Version == "" {
			return manifest{}, fmt.Errorf("module %d has an empty path or version", index)
		}
		if _, err := hex.DecodeString(dependency.ZipSHA256); err != nil || len(dependency.ZipSHA256) != sha256.Size*2 || dependency.ZipSHA256 != strings.ToLower(dependency.ZipSHA256) {
			return manifest{}, fmt.Errorf("module %s has an invalid zip_sha256", key)
		}
		if _, exists := seen[dependency.Path]; exists {
			return manifest{}, fmt.Errorf("duplicate module path %q", dependency.Path)
		}
		seen[dependency.Path] = struct{}{}
		if previous != "" && dependency.Path <= previous {
			return manifest{}, fmt.Errorf("modules must be sorted by path")
		}
		previous = dependency.Path
	}
	return result, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing json.RawMessage
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("decode trailing manifest data: %w", err)
	}
	return fmt.Errorf("dependency manifest contains trailing JSON")
}

func readRequiredModules(path string) ([]module, error) {
	content, err := readBoundedFile(path, maxGoModBytes, "go.mod")
	if err != nil {
		return nil, err
	}
	var modules []module
	inRequireBlock := false
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "replace" {
			return nil, fmt.Errorf("go.mod replacements are not supported by Homebrew readiness checks")
		}
		if line == "require (" {
			if inRequireBlock {
				return nil, fmt.Errorf("go.mod contains a nested require block")
			}
			inRequireBlock = true
			continue
		}
		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}
		if inRequireBlock {
			dependency, err := parseRequireFields(fields)
			if err != nil {
				return nil, err
			}
			modules = append(modules, dependency)
			continue
		}
		if len(fields) > 0 && fields[0] == "require" {
			dependency, err := parseRequireFields(fields[1:])
			if err != nil {
				return nil, err
			}
			modules = append(modules, dependency)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan go.mod: %w", err)
	}
	if inRequireBlock {
		return nil, fmt.Errorf("go.mod has an unterminated require block")
	}
	if len(modules) == 0 {
		return nil, fmt.Errorf("go.mod has no required modules")
	}
	return modules, nil
}

func parseRequireFields(fields []string) (module, error) {
	if len(fields) < 2 || (len(fields) > 2 && !(len(fields) == 4 && fields[2] == "//" && fields[3] == "indirect")) {
		return module{}, fmt.Errorf("unsupported require directive %q", strings.Join(fields, " "))
	}
	return module{Path: fields[0], Version: fields[1]}, nil
}

func compareClosure(locked, required []module) error {
	lockedByPath := make(map[string]string, len(locked))
	for _, dependency := range locked {
		lockedByPath[dependency.Path] = dependency.Version
	}
	requiredByPath := make(map[string]string, len(required))
	for _, dependency := range required {
		if _, exists := requiredByPath[dependency.Path]; exists {
			return fmt.Errorf("go.mod requires module %q more than once", dependency.Path)
		}
		requiredByPath[dependency.Path] = dependency.Version
	}
	var differences []string
	for path, version := range requiredByPath {
		lockedVersion, exists := lockedByPath[path]
		switch {
		case !exists:
			differences = append(differences, fmt.Sprintf("missing %s@%s", path, version))
		case lockedVersion != version:
			differences = append(differences, fmt.Sprintf("version mismatch %s: manifest %s, go.mod %s", path, lockedVersion, version))
		}
	}
	for path, version := range lockedByPath {
		if _, exists := requiredByPath[path]; !exists {
			differences = append(differences, fmt.Sprintf("extra %s@%s", path, version))
		}
	}
	if len(differences) > 0 {
		sort.Strings(differences)
		return fmt.Errorf("dependency manifest does not match go.mod: %s", strings.Join(differences, "; "))
	}
	return nil
}

func verifyGoSum(path string, modules []module) error {
	content, err := readBoundedFile(path, maxGoSumBytes, "go.sum")
	if err != nil {
		return err
	}
	wanted := make(map[string]int, len(modules)*2)
	for _, dependency := range modules {
		wanted[dependency.Path+" "+dependency.Version] = 0
		wanted[dependency.Path+" "+dependency.Version+"/go.mod"] = 0
	}
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 || !strings.HasPrefix(fields[2], "h1:") {
			return fmt.Errorf("go.sum contains an invalid line")
		}
		key := fields[0] + " " + fields[1]
		if _, exists := wanted[key]; exists {
			wanted[key]++
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan go.sum: %w", err)
	}
	var problems []string
	for key, count := range wanted {
		if count != 1 {
			problems = append(problems, fmt.Sprintf("%s occurs %d times", key, count))
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("go.sum does not cover the dependency manifest exactly: %s", strings.Join(problems, "; "))
	}
	return nil
}

func readBoundedFile(path string, limit int64, label string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", label, err)
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	if int64(len(content)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", label, limit)
	}
	return content, nil
}

func stageProxy(ctx context.Context, source, destination string, modules []module) error {
	for _, dependency := range modules {
		if err := ctx.Err(); err != nil {
			return err
		}
		escapedPath, err := escapeProxyValue(dependency.Path)
		if err != nil {
			return fmt.Errorf("escape module path %q: %w", dependency.Path, err)
		}
		escapedVersion, err := escapeProxyValue(dependency.Version)
		if err != nil {
			return fmt.Errorf("escape module version %q: %w", dependency.Version, err)
		}
		sourceZip := filepath.Join(source, filepath.FromSlash(escapedPath), "@v", escapedVersion+".zip")
		targetDir := filepath.Join(destination, filepath.FromSlash(escapedPath), "@v")
		if err := os.MkdirAll(targetDir, 0o755); err != nil {
			return fmt.Errorf("create synthetic proxy directory: %w", err)
		}
		targetZip := filepath.Join(targetDir, escapedVersion+".zip")
		goMod, err := snapshotModuleZip(ctx, sourceZip, targetZip, dependency, nil)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(targetDir, escapedVersion+".mod"), goMod, 0o644); err != nil {
			return fmt.Errorf("write synthetic proxy go.mod: %w", err)
		}
		info := []byte(fmt.Sprintf("{\"Version\":%q}\n", dependency.Version))
		if err := os.WriteFile(filepath.Join(targetDir, escapedVersion+".info"), info, 0o644); err != nil {
			return fmt.Errorf("write synthetic proxy info: %w", err)
		}
	}
	return nil
}

func verifyModuleZip(ctx context.Context, path string, dependency module) ([]byte, error) {
	tempDir, err := os.MkdirTemp("", "youtrack-homebrew-zip-")
	if err != nil {
		return nil, fmt.Errorf("create module zip snapshot directory: %w", err)
	}
	defer func() {
		// The directory contains only a copied public module archive.
		_ = os.RemoveAll(tempDir)
	}()
	return snapshotModuleZip(ctx, path, filepath.Join(tempDir, "module.zip"), dependency, nil)
}

func snapshotModuleZip(ctx context.Context, sourcePath, snapshotPath string, dependency module, afterOpen func()) ([]byte, error) {
	source, err := openNoFollow(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("open staged proxy zip for %s@%s without following symlinks: %w", dependency.Path, dependency.Version, err)
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat staged proxy zip for %s@%s: %w", dependency.Path, dependency.Version, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("staged proxy zip for %s@%s is not a regular file", dependency.Path, dependency.Version)
	}
	if info.Size() > maxProxyZipSize {
		return nil, fmt.Errorf("staged proxy zip for %s@%s exceeds %d bytes", dependency.Path, dependency.Version, maxProxyZipSize)
	}
	if afterOpen != nil {
		afterOpen()
	}
	snapshot, err := os.OpenFile(snapshotPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return nil, fmt.Errorf("create checker-owned proxy zip snapshot: %w", err)
	}
	closed := false
	keep := false
	defer func() {
		if !closed {
			_ = snapshot.Close()
		}
		if !keep {
			_ = os.Remove(snapshotPath)
		}
	}()
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(snapshot, hash), io.LimitReader(&contextReader{ctx: ctx, reader: source}, maxProxyZipSize+1))
	closeErr := snapshot.Close()
	closed = true
	if copyErr != nil {
		return nil, fmt.Errorf("snapshot staged proxy zip for %s@%s: %w", dependency.Path, dependency.Version, copyErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close checker-owned proxy zip snapshot: %w", closeErr)
	}
	if written > maxProxyZipSize {
		return nil, fmt.Errorf("staged proxy zip for %s@%s exceeds %d bytes", dependency.Path, dependency.Version, maxProxyZipSize)
	}
	got := hex.EncodeToString(hash.Sum(nil))
	if got != strings.ToLower(dependency.ZipSHA256) {
		return nil, fmt.Errorf("staged proxy zip digest mismatch for %s@%s: got %s", dependency.Path, dependency.Version, got)
	}
	goMod, err := inspectModuleZip(snapshotPath, dependency)
	if err != nil {
		return nil, err
	}
	keep = true
	return goMod, nil
}

func inspectModuleZip(path string, dependency module) ([]byte, error) {
	archive, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("open staged proxy archive for %s@%s: %w", dependency.Path, dependency.Version, err)
	}
	defer archive.Close()
	prefix := dependency.Path + "@" + dependency.Version + "/"
	var goMod []byte
	seenEntries := make(map[string]struct{}, len(archive.File))
	for _, entry := range archive.File {
		if !strings.HasPrefix(entry.Name, prefix) {
			return nil, fmt.Errorf("staged proxy zip for %s@%s has an invalid entry %q", dependency.Path, dependency.Version, entry.Name)
		}
		relative := strings.TrimPrefix(entry.Name, prefix)
		if relative == "" || !validArchivePath(relative) || !entry.Mode().IsRegular() {
			return nil, fmt.Errorf("staged proxy zip for %s@%s has an unsafe entry %q", dependency.Path, dependency.Version, entry.Name)
		}
		if _, exists := seenEntries[relative]; exists {
			return nil, fmt.Errorf("staged proxy zip for %s@%s contains duplicate archive entry %q", dependency.Path, dependency.Version, entry.Name)
		}
		seenEntries[relative] = struct{}{}
		if relative != "go.mod" {
			continue
		}
		if goMod != nil {
			return nil, fmt.Errorf("staged proxy zip for %s@%s contains duplicate go.mod files", dependency.Path, dependency.Version)
		}
		reader, err := entry.Open()
		if err != nil {
			return nil, fmt.Errorf("open go.mod in staged proxy zip: %w", err)
		}
		goMod, err = io.ReadAll(io.LimitReader(reader, (1<<20)+1))
		closeErr := reader.Close()
		if err != nil {
			return nil, fmt.Errorf("read go.mod in staged proxy zip: %w", err)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close go.mod in staged proxy zip: %w", closeErr)
		}
		if len(goMod) > 1<<20 {
			return nil, fmt.Errorf("go.mod in staged proxy zip for %s@%s exceeds 1 MiB", dependency.Path, dependency.Version)
		}
	}
	if goMod == nil {
		return nil, fmt.Errorf("staged proxy zip for %s@%s has no go.mod", dependency.Path, dependency.Version)
	}
	if declared := declaredModulePath(goMod); declared != dependency.Path {
		return nil, fmt.Errorf("staged proxy zip for %s@%s declares module %q", dependency.Path, dependency.Version, declared)
	}
	return goMod, nil
}

func declaredModulePath(goMod []byte) string {
	scanner := bufio.NewScanner(strings.NewReader(string(goMod)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && fields[0] == "module" {
			return strings.Trim(fields[1], "\"")
		}
	}
	return ""
}

func validArchivePath(path string) bool {
	if strings.Contains(path, "\\") || strings.HasPrefix(path, "/") {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func escapeProxyValue(value string) (string, error) {
	if value == "" || strings.Contains(value, "\\") {
		return "", fmt.Errorf("value is empty or contains a backslash")
	}
	parts := strings.Split(value, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("value contains an unsafe path segment")
		}
	}
	var escaped strings.Builder
	for _, character := range value {
		if character >= 'A' && character <= 'Z' {
			escaped.WriteByte('!')
			escaped.WriteRune(character + ('a' - 'A'))
			continue
		}
		escaped.WriteRune(character)
	}
	return escaped.String(), nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

func stageSource(ctx context.Context, root, destination string) error {
	if err := os.MkdirAll(destination, 0o755); err != nil {
		return fmt.Errorf("create staged source root: %w", err)
	}
	for _, relative := range []string{"go.mod", "go.sum", "cmd", "internal", "assets"} {
		if err := copyPath(ctx, filepath.Join(root, relative), filepath.Join(destination, relative)); err != nil {
			return fmt.Errorf("stage source %s: %w", relative, err)
		}
	}
	return nil
}

func copyPath(ctx context.Context, source, destination string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("symbolic links are not allowed: %s", source)
	}
	if info.IsDir() {
		if err := os.MkdirAll(destination, info.Mode().Perm()); err != nil {
			return err
		}
		entries, err := os.ReadDir(source)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := copyPath(ctx, filepath.Join(source, entry.Name()), filepath.Join(destination, entry.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("unsupported source file type: %s", source)
	}
	return copyFile(ctx, source, destination, info.Mode().Perm())
}

func copyFile(ctx context.Context, source, destination string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open %s: %w", source, err)
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", destination, err)
	}
	_, copyErr := io.Copy(output, &contextReader{ctx: ctx, reader: input})
	closeErr := output.Close()
	if copyErr != nil {
		return fmt.Errorf("copy %s: %w", source, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close %s: %w", destination, closeErr)
	}
	return nil
}

func deriveVendor(ctx context.Context, commandRunner runner, buildRoot, proxyDir, tempDir string) error {
	env, err := isolatedGoEnv(tempDir, "vendor")
	if err != nil {
		return err
	}
	env = replaceEnv(env, "GOPROXY", fileProxyURL(proxyDir))
	env = replaceEnv(env, "GOFLAGS", "-mod=mod")
	if err := commandRunner.Run(ctx, buildRoot, env, "go", "mod", "vendor"); err != nil {
		return fmt.Errorf("derive vendor tree from staged proxy: %w", err)
	}
	if _, err := os.Stat(filepath.Join(buildRoot, "vendor", "modules.txt")); err != nil {
		return fmt.Errorf("derived vendor metadata is missing: %w", err)
	}
	return nil
}

func rehearseBuild(ctx context.Context, commandRunner runner, buildRoot, tempDir string) error {
	env, err := isolatedGoEnv(tempDir, "build")
	if err != nil {
		return err
	}
	env = replaceEnv(env, "GOPROXY", "off")
	env = replaceEnv(env, "GOFLAGS", "-mod=vendor -trimpath")
	output := filepath.Join(tempDir, "youtrack-agent-cli")
	ldflags := strings.Join([]string{
		"-X", "github.com/abigotado/youtrack-agent-cli/internal/cli.releaseVersion=" + rehearsalVersion,
		"-X", "github.com/abigotado/youtrack-agent-cli/internal/cli.releaseCommit=" + rehearsalCommit,
		"-X", "github.com/abigotado/youtrack-agent-cli/internal/cli.releaseCommitTime=" + rehearsalCommitTime,
	}, " ")
	if err := commandRunner.Run(ctx, buildRoot, env, "go", "build", "-ldflags", ldflags, "-o", output, "./cmd/youtrack-agent-cli"); err != nil {
		return fmt.Errorf("rehearse offline Homebrew build: %w", err)
	}
	return verifyBuiltBinary(ctx, commandRunner, output, env, tempDir)
}

func verifyBuiltBinary(ctx context.Context, commandRunner runner, binary string, env []string, workDir string) error {
	versionData, err := successfulEnvelope(ctx, commandRunner, workDir, env, binary, "version", "-o", "json")
	if err != nil {
		return fmt.Errorf("verify version command: %w", err)
	}
	var version struct {
		Version    string `json:"version"`
		Commit     string `json:"commit"`
		CommitTime string `json:"commit_time"`
	}
	if err := json.Unmarshal(versionData, &version); err != nil {
		return fmt.Errorf("decode version data: %w", err)
	}
	if version.Version != rehearsalVersion || version.Commit != rehearsalCommit || version.CommitTime != rehearsalCommitTime {
		return fmt.Errorf("version command did not preserve injected Homebrew provenance")
	}
	contractData, err := successfulEnvelope(ctx, commandRunner, workDir, env, binary, "contract", "-o", "json")
	if err != nil {
		return fmt.Errorf("verify contract command: %w", err)
	}
	var contract struct {
		EnvelopeVersion int               `json:"envelope_version"`
		Codes           []json.RawMessage `json:"codes"`
	}
	if err := json.Unmarshal(contractData, &contract); err != nil {
		return fmt.Errorf("decode contract data: %w", err)
	}
	if contract.EnvelopeVersion != 1 || len(contract.Codes) == 0 {
		return fmt.Errorf("contract command returned an invalid v1 contract")
	}
	if runtime.GOOS != "darwin" {
		return nil
	}
	linked, err := commandRunner.Output(ctx, workDir, env, "/usr/bin/otool", "-L", binary)
	if err != nil {
		return fmt.Errorf("inspect Security.framework linkage: %w", err)
	}
	if len(linked.Stderr) != 0 {
		return fmt.Errorf("inspect Security.framework linkage: otool wrote to stderr")
	}
	if !bytes.Contains(linked.Stdout, []byte("/System/Library/Frameworks/Security.framework/")) {
		return fmt.Errorf("rehearsal binary is not linked to Security.framework")
	}
	binaryData, err := os.ReadFile(binary)
	if err != nil {
		return fmt.Errorf("read rehearsal binary: %w", err)
	}
	if bytes.Contains(binaryData, []byte("/usr/bin/security")) {
		return fmt.Errorf("rehearsal binary contains a forbidden /usr/bin/security dependency")
	}
	return nil
}

func successfulEnvelope(ctx context.Context, commandRunner runner, workDir string, env []string, binary string, args ...string) (json.RawMessage, error) {
	output, err := commandRunner.Output(ctx, workDir, env, binary, args...)
	if err != nil {
		return nil, err
	}
	if len(output.Stderr) != 0 {
		return nil, fmt.Errorf("command wrote to stderr while returning a success envelope")
	}
	decoder := json.NewDecoder(bytes.NewReader(output.Stdout))
	var envelope map[string]json.RawMessage
	if err := decoder.Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode JSON envelope: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, fmt.Errorf("validate JSON envelope: %w", err)
	}
	ok, exists := envelope["ok"]
	if !exists || !bytes.Equal(bytes.TrimSpace(ok), []byte("true")) {
		return nil, fmt.Errorf("command returned an invalid success envelope")
	}
	version, exists := envelope["v"]
	if !exists || !bytes.Equal(bytes.TrimSpace(version), []byte("1")) {
		return nil, fmt.Errorf("command returned an invalid success envelope")
	}
	data, exists := envelope["data"]
	if !exists || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil, fmt.Errorf("command returned an invalid success envelope")
	}
	if _, exists := envelope["error"]; exists {
		return nil, fmt.Errorf("command returned an invalid success envelope with forbidden error")
	}
	if _, exists := envelope["hint"]; exists {
		return nil, fmt.Errorf("command returned an invalid success envelope with forbidden hint")
	}
	if metadata, exists := envelope["meta"]; exists {
		if err := validateEnvelopeMetadata(metadata); err != nil {
			return nil, err
		}
	}
	return data, nil
}

func validateEnvelopeMetadata(raw json.RawMessage) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("command returned invalid null envelope metadata")
	}
	var metadata map[string]json.RawMessage
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return fmt.Errorf("command returned invalid envelope metadata: %w", err)
	}
	for name, value := range metadata {
		switch name {
		case "count":
			trimmed := bytes.TrimSpace(value)
			if len(trimmed) == 0 || strings.ContainsAny(string(trimmed), ".eE-") {
				return fmt.Errorf("command returned invalid envelope metadata count")
			}
			for _, character := range trimmed {
				if character < '0' || character > '9' {
					return fmt.Errorf("command returned invalid envelope metadata count")
				}
			}
		case "truncated":
			trimmed := bytes.TrimSpace(value)
			if !bytes.Equal(trimmed, []byte("true")) && !bytes.Equal(trimmed, []byte("false")) {
				return fmt.Errorf("command returned invalid envelope metadata truncated")
			}
		case "next_cursor", "profile", "instance", "account_id", "account_login":
			if trimmed := bytes.TrimSpace(value); len(trimmed) == 0 || trimmed[0] != '"' {
				return fmt.Errorf("command returned invalid envelope metadata %s", name)
			}
			var text string
			if err := json.Unmarshal(value, &text); err != nil {
				return fmt.Errorf("command returned invalid envelope metadata %s", name)
			}
		}
	}
	return nil
}

func isolatedGoEnv(tempDir, phase string) ([]string, error) {
	directories := map[string]string{
		"GOCACHE":    filepath.Join(tempDir, phase+"-gocache"),
		"GOMODCACHE": filepath.Join(tempDir, phase+"-gomodcache"),
		"GOPATH":     filepath.Join(tempDir, phase+"-gopath"),
		"GOTMPDIR":   filepath.Join(tempDir, phase+"-gotmp"),
	}
	for _, directory := range directories {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			return nil, fmt.Errorf("create isolated Go directory: %w", err)
		}
	}
	env := append([]string(nil), os.Environ()...)
	settings := map[string]string{
		"CGO_ENABLED": "1",
		"GOAUTH":      "off",
		"GOENV":       "off",
		"GOFLAGS":     "",
		"GONOPROXY":   "",
		"GONOSUMDB":   "",
		"GOPRIVATE":   "",
		"GOPROXY":     "off",
		"GOSUMDB":     "off",
		"GOTOOLCHAIN": "local",
		"GOVCS":       "*:off",
		"GOWORK":      "off",
	}
	for key, value := range directories {
		settings[key] = value
	}
	for key, value := range settings {
		env = replaceEnv(env, key, value)
	}
	return env, nil
}

func replaceEnv(env []string, key, value string) []string {
	prefix := key + "="
	result := make([]string, 0, len(env)+1)
	for _, item := range env {
		if !strings.HasPrefix(item, prefix) {
			result = append(result, item)
		}
	}
	return append(result, prefix+value)
}

func fileProxyURL(path string) string {
	return "file://" + filepath.ToSlash(path)
}

func repositoryRoot() (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory, nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", fmt.Errorf("no go.mod found above the working directory")
		}
		directory = parent
	}
}
