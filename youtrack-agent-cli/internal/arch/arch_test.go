package arch_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"
)

const module = "github.com/abigotado/youtrack-agent-cli"

type packageInfo struct {
	ImportPath string
	Imports    []string
	Deps       []string
}

func listedPackages(t *testing.T, pattern string) []packageInfo {
	t.Helper()
	command := exec.Command("go", "list", "-json", pattern)
	command.Dir = repositoryRoot(t)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(stdout)
	var result []packageInfo
	for {
		var value packageInfo
		err := decoder.Decode(&value)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("decode go list: %v", err)
		}
		result = append(result, value)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("go list %s: %v", pattern, err)
	}
	return result
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatal("repository root not found")
		}
		directory = parent
	}
}

func edges(names ...string) map[string]bool {
	result := make(map[string]bool, len(names))
	for _, name := range names {
		result[module+"/internal/"+name] = true
	}
	return result
}

func imports(names ...string) map[string]bool {
	result := make(map[string]bool, len(names))
	for _, name := range names {
		result[name] = true
	}
	return result
}

func TestInternalDependencyDAGIsExplicit(t *testing.T) {
	allowed := map[string]map[string]bool{
		module + "/internal/application":   edges("approval", "auth", "endpoint", "errx", "intent", "journal", "mutation", "oauth", "oauthrecovery", "operatorwrite", "profile", "skills", "writepolicy", "youtrack"),
		module + "/internal/approval":      edges("errx", "intent", "protocolvalue"),
		module + "/internal/arch":          {},
		module + "/internal/auth":          edges("profile"),
		module + "/internal/cli":           edges("application", "errx", "output"),
		module + "/internal/endpoint":      edges("protocolvalue"),
		module + "/internal/errx":          {},
		module + "/internal/gatecontract":  edges("protocolvalue"),
		module + "/internal/intent":        edges("endpoint", "protocolvalue"),
		module + "/internal/journal":       edges("errx", "intent", "lockfile"),
		module + "/internal/lockfile":      {},
		module + "/internal/mutation":      edges("errx", "intent"),
		module + "/internal/oauth":         edges("endpoint"),
		module + "/internal/oauthrecovery": edges("errx", "oauth"),
		module + "/internal/operatorwrite": edges("endpoint", "errx", "lockfile", "protocolvalue"),
		module + "/internal/output":        edges("errx"),
		module + "/internal/profile":       edges("endpoint", "lockfile"),
		module + "/internal/protocolvalue": {},
		module + "/internal/readonlycli":   edges("errx", "output", "profile", "skills"),
		module + "/internal/skills":        edges("errx", "lockfile"),
		module + "/internal/writepolicy":   edges("lockfile", "profile"),
		module + "/internal/youtrack":      edges("errx"),
	}

	packages := listedPackages(t, "./internal/...")
	for _, value := range packages {
		permitted, known := allowed[value.ImportPath]
		if !known {
			t.Errorf("internal package %s has no explicit DAG entry", value.ImportPath)
			continue
		}
		for _, imported := range value.Imports {
			if strings.HasPrefix(imported, module+"/internal/") && !permitted[imported] {
				t.Errorf("unlisted dependency edge %s -> %s", value.ImportPath, imported)
			}
		}
	}
	if len(packages) != len(allowed) {
		names := make([]string, 0, len(packages))
		for _, value := range packages {
			names = append(names, value.ImportPath)
		}
		sort.Strings(names)
		t.Fatalf("DAG inventory has %d entries for %d packages: %s", len(allowed), len(packages), strings.Join(names, ", "))
	}
}

func TestProcessEntryImportsOnlyCLIAndContract(t *testing.T) {
	allowed := map[string]bool{
		module + "/internal/cli":    true,
		module + "/internal/errx":   true,
		module + "/internal/output": true,
	}
	packages := listedPackages(t, "./cmd/youtrack-agent-cli")
	if len(packages) != 1 {
		t.Fatalf("listed %d command packages", len(packages))
	}
	for _, imported := range packages[0].Imports {
		if strings.HasPrefix(imported, module+"/internal/") && !allowed[imported] {
			t.Errorf("process entry bypasses CLI/application boundary through %s", imported)
		}
	}
}

func TestCLIDoesNotImportNetHTTP(t *testing.T) {
	packages := listedPackages(t, "./internal/cli")
	for _, imported := range packages[0].Imports {
		if imported == "net/http" {
			t.Fatal("internal/cli imports net/http")
		}
	}
}

func TestIsolatedGateContractRemainsPureAndDisconnected(t *testing.T) {
	const gatePackage = module + "/internal/gatecontract"
	allowed := map[string]map[string]bool{
		gatePackage: imports("bytes", "encoding/json", "errors", module+"/internal/protocolvalue"),
		module + "/internal/protocolvalue": imports(
			"crypto/sha256", "encoding/base32", "encoding/hex", "errors", "fmt", "strconv", "strings",
		),
	}
	for packagePath, permitted := range allowed {
		for _, imported := range allGoImports(t, packagePath) {
			if !permitted[imported] {
				t.Errorf("isolated Gate value package %s imports unapproved package %s", packagePath, imported)
			}
		}
	}
	// Inspect source imports, including platform-specific files, not test imports.
	// No current runtime consumer may treat a parsed syntax value as authority.
	for _, value := range listedPackages(t, "./...") {
		if value.ImportPath == gatePackage {
			continue
		}
		for _, imported := range allGoImports(t, value.ImportPath) {
			if imported == gatePackage {
				t.Errorf("runtime package %s imports the isolated Gate prerequisite", value.ImportPath)
			}
		}
	}
}

func TestApprovalProtocolHasNoProductionTransportImports(t *testing.T) {
	allowedInternal := edges("approval", "endpoint", "errx", "intent", "protocolvalue")
	allowedDirect := map[string]map[string]bool{
		module + "/internal/approval": imports(
			"bytes", "context", "crypto/ecdsa", "crypto/elliptic", "crypto/rand", "crypto/sha256", "crypto/subtle",
			"encoding/asn1", "encoding/base64", "encoding/binary", "encoding/hex", "encoding/json", "fmt", "io", "math/big", "time",
			module+"/internal/errx", module+"/internal/intent", module+"/internal/protocolvalue",
		),
		module + "/internal/endpoint": imports(
			"errors", "fmt", "net/netip", "net/url", "sort", "strconv", "strings", module+"/internal/protocolvalue",
		),
		module + "/internal/errx": imports("context", "errors", "fmt", "strings", "time"),
		module + "/internal/intent": imports(
			"bytes", "crypto/rand", "crypto/sha256", "encoding/base32", "encoding/hex", "encoding/json", "errors", "fmt", "io", "regexp", "sort", "strings", "unicode/utf8",
			module+"/internal/endpoint", module+"/internal/protocolvalue",
		),
		module + "/internal/protocolvalue": imports(
			"crypto/sha256", "encoding/base32", "encoding/hex", "errors", "fmt", "strconv", "strings",
		),
	}
	allPackages := listedPackages(t, "./internal/...")
	byPath := make(map[string]packageInfo, len(allPackages))
	for _, value := range allPackages {
		byPath[value.ImportPath] = value
	}
	root := byPath[module+"/internal/approval"]
	reachable := map[string]bool{root.ImportPath: true}
	for _, dependency := range root.Deps {
		if strings.HasPrefix(dependency, module+"/internal/") {
			reachable[dependency] = true
			if !allowedInternal[dependency] {
				t.Errorf("approval value protocol transitively imports unapproved internal package %s", dependency)
			}
		}
	}
	for packagePath := range reachable {
		_, ok := byPath[packagePath]
		if !ok {
			t.Errorf("approval dependency %s was not listed", packagePath)
			continue
		}
		allowed, ok := allowedDirect[packagePath]
		if !ok {
			t.Errorf("approval dependency %s has no direct-import allowlist", packagePath)
			continue
		}
		for _, imported := range allGoImports(t, packagePath) {
			if !allowed[imported] {
				t.Errorf("approval dependency %s directly imports unapproved package %s", packagePath, imported)
			}
		}
	}
	assertEndpointNetworkSelectors(t)
}

func allGoImports(t *testing.T, packagePath string) []string {
	t.Helper()
	relative := strings.TrimPrefix(packagePath, module+"/")
	files, err := filepath.Glob(filepath.Join(repositoryRoot(t), relative, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			seen[strings.Trim(spec.Path.Value, `"`)] = true
		}
	}
	result := make([]string, 0, len(seen))
	for imported := range seen {
		result = append(result, imported)
	}
	sort.Strings(result)
	return result
}

func assertEndpointNetworkSelectors(t *testing.T) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(repositoryRoot(t), "internal", "endpoint", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]map[string]bool{
		"net": {"ParseIP": true},
		"url": {"Parse": true, "ParseQuery": true, "URL": true},
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		aliases := map[string]string{}
		for _, spec := range file.Imports {
			importPath := strings.Trim(spec.Path.Value, `"`)
			if importPath != "net" && importPath != "net/url" {
				continue
			}
			alias := filepath.Base(importPath)
			if spec.Name != nil {
				alias = spec.Name.Name
			}
			if alias == "." || alias == "_" {
				t.Errorf("endpoint uses uninspectable %s import alias %q", importPath, alias)
				continue
			}
			aliases[alias] = filepath.Base(importPath)
		}
		file, err = parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			identifier, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			packageName, ok := aliases[identifier.Name]
			if ok && !allowed[packageName][selector.Sel.Name] {
				t.Errorf("endpoint uses unapproved %s selector %s in %s", packageName, selector.Sel.Name, filepath.Base(path))
			}
			return true
		})
	}
}

func TestNativeApprovalProtocolImportsArePinned(t *testing.T) {
	for _, path := range nativeApprovalSwiftSources(t) {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		tokens, err := lexSwift(string(raw))
		if err != nil {
			t.Errorf("tokenize %s: %v", filepath.Base(path), err)
			continue
		}
		imports, err := parseSwiftImports(tokens)
		if err != nil {
			t.Errorf("parse imports in %s: %v", filepath.Base(path), err)
			continue
		}
		if err := validateSwiftImports(imports); err != nil {
			t.Errorf("%s: %v", filepath.Base(path), err)
		}
	}
}

func TestNativeApprovalProtocolHasNoAmbientIOCapabilities(t *testing.T) {
	for _, path := range nativeApprovalSwiftSources(t) {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateSwiftCapabilities(string(raw)); err != nil {
			t.Errorf("%s: %v", filepath.Base(path), err)
		}
	}
}

func TestNativeApprovalSwiftPMManifestIsPinned(t *testing.T) {
	const expected = `// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "ApprovalProtocol",
    platforms: [
        .macOS(.v13),
    ],
    products: [
        .library(name: "ApprovalProtocol", targets: ["ApprovalProtocol"]),
    ],
    targets: [
        .target(name: "ApprovalProtocol"),
        .testTarget(name: "ApprovalProtocolTests", dependencies: ["ApprovalProtocol"]),
    ]
)`
	path := filepath.Join(repositoryRoot(t), "native", "macos", "ApprovalProtocol", "Package.swift")
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatal("ApprovalProtocol Package.swift must be a regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) != expected {
		t.Fatal("ApprovalProtocol Package.swift changed; review and re-pin its target path and sources")
	}
}

func TestSwiftImportGuardRequiresPinnedScopedFoundationSymbols(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{name: "allowed CryptoKit P256 enum", raw: "import enum CryptoKit.P256\n"},
		{name: "allowed CryptoKit SHA256 struct", raw: "import struct CryptoKit.SHA256\n"},
		{name: "allowed Foundation struct", raw: "import struct Foundation.Data\n"},
		{name: "allowed Foundation function", raw: "import func Foundation.floor\n"},
		{name: "BOM attributed access and semicolon", raw: "\ufeff@preconcurrency public import struct Foundation.Date; import struct CryptoKit.SHA256 // comment\n"},
		{name: "bare Foundation", raw: "import Foundation\n", wantErr: true},
		{name: "attributed bare Foundation", raw: "@_implementationOnly import Foundation\n", wantErr: true},
		{name: "unapproved Foundation symbol", raw: "import struct Foundation.URL\n", wantErr: true},
		{name: "unapproved module", raw: "internal import AppKit\n", wantErr: true},
		{name: "bare CryptoKit", raw: "import CryptoKit\n", wantErr: true},
		{name: "unapproved CryptoKit symbol", raw: "import struct CryptoKit.SymmetricKey\n", wantErr: true},
		{name: "CR comment before forbidden import", raw: "// inert\rimport Foundation\r", wantErr: true},
		{name: "malformed scoped import", raw: "import struct Foundation\n", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tokens, err := lexSwift(test.raw)
			if err == nil {
				var values []swiftImport
				values, err = parseSwiftImports(tokens)
				if err == nil {
					err = validateSwiftImports(values)
				}
			}
			if (err != nil) != test.wantErr {
				t.Fatalf("import guard error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestSwiftCapabilityGuardHostileAndNegativeControls(t *testing.T) {
	hostile := []struct {
		name string
		raw  string
	}{
		{name: "Process", raw: `let task = Process()`},
		{name: "backtick Process", raw: "let `Process` = 1"},
		{name: "NSTask", raw: `NSTask().launch()`},
		{name: "URLSession shared", raw: `URLSession.shared.dataTask(with: request)`},
		{name: "URLSession family", raw: `let task: URLSessionDataTask?`},
		{name: "NSURLSession shared", raw: `NSURLSession.sharedSession().dataTaskWithRequest(request)`},
		{name: "NSURLSession family", raw: `let task: NSURLSessionDataTask?`},
		{name: "NSURLConnection", raw: `NSURLConnection(request: request, delegate: nil)`},
		{name: "FileManager advisor", raw: `FileManager.default.createFile(atPath: "/tmp/x", contents: nil)`},
		{name: "NSFileManager", raw: `NSFileManager.defaultManager().createFileAtPath("/tmp/x", contents: nil)`},
		{name: "String write advisor", raw: `try "x".write(toFile: "/tmp/y", atomically: false, encoding: .utf8)`},
		{name: "InputStream advisor", raw: `InputStream(url: URL(fileURLWithPath: "/tmp/z"))`},
		{name: "OutputStream", raw: `OutputStream(toFileAtPath: "/tmp/z", append: false)`},
		{name: "FileHandle", raw: `FileHandle.standardInput.readDataToEndOfFile()`},
		{name: "NSFileHandle", raw: `NSFileHandle.fileHandleWithStandardInput().readDataToEndOfFile()`},
		{name: "Pipe", raw: `let pipe = Pipe()`},
		{name: "NSPipe", raw: `let pipe = NSPipe()`},
		{name: "Bundle loading advisor", raw: `Bundle(path: "/tmp/plugin.bundle")?.load()`},
		{name: "NSBundle loading", raw: `NSBundle(path: "/tmp/plugin.bundle")?.load()`},
		{name: "Data contents", raw: `let bytes = try Data(contentsOf: location)`},
		{name: "NSString contents", raw: `let text = NSString(contentsOfFile: path)`},
		{name: "member read", raw: `let bytes = source.read()`},
		{name: "member write reference", raw: `let writer = data.write; try writer(.init(fileURLWithPath: "/tmp/a"), [])`},
		{name: "Secure Enclave", raw: `let key = try SecureEnclave.P256.Signing.PrivateKey()`},
		{name: "CryptoKit private key", raw: `let key = P256.Signing.PrivateKey()`},
		{name: "stdin", raw: `let value = readLine()`},
		{name: "stdout", raw: `print("approval")`},
		{name: "debug stdout", raw: `debugPrint(value)`},
		{name: "dump stdout", raw: `dump(value)`},
		{name: "process arguments", raw: `let arguments = CommandLine.arguments`},
		{name: "fatal stderr", raw: `fatalError(secret)`},
		{name: "precondition failure stderr", raw: `preconditionFailure(secret)`},
		{name: "assertion failure stderr", raw: `assertionFailure(secret)`},
		{name: "assert stderr", raw: `assert(condition, secret)`},
		{name: "precondition stderr", raw: `precondition(condition, secret)`},
		{name: "silgen advisor", raw: `@_silgen_name("system") func harmless(_ command: UnsafePointer<CChar>) -> Int32`},
		{name: "cdecl", raw: `@_cdecl("entry") func entry() {}`},
		{name: "extern", raw: `@_extern(c, "open") func openFile(_ path: UnsafePointer<CChar>, _ flags: Int32) -> Int32`},
		{name: "C++ exposure", raw: `@_expose(Cxx) public func exposed() {}`},
		{name: "normal interpolation", raw: `let text = "value \(Process())"`},
		{name: "raw interpolation", raw: `let text = #"value \#(URLSession.shared)"#`},
		{name: "bare regex", raw: `let r = /Process()/`},
		{name: "raw regex masking advisor", raw: `let r = #/https://example.com/#; let p = Process()`},
		{name: "CR comment terminator", raw: "// inert\rfunc f() { print(\"ambient\") }\r"},
	}
	for _, test := range hostile {
		t.Run("reject "+test.name, func(t *testing.T) {
			if err := validateSwiftCapabilities(test.raw); err == nil {
				t.Fatal("capability guard accepted hostile Swift")
			}
		})
	}

	negative := []struct {
		name string
		raw  string
	}{
		{name: "line comment", raw: "// Process(); URLSession.shared\nlet safe = 1"},
		{name: "nested block comments", raw: `/* Process() /* URLSession.shared */ FileManager.default */ let safe = 1`},
		{name: "escaped string", raw: `let text = "Process() \"URLSession.shared\""`},
		{name: "multiline string", raw: "let text = \"\"\"\nProcess(); URLSession.shared\n\"\"\""},
		{name: "raw string", raw: `let text = ##"Process(); URLSession.shared"##`},
		{name: "raw multiline string", raw: "let text = #\"\"\"\nProcess(); URLSession.shared\n\"\"\"#"},
		{name: "safe interpolation", raw: `let text = "value \(safeValue)"`},
		{name: "raw safe interpolation", raw: `let text = #"value \#(safeValue)"#`},
		{name: "append contentsOf", raw: `output.append(contentsOf: bytes)`},
		{name: "division", raw: `let value = (count / 2) + (total / 4)`},
		{name: "integer literal division", raw: `let ratio = 4 / 2`},
		{name: "floating literal division", raw: `let minutes = 300.0 / 60.0`},
		{name: "hex literal division", raw: `let nibble = 0x10 / 0x04`},
		{name: "URL text", raw: `let text = "https://example.com/path"`},
		{name: "BOM", raw: "\ufefflet safe = 1"},
		{name: "CR comment before safe code", raw: "// inert\rlet safe = 1\r"},
		{name: "CRLF comment before safe code", raw: "// inert\r\nlet safe = 1\r\n"},
	}
	for _, test := range negative {
		t.Run("allow "+test.name, func(t *testing.T) {
			if err := validateSwiftCapabilities(test.raw); err != nil {
				t.Fatalf("capability guard rejected inert Swift: %v", err)
			}
		})
	}
}

func TestSwiftLexerFailsClosedOnMalformedForms(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "BOM after start", raw: "let x = 1\ufeff"},
		{name: "unterminated block comment", raw: `/* outer /* inner */`},
		{name: "unterminated string", raw: `let x = "value`},
		{name: "newline in string", raw: "let x = \"value\nnext\""},
		{name: "unterminated multiline", raw: "let x = \"\"\"value"},
		{name: "unterminated raw string", raw: `let x = #"value"`},
		{name: "unterminated interpolation", raw: `let x = "\(safeValue"`},
		{name: "unterminated backtick", raw: "let `value = 1"},
		{name: "bare regex form", raw: `let r = /unterminated`},
		{name: "raw regex form", raw: `let r = ##/value/##`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := lexSwift(test.raw); err == nil {
				t.Fatal("lexer accepted malformed or forbidden Swift form")
			}
		})
	}
}

func TestSwiftSourceInventoryRejectsSymlinks(t *testing.T) {
	root := t.TempDir()
	realSource := filepath.Join(root, "Real.swift")
	if err := os.WriteFile(realSource, []byte("struct Safe {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realSource, filepath.Join(root, "Linked.swift")); err != nil {
		t.Fatal(err)
	}
	if _, err := swiftSourcesUnder(root); err == nil {
		t.Fatal("Swift source inventory accepted a symlinked source")
	}
}

func nativeApprovalSwiftSources(t *testing.T) []string {
	t.Helper()
	root := filepath.Join(repositoryRoot(t), "native", "macos", "ApprovalProtocol", "Sources", "ApprovalProtocol")
	files, err := swiftSourcesUnder(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("native approval protocol target contains no Swift sources")
	}
	return files
}

func swiftSourcesUnder(root string) ([]string, error) {
	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("Swift source tree contains symlink %s", path)
		}
		if strings.HasSuffix(path, ".swift") && !info.Mode().IsRegular() {
			return fmt.Errorf("Swift source is not a regular file: %s", path)
		}
		if strings.HasSuffix(path, ".swift") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

type swiftToken struct {
	text       string
	identifier bool
	backticked bool
	literal    bool
	newline    bool
}

type swiftImport struct {
	kind   string
	module string
	symbol string
}

type swiftLexer struct {
	raw    string
	offset int
	tokens []swiftToken
}

func lexSwift(raw string) ([]swiftToken, error) {
	if !utf8.ValidString(raw) {
		return nil, errors.New("Swift source is not valid UTF-8")
	}
	lexer := &swiftLexer{raw: strings.TrimPrefix(raw, "\ufeff")}
	if err := lexer.scanCode(false); err != nil {
		return nil, err
	}
	return lexer.tokens, nil
}

func (lexer *swiftLexer) scanCode(interpolation bool) error {
	parentheses := 0
	for lexer.offset < len(lexer.raw) {
		if strings.HasPrefix(lexer.raw[lexer.offset:], "//") {
			lexer.skipLineComment()
			continue
		}
		if strings.HasPrefix(lexer.raw[lexer.offset:], "/*") {
			if err := lexer.skipBlockComment(); err != nil {
				return err
			}
			continue
		}
		value := lexer.raw[lexer.offset]
		switch {
		case value == ' ' || value == '\t':
			lexer.offset++
		case value == '\r':
			lexer.tokens = append(lexer.tokens, swiftToken{text: "\n", newline: true})
			lexer.offset++
			if lexer.offset < len(lexer.raw) && lexer.raw[lexer.offset] == '\n' {
				lexer.offset++
			}
		case value == '\n':
			lexer.tokens = append(lexer.tokens, swiftToken{text: "\n", newline: true})
			lexer.offset++
		case value == '`':
			if err := lexer.scanBacktickIdentifier(); err != nil {
				return err
			}
		case value == '"' || value == '#':
			matched, err := lexer.scanStringOrRawRegex()
			if err != nil {
				return err
			}
			if !matched {
				lexer.emitSymbol(value)
				lexer.offset++
			}
		case isSwiftIdentifierStart(value):
			lexer.scanIdentifier()
		case value >= '0' && value <= '9':
			lexer.scanNumber()
		case value == '/':
			if lexer.canStartRegex() {
				return fmt.Errorf("bare Swift regex literals are forbidden at byte %d", lexer.offset)
			}
			lexer.emitSymbol(value)
			lexer.offset++
		case value == '(':
			parentheses++
			lexer.emitSymbol(value)
			lexer.offset++
		case value == ')':
			if interpolation && parentheses == 0 {
				lexer.offset++
				return nil
			}
			if parentheses > 0 {
				parentheses--
			}
			lexer.emitSymbol(value)
			lexer.offset++
		case value < utf8.RuneSelf:
			lexer.emitSymbol(value)
			lexer.offset++
		default:
			return fmt.Errorf("unsupported non-ASCII Swift syntax at byte %d", lexer.offset)
		}
	}
	if interpolation {
		return errors.New("unterminated Swift string interpolation")
	}
	return nil
}

func (lexer *swiftLexer) skipLineComment() {
	for lexer.offset < len(lexer.raw) && lexer.raw[lexer.offset] != '\r' && lexer.raw[lexer.offset] != '\n' {
		lexer.offset++
	}
}

func (lexer *swiftLexer) skipBlockComment() error {
	depth := 0
	for lexer.offset < len(lexer.raw) {
		switch {
		case strings.HasPrefix(lexer.raw[lexer.offset:], "/*"):
			depth++
			lexer.offset += 2
		case strings.HasPrefix(lexer.raw[lexer.offset:], "*/"):
			depth--
			lexer.offset += 2
			if depth == 0 {
				return nil
			}
		default:
			lexer.offset++
		}
	}
	return errors.New("unterminated Swift block comment")
}

func (lexer *swiftLexer) scanStringOrRawRegex() (bool, error) {
	start := lexer.offset
	hashes := 0
	for start+hashes < len(lexer.raw) && lexer.raw[start+hashes] == '#' {
		hashes++
	}
	if start+hashes >= len(lexer.raw) {
		return false, nil
	}
	if hashes > 0 && lexer.raw[start+hashes] == '/' {
		return true, fmt.Errorf("raw Swift regex literals are forbidden at byte %d", start)
	}
	if lexer.raw[start+hashes] != '"' {
		return false, nil
	}
	multiline := strings.HasPrefix(lexer.raw[start+hashes:], `"""`)
	openingQuotes := 1
	if multiline {
		openingQuotes = 3
	}
	lexer.offset = start + hashes + openingQuotes
	terminator := strings.Repeat("\"", openingQuotes) + strings.Repeat("#", hashes)
	interpolationMarker := "\\" + strings.Repeat("#", hashes) + "("
	for lexer.offset < len(lexer.raw) {
		if strings.HasPrefix(lexer.raw[lexer.offset:], terminator) {
			lexer.offset += len(terminator)
			return true, nil
		}
		if strings.HasPrefix(lexer.raw[lexer.offset:], interpolationMarker) {
			lexer.offset += len(interpolationMarker)
			if err := lexer.scanCode(true); err != nil {
				return true, err
			}
			continue
		}
		if !multiline && (lexer.raw[lexer.offset] == '\r' || lexer.raw[lexer.offset] == '\n') {
			return true, fmt.Errorf("newline in single-line Swift string at byte %d", lexer.offset)
		}
		if hashes == 0 && lexer.raw[lexer.offset] == '\\' {
			lexer.offset++
			if lexer.offset >= len(lexer.raw) {
				return true, errors.New("unterminated Swift string escape")
			}
			lexer.offset++
			continue
		}
		lexer.offset++
	}
	return true, errors.New("unterminated Swift string literal")
}

func (lexer *swiftLexer) scanBacktickIdentifier() error {
	start := lexer.offset + 1
	end := strings.IndexByte(lexer.raw[start:], '`')
	if end < 0 {
		return errors.New("unterminated Swift backtick identifier")
	}
	end += start
	if end == start || strings.ContainsAny(lexer.raw[start:end], "\r\n") {
		return errors.New("malformed Swift backtick identifier")
	}
	lexer.tokens = append(lexer.tokens, swiftToken{text: lexer.raw[start:end], identifier: true, backticked: true})
	lexer.offset = end + 1
	return nil
}

func (lexer *swiftLexer) scanIdentifier() {
	start := lexer.offset
	lexer.offset++
	for lexer.offset < len(lexer.raw) && isSwiftIdentifierContinue(lexer.raw[lexer.offset]) {
		lexer.offset++
	}
	lexer.tokens = append(lexer.tokens, swiftToken{text: lexer.raw[start:lexer.offset], identifier: true})
}

func (lexer *swiftLexer) scanNumber() {
	start := lexer.offset
	for lexer.offset < len(lexer.raw) {
		value := lexer.raw[lexer.offset]
		if !isSwiftIdentifierContinue(value) && value != '.' {
			break
		}
		lexer.offset++
	}
	lexer.tokens = append(lexer.tokens, swiftToken{text: lexer.raw[start:lexer.offset], literal: true})
}

func (lexer *swiftLexer) emitSymbol(value byte) {
	lexer.tokens = append(lexer.tokens, swiftToken{text: string(value)})
}

func (lexer *swiftLexer) canStartRegex() bool {
	index := previousSwiftToken(lexer.tokens, len(lexer.tokens))
	if index < 0 {
		return true
	}
	previous := lexer.tokens[index]
	if previous.literal {
		return false
	}
	if previous.identifier {
		switch previous.text {
		case "return", "throw", "case", "in", "where", "else":
			return true
		default:
			return false
		}
	}
	switch previous.text {
	case ")", "]", "}":
		return false
	default:
		return true
	}
}

func isSwiftIdentifierStart(value byte) bool {
	return value == '_' || value == '$' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func isSwiftIdentifierContinue(value byte) bool {
	return isSwiftIdentifierStart(value) || value >= '0' && value <= '9'
}

func parseSwiftImports(tokens []swiftToken) ([]swiftImport, error) {
	kinds := map[string]bool{"class": true, "enum": true, "func": true, "let": true, "protocol": true, "struct": true, "typealias": true, "var": true}
	var result []swiftImport
	for index := 0; index < len(tokens); index++ {
		if !tokens[index].identifier || tokens[index].backticked || tokens[index].text != "import" {
			continue
		}
		cursor := index + 1
		if cursor >= len(tokens) || tokens[cursor].newline || tokens[cursor].text == ";" {
			return nil, errors.New("import is missing a module")
		}
		value := swiftImport{}
		if tokens[cursor].identifier && kinds[tokens[cursor].text] {
			value.kind = tokens[cursor].text
			cursor++
		}
		if cursor >= len(tokens) || tokens[cursor].newline || !tokens[cursor].identifier || tokens[cursor].backticked {
			return nil, errors.New("import has a malformed module")
		}
		value.module = tokens[cursor].text
		cursor++
		if cursor < len(tokens) && tokens[cursor].text == "." {
			cursor++
			if cursor >= len(tokens) || tokens[cursor].newline || !tokens[cursor].identifier || tokens[cursor].backticked {
				return nil, errors.New("scoped import is missing a symbol")
			}
			value.symbol = tokens[cursor].text
			cursor++
		}
		if value.kind != "" && value.symbol == "" || value.kind == "" && value.symbol != "" {
			return nil, fmt.Errorf("import %s must use kind Module.Symbol for scoped access", value.module)
		}
		if cursor < len(tokens) && !tokens[cursor].newline && tokens[cursor].text != ";" {
			return nil, fmt.Errorf("import %s has trailing tokens", value.module)
		}
		result = append(result, value)
	}
	return result, nil
}

func validateSwiftImports(values []swiftImport) error {
	allowedCryptoKit := map[string]bool{
		"enum P256":     true,
		"struct SHA256": true,
	}
	allowedFoundation := map[string]bool{
		"func floor":             true,
		"struct Calendar":        true,
		"struct Data":            true,
		"struct Date":            true,
		"struct TimeZone":        true,
		"typealias TimeInterval": true,
	}
	for _, value := range values {
		switch value.module {
		case "CryptoKit":
			if value.kind == "" || value.symbol == "" {
				return errors.New("bare CryptoKit import is forbidden")
			}
			if !allowedCryptoKit[value.kind+" "+value.symbol] {
				return fmt.Errorf("CryptoKit import %s %s is not allowlisted", value.kind, value.symbol)
			}
		case "Foundation":
			if value.kind == "" || value.symbol == "" {
				return errors.New("bare Foundation import is forbidden")
			}
			if !allowedFoundation[value.kind+" "+value.symbol] {
				return fmt.Errorf("Foundation import %s %s is not allowlisted", value.kind, value.symbol)
			}
		default:
			return fmt.Errorf("Swift module %s is not allowlisted", value.module)
		}
	}
	return nil
}

func validateSwiftCapabilities(raw string) error {
	tokens, err := lexSwift(raw)
	if err != nil {
		return err
	}
	for index, token := range tokens {
		if !token.identifier {
			continue
		}
		switch {
		case token.text == "Process" || token.text == "NSTask":
			return fmt.Errorf("process capability %s is forbidden", token.text)
		case token.text == "SecureEnclave" || token.text == "PrivateKey":
			return fmt.Errorf("private signing-key capability %s is forbidden", token.text)
		case token.text == "readLine" || token.text == "print" || token.text == "debugPrint" || token.text == "dump" || token.text == "CommandLine" ||
			token.text == "fatalError" || token.text == "preconditionFailure" || token.text == "assertionFailure" || token.text == "assert" || token.text == "precondition":
			return fmt.Errorf("ambient process I/O capability %s is forbidden", token.text)
		case strings.HasPrefix(token.text, "URLSession") || strings.HasPrefix(token.text, "NSURLSession") || token.text == "NSURLConnection":
			return fmt.Errorf("network capability %s is forbidden", token.text)
		case token.text == "FileHandle" || token.text == "NSFileHandle" || token.text == "Pipe" || token.text == "NSPipe" || token.text == "FileManager" || token.text == "NSFileManager":
			return fmt.Errorf("filesystem/process capability %s is forbidden", token.text)
		case token.text == "InputStream" || token.text == "OutputStream" || token.text == "Stream" || token.text == "NSInputStream" || token.text == "NSOutputStream":
			return fmt.Errorf("stream capability %s is forbidden", token.text)
		case token.text == "Bundle" || token.text == "NSBundle":
			return errors.New("dynamic Bundle access is forbidden")
		case isSwiftUnderscoredAttribute(tokens, index):
			return fmt.Errorf("foreign-call escape hatch %s is forbidden", token.text)
		case isSwiftMemberReference(tokens, index, "read") || isSwiftMemberReference(tokens, index, "write"):
			return fmt.Errorf("Foundation-style %s call is forbidden", token.text)
		case isSwiftContentsLabel(tokens, index) && !isSwiftAppendContentsLabel(tokens, index):
			return fmt.Errorf("Foundation contents-loading label %s is forbidden", token.text)
		}
	}
	return nil
}

func isSwiftUnderscoredAttribute(tokens []swiftToken, index int) bool {
	if !strings.HasPrefix(tokens[index].text, "_") {
		return false
	}
	previous := previousSwiftToken(tokens, index)
	return previous >= 0 && tokens[previous].text == "@"
}

func isSwiftMemberReference(tokens []swiftToken, index int, name string) bool {
	if tokens[index].text != name {
		return false
	}
	previous := previousSwiftToken(tokens, index)
	return previous >= 0 && tokens[previous].text == "."
}

func isSwiftContentsLabel(tokens []swiftToken, index int) bool {
	switch tokens[index].text {
	case "contentsOf", "contentsOfFile", "contentsOfURL":
		next := nextSwiftToken(tokens, index)
		return next >= 0 && tokens[next].text == ":"
	default:
		return false
	}
}

func isSwiftAppendContentsLabel(tokens []swiftToken, index int) bool {
	open := previousSwiftToken(tokens, index)
	callee := previousSwiftToken(tokens, open)
	return open >= 0 && tokens[open].text == "(" && callee >= 0 && tokens[callee].text == "append"
}

func previousSwiftToken(tokens []swiftToken, before int) int {
	for index := before - 1; index >= 0; index-- {
		if !tokens[index].newline {
			return index
		}
	}
	return -1
}

func nextSwiftToken(tokens []swiftToken, after int) int {
	for index := after + 1; index < len(tokens); index++ {
		if !tokens[index].newline {
			return index
		}
	}
	return -1
}
