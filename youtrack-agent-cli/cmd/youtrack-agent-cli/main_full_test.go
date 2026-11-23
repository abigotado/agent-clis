//go:build !portable_readonly && !macos_identity_readonly

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/output"
)

func decodeEnvelope(t *testing.T, raw []byte) output.Envelope {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var envelope output.Envelope
	if err := decoder.Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	if decoder.More() {
		t.Fatalf("stdout holds more than one value: %s", raw)
	}
	return envelope
}

func TestRunHardeningFailureIsInternalEnvelopeAndSkipsExecute(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		message string
	}{
		{"plain error leaks nothing", errors.New("HARDEN_SENTINEL"), "the process could not lower its core-dump limit"},
		{"status is reported as a number", &hardeningError{status: 13}, "the process could not lower its core-dump limit (status 13)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout bytes.Buffer
			executed := false
			code := run(
				func() error { return tc.err },
				func() errx.Code { executed = true; return errx.CodeOK },
				&stdout,
			)
			if code != errx.CodeInternal {
				t.Fatalf("code=%d want=%d", code, errx.CodeInternal)
			}
			if executed {
				t.Fatal("execute ran after hardening failed")
			}
			envelope := decodeEnvelope(t, stdout.Bytes())
			if envelope.OK || envelope.Error == nil || envelope.Error.Code != "INTERNAL" {
				t.Fatalf("envelope = %s", stdout.String())
			}
			if envelope.Error.Message != tc.message {
				t.Fatalf("message = %q want %q", envelope.Error.Message, tc.message)
			}
			if envelope.Hint == "" || strings.Contains(envelope.Hint, "bug") {
				t.Fatalf("hint = %q", envelope.Hint)
			}
			if bytes.Contains(stdout.Bytes(), []byte("HARDEN_SENTINEL")) {
				t.Fatalf("stdout leaks the cause: %s", stdout.String())
			}
		})
	}
}

func TestRunHardeningSuccessExecutes(t *testing.T) {
	var stdout bytes.Buffer
	executed := false
	code := run(
		func() error { return nil },
		func() errx.Code { executed = true; return errx.CodeOK },
		&stdout,
	)
	if !executed || code != errx.CodeOK {
		t.Fatalf("executed=%v code=%d", executed, code)
	}
}

func TestRunRecoversPanicInHardening(t *testing.T) {
	var stdout bytes.Buffer
	executed := false
	code := run(
		func() error { panic("PANIC_SENTINEL") },
		func() errx.Code { executed = true; return errx.CodeOK },
		&stdout,
	)
	if code != errx.CodeInternal || executed {
		t.Fatalf("code=%d executed=%v", code, executed)
	}
	envelope := decodeEnvelope(t, stdout.Bytes())
	if envelope.OK || envelope.Error == nil || envelope.Error.Code != "INTERNAL" || bytes.Contains(stdout.Bytes(), []byte("PANIC_SENTINEL")) {
		t.Fatalf("envelope = %s", stdout.String())
	}
}

// TestMainPassesDisableCoreDumpsToRun fails if the D7 wiring is removed or
// replaced by a different function.
func TestMainPassesDisableCoreDumpsToRun(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "main" || function.Body == nil {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			callee, ok := call.Fun.(*ast.Ident)
			if !ok || callee.Name != "run" || len(call.Args) == 0 {
				return true
			}
			if first, ok := call.Args[0].(*ast.Ident); ok && first.Name == "disableCoreDumps" {
				found = true
			}
			return true
		})
	}
	if !found {
		t.Fatal("main does not call run(disableCoreDumps, ...)")
	}
}
