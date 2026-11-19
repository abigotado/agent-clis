package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/output"
)

func TestRunWithRecoveryMapsPanicToInternalEnvelope(t *testing.T) {
	var stdout bytes.Buffer
	code := runWithRecovery(func() errx.Code {
		panic("PANIC_SENTINEL")
	}, &stdout)
	if code != errx.CodeInternal {
		t.Fatalf("code=%d want=%d", code, errx.CodeInternal)
	}
	var envelope output.Envelope
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.OK || envelope.Error == nil || envelope.Error.Code != "INTERNAL" || bytes.Contains(stdout.Bytes(), []byte("PANIC_SENTINEL")) {
		t.Fatalf("panic envelope = %s", stdout.String())
	}
}

func TestReadonlyEditionMainsDoNotReferenceCore(t *testing.T) {
	for _, name := range []string{"main_portable_readonly.go", "main_macos_identity_readonly.go"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"DisableCoreDumps", "disableCoreDumps", "agent-clis/core"} {
				if bytes.Contains(data, []byte(forbidden)) {
					t.Fatalf("%s references %q", name, forbidden)
				}
			}
		})
	}
}
