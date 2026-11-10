package main

import (
	"strings"
	"testing"
)

func TestRenderMarkdownSortsAndDocumentsCommands(t *testing.T) {
	tree := commandTree{
		Globals: []flagInfo{{Name: "profile", Type: "string", Usage: "explicit profile"}},
		Commands: []commandInfo{
			{Path: "youtrack-agent-cli mutation apply", Short: "Apply once", Flags: []flagInfo{{Name: "receipt", Type: "string", Usage: "receipt"}}},
			{Path: "youtrack-agent-cli profile list", Short: "List profiles"},
		},
	}
	got := renderMarkdown(tree)
	for _, phrase := range []string{
		"one stable envelope",
		"explicit `--profile`",
		"never replay the mutation",
		"GET-only `operator-write reconcile`",
		"WRITE_APPLIED_LOCAL_FAILURE",
		"success with a local failure: do not resend",
		"### `youtrack-agent-cli mutation apply`",
		"`--receipt`",
	} {
		if !strings.Contains(got, phrase) {
			t.Errorf("command reference is missing %q", phrase)
		}
	}
	if strings.Contains(got, "pages create") || strings.Contains(got, "allow-spaces") {
		t.Fatal("command reference retains a provider-specific predecessor command")
	}
}

func TestDescribeFlagOmitsFalseDefault(t *testing.T) {
	if got := code(""); got != "" {
		t.Fatalf("code empty = %q", got)
	}
}
