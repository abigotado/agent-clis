package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
)

func TestGeneratedContractIsCurrent(t *testing.T) {
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	want := renderMarkdown(errx.Describe())
	for _, target := range targets {
		t.Run(filepath.ToSlash(target), func(t *testing.T) {
			got, err := os.ReadFile(filepath.Join(root, target))
			if err != nil {
				t.Fatalf("read generated contract: %v", err)
			}
			if string(got) != want {
				t.Fatal("generated contract is stale; run go generate ./...")
			}
		})
	}
}

func TestContractRequiresReconciliationInsteadOfReplay(t *testing.T) {
	got := renderMarkdown(errx.Describe())
	for _, phrase := range []string{
		"A valid v1 stdout envelope is authoritative",
		"never replay the mutation",
		"mutation reconcile",
		"operator_resolution_required",
		"GET-only `operator-write reconcile`",
		"WRITE_APPLIED_LOCAL_FAILURE",
		"success with a local failure: do not resend",
	} {
		if !strings.Contains(got, phrase) {
			t.Errorf("contract is missing %q", phrase)
		}
	}
	if strings.Contains(got, "pages create") || strings.Contains(got, "allow-spaces") {
		t.Fatal("contract retains a provider-specific predecessor command")
	}
}
