package oauthrecovery

import (
	"strings"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/oauth"
)

func TestCatalogCoversEveryTokenFailureCategoryExactlyOnce(t *testing.T) {
	rows := Catalog()
	if got, want := len(rows), int(oauth.TokenFailureCategoryCount); got != want {
		t.Fatalf("catalog rows=%d, want %d typed categories plus legacy", got, want)
	}
	seenCategories := make(map[oauth.TokenFailureCategory]bool, len(rows))
	seenReasons := make(map[string]bool, len(rows))
	for _, row := range rows {
		if row.Reason == "" || seenReasons[row.Reason] {
			t.Fatalf("missing or duplicate reason: %q", row.Reason)
		}
		seenReasons[row.Reason] = true
		if row.Hint == "" || row.Recovery == "" || strings.Contains(row.Hint, "--yes") {
			t.Fatalf("unsafe or incomplete recovery for %q: %+v", row.Reason, row)
		}
		if row.Exit != errx.CodeAuth && row.Exit != errx.CodeRetryable {
			t.Fatalf("unsupported OAuth exit for %q: %d", row.Reason, row.Exit)
		}
		if row.Category == 0 {
			if row != Legacy() {
				t.Fatalf("legacy row differs from Legacy(): %+v", row)
			}
			continue
		}
		if row.Category >= oauth.TokenFailureCategoryCount || seenCategories[row.Category] {
			t.Fatalf("out-of-range or duplicate category: %d", row.Category)
		}
		seenCategories[row.Category] = true
		got, ok := Lookup(row.Category)
		if !ok || got != row {
			t.Fatalf("Lookup(%d)=(%+v,%t), want %+v", row.Category, got, ok, row)
		}
	}
	for category := oauth.TokenFailureCategory(1); category < oauth.TokenFailureCategoryCount; category++ {
		if !seenCategories[category] {
			t.Fatalf("category %d has no recovery descriptor", category)
		}
	}
	if _, ok := Lookup(0); ok {
		t.Fatal("zero category must use Legacy, not typed Lookup")
	}
	if _, ok := Lookup(oauth.TokenFailureCategoryCount); ok {
		t.Fatal("count sentinel must not resolve as a token failure")
	}
}

func TestCatalogReturnsDefensiveCopy(t *testing.T) {
	first := Catalog()
	first[0].Hint = "mutated"
	second := Catalog()
	if second[0].Hint == "mutated" {
		t.Fatal("catalog mutation changed canonical descriptor")
	}
}
