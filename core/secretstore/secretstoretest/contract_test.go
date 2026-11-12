package secretstoretest

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/abigotado/agent-clis/core/secretstore"
)

// The redaction row only guards anything if the detector can fail.
func TestLeakDetector(t *testing.T) {
	const marker = "marker-0123456789abcdef"
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"typed error without key text", &secretstore.Error{Op: "load", Backend: "memory", Kind: secretstore.KindNotFound}, false},
		{"wrapped context error", fmt.Errorf("secretstore: load: %w", errors.New("context canceled")), false},
		{"message carrying the marker", fmt.Errorf("load %s failed", marker), true},
		{"wrapped message carrying the marker", fmt.Errorf("outer: %w", fmt.Errorf("inner %s", marker)), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found := leaks(tt.err, marker)
			if (len(found) > 0) != tt.want {
				t.Fatalf("leaks = %v, want leak=%v", found, tt.want)
			}
			for _, line := range found {
				if strings.Contains(line, marker) {
					t.Fatalf("a leak report must not repeat the marker: %q", line)
				}
			}
		})
	}

	t.Run("every output path is covered", func(t *testing.T) {
		err := fmt.Errorf("x %s", marker)
		if got := len(leaks(err, marker)); got != 6 {
			t.Fatalf("a leaking error was reported by %d output paths, want 6 (%%v %%+v %%#v %%s, slog text, slog json)", got)
		}
	})
}
