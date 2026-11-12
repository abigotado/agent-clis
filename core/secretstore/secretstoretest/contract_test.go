package secretstoretest

import (
	"context"
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

// leakyService returns a Memory whose Load errors echo the key's Service.
type leakyService struct{ *Memory }

func (l leakyService) Load(ctx context.Context, key secretstore.Key) ([]byte, error) {
	secret, err := l.Memory.Load(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", key.Service, err)
	}
	return secret, nil
}

func TestRedactionCatchesALeakedService(t *testing.T) {
	const max = 64
	run := func(t *testing.T, s secretstore.Store) []string {
		c := &contract{s: s, max: max, service: "secretstore-test-" + randomHex(t, 8), used: map[secretstore.Key]struct{}{}}
		return c.redactionFindings(t)
	}
	t.Run("clean store", func(t *testing.T) {
		if found := run(t, NewMemory(secretstore.Options{MaxSecretBytes: max})); len(found) > 0 {
			t.Fatalf("clean store reported leaks: %v", found)
		}
	})
	t.Run("store that leaks the service", func(t *testing.T) {
		if found := run(t, leakyService{NewMemory(secretstore.Options{MaxSecretBytes: max})}); len(found) == 0 {
			t.Fatal("a store leaking key.Service in an error was not caught")
		}
	})
}
