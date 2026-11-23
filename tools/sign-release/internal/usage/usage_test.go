package usage

import (
	"strings"
	"testing"
)

func TestTextNamesTheInvocation(t *testing.T) {
	t.Parallel()

	text := Text()
	tests := []struct {
		name string
		want string
	}{
		{name: "starts with usage", want: "usage: "},
		{name: "names the tool", want: "sign-release"},
		{name: "names the arguments", want: "<cli> <version>"},
		{name: "runs from the module directory", want: "Run it from tools/sign-release, its own module: GOWORK=off go run . <cli> <version>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if !strings.Contains(text, tt.want) {
				t.Fatalf("Text() = %q, want it to contain %q", text, tt.want)
			}
		})
	}
	if strings.Contains(text, "./tools/sign-release") {
		t.Fatalf("Text() = %q names a path the repository root cannot build: it has no go.mod", text)
	}
	if !strings.HasSuffix(text, "\n") {
		t.Fatalf("Text() = %q, want a trailing newline", text)
	}
}

// TestTextStatesTheOperatorContract pins the three things the operator must
// know before running the tool.
func TestTextStatesTheOperatorContract(t *testing.T) {
	t.Parallel()

	text := Text()
	tests := []struct {
		name string
		want string
	}{
		{name: "gh uses its own stored login", want: "gh must be logged in through its own stored login"},
		{name: "GH_TOKEN is ignored", want: "GH_TOKEN"},
		{name: "GH_HOST is ignored", want: "GH_HOST"},
		{name: "proxy variables are ignored", want: "proxy variables are ignored on purpose"},
		{name: "one Keychain prompt per binary", want: "one Keychain prompt per binary"},
		{name: "Allow", want: "choose Allow, never\nAlways Allow"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if !strings.Contains(text, tt.want) {
				t.Fatalf("Text() = %q, want it to contain %q", text, tt.want)
			}
		})
	}
}
