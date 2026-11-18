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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if !strings.Contains(text, tt.want) {
				t.Fatalf("Text() = %q, want it to contain %q", text, tt.want)
			}
		})
	}
	if !strings.HasSuffix(text, "\n") {
		t.Fatalf("Text() = %q, want a trailing newline", text)
	}
}
