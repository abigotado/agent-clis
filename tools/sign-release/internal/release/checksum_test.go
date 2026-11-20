package release

import (
	"crypto/sha256"
	"strings"
	"testing"
)

func TestParseChecksums(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	names := []string{"one.tar.gz", "two.tar.gz"}
	tests := []struct {
		name   string
		text   string
		reason string
	}{
		{name: "two lines", text: a + "  one.tar.gz\n" + b + "  two.tar.gz\n"},
		{name: "any order", text: b + "  two.tar.gz\n" + a + "  one.tar.gz\n"},
		{name: "extra name", text: a + "  one.tar.gz\n" + b + "  two.tar.gz\n" + a + "  three.tar.gz\n", reason: "unexpected name"},
		{name: "missing name", text: a + "  one.tar.gz\n", reason: "does not list"},
		{name: "duplicate name", text: a + "  one.tar.gz\n" + b + "  one.tar.gz\n", reason: "second time"},
		{name: "single space separator", text: a + " one.tar.gz\n" + b + "  two.tar.gz\n", reason: "is not `<64 lowercase hex>"},
		{name: "binary-mode star marker", text: a + " *one.tar.gz\n" + b + "  two.tar.gz\n", reason: "is not `<64 lowercase hex>"},
		{name: "uppercase hex", text: strings.ToUpper(a) + "  one.tar.gz\n" + b + "  two.tar.gz\n", reason: "is not `<64 lowercase hex>"},
		{name: "short digest", text: a[:63] + "  one.tar.gz\n" + b + "  two.tar.gz\n", reason: "is not `<64 lowercase hex>"},
		{name: "non-hex digest", text: strings.Repeat("g", 64) + "  one.tar.gz\n" + b + "  two.tar.gz\n", reason: "is not `<64 lowercase hex>"},
		{name: "path in the name", text: a + "  dist/one.tar.gz\n" + b + "  two.tar.gz\n", reason: "is not `<64 lowercase hex>"},
		{name: "CRLF line ends", text: a + "  one.tar.gz\r\n" + b + "  two.tar.gz\r\n", reason: "is not `<64 lowercase hex>"},
		{name: "blank line", text: a + "  one.tar.gz\n\n" + b + "  two.tar.gz\n", reason: "is not `<64 lowercase hex>"},
		{name: "no trailing newline", text: a + "  one.tar.gz\n" + b + "  two.tar.gz", reason: "newline"},
		{name: "empty file", text: "", reason: "newline"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sums, err := parseChecksums([]byte(tc.text), names)
			if tc.reason == "" {
				if err != nil {
					t.Fatalf("parseChecksums() error = %v", err)
				}
				if len(sums) != 2 || sums["one.tar.gz"][0] != 0xaa || sums["two.tar.gz"][0] != 0xbb {
					t.Fatalf("sums = %x", sums)
				}
				return
			}
			if err == nil {
				t.Fatalf("parseChecksums() error = nil, want a refusal containing %q", tc.reason)
			}
			wantRefusal(t, err, StepChecksum, tc.reason)
		})
	}
}

func TestVerifySum(t *testing.T) {
	data := []byte("archive")
	if err := verifySum("x", data, sha256.Sum256(data)); err != nil {
		t.Fatalf("verifySum() error = %v", err)
	}
	err := verifySum("x", data, sha256.Sum256([]byte("other")))
	wantRefusal(t, err, StepChecksum, "sha256 of")
}
