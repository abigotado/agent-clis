package youtrack

import "testing"

func TestAttachmentMimeConflicts(t *testing.T) {
	tests := []struct {
		name, observed, confirmed string
		want                      bool
	}{
		{"absent is unverifiable", "", "image/png", false},
		{"equal", "image/png", "image/png", false},
		{"case and parameters ignored", " IMAGE/PNG; charset=binary", "image/png", false},
		{"html replaces png", "text/html", "image/png", true},
		{"malformed nonempty", "; charset=binary", "image/png", true},
		{"other image type", "image/jpeg", "image/png", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AttachmentMimeConflicts(tt.observed, tt.confirmed); got != tt.want {
				t.Fatalf("AttachmentMimeConflicts(%q, %q) = %v, want %v", tt.observed, tt.confirmed, got, tt.want)
			}
		})
	}
}
