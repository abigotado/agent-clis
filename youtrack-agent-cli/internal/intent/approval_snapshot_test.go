package intent

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestParseApprovalSnapshotSharedFixtures(t *testing.T) {
	for _, name := range []string{"plan-issue-create.json", "plan-issue-update.json", "plan-comment-add.json"} {
		t.Run(name, func(t *testing.T) {
			raw := approvalFixture(t, name)
			plan, err := ParseApprovalSnapshot(raw, MaxCanonicalPlanBytes)
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := ApprovalDisplayBytes(plan)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(canonical, raw) {
				t.Fatal("parsed plan did not re-encode to the exact fixture bytes")
			}
		})
	}
}

func TestParseApprovalSnapshotRejectsNonCanonicalInput(t *testing.T) {
	valid := approvalFixture(t, "plan-comment-add.json")
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "empty", raw: nil},
		{name: "oversized before decode", raw: bytes.Repeat([]byte{'x'}, MaxCanonicalPlanBytes+1)},
		{name: "unknown field", raw: bytes.Replace(valid, []byte(`{"schema_version":1`), []byte(`{"unknown":0,"schema_version":1`), 1)},
		{name: "duplicate field", raw: bytes.Replace(valid, []byte(`{"schema_version":1`), []byte(`{"schema_version":1,"schema_version":1`), 1)},
		{name: "trailing JSON", raw: append(append([]byte(nil), valid...), []byte(`{}`)...)},
		{name: "whitespace", raw: append([]byte{' '}, valid...)},
		{name: "default port", raw: bytes.Replace(valid, []byte(`https://acme.youtrack.cloud`), []byte(`https://acme.youtrack.cloud:443`), 1)},
		{name: "Unicode host", raw: bytes.Replace(valid, []byte(`https://acme.youtrack.cloud`), []byte(`https://münchen.example`), 1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseApprovalSnapshot(tt.raw, MaxCanonicalPlanBytes); err == nil {
				t.Fatal("ParseApprovalSnapshot() accepted non-canonical input")
			}
		})
	}

	if _, err := ParseApprovalSnapshot(valid, 0); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("nonpositive maximum error = %v, want ErrInvalidPlan", err)
	}
	oversizedWithLargeCallerMaximum := bytes.Replace(
		valid,
		[]byte("Comment fixture"),
		bytes.Repeat([]byte{'x'}, MaxCanonicalPlanBytes+1),
		1,
	)
	if _, err := ParseApprovalSnapshot(oversizedWithLargeCallerMaximum, MaxCanonicalPlanBytes*2); !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("caller maximum above global cap error = %v, want ErrInputTooLarge", err)
	}
}

func approvalFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "gate1a", name))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		t.Fatalf("fixture %q must end with one LF", name)
	}
	return append([]byte(nil), raw[:len(raw)-1]...)
}
