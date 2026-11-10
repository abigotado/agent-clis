//go:build (!darwin && !linux) || (darwin && !cgo)

package operatorwrite

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestUnsupportedStorageFailsClosedWithoutFiles(t *testing.T) {
	s := New(t.TempDir())
	ctx := context.Background()
	p := testPlan(t, KindIssueUpdate)
	if _, err := s.Create(ctx, p); err == nil {
		t.Fatal("unsupported platform created a plan")
	}
	if _, err := s.Claim(ctx, p.ID, p.SHA256, p.CreatedAt); err == nil {
		t.Fatal("unsupported platform authorized a dispatch")
	}
	if _, err := os.Stat(s.Root()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsupported platform changed storage: %v", err)
	}
}
