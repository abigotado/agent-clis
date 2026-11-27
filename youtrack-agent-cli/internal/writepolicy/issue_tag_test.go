package writepolicy

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/profile"
)

func TestIssueTagOnlyProfileBindsExactWritePolicy(t *testing.T) {
	ctx := context.Background()
	registry := NewRegistry(filepath.Join(t.TempDir(), "config", "write-policies.json"))
	tagProfile := policyProfile("tag-only")
	tagProfile.Capabilities = []profile.Capability{profile.CapabilityRead, profile.CapabilityIssueTag}
	if err := tagProfile.Validate(); err != nil {
		t.Fatalf("tag-only profile validation failed: %v", err)
	}
	if _, err := registry.Set(ctx, tagProfile, []Project{{ID: "0-1", Key: "CORE"}}); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if _, err := registry.RequireProject(ctx, tagProfile, "0-1", "CORE"); err != nil {
		t.Fatalf("RequireProject() error = %v", err)
	}
	if _, err := registry.RequireProject(ctx, tagProfile, "0-2", "OTHER"); !errors.Is(err, ErrProjectDenied) {
		t.Fatalf("RequireProject() error = %v, want %v", err, ErrProjectDenied)
	}
}
