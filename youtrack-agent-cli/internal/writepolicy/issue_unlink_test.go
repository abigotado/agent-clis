package writepolicy

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/profile"
)

func TestIssueUnlinkOnlyProfileBindsExactWritePolicy(t *testing.T) {
	ctx := context.Background()
	registry := NewRegistry(filepath.Join(t.TempDir(), "config", "write-policies.json"))
	unlinkProfile := policyProfile("unlink-only")
	unlinkProfile.Capabilities = []profile.Capability{profile.CapabilityRead, profile.CapabilityIssueUnlink}
	if err := unlinkProfile.Validate(); err != nil {
		t.Fatalf("unlink-only profile validation failed: %v", err)
	}
	if _, err := registry.Set(ctx, unlinkProfile, []Project{{ID: "0-1", Key: "CORE"}}); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if _, err := registry.RequireProject(ctx, unlinkProfile, "0-1", "CORE"); err != nil {
		t.Fatalf("RequireProject() error = %v", err)
	}
	if _, err := registry.RequireProject(ctx, unlinkProfile, "0-2", "OTHER"); !errors.Is(err, ErrProjectDenied) {
		t.Fatalf("RequireProject() error = %v, want %v", err, ErrProjectDenied)
	}
}
