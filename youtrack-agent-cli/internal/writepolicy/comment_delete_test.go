package writepolicy

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/profile"
)

func TestDeletionOnlyProfileBindsExactWritePolicy(t *testing.T) {
	ctx := context.Background()
	registry := NewRegistry(filepath.Join(t.TempDir(), "config", "write-policies.json"))
	deleteProfile := policyProfile("delete-only")
	deleteProfile.Capabilities = []profile.Capability{profile.CapabilityRead, profile.CapabilityCommentDelete}
	if err := deleteProfile.Validate(); err != nil {
		t.Fatalf("deletion-only profile validation failed: %v", err)
	}

	tests := []struct {
		name       string
		profile    profile.Profile
		projectID  string
		projectKey string
		wantErr    error
	}{
		{name: "missing policy is denied", profile: deleteProfile, projectID: "0-1", projectKey: "CORE", wantErr: ErrNotFound},
		{name: "exact project is allowed after explicit binding", profile: deleteProfile, projectID: "0-1", projectKey: "CORE"},
		{name: "mismatched project key is denied", profile: deleteProfile, projectID: "0-1", projectKey: "OTHER", wantErr: ErrProjectDenied},
		{name: "mismatched project id is denied", profile: deleteProfile, projectID: "0-2", projectKey: "CORE", wantErr: ErrProjectDenied},
		{name: "legacy profile identity is stale", profile: policyProfile("delete-only"), projectID: "0-1", projectKey: "CORE", wantErr: ErrStale},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if index == 1 {
				if _, err := registry.Set(ctx, deleteProfile, []Project{{ID: "0-1", Key: "CORE"}}); err != nil {
					t.Fatalf("Set() error = %v", err)
				}
			}
			_, err := registry.RequireProject(ctx, test.profile, test.projectID, test.projectKey)
			if test.wantErr == nil && err != nil {
				t.Fatalf("RequireProject() error = %v", err)
			}
			if test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Fatalf("RequireProject() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}
