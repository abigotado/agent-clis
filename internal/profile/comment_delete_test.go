package profile

import (
	"errors"
	"testing"
)

func TestCommentDeleteCapabilityIsExplicitAndCanonical(t *testing.T) {
	tests := []struct {
		name         string
		capabilities []Capability
		wantValid    bool
	}{
		{name: "delete only after read is canonical", capabilities: []Capability{CapabilityRead, CapabilityCommentDelete}, wantValid: true},
		{name: "delete after comment add is canonical", capabilities: []Capability{CapabilityRead, CapabilityCommentAdd, CapabilityCommentDelete}, wantValid: true},
		{name: "delete before comment add is rejected", capabilities: []Capability{CapabilityRead, CapabilityCommentDelete, CapabilityCommentAdd}},
		{name: "duplicate delete is rejected", capabilities: []Capability{CapabilityRead, CapabilityCommentDelete, CapabilityCommentDelete}},
		{name: "unknown capability is rejected", capabilities: []Capability{CapabilityRead, Capability("future-write")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateCapabilities(test.capabilities)
			if test.wantValid && err != nil {
				t.Fatalf("ValidateCapabilities() error = %v", err)
			}
			if !test.wantValid && !errors.Is(err, ErrInvalidProfile) {
				t.Fatalf("ValidateCapabilities() error = %v, want ErrInvalidProfile", err)
			}
		})
	}
}

func TestCommentDeleteCapabilityRequiresExplicitProfileChange(t *testing.T) {
	legacy, err := testProfile("work").WithNewCredentialGeneration()
	if err != nil {
		t.Fatal(err)
	}
	if legacy.HasCapability(CapabilityCommentDelete) {
		t.Fatal("legacy comment-add profile unexpectedly grants comment-delete")
	}

	deleteEnabled := legacy
	deleteEnabled.Capabilities = append(append([]Capability(nil), legacy.Capabilities...), CapabilityCommentDelete)
	if err := deleteEnabled.Validate(); err != nil {
		t.Fatalf("explicit delete profile validation failed: %v", err)
	}
	if !deleteEnabled.HasCapability(CapabilityCommentDelete) {
		t.Fatal("explicit comment-delete profile does not grant comment-delete")
	}
	if CredentialIdentity(legacy) == CredentialIdentity(deleteEnabled) {
		t.Fatal("credential identity did not bind the explicit comment-delete grant")
	}
	if SelectionIdentity(legacy) == SelectionIdentity(deleteEnabled) {
		t.Fatal("selection identity did not bind the explicit comment-delete grant")
	}
}
