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

func TestIssueEditCapabilityIsExplicitAndCanonical(t *testing.T) {
	tests := []struct {
		name         string
		capabilities []Capability
		wantValid    bool
	}{
		{name: "edit only after read", capabilities: []Capability{CapabilityRead, CapabilityIssueEdit}, wantValid: true},
		{name: "edit after delete", capabilities: []Capability{CapabilityRead, CapabilityCommentAdd, CapabilityCommentDelete, CapabilityIssueEdit}, wantValid: true},
		{name: "edit before delete is rejected", capabilities: []Capability{CapabilityRead, CapabilityIssueEdit, CapabilityCommentDelete}},
		{name: "edit before issue update is rejected", capabilities: []Capability{CapabilityRead, CapabilityIssueEdit, CapabilityIssueUpdate}},
		{name: "duplicate edit is rejected", capabilities: []Capability{CapabilityRead, CapabilityIssueEdit, CapabilityIssueEdit}},
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
	if capabilityRank(CapabilityIssueEdit) != 5 || capabilityRank(CapabilityCommentDelete) != 4 {
		t.Fatalf("ranks edit=%d delete=%d", capabilityRank(CapabilityIssueEdit), capabilityRank(CapabilityCommentDelete))
	}
}

func TestIssueEditCapabilityRequiresExplicitProfileChange(t *testing.T) {
	legacy, err := testProfile("work").WithNewCredentialGeneration()
	if err != nil {
		t.Fatal(err)
	}
	if legacy.HasCapability(CapabilityIssueEdit) {
		t.Fatal("legacy profile unexpectedly grants issue-edit")
	}
	withDelete := legacy
	withDelete.Capabilities = append(append([]Capability(nil), legacy.Capabilities...), CapabilityCommentDelete)
	if withDelete.HasCapability(CapabilityIssueEdit) {
		t.Fatal("comment-delete implies issue-edit")
	}
	edit := withDelete
	edit.Capabilities = append(append([]Capability(nil), withDelete.Capabilities...), CapabilityIssueEdit)
	if err := edit.Validate(); err != nil {
		t.Fatalf("explicit edit profile validation failed: %v", err)
	}
	if !edit.HasCapability(CapabilityIssueEdit) || !edit.HasCapability(CapabilityCommentDelete) {
		t.Fatal("explicit issue-edit profile lost a capability")
	}
	if CredentialIdentity(withDelete) == CredentialIdentity(edit) || SelectionIdentity(withDelete) == SelectionIdentity(edit) {
		t.Fatal("identity did not bind the explicit issue-edit grant")
	}
}
