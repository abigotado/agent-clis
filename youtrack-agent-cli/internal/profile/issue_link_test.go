package profile

import (
	"errors"
	"testing"
)

func TestIssueLinkCapabilityIsExplicitAndCanonical(t *testing.T) {
	tests := []struct {
		name         string
		capabilities []Capability
		wantValid    bool
	}{
		{name: "link only after read", capabilities: []Capability{CapabilityRead, CapabilityIssueLink}, wantValid: true},
		{name: "link after edit", capabilities: []Capability{CapabilityRead, CapabilityCommentAdd, CapabilityCommentDelete, CapabilityIssueEdit, CapabilityIssueLink}, wantValid: true},
		{name: "link before edit is rejected", capabilities: []Capability{CapabilityRead, CapabilityIssueLink, CapabilityIssueEdit}},
		{name: "link before issue create is rejected", capabilities: []Capability{CapabilityRead, CapabilityIssueLink, CapabilityIssueCreate}},
		{name: "duplicate link is rejected", capabilities: []Capability{CapabilityRead, CapabilityIssueLink, CapabilityIssueLink}},
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
	if capabilityRank(CapabilityIssueLink) != 6 || capabilityRank(CapabilityIssueEdit) != 5 {
		t.Fatalf("ranks link=%d edit=%d", capabilityRank(CapabilityIssueLink), capabilityRank(CapabilityIssueEdit))
	}
}

func TestIssueLinkCapabilityRequiresExplicitProfileChange(t *testing.T) {
	legacy, err := testProfile("work").WithNewCredentialGeneration()
	if err != nil {
		t.Fatal(err)
	}
	if legacy.HasCapability(CapabilityIssueLink) {
		t.Fatal("legacy profile unexpectedly grants issue-link")
	}
	withEdit := legacy
	withEdit.Capabilities = append(append([]Capability(nil), legacy.Capabilities...), CapabilityIssueEdit)
	if withEdit.HasCapability(CapabilityIssueLink) {
		t.Fatal("issue-edit implies issue-link")
	}
	link := withEdit
	link.Capabilities = append(append([]Capability(nil), withEdit.Capabilities...), CapabilityIssueLink)
	if err := link.Validate(); err != nil {
		t.Fatalf("explicit link profile validation failed: %v", err)
	}
	if !link.HasCapability(CapabilityIssueLink) || !link.HasCapability(CapabilityIssueEdit) {
		t.Fatal("explicit issue-link profile lost a capability")
	}
	if CredentialIdentity(withEdit) == CredentialIdentity(link) || SelectionIdentity(withEdit) == SelectionIdentity(link) {
		t.Fatal("identity did not bind the explicit issue-link grant")
	}
}
