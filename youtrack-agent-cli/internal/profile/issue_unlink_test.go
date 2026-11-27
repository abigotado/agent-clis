package profile

import (
	"errors"
	"testing"
)

func TestIssueUnlinkCapabilityIsExplicitAndCanonical(t *testing.T) {
	tests := []struct {
		name         string
		capabilities []Capability
		wantValid    bool
	}{
		{name: "after read", capabilities: []Capability{CapabilityRead, CapabilityIssueUnlink}, wantValid: true},
		{name: "after attachment-add", capabilities: []Capability{CapabilityRead, CapabilityIssueLink, CapabilityAttachmentAdd, CapabilityIssueUnlink}, wantValid: true},
		{name: "after every other capability", capabilities: []Capability{CapabilityRead, CapabilityIssueCreate, CapabilityIssueUpdate, CapabilityCommentAdd, CapabilityCommentDelete, CapabilityIssueEdit, CapabilityIssueCreateUserFields, CapabilityIssueLink, CapabilityAttachmentAdd, CapabilityIssueUnlink}, wantValid: true},
		{name: "before attachment-add is rejected", capabilities: []Capability{CapabilityRead, CapabilityIssueUnlink, CapabilityAttachmentAdd}},
		{name: "before issue-link is rejected", capabilities: []Capability{CapabilityRead, CapabilityIssueUnlink, CapabilityIssueLink}},
		{name: "duplicate is rejected", capabilities: []Capability{CapabilityRead, CapabilityIssueUnlink, CapabilityIssueUnlink}},
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
	if capabilityRank(CapabilityIssueUnlink) != 9 {
		t.Fatalf("issue-unlink rank = %d", capabilityRank(CapabilityIssueUnlink))
	}
}

func TestIssueUnlinkCapabilityChangesCredentialIdentity(t *testing.T) {
	base, err := testProfile("work").WithNewCredentialGeneration()
	if err != nil {
		t.Fatal(err)
	}
	withLink := base
	withLink.Capabilities = append(append([]Capability(nil), base.Capabilities...), CapabilityIssueLink)
	if withLink.HasCapability(CapabilityIssueUnlink) || base.HasCapability(CapabilityIssueUnlink) {
		t.Fatal("existing capabilities imply issue-unlink")
	}
	explicit := withLink
	explicit.Capabilities = append(append([]Capability(nil), withLink.Capabilities...), CapabilityIssueUnlink)
	if err := explicit.Validate(); err != nil {
		t.Fatalf("explicit profile validation failed: %v", err)
	}
	if !explicit.HasCapability(CapabilityIssueUnlink) || !explicit.HasCapability(CapabilityIssueLink) {
		t.Fatal("explicit profile lost a capability")
	}
	if CredentialIdentity(withLink) == CredentialIdentity(explicit) || SelectionIdentity(withLink) == SelectionIdentity(explicit) {
		t.Fatal("identity did not bind the issue-unlink grant")
	}
}
