package profile

import (
	"errors"
	"testing"
)

func TestIssueTagCapabilityIsExplicitAndCanonical(t *testing.T) {
	tests := []struct {
		name         string
		capabilities []Capability
		wantValid    bool
	}{
		{name: "after read", capabilities: []Capability{CapabilityRead, CapabilityIssueTag}, wantValid: true},
		{name: "after issue-unlink", capabilities: []Capability{CapabilityRead, CapabilityIssueLink, CapabilityAttachmentAdd, CapabilityIssueUnlink, CapabilityIssueTag}, wantValid: true},
		{name: "after every other capability", capabilities: []Capability{CapabilityRead, CapabilityIssueCreate, CapabilityIssueUpdate, CapabilityCommentAdd, CapabilityCommentDelete, CapabilityIssueEdit, CapabilityIssueCreateUserFields, CapabilityIssueLink, CapabilityAttachmentAdd, CapabilityIssueUnlink, CapabilityIssueTag}, wantValid: true},
		{name: "before issue-unlink is rejected", capabilities: []Capability{CapabilityRead, CapabilityIssueTag, CapabilityIssueUnlink}},
		{name: "before issue-link is rejected", capabilities: []Capability{CapabilityRead, CapabilityIssueTag, CapabilityIssueLink}},
		{name: "duplicate is rejected", capabilities: []Capability{CapabilityRead, CapabilityIssueTag, CapabilityIssueTag}},
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
	if capabilityRank(CapabilityIssueTag) != 10 {
		t.Fatalf("issue-tag rank = %d", capabilityRank(CapabilityIssueTag))
	}
}

func TestIssueTagCapabilityChangesCredentialIdentity(t *testing.T) {
	base, err := testProfile("work").WithNewCredentialGeneration()
	if err != nil {
		t.Fatal(err)
	}
	withUnlink := base
	withUnlink.Capabilities = append(append([]Capability(nil), base.Capabilities...), CapabilityIssueUnlink)
	if withUnlink.HasCapability(CapabilityIssueTag) || base.HasCapability(CapabilityIssueTag) {
		t.Fatal("existing capabilities imply issue-tag")
	}
	explicit := withUnlink
	explicit.Capabilities = append(append([]Capability(nil), withUnlink.Capabilities...), CapabilityIssueTag)
	if err := explicit.Validate(); err != nil {
		t.Fatalf("explicit profile validation failed: %v", err)
	}
	if !explicit.HasCapability(CapabilityIssueTag) || !explicit.HasCapability(CapabilityIssueUnlink) {
		t.Fatal("explicit profile lost a capability")
	}
	if CredentialIdentity(withUnlink) == CredentialIdentity(explicit) || SelectionIdentity(withUnlink) == SelectionIdentity(explicit) {
		t.Fatal("identity did not bind the issue-tag grant")
	}
}
