package profile

import (
	"errors"
	"testing"
)

func TestAttachmentAddCapabilityIsExplicitAndCanonical(t *testing.T) {
	tests := []struct {
		name         string
		capabilities []Capability
		wantValid    bool
	}{
		{name: "after read", capabilities: []Capability{CapabilityRead, CapabilityAttachmentAdd}, wantValid: true},
		{name: "after every other capability", capabilities: []Capability{CapabilityRead, CapabilityIssueCreate, CapabilityIssueUpdate, CapabilityCommentAdd, CapabilityCommentDelete, CapabilityIssueEdit, CapabilityIssueCreateUserFields, CapabilityAttachmentAdd}, wantValid: true},
		{name: "before user fields is rejected", capabilities: []Capability{CapabilityRead, CapabilityAttachmentAdd, CapabilityIssueCreateUserFields}},
		{name: "before edit is rejected", capabilities: []Capability{CapabilityRead, CapabilityAttachmentAdd, CapabilityIssueEdit}},
		{name: "duplicate is rejected", capabilities: []Capability{CapabilityRead, CapabilityAttachmentAdd, CapabilityAttachmentAdd}},
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
	if capabilityRank(CapabilityAttachmentAdd) != 8 {
		t.Fatalf("attachment-add rank = %d", capabilityRank(CapabilityAttachmentAdd))
	}
}

func TestAttachmentAddCapabilityChangesCredentialIdentity(t *testing.T) {
	base, err := testProfile("work").WithNewCredentialGeneration()
	if err != nil {
		t.Fatal(err)
	}
	if base.HasCapability(CapabilityAttachmentAdd) {
		t.Fatal("existing capabilities imply attachment-add")
	}
	explicit := base
	explicit.Capabilities = append(append([]Capability(nil), base.Capabilities...), CapabilityAttachmentAdd)
	if err := explicit.Validate(); err != nil {
		t.Fatalf("explicit profile validation failed: %v", err)
	}
	if CredentialIdentity(base) == CredentialIdentity(explicit) || SelectionIdentity(base) == SelectionIdentity(explicit) {
		t.Fatal("identity did not bind the attachment-add grant")
	}
}
