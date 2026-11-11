package profile

import (
	"errors"
	"testing"
)

func TestIssueCreateUserFieldsCapabilityIsExplicitAndCanonical(t *testing.T) {
	tests := []struct {
		name         string
		capabilities []Capability
		wantValid    bool
	}{
		{name: "after read", capabilities: []Capability{CapabilityRead, CapabilityIssueCreateUserFields}, wantValid: true},
		{name: "after create", capabilities: []Capability{CapabilityRead, CapabilityIssueCreate, CapabilityIssueCreateUserFields}, wantValid: true},
		{name: "after every other capability", capabilities: []Capability{CapabilityRead, CapabilityIssueCreate, CapabilityIssueUpdate, CapabilityCommentAdd, CapabilityCommentDelete, CapabilityIssueEdit, CapabilityIssueCreateUserFields}, wantValid: true},
		{name: "before create is rejected", capabilities: []Capability{CapabilityRead, CapabilityIssueCreateUserFields, CapabilityIssueCreate}},
		{name: "before edit is rejected", capabilities: []Capability{CapabilityRead, CapabilityIssueCreateUserFields, CapabilityIssueEdit}},
		{name: "duplicate is rejected", capabilities: []Capability{CapabilityRead, CapabilityIssueCreateUserFields, CapabilityIssueCreateUserFields}},
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
	if capabilityRank(CapabilityIssueCreateUserFields) != 6 || capabilityRank(CapabilityIssueEdit) != 5 {
		t.Fatalf("ranks user-fields=%d edit=%d", capabilityRank(CapabilityIssueCreateUserFields), capabilityRank(CapabilityIssueEdit))
	}
}

func TestIssueCreateUserFieldsCapabilityRequiresExplicitProfileChange(t *testing.T) {
	legacy, err := testProfile("work").WithNewCredentialGeneration()
	if err != nil {
		t.Fatal(err)
	}
	withCreate := legacy
	if !withCreate.HasCapability(CapabilityIssueCreate) {
		t.Fatal("fixture profile lacks issue-create")
	}
	if withCreate.HasCapability(CapabilityIssueCreateUserFields) {
		t.Fatal("issue-create implies issue-create-user-fields")
	}
	explicit := withCreate
	explicit.Capabilities = append(append([]Capability(nil), withCreate.Capabilities...), CapabilityIssueCreateUserFields)
	if err := explicit.Validate(); err != nil {
		t.Fatalf("explicit profile validation failed: %v", err)
	}
	if !explicit.HasCapability(CapabilityIssueCreateUserFields) || !explicit.HasCapability(CapabilityIssueCreate) {
		t.Fatal("explicit profile lost a capability")
	}
	if CredentialIdentity(withCreate) == CredentialIdentity(explicit) || SelectionIdentity(withCreate) == SelectionIdentity(explicit) {
		t.Fatal("identity did not bind the explicit user-fields grant")
	}
}
