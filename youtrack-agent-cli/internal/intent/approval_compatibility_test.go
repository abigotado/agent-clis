package intent

import (
	"errors"
	"testing"
)

func TestPlanValidateKeepsLegacyURLsReadableButApprovalBoundaryRejectsThem(t *testing.T) {
	profile, policy := validBindings()
	plan, err := PrepareWithSource(profile, policy, KindIssueCreate,
		[]byte(`{"summary":"hello","description":"","visibility":{"mode":"public"},"marker":"none"}`),
		[]byte(`{"project_state_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`),
		fixedIDSource("YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA"))
	if err != nil {
		t.Fatal(err)
	}
	plan.Profile.Instance = "https://acme.youtrack.cloud:443"
	plan.Profile.RESTBaseURL = "https://acme.youtrack.cloud:443/api"
	plan.Profile.OAuthIssuerURL = "https://hub.example.test:443"
	raw, err := canonicalBytesUnchecked(plan)
	if err != nil {
		t.Fatal(err)
	}
	plan.IntentSHA256 = digest(raw)
	if err := plan.Validate(); err != nil {
		t.Fatalf("legacy journal plan no longer validates: %v", err)
	}
	if _, err := ApprovalDisplayBytes(plan); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("ApprovalDisplayBytes error = %v, want ErrInvalidPlan", err)
	}
	if _, err := ParseApprovalSnapshot(raw, MaxCanonicalPlanBytes); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("ParseApprovalSnapshot error = %v, want ErrInvalidPlan", err)
	}
	if _, err := PrepareWithSource(plan.Profile, policy, KindIssueCreate,
		[]byte(`{"summary":"hello","description":"","visibility":{"mode":"public"},"marker":"none"}`),
		[]byte(`{"project_state_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`),
		fixedIDSource("YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA")); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("PrepareWithSource error = %v, want ErrInvalidPlan", err)
	}
}
