package mutation

import (
	"strings"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/intent"
)

type fixedID string

func (f fixedID) NewPlanID() (string, error) { return string(f), nil }

func mutationPlan(t *testing.T) intent.Plan {
	t.Helper()
	plan, err := intent.PrepareWithSource(
		intent.ProfileSnapshot{Name: "work", Instance: "https://acme.youtrack.cloud", RESTBaseURL: "https://acme.youtrack.cloud/api", OAuthIssuerURL: "https://hub.example.test", IdentitySHA256: strings.Repeat("a", 64), CredentialGeneration: "gen-1", Account: intent.AccountBinding{ID: "1-2", Login: "alice"}},
		intent.ProjectPolicy{Project: intent.ProjectBinding{ID: "0-1", Key: "APP"}, PolicyRevision: 1, PolicySHA256: strings.Repeat("b", 64), SchemaSHA256: strings.Repeat("c", 64), ExecutorAssurance: "rest-best-effort", AuthorizedCapability: "issue-update", NotificationPolicy: "youtrack-default", ReconciliationStrategy: "bounded-exact-and-marker"},
		intent.KindIssueUpdate,
		[]byte(`{"issue_id":"APP-1","set":{"summary":"new"}}`),
		[]byte(`{"issue_id":"APP-1","issue_state_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","touched_fields_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}`),
		fixedID("YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestPreflightRejectsDrift(t *testing.T) {
	plan := mutationPlan(t)
	valid := Preflight{
		ProfileIdentitySHA256: plan.Profile.IdentitySHA256, AccountID: plan.Profile.Account.ID,
		ProjectID: plan.Policy.Project.ID, ProjectKey: plan.Policy.Project.Key,
		SchemaSHA256: plan.Policy.SchemaSHA256, ExpectedSHA256: plan.ExpectedSHA256,
	}
	if err := valid.Validate(plan); err != nil {
		t.Fatal(err)
	}
	valid.AccountID = "different"
	if err := valid.Validate(plan); err == nil {
		t.Fatal("changed account passed preflight")
	}
}

func TestExecutionEnforcesOneShotResult(t *testing.T) {
	tests := []struct {
		name    string
		value   Execution
		wantErr bool
	}{
		{"applied", Execution{Disposition: DispositionApplied, MutationAttempts: 1, RemoteID: "APP-2"}, false},
		{"zero attempts", Execution{Disposition: DispositionAmbiguous}, true},
		{"two attempts", Execution{Disposition: DispositionAmbiguous, MutationAttempts: 2}, true},
		{"applied missing ID", Execution{Disposition: DispositionApplied, MutationAttempts: 1}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.value.Validate(); (got != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", got, tt.wantErr)
			}
		})
	}
}
