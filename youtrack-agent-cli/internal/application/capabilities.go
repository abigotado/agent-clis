package application

import (
	"context"
	"errors"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/operatorwrite"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/profile"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/writepolicy"
)

// CapabilitiesInfo describes local configuration, never server permissions or
// credential-store accessibility. Reading it is entirely offline.
type CapabilitiesInfo struct {
	Edition                        string         `json:"edition"`
	OperatorWriteSupported         bool           `json:"operator_write_supported"`
	NativeUserPresenceSupported    bool           `json:"native_user_presence_supported"`
	ConfirmationMode               string         `json:"confirmation_mode"`
	PlanVersion                    int            `json:"plan_version"`
	PlanLifetime                   string         `json:"plan_lifetime"`
	PlanVersions                   map[string]int `json:"plan_versions"`
	Profile                        string         `json:"profile,omitempty"`
	Instance                       string         `json:"instance,omitempty"`
	AccountID                      string         `json:"account_id,omitempty"`
	AccountLogin                   string         `json:"account_login,omitempty"`
	LocallyReady                   bool           `json:"locally_ready"`
	CredentialGenerationConfigured bool           `json:"credential_generation_configured"`
	ProjectPolicyConfigured        bool           `json:"project_policy_configured"`
	Kinds                          []string       `json:"kinds"`
	ReadinessScope                 string         `json:"readiness_scope"`
}

// Capabilities reports build support and, optionally, one explicit profile's
// non-secret local generation and current identity-bound policy.
func (s *Service) Capabilities(ctx context.Context, name string) (CapabilitiesInfo, error) {
	result := CapabilitiesInfo{Edition: "standard", OperatorWriteSupported: s.OperatorBackendSupported(),
		ConfirmationMode: "operator_confirmed", PlanVersion: operatorwrite.PlanVersion3,
		PlanLifetime: operatorwrite.PlanLifetime(operatorwrite.PlanVersion3),
		PlanVersions: map[string]int{"issue.create": operatorwrite.PlanVersion2, "issue.update": operatorwrite.PlanVersion2, "comment.add": operatorwrite.PlanVersion2, "comment.delete": operatorwrite.PlanVersion3},
		Kinds:        []string{}, ReadinessScope: "local_configuration_only"}
	if name == "" {
		return result, nil
	}
	selected, err := s.GetProfile(ctx, name)
	if err != nil {
		return result, err
	}
	result.Profile, result.Instance = selected.Name, selected.ServiceURL
	result.AccountID, result.AccountLogin = selected.ExpectedAccountID, selected.ExpectedLogin
	result.CredentialGenerationConfigured = selected.CredentialGeneration != ""
	if selected.Executor == profile.ExecutorRESTBestEffort && selected.Assurance == profile.AssuranceBestEffort {
		if selected.HasCapability(profile.CapabilityIssueCreate) {
			result.Kinds = append(result.Kinds, "issue.create")
		}
		if selected.HasCapability(profile.CapabilityIssueUpdate) {
			result.Kinds = append(result.Kinds, "issue.update")
		}
		if selected.HasCapability(profile.CapabilityCommentAdd) {
			result.Kinds = append(result.Kinds, "comment.add")
		}
		if selected.HasCapability(profile.CapabilityCommentDelete) {
			result.Kinds = append(result.Kinds, "comment.delete")
		}
	}
	if s.Policies != nil {
		policy, policyErr := s.Policies.GetBound(ctx, selected)
		if policyErr == nil {
			result.ProjectPolicyConfigured = len(policy.Projects) > 0
		} else if !errors.Is(policyErr, writepolicy.ErrNotFound) && !errors.Is(policyErr, writepolicy.ErrStale) {
			return result, policyErr
		}
	}
	result.LocallyReady = result.OperatorWriteSupported && result.CredentialGenerationConfigured && result.ProjectPolicyConfigured && len(result.Kinds) > 0
	return result, nil
}
