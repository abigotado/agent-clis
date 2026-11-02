package cli

import (
	"strconv"

	"github.com/abigotado/youtrack-agent-cli/internal/application"
	"github.com/abigotado/youtrack-agent-cli/internal/output"
	"github.com/spf13/cobra"
)

type capabilitiesView struct{ application.CapabilitiesInfo }

func (view capabilitiesView) Fields() []output.Field {
	return []output.Field{
		{Name: "edition", Value: view.Edition, Raw: view.Edition},
		{Name: "operator_write_supported", Value: strconv.FormatBool(view.OperatorWriteSupported), Raw: view.OperatorWriteSupported},
		{Name: "native_user_presence_supported", Value: strconv.FormatBool(view.NativeUserPresenceSupported), Raw: view.NativeUserPresenceSupported},
		{Name: "confirmation_mode", Value: view.ConfirmationMode, Raw: view.ConfirmationMode, Always: true},
		{Name: "plan_version", Value: strconv.Itoa(view.PlanVersion), Raw: view.PlanVersion},
		{Name: "plan_lifetime", Value: view.PlanLifetime, Raw: view.PlanLifetime},
		{Name: "locally_ready", Value: strconv.FormatBool(view.LocallyReady), Raw: view.LocallyReady},
		{Name: "credential_generation_configured", Value: strconv.FormatBool(view.CredentialGenerationConfigured), Raw: view.CredentialGenerationConfigured},
		{Name: "project_policy_configured", Value: strconv.FormatBool(view.ProjectPolicyConfigured), Raw: view.ProjectPolicyConfigured},
		{Name: "kinds", Raw: view.Kinds},
		{Name: "readiness_scope", Value: view.ReadinessScope, Raw: view.ReadinessScope, Always: true},
		{Name: "profile", Value: view.Profile, Raw: view.Profile, OnRequest: true},
	}
}

func (a *App) newCapabilitiesCommand() *cobra.Command {
	return &cobra.Command{Use: "capabilities", Short: "Report build support and optional offline profile readiness", Args: usageArgs(cobra.NoArgs), RunE: func(cmd *cobra.Command, _ []string) error {
		if err := a.out.Validate(capabilitiesView{}); err != nil {
			return err
		}
		result, err := a.service.Capabilities(cmd.Context(), a.profileName)
		if err != nil {
			return err
		}
		a.out.WithContext(result.Profile, result.Instance, result.AccountID, result.AccountLogin)
		return a.out.Success(capabilitiesView{result})
	}}
}
