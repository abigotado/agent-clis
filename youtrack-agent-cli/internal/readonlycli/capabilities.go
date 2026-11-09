package readonlycli

import (
	"github.com/abigotado/youtrack-agent-cli/internal/output"
	"github.com/spf13/cobra"
)

type capabilitiesView struct {
	Edition                     string   `json:"edition"`
	OperatorWriteSupported      bool     `json:"operator_write_supported"`
	NativeUserPresenceSupported bool     `json:"native_user_presence_supported"`
	LocallyReady                bool     `json:"locally_ready"`
	ReadinessScope              string   `json:"readiness_scope"`
	Kinds                       []string `json:"kinds"`
}

func (v capabilitiesView) Fields() []output.Field {
	return []output.Field{
		{Name: "edition", Value: v.Edition, Raw: v.Edition},
		{Name: "operator_write_supported", Value: "false", Raw: false},
		{Name: "native_user_presence_supported", Value: "false", Raw: false},
		{Name: "locally_ready", Value: "false", Raw: false},
		{Name: "readiness_scope", Value: v.ReadinessScope, Raw: v.ReadinessScope, Always: true},
		{Name: "kinds", Raw: v.Kinds},
	}
}

func (a *App) newCapabilitiesCommand() *cobra.Command {
	return &cobra.Command{Use: "capabilities", Short: "Report this edition's disabled write capabilities", Args: usageArgs(cobra.NoArgs), RunE: func(cmd *cobra.Command, _ []string) error {
		if err := a.out.Validate(capabilitiesView{}); err != nil {
			return err
		}
		if a.profileName != "" {
			if err := a.requireProfile(); err != nil {
				return err
			}
			selected, err := a.getProfile(cmd.Context(), a.profileName)
			if err != nil {
				return a.translate(err)
			}
			a.out.WithContext(selected.Name, selected.ServiceURL, selected.ExpectedAccountID, selected.ExpectedLogin)
		}
		return a.out.Success(capabilitiesView{Edition: a.policy.id, ReadinessScope: "local_configuration_only", Kinds: []string{}})
	}}
}
