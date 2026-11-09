package cli

import (
	"github.com/abigotado/youtrack-agent-cli/internal/application"
	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/output"
	"github.com/spf13/cobra"
)

type profileDefaultSlotView struct {
	State                 string `json:"state"`
	ProfileName           string `json:"profile_name,omitempty"`
	ProfileIdentitySHA256 string `json:"profile_identity_sha256,omitempty"`
}

type profileDefaultsView struct {
	Read  profileDefaultSlotView `json:"read"`
	Write profileDefaultSlotView `json:"write"`
}

func newProfileDefaultsView(value application.ProfileDefaultsInfo) profileDefaultsView {
	return profileDefaultsView{
		Read: profileDefaultSlotView{
			State:                 value.Read.State,
			ProfileName:           value.Read.ProfileName,
			ProfileIdentitySHA256: value.Read.ProfileIdentitySHA256,
		},
		Write: profileDefaultSlotView{
			State:                 value.Write.State,
			ProfileName:           value.Write.ProfileName,
			ProfileIdentitySHA256: value.Write.ProfileIdentitySHA256,
		},
	}
}

func (view profileDefaultsView) Fields() []output.Field {
	return []output.Field{
		{Name: "read", Value: profileDefaultSlotText(view.Read), Raw: view.Read},
		{Name: "write", Value: profileDefaultSlotText(view.Write), Raw: view.Write},
		{Name: "read_state", Value: view.Read.State, Raw: view.Read.State, OnRequest: true},
		{Name: "read_profile_name", Value: view.Read.ProfileName, Raw: view.Read.ProfileName, OnRequest: true},
		{Name: "write_state", Value: view.Write.State, Raw: view.Write.State, OnRequest: true},
		{Name: "write_profile_name", Value: view.Write.ProfileName, Raw: view.Write.ProfileName, OnRequest: true},
		{Name: "read_profile_identity_sha256", Value: view.Read.ProfileIdentitySHA256, Raw: view.Read.ProfileIdentitySHA256, OnRequest: true},
		{Name: "write_profile_identity_sha256", Value: view.Write.ProfileIdentitySHA256, Raw: view.Write.ProfileIdentitySHA256, OnRequest: true},
	}
}

func profileDefaultSlotText(view profileDefaultSlotView) string {
	if view.ProfileName == "" {
		return view.State
	}
	return view.State + " " + view.ProfileName
}

func (a *App) newProfileDefaultsCommand() *cobra.Command {
	command := commandGroup("defaults", "Manage saved read and write profile defaults")
	command.AddCommand(a.newProfileDefaultsShowCommand(), a.newProfileDefaultsSetCommand(), a.newProfileDefaultsClearCommand())
	return command
}

func (a *App) rejectDefaultProfileOverride(cmd *cobra.Command) error {
	if cmd.Flags().Changed("profile") {
		return errx.Usage("profile defaults does not accept --profile")
	}
	return nil
}

func (a *App) newProfileDefaultsShowCommand() *cobra.Command {
	return &cobra.Command{
		Use: "show", Short: "Show saved read and write profile defaults", Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.rejectDefaultProfileOverride(cmd); err != nil {
				return err
			}
			if a.assumeYes || a.dryRun {
				return errx.Usage("profile defaults show does not accept --yes or --dry-run")
			}
			value, err := a.service.GetProfileDefaults(cmd.Context())
			if err != nil {
				return err
			}
			return a.out.Success(newProfileDefaultsView(value))
		},
	}
}

func (a *App) newProfileDefaultsSetCommand() *cobra.Command {
	var readName, writeName string
	command := &cobra.Command{
		Use: "set", Short: "Set saved read and write profile defaults", Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.rejectDefaultProfileOverride(cmd); err != nil {
				return err
			}
			var read, write *string
			if cmd.Flags().Changed("read") {
				if readName == "" {
					return errx.Usage("--read must not be empty")
				}
				read = &readName
			}
			if cmd.Flags().Changed("write") {
				if writeName == "" {
					return errx.Usage("--write must not be empty")
				}
				write = &writeName
			}
			if read == nil && write == nil {
				return errx.Usage("profile defaults set requires --read NAME or --write NAME")
			}
			preview, err := a.service.ChangeProfileDefaults(cmd.Context(), read, write, true)
			if err != nil {
				return err
			}
			view := newProfileDefaultsView(preview)
			if err := a.out.Validate(view); err != nil {
				return err
			}
			if a.dryRun {
				return a.out.Success(view)
			}
			if !a.assumeYes {
				return errx.ConfirmRequired("profile defaults set")
			}
			updated, err := a.service.ChangeProfileDefaults(cmd.Context(), read, write, false)
			if err != nil {
				return err
			}
			return a.out.Success(newProfileDefaultsView(updated))
		},
	}
	flags := command.Flags()
	flags.StringVar(&readName, "read", "", "profile name for supported read operations")
	flags.StringVar(&writeName, "write", "", "profile name for supported operator-write operations")
	return command
}

func (a *App) newProfileDefaultsClearCommand() *cobra.Command {
	var clearRead, clearWrite bool
	command := &cobra.Command{
		Use: "clear", Short: "Clear saved read and write profile defaults", Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.rejectDefaultProfileOverride(cmd); err != nil {
				return err
			}
			if !clearRead && !clearWrite {
				return errx.Usage("profile defaults clear requires --read or --write")
			}
			preview, err := a.service.ClearProfileDefaults(cmd.Context(), clearRead, clearWrite, true)
			if err != nil {
				return err
			}
			view := newProfileDefaultsView(preview)
			if err := a.out.Validate(view); err != nil {
				return err
			}
			if a.dryRun {
				return a.out.Success(view)
			}
			if !a.assumeYes {
				return errx.ConfirmRequired("profile defaults clear")
			}
			updated, err := a.service.ClearProfileDefaults(cmd.Context(), clearRead, clearWrite, false)
			if err != nil {
				return err
			}
			return a.out.Success(newProfileDefaultsView(updated))
		},
	}
	flags := command.Flags()
	flags.BoolVar(&clearRead, "read", false, "clear the saved read default")
	flags.BoolVar(&clearWrite, "write", false, "clear the saved write default")
	return command
}
