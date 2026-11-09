package cli

import (
	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/spf13/cobra"
)

func (a *App) newContractCommand() *cobra.Command {
	return &cobra.Command{
		Use: "contract", Short: "Print the versioned envelope and exit-code contract", Args: usageArgs(cobra.NoArgs),
		RunE: func(*cobra.Command, []string) error { return a.out.Success(errx.Describe()) },
	}
}

func (a *App) newProfileCommand() *cobra.Command {
	command := commandGroup("profile", "Manage strict non-secret YouTrack profiles")
	command.AddCommand(a.newProfileListCommand(), a.newProfileShowCommand(), a.newProfileValidateCommand(), a.newProfileAddCommand(), a.newProfileRemoveCommand(), a.newProfileDefaultsCommand())
	return command
}

func (a *App) newProfileListCommand() *cobra.Command {
	return &cobra.Command{
		Use: "list", Short: "List non-secret profiles without reading Keychain", Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			values, err := a.service.ListProfileInfo(cmd.Context())
			if err != nil {
				return err
			}
			views := make([]profileView, len(values))
			for index, value := range values {
				views[index] = newProfileView(value)
			}
			return a.out.Success(views)
		},
	}
}

func (a *App) newProfileShowCommand() *cobra.Command {
	return &cobra.Command{
		Use: "show", Short: "Show one non-secret profile", Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.requireProfile(); err != nil {
				return err
			}
			value, err := a.service.GetProfileInfo(cmd.Context(), a.profileName)
			if err != nil {
				return err
			}
			return a.out.Success(newProfileView(value))
		},
	}
}

func (a *App) newProfileValidateCommand() *cobra.Command {
	var offline bool
	command := &cobra.Command{
		Use: "validate", Short: "Validate one profile without credentials or network", Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !offline {
				return errx.Usage("profile validate requires --offline")
			}
			if err := a.requireProfile(); err != nil {
				return err
			}
			value, err := a.service.GetProfileInfo(cmd.Context(), a.profileName)
			if err != nil {
				return err
			}
			view := newProfileView(value)
			view.State = "valid_offline"
			return a.out.Success(view)
		},
	}
	command.Flags().BoolVar(&offline, "offline", false, "guarantee no credential or network access")
	return command
}

func (a *App) newProfileAddCommand() *cobra.Command {
	var from string
	command := &cobra.Command{
		Use: "add", Short: "Add or replace one strict non-secret profile", Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if from == "" {
				return errx.Usage("profile add requires --from FILE")
			}
			raw, err := readBoundedRegular(from, maxProfileFileBytes)
			if err != nil {
				return err
			}
			value, err := a.service.ValidateProfileJSON(raw, a.profileName)
			if err != nil {
				return err
			}
			if a.dryRun {
				view := newProfileView(value)
				view.State = "validated_not_applied"
				return a.out.Success(view)
			}
			preview := newProfileView(value)
			preview.State = "applied"
			if err := a.out.Validate(preview); err != nil {
				return err
			}
			if !a.assumeYes {
				return errx.ConfirmRequired("profile add")
			}
			saved, err := a.service.SaveProfileJSON(cmd.Context(), raw, a.profileName, true)
			if err != nil {
				return err
			}
			view := newProfileView(saved)
			view.State = "applied"
			return a.out.Success(view)
		},
	}
	command.Flags().StringVar(&from, "from", "", "bounded non-secret profile JSON file")
	return command
}

func (a *App) newProfileRemoveCommand() *cobra.Command {
	return &cobra.Command{
		Use: "remove", Short: "Remove one credential-free profile", Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.requireProfile(); err != nil {
				return err
			}
			if a.dryRun {
				return a.out.Success(map[string]any{"profile": a.profileName, "dry_run": true, "removed": false})
			}
			result := map[string]any{"profile": a.profileName, "removed": true}
			if err := a.out.Validate(result); err != nil {
				return err
			}
			if !a.assumeYes {
				return errx.ConfirmRequired("profile remove")
			}
			if err := a.service.RemoveProfile(cmd.Context(), a.profileName); err != nil {
				return err
			}
			return a.out.Success(result)
		},
	}
}
