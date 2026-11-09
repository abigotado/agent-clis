package readonlycli

import (
	"context"
	"errors"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/output"
	"github.com/abigotado/youtrack-agent-cli/internal/profile"
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

func (a *App) profileDefaultsView(ctx context.Context, value profile.Defaults) (profileDefaultsView, error) {
	read, err := a.profileDefaultSlotView(ctx, value.Read)
	if err != nil {
		return profileDefaultsView{}, err
	}
	write, err := a.profileDefaultSlotView(ctx, value.Write)
	if err != nil {
		return profileDefaultsView{}, err
	}
	return profileDefaultsView{Read: read, Write: write}, nil
}

func (a *App) profileDefaultSlotView(ctx context.Context, value *profile.DefaultSlot) (profileDefaultSlotView, error) {
	if value == nil {
		return profileDefaultSlotView{State: "unset"}, nil
	}
	view := profileDefaultSlotView{ProfileName: value.ProfileName, ProfileIdentitySHA256: value.ProfileIdentitySHA256}
	selected, err := a.profiles.Get(ctx, value.ProfileName)
	if errors.Is(err, profile.ErrNotFound) {
		view.State = "missing_profile"
		return view, nil
	}
	if err != nil {
		return profileDefaultSlotView{}, a.translate(err)
	}
	if a.policy.validateAdmissionProfile(selected) != nil || profile.SelectionIdentity(selected) != value.ProfileIdentitySHA256 {
		view.State = "stale"
		return view, nil
	}
	view.State = "valid"
	return view, nil
}

func (a *App) newProfileDefaultsCommand() *cobra.Command {
	command := commandGroup("defaults", "Manage saved local read and write profile defaults")
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
	return &cobra.Command{Use: "show", Short: "Show saved local profile defaults", Args: usageArgs(cobra.NoArgs), RunE: func(cmd *cobra.Command, _ []string) error {
		if err := a.rejectDefaultProfileOverride(cmd); err != nil {
			return err
		}
		if a.assumeYes || a.dryRun {
			return errx.Usage("profile defaults show does not accept --yes or --dry-run")
		}
		defaults, err := a.profiles.GetDefaults(cmd.Context())
		if err != nil {
			return a.translate(err)
		}
		view, err := a.profileDefaultsView(cmd.Context(), defaults)
		if err != nil {
			return err
		}
		return a.out.Success(view)
	}}
}

func (a *App) newProfileDefaultsSetCommand() *cobra.Command {
	var readName string
	command := &cobra.Command{Use: "set", Short: "Set the saved local read profile default", Args: usageArgs(cobra.NoArgs), RunE: func(cmd *cobra.Command, _ []string) error {
		if err := a.rejectDefaultProfileOverride(cmd); err != nil {
			return err
		}
		if cmd.Flags().Changed("write") {
			return errx.Usage("the read-only edition does not support --write")
		}
		if !cmd.Flags().Changed("read") || readName == "" {
			return errx.Usage("profile defaults set requires --read NAME")
		}
		if err := profile.RequireName(readName); err != nil {
			return errx.Usage("invalid --read")
		}
		selected, err := a.profiles.Get(cmd.Context(), readName)
		if err != nil {
			return a.translate(err)
		}
		if err := a.policy.validateAdmissionProfile(selected); err != nil {
			return err
		}
		preview, err := a.profiles.GetDefaults(cmd.Context())
		if err != nil {
			return a.translate(err)
		}
		preview.Read = &profile.DefaultSlot{ProfileName: selected.Name, ProfileIdentitySHA256: profile.SelectionIdentity(selected)}
		view, err := a.profileDefaultsView(cmd.Context(), preview)
		if err != nil {
			return err
		}
		if err := a.out.Validate(view); err != nil {
			return err
		}
		if a.dryRun {
			return a.out.Success(view)
		}
		if !a.assumeYes {
			return errx.ConfirmRequired("profile defaults set")
		}
		var updated profile.Defaults
		err = a.profiles.WithProfileLock(cmd.Context(), readName, func() error {
			current, getErr := a.profiles.Get(cmd.Context(), readName)
			if getErr != nil {
				return getErr
			}
			if validateErr := a.policy.validateAdmissionProfile(current); validateErr != nil {
				return validateErr
			}
			updated, getErr = a.profiles.UpdateDefaults(cmd.Context(), func(defaults profile.Defaults) (profile.Defaults, error) {
				defaults.Read = &profile.DefaultSlot{ProfileName: current.Name, ProfileIdentitySHA256: profile.SelectionIdentity(current)}
				return defaults, nil
			})
			return getErr
		})
		if err != nil {
			return a.translate(err)
		}
		view, err = a.profileDefaultsView(cmd.Context(), updated)
		if err != nil {
			return err
		}
		return a.out.Success(view)
	}}
	flags := command.Flags()
	flags.StringVar(&readName, "read", "", "read-only profile name for supported read operations")
	flags.String("write", "", "unsupported in the read-only edition")
	return command
}

func (a *App) newProfileDefaultsClearCommand() *cobra.Command {
	var clearRead, clearWrite bool
	command := &cobra.Command{Use: "clear", Short: "Clear saved local profile defaults", Args: usageArgs(cobra.NoArgs), RunE: func(cmd *cobra.Command, _ []string) error {
		if err := a.rejectDefaultProfileOverride(cmd); err != nil {
			return err
		}
		if !clearRead && !clearWrite {
			return errx.Usage("profile defaults clear requires --read or --write")
		}
		preview, err := a.profiles.GetDefaults(cmd.Context())
		if err != nil {
			return a.translate(err)
		}
		if clearRead {
			preview.Read = nil
		}
		if clearWrite {
			preview.Write = nil
		}
		view, err := a.profileDefaultsView(cmd.Context(), preview)
		if err != nil {
			return err
		}
		if err := a.out.Validate(view); err != nil {
			return err
		}
		if a.dryRun {
			return a.out.Success(view)
		}
		if !a.assumeYes {
			return errx.ConfirmRequired("profile defaults clear")
		}
		updated, err := a.profiles.ClearDefaults(cmd.Context(), clearRead, clearWrite)
		if err != nil {
			return a.translate(err)
		}
		view, err = a.profileDefaultsView(cmd.Context(), updated)
		if err != nil {
			return err
		}
		return a.out.Success(view)
	}}
	flags := command.Flags()
	flags.BoolVar(&clearRead, "read", false, "clear the saved read default")
	flags.BoolVar(&clearWrite, "write", false, "clear the saved write default")
	return command
}
