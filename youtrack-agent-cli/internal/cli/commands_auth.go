package cli

import (
	"github.com/abigotado/youtrack-agent-cli/internal/application"
	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/spf13/cobra"
)

func (a *App) newAuthCommand() *cobra.Command {
	command := commandGroup("auth", "Authenticate explicit YouTrack profiles")
	command.AddCommand(
		a.newAuthLoginCommand(), a.newAuthImportTokenCommand(), a.newAuthStatusCommand(),
		a.newAuthWhoamiCommand(), a.newAuthLogoutCommand(), a.newAuthMigrateKeychainCommand(), a.newAllowProjectsCommand(),
	)
	return command
}

func (a *App) newAuthMigrateKeychainCommand() *cobra.Command {
	return &cobra.Command{
		Use: "migrate-keychain", Short: "Rebind one credential ACL to the current application", Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.requireProfile(); err != nil {
				return err
			}
			if a.dryRun {
				return errx.Usage("--dry-run is not supported by auth migrate-keychain")
			}
			result := map[string]any{"profile": a.profileName, "migrated": true}
			if err := a.out.Validate(result); err != nil {
				return err
			}
			if !a.assumeYes {
				return errx.ConfirmRequired("auth migrate-keychain")
			}
			if err := a.service.MigrateKeychain(cmd.Context(), a.profileName); err != nil {
				return err
			}
			return a.out.Success(result)
		},
	}
}

func (a *App) newAuthLoginCommand() *cobra.Command {
	return &cobra.Command{
		Use: "login", Short: "Run public-client OAuth Authorization Code with PKCE", Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.requireProfile(); err != nil {
				return err
			}
			if a.dryRun {
				return errx.Usage("--dry-run is not supported by OAuth login")
			}
			if err := a.out.Validate(profileView{}); err != nil {
				return err
			}
			value, err := a.service.LoginOAuthInfo(cmd.Context(), a.profileName, a.assumeYes, nil)
			if err != nil {
				return err
			}
			view := newProfileView(value)
			view.State = "authenticated"
			a.out.WithContext(value.Name, value.Instance, value.AccountID, value.Login)
			return a.out.Success(view)
		},
	}
}

func (a *App) newAuthImportTokenCommand() *cobra.Command {
	var interactive bool
	command := &cobra.Command{
		Use: "import-token", Short: "Verify and store one permanent token from a trusted terminal", Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.requireProfile(); err != nil {
				return err
			}
			if a.dryRun {
				return errx.Usage("--dry-run is not supported by auth import-token")
			}
			if !interactive {
				return errx.Usage("auth import-token requires --interactive")
			}
			if err := a.out.Validate(profileView{}); err != nil {
				return err
			}
			value, err := a.service.ImportPermanentTokenReader(cmd.Context(), a.profileName, a.stdin, a.assumeYes)
			if err != nil {
				return err
			}
			view := newProfileView(value)
			view.State = "authenticated"
			a.out.WithContext(value.Name, value.Instance, value.AccountID, value.Login)
			return a.out.Success(view)
		},
	}
	command.Flags().BoolVar(&interactive, "interactive", false, "read one bounded token from a real terminal with echo disabled")
	return command
}

func (a *App) newAuthStatusCommand() *cobra.Command {
	var check bool
	command := &cobra.Command{
		Use: "status", Short: "Show credential presence and optionally verify the account", Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.requireProfile(); err != nil {
				return err
			}
			value, err := a.service.GetAuthStatus(cmd.Context(), a.profileName, check)
			if err != nil {
				return err
			}
			if value.Account != nil {
				a.out.WithContext(value.Profile, value.Instance, value.Account.ID, value.Account.Login)
			} else {
				a.out.WithContext(value.Profile, value.Instance)
			}
			return a.out.Success(newAuthStatusView(value))
		},
	}
	command.Flags().BoolVar(&check, "check", false, "read the exact Keychain item and call users/me")
	return command
}

func (a *App) newAuthWhoamiCommand() *cobra.Command {
	return &cobra.Command{
		Use: "whoami", Short: "Verify and return the exact authenticated account", Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.requireProfile(); err != nil {
				return err
			}
			value, err := a.service.GetAuthStatus(cmd.Context(), a.profileName, true)
			if err != nil {
				return err
			}
			if value.Account == nil {
				return errx.Internal("verified identity response is missing its account")
			}
			a.out.WithContext(value.Profile, value.Instance, value.Account.ID, value.Account.Login)
			return a.out.Success(newUserView(*value.Account))
		},
	}
}

func (a *App) newAuthLogoutCommand() *cobra.Command {
	return &cobra.Command{
		Use: "logout", Short: "Delete one exact credential and its profile metadata", Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.requireProfile(); err != nil {
				return err
			}
			if a.dryRun {
				return errx.Usage("--dry-run is not supported by auth logout")
			}
			result := map[string]any{"profile": a.profileName, "removed": true}
			if err := a.out.Validate(result); err != nil {
				return err
			}
			if !a.assumeYes {
				return errx.ConfirmRequired("auth logout")
			}
			if err := a.service.Logout(cmd.Context(), a.profileName); err != nil {
				return err
			}
			return a.out.Success(result)
		},
	}
}

func (a *App) newAllowProjectsCommand() *cobra.Command {
	command := commandGroup("allow-projects", "Manage the exact project ID+key write policy")
	command.AddCommand(a.newAllowProjectsShowCommand(), a.newAllowProjectsSetCommand(), a.newAllowProjectsClearCommand())
	return command
}

func (a *App) newAllowProjectsShowCommand() *cobra.Command {
	return &cobra.Command{
		Use: "show", Short: "Show the current identity-bound project policy", Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.requireProfile(); err != nil {
				return err
			}
			value, err := a.service.GetPolicyInfo(cmd.Context(), a.profileName)
			if err != nil {
				return err
			}
			return a.out.Success(newPolicyView(value, false, false))
		},
	}
}

func (a *App) newAllowProjectsSetCommand() *cobra.Command {
	var rawProjects []string
	command := &cobra.Command{
		Use: "set", Short: "Replace the complete exact project allowlist", Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.requireProfile(); err != nil {
				return err
			}
			projects, err := parseProjects(rawProjects)
			if err != nil {
				return err
			}
			if a.dryRun {
				value, err := a.service.PreviewPolicyInfo(cmd.Context(), a.profileName, projects)
				if err != nil {
					return err
				}
				return a.out.Success(newPolicyView(value, true, false))
			}
			if err := a.out.Validate(policyView{}); err != nil {
				return err
			}
			if !a.assumeYes {
				return errx.ConfirmRequired("auth allow-projects set")
			}
			value, err := a.service.SetPolicyInfo(cmd.Context(), a.profileName, projects)
			if err != nil {
				return err
			}
			return a.out.Success(newPolicyView(value, false, true))
		},
	}
	command.Flags().StringArrayVar(&rawProjects, "project", nil, "exact immutable project ID and key as ID:KEY (repeatable)")
	return command
}

func (a *App) newAllowProjectsClearCommand() *cobra.Command {
	return &cobra.Command{
		Use: "clear", Short: "Remove the local project write policy", Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.requireProfile(); err != nil {
				return err
			}
			if a.dryRun {
				return a.out.Success(map[string]any{"profile": a.profileName, "dry_run": true, "cleared": false})
			}
			result := map[string]any{"profile": a.profileName, "cleared": true}
			if err := a.out.Validate(result); err != nil {
				return err
			}
			if !a.assumeYes {
				return errx.ConfirmRequired("auth allow-projects clear")
			}
			if err := a.service.ClearPolicy(cmd.Context(), a.profileName); err != nil {
				return err
			}
			return a.out.Success(result)
		},
	}
}

func parseProjects(values []string) ([]application.ProjectRef, error) {
	if len(values) == 0 {
		return nil, errx.Usage("at least one --project ID:KEY is required")
	}
	projects := make([]application.ProjectRef, 0, len(values))
	for _, value := range values {
		index := splitProject(value)
		if index <= 0 || index == len(value)-1 {
			return nil, errx.Usage("project %q must use ID:KEY", value)
		}
		projects = append(projects, application.ProjectRef{ID: value[:index], Key: value[index+1:]})
	}
	canonical, err := application.CanonicalProjects(projects)
	if err != nil {
		return nil, err
	}
	return canonical, nil
}

func splitProject(value string) int {
	for index := len(value) - 1; index >= 0; index-- {
		if value[index] == ':' {
			return index
		}
	}
	return -1
}
