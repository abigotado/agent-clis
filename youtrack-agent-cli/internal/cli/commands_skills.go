package cli

import (
	"github.com/abigotado/youtrack-agent-cli/internal/application"
	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/spf13/cobra"
)

func (a *App) newSkillsCommand() *cobra.Command {
	command := commandGroup("skills", "Install the provider-neutral YouTrack Agent Skill")
	command.AddCommand(a.newSkillsInstallCommand(), a.newSkillsUninstallCommand())
	return command
}

func (a *App) newSkillsInstallCommand() *cobra.Command {
	return a.skillMutationCommand("install", "Install or update manifest-owned skill files", a.serviceInstallSkill)
}

func (a *App) newSkillsUninstallCommand() *cobra.Command {
	return a.skillMutationCommand("uninstall", "Remove only unchanged manifest-owned skill files", a.serviceUninstallSkill)
}

type skillOperation func(*cobra.Command, application.SkillOptions) ([]application.SkillResultInfo, error)

func (a *App) skillMutationCommand(use, short string, run skillOperation) *cobra.Command {
	var providerValue, scopeValue, projectDir, dest string
	command := &cobra.Command{
		Use: use, Short: short, Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts := application.SkillOptions{
				Provider: providerValue, Scope: scopeValue, ProjectDir: projectDir, Dest: dest,
				Confirmed: a.assumeYes, DryRun: a.dryRun,
			}
			if err := application.ValidateSkillOptions(opts); err != nil {
				return err
			}
			if err := a.out.Validate([]application.SkillResultInfo{}); err != nil {
				return err
			}
			if !a.dryRun && !a.assumeYes {
				return errx.ConfirmRequired("skills " + use)
			}
			results, err := run(cmd, opts)
			if err != nil {
				return err
			}
			return a.out.Success(results)
		},
	}
	flags := command.Flags()
	flags.StringVar(&providerValue, "provider", "all", "skill host: codex, claude, or all")
	flags.StringVar(&scopeValue, "scope", "user", "install scope: user or project")
	flags.StringVar(&projectDir, "project-dir", "", "existing project root for project scope")
	flags.StringVar(&dest, "dest", "", "explicit existing user-scope skills root")
	return command
}

func (a *App) serviceInstallSkill(cmd *cobra.Command, opts application.SkillOptions) ([]application.SkillResultInfo, error) {
	return a.service.InstallAgentSkill(cmd.Context(), opts)
}

func (a *App) serviceUninstallSkill(cmd *cobra.Command, opts application.SkillOptions) ([]application.SkillResultInfo, error) {
	return a.service.UninstallAgentSkill(cmd.Context(), opts)
}
