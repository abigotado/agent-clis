package cli

import (
	"strings"

	"github.com/abigotado/youtrack-agent-cli/internal/application"
	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/spf13/cobra"
)

func (a *App) newMutationCommand() *cobra.Command {
	command := commandGroup("mutation", "Prepare and inspect guarded YouTrack mutation plans")
	command.AddCommand(
		a.newMutationPrepareCommand(), a.newMutationStatusCommand(), a.newMutationExportCommand(),
		a.newMutationConfirmCommand(), a.newMutationApplyCommand(), a.newMutationReconcileCommand(),
	)
	return command
}

func (a *App) newMutationExportCommand() *cobra.Command {
	var planID, outputPath string
	command := &cobra.Command{
		Use: "export", Short: "Export one existing journaled plan without network access", Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if planID == "" || outputPath == "" {
				return errx.Usage("mutation export requires --plan-id and --out")
			}
			if a.assumeYes || a.dryRun {
				return errx.Usage("mutation export is exclusive and does not accept --yes or --dry-run")
			}
			if err := a.out.Validate(mutationView{}); err != nil {
				return err
			}
			record, err := a.service.ExportMutationInfo(cmd.Context(), planID, outputPath)
			if err != nil {
				return err
			}
			a.out.WithContext(record.Profile, record.Instance, record.AccountID, record.AccountLogin)
			return a.out.Success(newMutationView(record))
		},
	}
	command.Flags().StringVar(&planID, "plan-id", "", "exact local mutation plan ID")
	command.Flags().StringVar(&outputPath, "out", "", "new exclusive 0600 plan export path")
	return command
}

func (a *App) newMutationPrepareCommand() *cobra.Command {
	var offline, requestStdin bool
	var kind, project, expectedPath, schemaSHA256, outputPath string
	command := &cobra.Command{
		Use: "prepare", Short: "Create one complete network-free mutation plan", Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.requireProfile(); err != nil {
				return err
			}
			if !offline || !requestStdin {
				return errx.Usage("mutation prepare requires --offline and --request-stdin")
			}
			if a.assumeYes {
				return errx.Usage("--yes is not accepted by guarded mutation commands")
			}
			if kind == "" || project == "" || expectedPath == "" || schemaSHA256 == "" || outputPath == "" {
				return errx.Usage("mutation prepare requires --kind, --project, --expected-state, --schema-sha256, and --out")
			}
			projects, err := parseProjects([]string{project})
			if err != nil {
				return err
			}
			requestJSON, err := readBounded(a.stdin, application.MaxMutationRequestBytes)
			if err != nil {
				return errx.Usage("mutation request input failed bounded validation")
			}
			expectedJSON, err := readBoundedRegular(expectedPath, application.MaxMutationExpectedBytes)
			if err != nil {
				return errx.Usage("expected-state file failed bounded validation")
			}
			if a.dryRun {
				return errx.Usage("mutation prepare is already network-free and does not support --dry-run")
			}
			if err := a.out.Validate(mutationView{}); err != nil {
				return err
			}
			record, err := a.service.PrepareMutationInfo(cmd.Context(), application.MutationPrepareInput{
				Profile: a.profileName, Kind: kind, Project: projects[0], SchemaSHA256: strings.ToLower(schemaSHA256),
				RequestJSON: requestJSON, ExpectedJSON: expectedJSON, OutputPath: outputPath,
			})
			if err != nil {
				return err
			}
			a.out.WithContext(record.Profile, record.Instance, record.AccountID, record.AccountLogin)
			return a.out.Success(newMutationView(record))
		},
	}
	flags := command.Flags()
	flags.BoolVar(&offline, "offline", false, "guarantee no credential, browser, or network access")
	flags.BoolVar(&requestStdin, "request-stdin", false, "read one bounded typed request JSON object from stdin")
	flags.StringVar(&kind, "kind", "", "mutation kind: issue.create, issue.update, or comment.add")
	flags.StringVar(&project, "project", "", "exact allowlisted project as ID:KEY")
	flags.StringVar(&expectedPath, "expected-state", "", "bounded expected-state JSON file")
	flags.StringVar(&schemaSHA256, "schema-sha256", "", "lowercase SHA-256 of the inspected project schema")
	flags.StringVar(&outputPath, "out", "", "new exclusive 0600 plan export path")
	return command
}

func (a *App) newMutationStatusCommand() *cobra.Command {
	var planID string
	command := &cobra.Command{
		Use: "status", Short: "Read one durable local mutation record without network access", Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if planID == "" {
				return errx.Usage("mutation status requires --plan-id")
			}
			record, err := a.service.MutationStatusInfo(cmd.Context(), planID)
			if err != nil {
				return err
			}
			a.out.WithContext(record.Profile, record.Instance, record.AccountID, record.AccountLogin)
			return a.out.Success(newMutationView(record))
		},
	}
	command.Flags().StringVar(&planID, "plan-id", "", "exact local mutation plan ID")
	return command
}

func (a *App) newMutationConfirmCommand() *cobra.Command {
	return a.disabledMutationCommand("confirm", "Request native trusted-user-presence confirmation", false, func(command *cobra.Command, planID string) error {
		return a.service.ConfirmMutation(command.Context(), planID)
	})
}

func (a *App) newMutationApplyCommand() *cobra.Command {
	return a.disabledMutationCommand("apply", "Consume one approved plan for at most one mutation attempt", true, func(command *cobra.Command, planID string) error {
		return a.service.ApplyMutation(command.Context(), a.profileName, planID)
	})
}

func (a *App) newMutationReconcileCommand() *cobra.Command {
	return a.disabledMutationCommand("reconcile", "Collect bounded read-only evidence for an ambiguous outcome", true, func(command *cobra.Command, planID string) error {
		return a.service.ReconcileMutation(command.Context(), a.profileName, planID)
	})
}

func (a *App) disabledMutationCommand(use, short string, remote bool, run func(*cobra.Command, string) error) *cobra.Command {
	var planID string
	command := &cobra.Command{
		Use: use, Short: short, Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if a.assumeYes {
				return errx.Usage("--yes is not accepted by this guarded mutation command")
			}
			if a.dryRun {
				return errx.Usage("--dry-run is not accepted by this guarded mutation command")
			}
			if planID == "" {
				return errx.Usage("mutation %s requires --plan-id", use)
			}
			if remote {
				if err := a.requireProfile(); err != nil {
					return err
				}
			}
			return run(cmd, planID)
		},
	}
	command.Flags().StringVar(&planID, "plan-id", "", "exact local mutation plan ID")
	return command
}
