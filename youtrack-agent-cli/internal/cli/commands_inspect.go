package cli

import (
	"github.com/abigotado/youtrack-agent-cli/internal/application"
	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/spf13/cobra"
)

func (a *App) newInspectCommand() *cobra.Command {
	command := commandGroup("inspect", "Perform exact or bounded REST reads")
	command.AddCommand(a.newInspectIssueCommand(), a.newInspectIssuesCommand(), a.newInspectCommentsCommand(), a.newInspectProjectCommand(), a.newInspectSchemaCommand())
	return command
}

func (a *App) newInspectIssuesCommand() *cobra.Command {
	var query string
	var limit int
	var offset int
	command := &cobra.Command{
		Use: "issues", Short: "Search one bounded page of compact issue summaries", Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := application.ValidateIssueSearchInput(query, limit, offset); err != nil {
				return err
			}
			if err := a.out.Validate(issueSearchView{}); err != nil {
				return err
			}
			if err := a.resolveOperationProfile(cmd, "read"); err != nil {
				return err
			}
			values, truncated, selected, err := a.service.InspectIssuesInfo(cmd.Context(), a.profileName, query, limit, offset)
			if err != nil {
				return err
			}
			views := make([]issueSearchView, len(values))
			for index, value := range values {
				views[index] = newIssueSearchView(value)
			}
			a.out.WithContext(selected.Name, selected.Instance, selected.AccountID, selected.Login)
			return a.out.SuccessPage(views, truncated, "")
		},
	}
	flags := command.Flags()
	flags.StringVar(&query, "query", "", "one bounded YouTrack search query")
	flags.IntVar(&limit, "limit", 10, "maximum issues in this page (1-50)")
	flags.IntVar(&offset, "offset", 0, "explicit bounded page offset; pages are not a stable snapshot")
	return command
}

func (a *App) newInspectIssueCommand() *cobra.Command {
	var id string
	command := &cobra.Command{
		Use: "issue", Short: "Read one exact issue through the narrow REST helper", Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.resolveOperationProfile(cmd, "read"); err != nil {
				return err
			}
			if id == "" {
				return errx.Usage("inspect issue requires --id")
			}
			value, selected, err := a.service.InspectIssueInfo(cmd.Context(), a.profileName, id)
			if err != nil {
				return err
			}
			a.out.WithContext(selected.Name, selected.Instance, selected.AccountID, selected.Login)
			return a.out.Success(newIssueView(value))
		},
	}
	command.Flags().StringVar(&id, "id", "", "exact YouTrack issue database ID or readable ID")
	return command
}

func (a *App) newInspectCommentsCommand() *cobra.Command {
	var id string
	var limit int
	var offset int
	command := &cobra.Command{
		Use: "comments", Short: "Read one bounded page of comments on an exact issue", Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.resolveOperationProfile(cmd, "read"); err != nil {
				return err
			}
			if id == "" {
				return errx.Usage("inspect comments requires --id")
			}
			if limit < 1 || limit > 100 || offset < 0 {
				return errx.Usage("--limit must be 1-100 and --offset must be nonnegative")
			}
			if err := a.out.Validate(commentView{}); err != nil {
				return err
			}
			value, truncated, selected, err := a.service.InspectCommentsInfo(cmd.Context(), a.profileName, id, limit, offset)
			if err != nil {
				return err
			}
			views := make([]commentView, len(value))
			for index, comment := range value {
				views[index] = newCommentView(comment)
			}
			a.out.WithContext(selected.Name, selected.Instance, selected.AccountID, selected.Login)
			return a.out.SuccessPage(views, truncated, "")
		},
	}
	flags := command.Flags()
	flags.StringVar(&id, "id", "", "exact YouTrack issue database ID or readable ID")
	flags.IntVar(&limit, "limit", 10, "maximum comments in this page (1-100)")
	flags.IntVar(&offset, "offset", 0, "explicit bounded page offset")
	return command
}

func (a *App) newInspectProjectCommand() *cobra.Command {
	var id string
	command := &cobra.Command{
		Use: "project", Short: "Read one exact project", Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.resolveOperationProfile(cmd, "read"); err != nil {
				return err
			}
			if id == "" {
				return errx.Usage("inspect project requires --project")
			}
			value, selected, err := a.service.InspectProjectInfo(cmd.Context(), a.profileName, id)
			if err != nil {
				return err
			}
			a.out.WithContext(selected.Name, selected.Instance, selected.AccountID, selected.Login)
			return a.out.Success(newProjectView(value))
		},
	}
	command.Flags().StringVar(&id, "project", "", "exact project entity ID or key")
	return command
}

func (a *App) newInspectSchemaCommand() *cobra.Command {
	var id string
	var limit int
	var offset int
	command := &cobra.Command{
		Use: "schema", Short: "Read one bounded page of project field schema", Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.resolveOperationProfile(cmd, "read"); err != nil {
				return err
			}
			if id == "" {
				return errx.Usage("inspect schema requires --project")
			}
			if limit < 1 || limit > 100 || offset < 0 {
				return errx.Usage("--limit must be 1-100 and --offset must be nonnegative")
			}
			value, truncated, selected, err := a.service.InspectSchemaInfo(cmd.Context(), a.profileName, id, limit, offset)
			if err != nil {
				return err
			}
			a.out.WithContext(selected.Name, selected.Instance, selected.AccountID, selected.Login)
			views := make([]projectFieldView, len(value))
			for index, field := range value {
				views[index] = newProjectFieldView(field)
			}
			return a.out.SuccessPage(views, truncated, "")
		},
	}
	flags := command.Flags()
	flags.StringVar(&id, "project", "", "exact project entity ID or key")
	flags.IntVar(&limit, "limit", 50, "maximum field schemas in this page (1-100)")
	flags.IntVar(&offset, "offset", 0, "explicit bounded page offset")
	return command
}
