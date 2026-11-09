// Package cli wires youtrack-agent-cli's command tree. Business logic and
// network behavior live behind internal/application.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/application"
	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/output"
	"github.com/spf13/cobra"
)

const defaultTimeout = 30 * time.Second

// App contains per-invocation flags, streams, and an injectable application
// service. It does not construct HTTP requests itself.
type App struct {
	service *application.Service
	stdin   io.Reader
	stdout  io.Writer
	stderr  io.Writer

	profileName string
	format      string
	jsonAlias   bool
	fields      []string
	timeout     time.Duration
	verbose     bool
	assumeYes   bool
	dryRun      bool

	out     *output.Writer
	log     *slog.Logger
	cancels []context.CancelFunc
}

// NewApp builds an App without reading config, Keychain, or network state.
func NewApp() *App {
	return &App{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr}
}

//go:generate go run github.com/abigotado/youtrack-agent-cli/tools/gencommands

// NewRootCommand assembles the public command surface.
func (a *App) NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use: "youtrack-agent-cli", Short: "Use named YouTrack instances safely from agents and the command line",
		SilenceUsage: true, SilenceErrors: true,
		Args: usageArgs(func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("unknown command %q for %q", args[0], cmd.CommandPath())
			}
			return nil
		}),
		RunE: func(cmd *cobra.Command, _ []string) error { return errx.Usage("%s needs a command", cmd.CommandPath()) },
	}
	root.SetOut(a.stdout)
	root.SetErr(a.stderr)
	flags := root.PersistentFlags()
	flags.StringVar(&a.profileName, "profile", "", "explicit named YouTrack profile; overrides a saved default on supported commands")
	flags.StringVarP(&a.format, "output", "o", "", "output format: text, json, or raw")
	flags.BoolVar(&a.jsonAlias, "json", false, "emit the JSON envelope")
	_ = flags.MarkHidden("json")
	flags.StringSliceVar(&a.fields, "fields", nil, "comma-separated output fields")
	flags.DurationVar(&a.timeout, "timeout", defaultTimeout, "abort the command after this duration")
	flags.BoolVarP(&a.verbose, "verbose", "v", false, "write redacted request activity to stderr")
	flags.BoolVar(&a.assumeYes, "yes", false, "confirm a supported local configuration change or exact operator-write intent")
	flags.BoolVar(&a.dryRun, "dry-run", false, "preview a supported local or offline change")
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return errx.Usage("%v", err) })
	root.PersistentPreRunE = a.setup
	root.AddCommand(
		a.newVersionCommand(), a.newContractCommand(), a.newCapabilitiesCommand(), a.newProfileCommand(), a.newAuthCommand(),
		a.newInspectCommand(), a.newMutationCommand(), a.newOperatorWriteCommand(), a.newSkillsCommand(),
	)
	return root
}

func (a *App) setup(cmd *cobra.Command, _ []string) error {
	if a.jsonAlias && a.format != "" && a.format != string(output.FormatJSON) {
		return errx.Usage("--json cannot be combined with --output %s", a.format)
	}
	format := defaultFormat(a.stdout)
	if a.jsonAlias {
		format = output.FormatJSON
	} else if a.format != "" {
		parsed, err := output.ParseFormat(a.format)
		if err != nil {
			return err
		}
		format = parsed
	}
	if format == output.FormatRaw && len(a.fields) > 0 {
		return errx.Usage("--fields cannot be combined with --output raw")
	}
	a.out = &output.Writer{Format: format, Fields: a.fields, Out: a.stdout, Err: a.stderr}
	level := slog.LevelWarn
	if a.verbose {
		level = slog.LevelDebug
	}
	a.log = slog.New(slog.NewTextHandler(a.stderr, &slog.HandlerOptions{Level: level}))
	if a.timeout <= 0 {
		return errx.Usage("--timeout must be greater than zero")
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), a.timeout)
	a.cancels = append(a.cancels, cancel)
	cmd.SetContext(ctx)
	if a.service == nil {
		service, err := application.NewDefault(a.log)
		if err != nil {
			return errx.Internal("initialize local service safely: %v", err)
		}
		a.service = service
	}
	return nil
}

func defaultFormat(writer io.Writer) output.Format {
	if file, ok := writer.(*os.File); ok {
		return output.DefaultFormat(file)
	}
	return output.FormatJSON
}

func (a *App) requireProfile() error {
	if a.profileName == "" {
		return errx.ProfileRequired()
	}
	return application.ValidateProfileName(a.profileName)
}

// resolveOperationProfile selects a role-specific saved default only when the
// caller did not provide --profile. An explicit empty value is rejected rather
// than silently falling back to a saved default.
func (a *App) resolveOperationProfile(cmd *cobra.Command, role string) error {
	if cmd.Flags().Changed("profile") {
		if a.profileName == "" {
			return errx.Usage("--profile must not be empty")
		}
		return application.ValidateProfileName(a.profileName)
	}
	ctx, name, err := a.service.ResolveSavedProfile(cmd.Context(), role)
	if err != nil {
		return err
	}
	cmd.SetContext(ctx)
	a.profileName = name
	return nil
}

func usageArgs(validator cobra.PositionalArgs) cobra.PositionalArgs {
	if validator == nil {
		validator = cobra.ArbitraryArgs
	}
	return func(cmd *cobra.Command, args []string) error {
		if err := validator(cmd, args); err != nil {
			var typed *errx.Error
			if errors.As(err, &typed) {
				return err
			}
			return errx.Usage("%v", err)
		}
		return nil
	}
}

// Run executes one command tree and returns its process status.
func (a *App) Run(ctx context.Context, root *cobra.Command, args []string) (code errx.Code) {
	defer func() {
		for _, cancel := range a.cancels {
			cancel()
		}
		if recover() != nil {
			if a.out == nil {
				a.out = &output.Writer{Format: defaultFormat(a.stdout), Out: a.stdout, Err: a.stderr}
			}
			code = a.out.Failure(errx.Internal("youtrack-agent-cli stopped after an unexpected internal failure"))
		}
	}()
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return errx.CodeOK
	}
	if a.out == nil {
		format := defaultFormat(a.stdout)
		if a.jsonAlias {
			format = output.FormatJSON
		} else if parsed, parseErr := output.ParseFormat(a.format); a.format != "" && parseErr == nil {
			format = parsed
		}
		a.out = &output.Writer{Format: format, Out: a.stdout, Err: a.stderr}
	}
	return a.out.Failure(application.TranslateError(err, a.profileName))
}

// Execute runs youtrack-agent-cli with signal cancellation.
func Execute(args []string) errx.Code {
	app := NewApp()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return app.Run(ctx, app.NewRootCommand(), args)
}

func commandGroup(use, short string) *cobra.Command {
	return &cobra.Command{Use: use, Short: short, Args: usageArgs(cobra.NoArgs), RunE: func(cmd *cobra.Command, _ []string) error {
		return errx.Usage("%s needs a subcommand", cmd.CommandPath())
	}}
}
