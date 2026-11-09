// Package readonlycli implements the portable Remote-MCP-only command surface.
// It intentionally does not import authentication, HTTP, journal, mutation, or
// application packages, so those capabilities cannot be linked into its build.
package readonlycli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/output"
	"github.com/abigotado/youtrack-agent-cli/internal/profile"
	"github.com/abigotado/youtrack-agent-cli/internal/skills"
	"github.com/spf13/cobra"
)

const (
	devVersion          = "devel"
	maxProfileFileBytes = 64 << 10
)

// These values are injected by the release build. The complete pair is
// required so a published binary never reports partial provenance.
var (
	releaseVersion    = devVersion
	releaseCommit     string
	releaseCommitTime string
)

// App owns one portable command invocation and its explicitly injected local
// profile registry. It never opens a credential store or a network client.
type App struct {
	stdin    io.Reader
	stdout   io.Writer
	stderr   io.Writer
	profiles *profile.Registry
	policy   EditionPolicy

	profileName string
	format      string
	jsonAlias   bool
	fields      []string
	timeout     time.Duration
	assumeYes   bool
	dryRun      bool
	out         *output.Writer
	cancels     []context.CancelFunc
}

// NewApp builds an app without reading local metadata, credentials, or the
// network. Tests may inject a registry before Run.
func NewApp() *App {
	return &App{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, policy: editionPolicy()}
}

// NewRootCommand assembles the deliberately small portable surface.
func (a *App) NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use: "youtrack-agent-cli", Short: "Install a safe YouTrack Remote MCP read-only boundary",
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
	flags.StringVar(&a.profileName, "profile", "", "explicit named YouTrack profile")
	flags.StringVarP(&a.format, "output", "o", "", "output format: text, json, or raw")
	flags.BoolVar(&a.jsonAlias, "json", false, "emit the JSON envelope")
	_ = flags.MarkHidden("json")
	flags.StringSliceVar(&a.fields, "fields", nil, "comma-separated output fields")
	flags.DurationVar(&a.timeout, "timeout", 30*time.Second, "abort the command after this duration")
	flags.BoolVar(&a.assumeYes, "yes", false, "confirm a supported local metadata change")
	flags.BoolVar(&a.dryRun, "dry-run", false, "preview a supported local change")
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return errx.Usage("%v", err) })
	root.PersistentPreRunE = a.setup
	root.AddCommand(a.newVersionCommand(), a.newContractCommand(), a.newCapabilitiesCommand(), a.newProfileCommand(), a.newSkillsCommand())
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
	if a.timeout <= 0 {
		return errx.Usage("--timeout must be greater than zero")
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), a.timeout)
	a.cancels = append(a.cancels, cancel)
	cmd.SetContext(ctx)
	if a.profiles == nil {
		registry, err := a.policy.newRegistry()
		if err != nil {
			return errx.Internal("initialize profile metadata safely: %v", err)
		}
		a.profiles = registry
	}
	return nil
}

func (a *App) newVersionCommand() *cobra.Command {
	return &cobra.Command{Use: "version", Short: a.policy.versionShort, Args: usageArgs(cobra.NoArgs), RunE: func(_ *cobra.Command, _ []string) error {
		return a.out.Success(buildVersion(a.policy, debug.ReadBuildInfo, releaseVersion, releaseCommit, releaseCommitTime))
	}}
}

func (a *App) newContractCommand() *cobra.Command {
	return &cobra.Command{Use: "contract", Short: "Print the versioned envelope and exit-code contract", Args: usageArgs(cobra.NoArgs), RunE: func(*cobra.Command, []string) error {
		return a.out.Success(errx.Describe())
	}}
}

func (a *App) newProfileCommand() *cobra.Command {
	command := commandGroup("profile", "Manage non-secret read-only Remote MCP profiles")
	command.AddCommand(a.newProfileListCommand(), a.newProfileShowCommand(), a.newProfileValidateCommand(), a.newProfileAddCommand(), a.newProfileRemoveCommand(), a.newProfileDefaultsCommand())
	return command
}

func (a *App) newProfileListCommand() *cobra.Command {
	return &cobra.Command{Use: "list", Short: "List non-secret profiles without credentials", Args: usageArgs(cobra.NoArgs), RunE: func(cmd *cobra.Command, _ []string) error {
		values, err := a.listProfiles(cmd.Context())
		if err != nil {
			return a.translate(err)
		}
		views := make([]profileView, len(values))
		for index, value := range values {
			views[index] = newProfileView(value)
		}
		return a.out.Success(views)
	}}
}

func (a *App) newProfileShowCommand() *cobra.Command {
	return &cobra.Command{Use: "show", Short: "Show one non-secret profile", Args: usageArgs(cobra.NoArgs), RunE: func(cmd *cobra.Command, _ []string) error {
		if err := a.requireProfile(); err != nil {
			return err
		}
		value, err := a.getProfile(cmd.Context(), a.profileName)
		if err != nil {
			return a.translate(err)
		}
		return a.out.Success(newProfileView(value))
	}}
}

func (a *App) newProfileValidateCommand() *cobra.Command {
	var offline bool
	command := &cobra.Command{Use: "validate", Short: "Validate one profile without credentials or network", Args: usageArgs(cobra.NoArgs), RunE: func(cmd *cobra.Command, _ []string) error {
		if !offline {
			return errx.Usage("profile validate requires --offline")
		}
		if err := a.requireProfile(); err != nil {
			return err
		}
		value, err := a.getProfile(cmd.Context(), a.profileName)
		if err != nil {
			return a.translate(err)
		}
		if err := a.policy.validateAdmissionProfile(value); err != nil {
			return err
		}
		view := newProfileView(value)
		view.State = "valid_offline"
		return a.out.Success(view)
	}}
	command.Flags().BoolVar(&offline, "offline", false, "guarantee no credential or network access")
	return command
}

func (a *App) newProfileAddCommand() *cobra.Command {
	var source string
	command := &cobra.Command{Use: "add", Short: "Add or replace one read-only non-secret profile", Args: usageArgs(cobra.NoArgs), RunE: func(cmd *cobra.Command, _ []string) error {
		if source == "" {
			return errx.Usage("profile add requires --from FILE")
		}
		raw, err := readBoundedRegular(source, maxProfileFileBytes)
		if err != nil {
			return errx.Usage("profile input failed bounded validation")
		}
		value, err := decodePortableProfile(a.policy, raw, a.profileName)
		if err != nil {
			return err
		}
		if a.dryRun {
			if a.policy.validateRegistryOnDryRun {
				if _, err := a.listProfiles(cmd.Context()); err != nil {
					return a.translate(err)
				}
			}
			view := newProfileView(value)
			view.State = "validated_not_applied"
			return a.out.Success(view)
		}
		view := newProfileView(value)
		view.State = "applied"
		if err := a.out.Validate(view); err != nil {
			return err
		}
		if !a.assumeYes {
			return errx.ConfirmRequired("profile add")
		}
		err = a.profiles.WithProfileLock(cmd.Context(), value.Name, func() error {
			return a.profiles.MutateValidated(cmd.Context(), a.policy.validateLoadedProfile, func(profiles []profile.Profile) ([]profile.Profile, error) {
				for index, existing := range profiles {
					if existing.Name != value.Name {
						continue
					}
					if existing.CredentialGeneration != "" {
						return nil, errx.Conflict("PROFILE_AUTHENTICATED", "profile %q has credential metadata and cannot be replaced by the %s", value.Name, a.policy.name)
					}
					profiles[index] = value
					return profiles, nil
				}
				return append(profiles, value), nil
			})
		})
		if err != nil {
			return a.translate(err)
		}
		return a.out.Success(view)
	}}
	command.Flags().StringVar(&source, "from", "", "bounded non-secret profile JSON file")
	return command
}

func (a *App) newProfileRemoveCommand() *cobra.Command {
	return &cobra.Command{Use: "remove", Short: "Remove one credential-free profile", Args: usageArgs(cobra.NoArgs), RunE: func(cmd *cobra.Command, _ []string) error {
		if err := a.requireProfile(); err != nil {
			return err
		}
		if a.dryRun {
			if a.policy.validateRegistryOnDryRun {
				if _, err := a.listProfiles(cmd.Context()); err != nil {
					return a.translate(err)
				}
			}
			return a.out.Success(map[string]any{"profile": a.profileName, "dry_run": true, "removed": false})
		}
		result := map[string]any{"profile": a.profileName, "removed": true}
		if err := a.out.Validate(result); err != nil {
			return err
		}
		if !a.assumeYes {
			return errx.ConfirmRequired("profile remove")
		}
		err := a.profiles.WithProfileLock(cmd.Context(), a.profileName, func() error {
			return a.profiles.MutateValidated(cmd.Context(), a.policy.validateLoadedProfile, func(profiles []profile.Profile) ([]profile.Profile, error) {
				for index, value := range profiles {
					if value.Name != a.profileName {
						continue
					}
					if value.CredentialGeneration != "" {
						return nil, errx.Conflict("PROFILE_AUTHENTICATED", "profile %q has credential metadata and cannot be removed by the %s", a.profileName, a.policy.name)
					}
					return append(profiles[:index:index], profiles[index+1:]...), nil
				}
				return nil, fmt.Errorf("%w: %s", profile.ErrNotFound, a.profileName)
			})
		})
		if err != nil {
			return a.translate(err)
		}
		return a.out.Success(result)
	}}
}

func (a *App) newSkillsCommand() *cobra.Command {
	command := commandGroup("skills", "Install the provider-neutral YouTrack Remote MCP read-only skill")
	command.AddCommand(a.newSkillsMutationCommand("install", "Install or update manifest-owned read-only skill files", skills.Install), a.newSkillsMutationCommand("uninstall", "Remove only unchanged manifest-owned read-only skill files", skills.Uninstall))
	return command
}

type skillOperation func(context.Context, skills.Options) ([]skills.Result, error)

func (a *App) newSkillsMutationCommand(use, short string, run skillOperation) *cobra.Command {
	var providerValue, scopeValue, projectDir, dest string
	command := &cobra.Command{Use: use, Short: short, Args: usageArgs(cobra.NoArgs), RunE: func(cmd *cobra.Command, _ []string) error {
		provider, err := skills.ParseProvider(providerValue)
		if err != nil {
			return err
		}
		scope, err := skills.ParseScope(scopeValue)
		if err != nil {
			return err
		}
		if !a.dryRun && !a.assumeYes {
			return errx.ConfirmRequired("skills " + use)
		}
		results, err := run(cmd.Context(), skills.Options{Provider: provider, Scope: scope, ProjectDir: projectDir, Dest: dest, Confirmed: a.assumeYes, DryRun: a.dryRun})
		if err != nil {
			return err
		}
		return a.out.Success(results)
	}}
	flags := command.Flags()
	flags.StringVar(&providerValue, "provider", "all", "skill host: codex, claude, or all")
	flags.StringVar(&scopeValue, "scope", "user", "install scope: user or project")
	flags.StringVar(&projectDir, "project-dir", "", "existing project root for project scope")
	flags.StringVar(&dest, "dest", "", "explicit existing user-scope skills root")
	return command
}

func (a *App) requireProfile() error {
	if a.profileName == "" {
		return errx.ProfileRequired()
	}
	if err := profile.ValidateName(a.profileName); err != nil {
		return errx.Usage("invalid --profile")
	}
	return nil
}

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
	if err := root.ExecuteContext(ctx); err != nil {
		if a.out == nil {
			format := defaultFormat(a.stdout)
			if a.jsonAlias {
				format = output.FormatJSON
			} else if parsed, parseErr := output.ParseFormat(a.format); a.format != "" && parseErr == nil {
				format = parsed
			}
			a.out = &output.Writer{Format: format, Out: a.stdout, Err: a.stderr}
		}
		return a.out.Failure(a.translate(err))
	}
	return errx.CodeOK
}

// Execute runs the portable command with signal cancellation.
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

func usageArgs(validator cobra.PositionalArgs) cobra.PositionalArgs {
	if validator == nil {
		validator = cobra.ArbitraryArgs
	}
	return func(cmd *cobra.Command, args []string) error {
		if err := validator(cmd, args); err != nil {
			return errx.Usage("%v", err)
		}
		return nil
	}
}

func defaultFormat(writer io.Writer) output.Format {
	if file, ok := writer.(*os.File); ok {
		return output.DefaultFormat(file)
	}
	return output.FormatJSON
}

type versionView struct {
	Edition    string `json:"edition"`
	Version    string `json:"version"`
	Commit     string `json:"commit,omitempty"`
	CommitTime string `json:"commit_time,omitempty"`
	Go         string `json:"go"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
}

func (view versionView) Fields() []output.Field {
	return []output.Field{
		{Name: "edition", Value: view.Edition, Raw: view.Edition},
		{Name: "version", Value: view.Version, Raw: view.Version},
		{Name: "go", Value: view.Go, Raw: view.Go},
		{Name: "os", Value: view.OS, Raw: view.OS},
		{Name: "arch", Value: view.Arch, Raw: view.Arch},
		{Name: "commit", Value: view.Commit, Raw: view.Commit, OnRequest: view.Commit == ""},
		{Name: "commit_time", Value: view.CommitTime, Raw: view.CommitTime, OnRequest: view.CommitTime == ""},
	}
}

func buildVersion(policy EditionPolicy, read func() (*debug.BuildInfo, bool), fallback, commit, commitTime string) versionView {
	if fallback == "" {
		fallback = devVersion
	}
	view := versionView{Edition: policy.id, Version: fallback, Commit: commit, CommitTime: commitTime, Go: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH}
	if info, ok := read(); ok && info.GoVersion != "" {
		view.Go = info.GoVersion
	}
	return view
}

type profileView struct {
	Name         string   `json:"name"`
	Instance     string   `json:"instance"`
	MCPURL       string   `json:"mcp_url"`
	AccountID    string   `json:"account_id"`
	Login        string   `json:"login"`
	Capabilities []string `json:"capabilities"`
	State        string   `json:"state,omitempty"`
}

func newProfileView(value profile.Profile) profileView {
	caps := make([]string, len(value.Capabilities))
	for i, capability := range value.Capabilities {
		caps[i] = string(capability)
	}
	return profileView{Name: value.Name, Instance: value.ServiceURL, MCPURL: value.MCPURL, AccountID: value.ExpectedAccountID, Login: value.ExpectedLogin, Capabilities: caps}
}

func (view profileView) Fields() []output.Field {
	return []output.Field{
		{Name: "name", Value: view.Name, Raw: view.Name},
		{Name: "instance", Value: view.Instance, Raw: view.Instance},
		{Name: "account_id", Value: view.AccountID, Raw: view.AccountID},
		{Name: "login", Value: view.Login, Raw: view.Login},
		{Name: "capabilities", Value: strings.Join(view.Capabilities, ","), Raw: view.Capabilities},
		{Name: "state", Value: view.State, Raw: view.State, OnRequest: view.State == ""},
		{Name: "mcp_url", Value: view.MCPURL, Raw: view.MCPURL, OnRequest: true},
	}
}

func (a *App) listProfiles(ctx context.Context) ([]profile.Profile, error) {
	values, err := a.profiles.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, value := range values {
		if err := a.policy.validateLoadedProfile(value); err != nil {
			return nil, err
		}
	}
	return values, nil
}

func (a *App) getProfile(ctx context.Context, name string) (profile.Profile, error) {
	values, err := a.listProfiles(ctx)
	if err != nil {
		return profile.Profile{}, err
	}
	for _, value := range values {
		if value.Name == name {
			return value, nil
		}
	}
	return profile.Profile{}, fmt.Errorf("%w: %s", profile.ErrNotFound, name)
}

func decodePortableProfile(policy EditionPolicy, raw []byte, requestedName string) (profile.Profile, error) {
	var value profile.Profile
	if err := json.Unmarshal(raw, &value); err != nil {
		return profile.Profile{}, errx.Usage("profile JSON is invalid")
	}
	if requestedName != "" && requestedName != value.Name {
		return profile.Profile{}, errx.Usage("--profile must match the profile file name")
	}
	if err := policy.validateAdmissionProfile(value); err != nil {
		return profile.Profile{}, err
	}
	return value, nil
}

func readBoundedRegular(path string, maximum int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect input file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > int64(maximum) {
		return nil, errors.New("input path is not a bounded regular non-symlink file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open input file: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, errors.New("input file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(data) > maximum {
		return nil, errors.New("input exceeds bounded size")
	}
	return data, nil
}

func (a *App) translate(err error) error {
	if err == nil {
		return nil
	}
	var typed *errx.Error
	if errors.As(err, &typed) {
		return err
	}
	if errors.Is(err, profile.ErrNotFound) {
		return errx.NotFound("profile", "selected", nil)
	}
	if errors.Is(err, profile.ErrAlreadyExists) {
		return errx.Conflict("PROFILE_EXISTS", "profile already exists")
	}
	if errors.Is(err, profile.ErrInvalidProfile) || errors.Is(err, profile.ErrCorruptRegistry) || errors.Is(err, profile.ErrInsecurePermissions) {
		return errx.Usage("profile metadata failed validation")
	}
	return errx.Internal("%s", a.policy.failureMessage)
}
