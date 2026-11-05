// Package application owns youtrack-agent-cli use-case orchestration. CLI
// commands only parse inputs and render the values returned from this package.
package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/approval"
	"github.com/abigotado/youtrack-agent-cli/internal/auth"
	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/intent"
	"github.com/abigotado/youtrack-agent-cli/internal/journal"
	"github.com/abigotado/youtrack-agent-cli/internal/mutation"
	"github.com/abigotado/youtrack-agent-cli/internal/oauth"
	"github.com/abigotado/youtrack-agent-cli/internal/oauthrecovery"
	"github.com/abigotado/youtrack-agent-cli/internal/operatorwrite"
	"github.com/abigotado/youtrack-agent-cli/internal/profile"
	"github.com/abigotado/youtrack-agent-cli/internal/skills"
	"github.com/abigotado/youtrack-agent-cli/internal/writepolicy"
	"github.com/abigotado/youtrack-agent-cli/internal/youtrack"
)

const refreshSkew = 30 * time.Second

const (
	refreshRepairBindingMismatch   = "inspect and repair local profile/credential binding"
	refreshRepairInvalidCredential = "inspect local token validation and OAuth client configuration"
	refreshRepairBindingOther      = "inspect local post-refresh binding validation and repair the local configuration"
	refreshRepairInteraction       = "restore interactive Keychain access"
	refreshRepairMigration         = "inspect Keychain ACL and perform operator-approved migration if required"
	refreshRepairCanceledMigration = "resolve canceled Keychain authorization"
	refreshRepairCanceledSave      = "inspect interrupted credential-store save"
	refreshRepairTimedOutSave      = "inspect timed-out credential-store save"
	refreshRepairKeychainStatus    = "inspect Keychain availability and permissions"
	refreshRepairSaveOther         = "inspect local credential-store save failure"
)

// Service owns the profile, policy, credential, intent, and journal boundary.
type Service struct {
	Profiles       *profile.Registry
	Policies       *writepolicy.Registry
	Credentials    auth.CredentialAccessStore
	Journal        journal.Store
	Approver       approval.Approver
	Executor       mutation.Executor
	Reconciler     mutation.Reconciler
	HTTP           http.RoundTripper
	Logger         *slog.Logger
	Now            func() time.Time
	OperatorWrites *operatorwrite.Store
	// OperatorWriteSupport permits tests to supply an in-process backend. The
	// production default is fixed by build tags, with no flag or environment bypass.
	OperatorWriteSupport func() bool
}

// NewDefault creates the user-scoped production service without reading any
// credential or contacting YouTrack.
func NewDefault(logger *slog.Logger) (*Service, error) {
	profiles, err := profile.NewDefaultRegistry()
	if err != nil {
		return nil, fmt.Errorf("create profile registry: %w", err)
	}
	policies, err := writepolicy.NewDefaultRegistry()
	if err != nil {
		return nil, fmt.Errorf("create write-policy registry: %w", err)
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("locate user config directory: %w", err)
	}
	return &Service{
		Profiles: profiles, Policies: policies, Credentials: auth.KeychainStore{},
		Journal:  journal.New(filepath.Join(configDir, "youtrack-agent-cli", "journal")),
		Approver: approval.Unsupported{}, HTTP: http.DefaultTransport, Logger: logger, Now: time.Now,
		OperatorWrites: operatorwrite.New(filepath.Join(configDir, "youtrack-agent-cli")),
	}, nil
}

// ListProfiles reads only the non-secret profile registry.
func (s *Service) ListProfiles(ctx context.Context) ([]profile.Profile, error) {
	if s == nil || s.Profiles == nil {
		return nil, errx.Internal("profile registry is unavailable")
	}
	return s.Profiles.List(ctx)
}

// GetProfile reads one explicitly named non-secret profile.
func (s *Service) GetProfile(ctx context.Context, name string) (profile.Profile, error) {
	if s == nil || s.Profiles == nil {
		return profile.Profile{}, errx.Internal("profile registry is unavailable")
	}
	value, err := s.Profiles.Get(ctx, name)
	if err != nil {
		return profile.Profile{}, checkSelectionLookupError(ctx, name, err)
	}
	if err := s.checkSelectionGuard(ctx, value); err != nil {
		return profile.Profile{}, err
	}
	return value, nil
}

// SaveProfile installs a validated, unauthenticated profile. Replacing an
// existing definition requires an explicit local confirmation.
func (s *Service) SaveProfile(ctx context.Context, value profile.Profile, replace bool) (profile.Profile, error) {
	if s == nil || s.Profiles == nil || s.Credentials == nil {
		return profile.Profile{}, errx.Internal("profile or credential store is unavailable")
	}
	if err := value.ValidateLoginIntent(); err != nil {
		return profile.Profile{}, err
	}
	err := s.Profiles.WithProfileLock(ctx, value.Name, func() error {
		existing, getErr := s.Profiles.Get(ctx, value.Name)
		if errors.Is(getErr, profile.ErrNotFound) {
			return s.Profiles.Add(ctx, value)
		}
		if getErr != nil {
			return getErr
		}
		credentialExists, credentialErr := s.Credentials.Exists(ctx, value.Name)
		if credentialErr != nil {
			return credentialErr
		}
		if credentialExists || getErr == nil && existing.CredentialGeneration != "" {
			return errx.Conflict("PROFILE_AUTHENTICATED", "profile %q has a bound credential and cannot be replaced as plain metadata", value.Name).
				WithHint("run auth logout for this exact profile before replacing its topology")
		}
		switch {
		case getErr == nil && !replace:
			return errx.ConfirmRequired("profile replacement")
		case getErr == nil:
			return s.Profiles.Put(ctx, value)
		default:
			return getErr
		}
	})
	return value, err
}

// RemoveProfile removes only a credential-free profile. Authenticated profiles
// must use Logout so the Keychain and registry remain transactional.
func (s *Service) RemoveProfile(ctx context.Context, name string) error {
	if s == nil || s.Profiles == nil || s.Credentials == nil {
		return errx.Internal("profile or credential store is unavailable")
	}
	return s.Profiles.WithProfileLock(ctx, name, func() error {
		exists, err := s.Credentials.Exists(ctx, name)
		if err != nil {
			return err
		}
		if exists {
			return errx.Conflict("PROFILE_HAS_CREDENTIAL", "profile %q still has a Keychain credential", name).
				WithHint("run auth logout for this exact profile")
		}
		return s.Profiles.Remove(ctx, name)
	})
}

// AuthStatus reports non-secret credential presence and optionally verifies
// the exact current account through YouTrack.
func (s *Service) AuthStatus(ctx context.Context, name string, check bool) (AuthStatus, error) {
	value, err := s.GetProfile(ctx, name)
	if err != nil {
		return AuthStatus{}, err
	}
	if !check {
		exists, err := s.Credentials.Exists(ctx, name)
		if err != nil {
			return AuthStatus{}, err
		}
		return AuthStatus{Profile: value, CredentialPresent: exists, State: "unchecked"}, nil
	}
	client, checked, err := s.client(ctx, name)
	if err != nil {
		return AuthStatus{}, err
	}
	current, err := client.CurrentUser(ctx)
	if err != nil {
		return AuthStatus{}, err
	}
	if err := verifyAccount(checked, current); err != nil {
		return AuthStatus{}, err
	}
	return AuthStatus{Profile: checked, CredentialPresent: true, State: "valid", Account: &current}, nil
}

// ImportPermanentToken verifies an exact account before atomically binding the
// bounded token to a fresh credential generation.
func (s *Service) ImportPermanentToken(ctx context.Context, name string, credential auth.Credential, replace bool) (profile.Profile, error) {
	value, err := s.GetProfile(ctx, name)
	if err != nil {
		return profile.Profile{}, err
	}
	loginIntent, err := value.LoginIntent()
	if err != nil {
		return profile.Profile{}, err
	}
	if credential.Kind != auth.CredentialPermanentToken {
		return profile.Profile{}, errx.Usage("auth import-token requires a permanent-token credential")
	}
	if err := s.requireCredentialReplacementConfirmation(ctx, name, replace); err != nil {
		return profile.Profile{}, err
	}
	token, err := credential.BearerToken(s.currentTime())
	if err != nil {
		return profile.Profile{}, err
	}
	client, err := youtrack.New(youtrack.Config{RESTBaseURL: value.RESTBaseURL}, youtrack.Credential{Token: token}, youtrack.WithHTTPClient(&http.Client{Transport: s.HTTP}), youtrack.WithLogger(s.Logger))
	if err != nil {
		return profile.Profile{}, err
	}
	current, err := client.CurrentUser(ctx)
	if err != nil {
		return profile.Profile{}, err
	}
	if err := verifyAccount(value, current); err != nil {
		return profile.Profile{}, err
	}
	return auth.Login(ctx, s.Credentials, s.Profiles, loginIntent, credential, replace)
}

func (s *Service) requireCredentialReplacementConfirmation(ctx context.Context, name string, confirmed bool) error {
	if s == nil || s.Credentials == nil {
		return errx.Internal("credential store is unavailable")
	}
	exists, err := s.Credentials.Exists(ctx, name)
	if err != nil {
		return fmt.Errorf("check existing credential: %w", err)
	}
	if exists && !confirmed {
		return fmt.Errorf("%w: %s", auth.ErrOverwriteConfirmationRequired, name)
	}
	return nil
}

// Logout removes exactly one selected Keychain credential and its metadata.
func (s *Service) Logout(ctx context.Context, name string) error {
	if s == nil || s.Profiles == nil || s.Credentials == nil {
		return errx.Internal("profile or credential store is unavailable")
	}
	return auth.Logout(ctx, s.Credentials, s.Profiles, name)
}

// MigrateKeychain rebinds one existing item to the current application ACL
// without reading or returning its credential value.
func (s *Service) MigrateKeychain(ctx context.Context, name string) error {
	if s == nil || s.Profiles == nil || s.Credentials == nil {
		return errx.Internal("profile or credential store is unavailable")
	}
	return auth.MigrateKeychain(ctx, s.Credentials, s.Profiles, name)
}

// GetPolicy reads an identity-bound exact project allowlist.
func (s *Service) GetPolicy(ctx context.Context, name string) (writepolicy.Policy, error) {
	value, err := s.GetProfile(ctx, name)
	if err != nil {
		return writepolicy.Policy{}, err
	}
	return s.Policies.GetBound(ctx, value)
}

// PreviewPolicy validates a complete local policy without changing it.
func (s *Service) PreviewPolicy(ctx context.Context, name string, projects []writepolicy.Project) (writepolicy.Policy, error) {
	value, err := s.GetProfile(ctx, name)
	if err != nil {
		return writepolicy.Policy{}, err
	}
	if !hasWriteCapability(value) {
		return writepolicy.Policy{}, errx.Permission("WRITE_CAPABILITY_REQUIRED", "profile %q has no declared write capability", name)
	}
	canonical, err := writepolicy.CanonicalProjects(projects)
	if err != nil {
		return writepolicy.Policy{}, err
	}
	return writepolicy.Policy{Profile: name, Identity: writepolicy.IdentityFor(value), Projects: canonical}, nil
}

// SetPolicy atomically replaces the selected profile's complete project list.
func (s *Service) SetPolicy(ctx context.Context, name string, projects []writepolicy.Project) (writepolicy.Policy, error) {
	if s == nil || s.Profiles == nil || s.Policies == nil {
		return writepolicy.Policy{}, errx.Internal("profile or policy registry is unavailable")
	}
	var saved writepolicy.Policy
	err := s.Profiles.WithProfileLock(ctx, name, func() error {
		value, err := s.Profiles.Get(ctx, name)
		if err != nil {
			return err
		}
		if !hasWriteCapability(value) {
			return errx.Permission("WRITE_CAPABILITY_REQUIRED", "profile %q has no declared write capability", name)
		}
		return s.Policies.WithPolicyLock(ctx, name, func() error {
			saved, err = s.Policies.Set(ctx, value, projects)
			return err
		})
	})
	return saved, err
}

// ClearPolicy removes the selected profile's local project policy.
func (s *Service) ClearPolicy(ctx context.Context, name string) error {
	if s == nil || s.Profiles == nil || s.Policies == nil {
		return errx.Internal("profile or policy registry is unavailable")
	}
	return s.Profiles.WithProfileLock(ctx, name, func() error {
		if _, err := s.Profiles.Get(ctx, name); err != nil {
			return err
		}
		return s.Policies.WithPolicyLock(ctx, name, func() error { return s.Policies.Clear(ctx, name) })
	})
}

// InspectIssue reads one exact issue using a field-minimal fixed REST shape.
func (s *Service) InspectIssue(ctx context.Context, name, issueID string) (youtrack.Issue, profile.Profile, error) {
	client, selected, err := s.client(ctx, name)
	if err != nil {
		return youtrack.Issue{}, profile.Profile{}, err
	}
	if err := verifyClientAccount(ctx, client, selected); err != nil {
		return youtrack.Issue{}, selected, err
	}
	value, err := client.GetIssue(ctx, issueID)
	return value, selected, err
}

// InspectComments reads one bounded page plus a sentinel item. Comments remain
// untrusted content, and the API promises no stable ordering between pages.
func (s *Service) InspectComments(ctx context.Context, name, issueID string, top, skip int) ([]youtrack.Comment, bool, profile.Profile, error) {
	if top < 1 || top > 100 || skip < 0 {
		return nil, false, profile.Profile{}, errx.Usage("--limit must be 1-100 and --offset must be nonnegative")
	}
	client, selected, err := s.client(ctx, name)
	if err != nil {
		return nil, false, profile.Profile{}, err
	}
	if err := verifyClientAccount(ctx, client, selected); err != nil {
		return nil, false, selected, err
	}
	values, err := client.ListComments(ctx, issueID, youtrack.PageOptions{Top: top + 1, Skip: skip, CanReduce: top > 1})
	if err != nil {
		return nil, false, selected, err
	}
	truncated := len(values) > top
	if truncated {
		values = values[:top]
	}
	return values, truncated, selected, nil
}

// InspectProject reads one exact project.
func (s *Service) InspectProject(ctx context.Context, name, projectID string) (youtrack.Project, profile.Profile, error) {
	client, selected, err := s.client(ctx, name)
	if err != nil {
		return youtrack.Project{}, profile.Profile{}, err
	}
	if err := verifyClientAccount(ctx, client, selected); err != nil {
		return youtrack.Project{}, selected, err
	}
	value, err := client.GetProject(ctx, projectID)
	return value, selected, err
}

// InspectSchema reads one bounded page plus one sentinel item so truncation is
// based on evidence rather than equality with the caller's requested limit.
func (s *Service) InspectSchema(ctx context.Context, name, projectID string, top, skip int) ([]youtrack.ProjectField, bool, profile.Profile, error) {
	client, selected, err := s.client(ctx, name)
	if err != nil {
		return nil, false, profile.Profile{}, err
	}
	if err := verifyClientAccount(ctx, client, selected); err != nil {
		return nil, false, selected, err
	}
	value, err := client.ListProjectFields(ctx, projectID, youtrack.PageOptions{Top: top + 1, Skip: skip, CanReduce: top > 1})
	if err != nil {
		return nil, false, selected, err
	}
	truncated := len(value) > top
	if truncated {
		value = value[:top]
	}
	return value, truncated, selected, nil
}

// PrepareMutation creates and journals a complete network-free plan. This
// method does not read Keychain, construct HTTP clients, or open a browser.
func (s *Service) PrepareMutation(ctx context.Context, input PrepareInput) (journal.Record, error) {
	if s == nil || s.Profiles == nil || s.Policies == nil {
		return journal.Record{}, errx.Internal("offline mutation dependencies are unavailable")
	}
	var record journal.Record
	err := s.Profiles.WithProfileLock(ctx, input.Profile, func() error {
		selected, err := s.Profiles.Get(ctx, input.Profile)
		if err != nil {
			return err
		}
		if err := intent.ValidateApprovalProfile(intent.ProfileSnapshot{
			Instance: selected.ServiceURL, RESTBaseURL: selected.RESTBaseURL,
			OAuthIssuerURL: selected.OAuth.IssuerURL,
		}); err != nil {
			return (&errx.Error{
				Code:    errx.CodeUsage,
				Reason:  "MUTATION_PROFILE_INCOMPATIBLE",
				Message: fmt.Sprintf("profile %q cannot be represented by the trusted approval protocol", input.Profile),
				Hint:    "recreate the profile with canonical DNS or IPv4 HTTPS URLs and no explicit :443 port",
			}).Wrap(err)
		}
		if selected.CredentialGeneration == "" {
			return errx.Auth("PROFILE_NOT_AUTHENTICATED", "profile %q has no credential generation", input.Profile)
		}
		required, err := requiredCapability(input.Kind)
		if err != nil {
			return err
		}
		if !selected.HasCapability(required) {
			return errx.Permission("MUTATION_CAPABILITY_REQUIRED", "profile %q does not authorize %s", input.Profile, input.Kind)
		}
		return s.Policies.WithPolicyLock(ctx, input.Profile, func() error {
			policy, err := s.Policies.RequireProject(ctx, selected, input.Project.ID, input.Project.Key)
			if err != nil {
				return err
			}
			policyBytes, err := json.Marshal(policy)
			if err != nil {
				return fmt.Errorf("encode project policy: %w", err)
			}
			plan, err := intent.Prepare(intent.ProfileSnapshot{
				Name: selected.Name, Instance: selected.ServiceURL,
				RESTBaseURL: selected.RESTBaseURL, OAuthIssuerURL: selected.OAuth.IssuerURL,
				IdentitySHA256: profile.CredentialIdentity(selected), CredentialGeneration: selected.CredentialGeneration,
				Account: intent.AccountBinding{ID: selected.ExpectedAccountID, Login: selected.ExpectedLogin},
			}, intent.ProjectPolicy{
				Project:        intent.ProjectBinding{ID: input.Project.ID, Key: input.Project.Key},
				PolicyRevision: policy.Revision, PolicySHA256: sha256Hex(policyBytes), SchemaSHA256: input.SchemaSHA256,
				ExecutorAssurance: string(selected.Executor), AuthorizedCapability: string(required),
				NotificationPolicy: "youtrack-default", ReconciliationStrategy: "bounded-exact-and-marker",
			}, input.Kind, input.RequestJSON, input.ExpectedJSON)
			if err != nil {
				return err
			}
			record, err = s.Journal.Create(ctx, plan)
			return err
		})
	})
	if err != nil {
		if journal.WasCommitted(err) && record.Plan.PlanID != "" {
			return record, errx.Internal("mutation plan %q may be committed but directory durability could not be confirmed", record.Plan.PlanID).Wrap(err)
		}
		return journal.Record{}, err
	}
	if input.OutputPath != "" {
		if err := exportPlan(input.OutputPath, record.Plan); err != nil {
			return record, planExportError(record.Plan.PlanID, input.OutputPath, err)
		}
	}
	return record, nil
}

// MutationStatus returns the durable local record without network access.
func (s *Service) MutationStatus(ctx context.Context, planID string) (journal.Record, error) {
	return s.Journal.Get(ctx, planID)
}

// ExportMutation writes a new exclusive 0600 copy of an existing journaled
// plan. It is network-free and never changes the authoritative record.
func (s *Service) ExportMutation(ctx context.Context, planID, outputPath string) (journal.Record, error) {
	record, err := s.Journal.Get(ctx, planID)
	if err != nil {
		return journal.Record{}, err
	}
	if err := exportPlan(outputPath, record.Plan); err != nil {
		return record, planExportError(record.Plan.PlanID, outputPath, err)
	}
	return record, nil
}

func planExportError(planID, outputPath string, cause error) error {
	return (&errx.Error{
		Code:    errx.CodeUsage,
		Reason:  "PLAN_EXPORT_FAILED",
		Message: fmt.Sprintf("mutation plan %q remains journaled but could not be exported to %q", planID, outputPath),
		Hint:    fmt.Sprintf("choose a new non-existing writable path and run mutation export --plan-id %s --out NEW_PATH", planID),
	}).Wrap(cause)
}

// ConfirmMutation is intentionally fail-closed until the signed native helper
// passes Gate 1A. It never falls back to terminal input or --yes.
func (s *Service) ConfirmMutation(ctx context.Context, planID string) error {
	record, err := s.Journal.Get(ctx, planID)
	if err != nil {
		return err
	}
	canonical, err := intent.ApprovalDisplayBytes(record.Plan)
	if err != nil {
		return err
	}
	_, err = s.Approver.Confirm(ctx, canonical)
	return err
}

// ApplyMutation is disabled until Gate 1A and an audited executor both pass.
func (s *Service) ApplyMutation(ctx context.Context, profileName, planID string) error {
	record, err := s.Journal.Get(ctx, planID)
	if err != nil {
		return err
	}
	if err := requireMutationProfile(record, profileName); err != nil {
		return err
	}
	return &errx.Error{Code: errx.CodeConfirm, Reason: "USER_PRESENCE_UNAVAILABLE", Message: "guarded mutation apply is disabled because Gate 1A has not passed", Hint: "use prepare/status only; do not bypass approval through MCP or raw REST"}
}

// ReconcileMutation refuses to invent evidence before an audited executor has
// produced a non-replayable record.
func (s *Service) ReconcileMutation(ctx context.Context, profileName, planID string) error {
	record, err := s.Journal.Get(ctx, planID)
	if err != nil {
		return err
	}
	if err := requireMutationProfile(record, profileName); err != nil {
		return err
	}
	if !record.RequiresReconciliation() {
		return errx.Conflict("RECONCILIATION_NOT_REQUIRED", "mutation plan %q in state %s is not eligible for reconciliation", planID, record.State)
	}
	return &errx.Error{Code: errx.CodeConflict, Reason: "RECONCILER_DISABLED", Message: "bounded REST reconciliation is disabled until the write executor passes its compatibility gate", Hint: "do not retry the mutation; resolve the record with an audited release"}
}

// InstallSkill delegates the provider-neutral, network-free skill installer.
func (s *Service) InstallSkill(ctx context.Context, opts skills.Options) ([]skills.Result, error) {
	return skills.Install(ctx, opts)
}

// UninstallSkill delegates the manifest-owned, hash-safe uninstaller.
func (s *Service) UninstallSkill(ctx context.Context, opts skills.Options) ([]skills.Result, error) {
	return skills.Uninstall(ctx, opts)
}

// AuthStatus contains no credential material.
type AuthStatus struct {
	Profile           profile.Profile `json:"profile"`
	CredentialPresent bool            `json:"credential_present"`
	State             string          `json:"state"`
	Account           *youtrack.User  `json:"account,omitempty"`
}

// PrepareInput is the complete local input to offline plan creation.
type PrepareInput struct {
	Profile      string
	Kind         intent.Kind
	Project      writepolicy.Project
	SchemaSHA256 string
	RequestJSON  []byte
	ExpectedJSON []byte
	OutputPath   string
}

func (s *Service) client(ctx context.Context, name string) (*youtrack.Client, profile.Profile, error) {
	if s == nil || s.Profiles == nil || s.Credentials == nil {
		return nil, profile.Profile{}, errx.Internal("profile or credential store is unavailable")
	}
	var selected profile.Profile
	var client *youtrack.Client
	err := s.Profiles.WithProfileLock(ctx, name, func() error {
		var err error
		selected, err = s.Profiles.Get(ctx, name)
		if err != nil {
			return checkSelectionLookupError(ctx, name, err)
		}
		if err := s.checkSelectionGuard(ctx, selected); err != nil {
			return err
		}
		credential, err := s.Credentials.Load(ctx, name)
		if err != nil {
			return err
		}
		if err := auth.ValidateCredentialBinding(credential, selected); err != nil {
			return err
		}
		credential, err = s.refreshIfNeeded(ctx, selected, credential)
		if err != nil {
			return err
		}
		token, err := credential.BearerToken(s.currentTime())
		if err != nil {
			return err
		}
		client, err = youtrack.New(youtrack.Config{RESTBaseURL: selected.RESTBaseURL}, youtrack.Credential{Token: token}, youtrack.WithHTTPClient(&http.Client{Transport: s.HTTP}), youtrack.WithLogger(s.Logger))
		return err
	})
	// Mapped here rather than in TranslateError, where a denial can follow a
	// committed change. Refresh is the one step here that changes state, and its
	// failures are typed without their cause; a typed error keeps its recovery.
	var typed *errx.Error
	if !errors.As(err, &typed) && errors.Is(err, fs.ErrPermission) {
		return nil, profile.Profile{}, errx.Permission("LOCAL_STATE_ACCESS_DENIED", "the operating system denied access to local youtrack-agent-cli state").
			WithHint("stop and ask the operator to allow access to the youtrack-agent-cli directory under the user config directory, including writing its lock files; do not change a sandbox policy yourself")
	}
	return client, selected, err
}

func (s *Service) refreshIfNeeded(ctx context.Context, selected profile.Profile, credential auth.Credential) (auth.Credential, error) {
	if credential.Kind != auth.CredentialOAuth || s.currentTime().Add(refreshSkew).Before(credential.AccessTokenExpiresAt) {
		return credential, nil
	}
	client, err := oauth.NewClient(oauthConfig(selected), s.HTTP)
	if err != nil {
		return auth.Credential{}, err
	}
	currentScopes := credential.OAuthScopes
	if len(currentScopes) == 0 {
		// v1 credentials predate persisted grants. The old exchange path only
		// accepted the complete configured scope set, so this is a strict and
		// deterministic migration default.
		currentScopes = selected.OAuth.Scopes
	}
	refreshed, err := client.Refresh(ctx, oauth.TokenSet{
		AccessToken: credential.AccessToken, RefreshToken: credential.RefreshToken,
		TokenType: credential.TokenType, ExpiresAt: credential.AccessTokenExpiresAt,
		Scopes: append([]string(nil), currentScopes...),
	})
	if err != nil {
		if errors.Is(err, oauth.ErrTokenExchange) {
			return auth.Credential{}, oauthRecoveryError(oauthrecovery.Legacy(), "OAuth refresh failed")
		}
		return auth.Credential{}, err
	}
	credential.AccessToken = refreshed.AccessToken
	credential.RefreshToken = refreshed.RefreshToken
	credential.TokenType = refreshed.TokenType
	credential.AccessTokenExpiresAt = refreshed.ExpiresAt
	credential.OAuthScopes = append([]string(nil), refreshed.Scopes...)
	if err := auth.ValidateCredentialBinding(credential, selected); err != nil {
		return auth.Credential{}, refreshPreSaveBindingFailure(err, s.Logger)
	}
	if err := s.Credentials.Save(ctx, selected.Name, credential); err != nil {
		return auth.Credential{}, refreshPersistenceUncertain(err, s.Logger)
	}
	return credential, nil
}

// This path is a defensive fence after a successful token response and before
// the first credential-store write. Never retain the rejected credential or
// the underlying validation error in logs or the user-facing error.
func refreshPreSaveBindingFailure(err error, logger *slog.Logger) *errx.Error {
	category := "other"
	localRepair := refreshRepairBindingOther
	switch {
	case errors.Is(err, auth.ErrCredentialBindingMismatch):
		category = "binding_mismatch"
		localRepair = refreshRepairBindingMismatch
	case errors.Is(err, auth.ErrInvalidToken):
		category = "invalid_credential"
		localRepair = refreshRepairInvalidCredential
	}
	if logger != nil {
		logger.Warn("OAuth refresh binding rejected before persistence", "category", category)
	}
	descriptor := oauthrecovery.Legacy()
	return oauthRecoveryError(descriptor, "refreshed OAuth credential local binding rejected before persistence").
		WithHint("%s; %s", localRepair, descriptor.Hint)
}

// refreshPersistenceUncertain intentionally drops the local cause. The server
// may have rotated the refresh token, and a failed save does not prove whether
// the replacement credential was persisted. In particular, a canceled save
// must not become the ordinary retryable CANCELED recovery.
func refreshPersistenceUncertain(err error, logger *slog.Logger) *errx.Error {
	category := "other"
	localRepair := refreshRepairSaveOther
	var status *auth.StatusError
	switch {
	case errors.Is(err, auth.ErrInteractionNotAllowed):
		category = "interaction_blocked"
		localRepair = refreshRepairInteraction
	case errors.Is(err, auth.ErrKeychainMigrationRequired):
		category = "migration_required"
		localRepair = refreshRepairMigration
	case errors.Is(err, auth.ErrKeychainMigrationCanceled):
		category = "user_canceled"
		localRepair = refreshRepairCanceledMigration
	case errors.Is(err, context.Canceled):
		category = "context_canceled"
		localRepair = refreshRepairCanceledSave
	case errors.Is(err, context.DeadlineExceeded):
		category = "deadline_exceeded"
		localRepair = refreshRepairTimedOutSave
	case errors.As(err, &status):
		category = "keychain_status_failure"
		localRepair = refreshRepairKeychainStatus
	}
	if logger != nil {
		logger.Warn("OAuth refresh credential persistence is uncertain", "category", category)
	}
	descriptor := oauthrecovery.Legacy()
	return oauthRecoveryError(descriptor, "rotated OAuth credential persistence is uncertain").
		WithHint("%s; persisted state is unknown; %s", localRepair, descriptor.Hint)
}

func oauthConfig(value profile.Profile) oauth.Config {
	return oauth.Config{IssuerURL: value.OAuth.IssuerURL, AuthorizationURL: value.OAuth.AuthorizationURL, TokenURL: value.OAuth.TokenURL, ClientID: value.OAuth.ClientID, Scopes: append([]string(nil), value.OAuth.Scopes...), RedirectURI: value.OAuth.RedirectURI}
}

func verifyAccount(expected profile.Profile, actual youtrack.User) error {
	if actual.ID != expected.ExpectedAccountID || actual.Login != expected.ExpectedLogin {
		return errx.Auth("ACCOUNT_IDENTITY_MISMATCH", "authenticated YouTrack account does not match profile %q", expected.Name).
			WithHint("reauthorize the exact expected account or correct the non-secret profile")
	}
	return nil
}

func verifyClientAccount(ctx context.Context, client *youtrack.Client, expected profile.Profile) error {
	current, err := client.CurrentUser(ctx)
	if err != nil {
		return err
	}
	return verifyAccount(expected, current)
}

func requireMutationProfile(record journal.Record, name string) error {
	if record.Plan.Profile.Name != name {
		return errx.Conflict("MUTATION_PROFILE_MISMATCH", "mutation plan %q belongs to profile %q, not %q", record.Plan.PlanID, record.Plan.Profile.Name, name)
	}
	return nil
}

func hasWriteCapability(value profile.Profile) bool {
	return value.HasCapability(profile.CapabilityIssueCreate) || value.HasCapability(profile.CapabilityIssueUpdate) || value.HasCapability(profile.CapabilityCommentAdd) || value.HasCapability(profile.CapabilityCommentDelete)
}

func requiredCapability(kind intent.Kind) (profile.Capability, error) {
	switch kind {
	case intent.KindIssueCreate:
		return profile.CapabilityIssueCreate, nil
	case intent.KindIssueUpdate:
		return profile.CapabilityIssueUpdate, nil
	case intent.KindCommentAdd:
		return profile.CapabilityCommentAdd, nil
	default:
		return "", errx.Usage("unsupported mutation kind %q", kind)
	}
}

func (s *Service) currentTime() time.Time {
	if s != nil && s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func sha256Hex(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func exportPlan(path string, plan intent.Plan) error {
	raw, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return fmt.Errorf("encode plan export: %w", err)
	}
	raw = append(raw, '\n')
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create exclusive plan export: %w", err)
	}
	name := file.Name()
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(name)
		}
	}()
	if _, err := file.Write(raw); err != nil {
		return errors.Join(fmt.Errorf("write plan export: %w", err), file.Close())
	}
	if err := file.Sync(); err != nil {
		return errors.Join(fmt.Errorf("sync plan export: %w", err), file.Close())
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close plan export: %w", err)
	}
	remove = false
	return nil
}
