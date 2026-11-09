package application

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/approval"
	"github.com/abigotado/youtrack-agent-cli/internal/auth"
	"github.com/abigotado/youtrack-agent-cli/internal/endpoint"
	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/intent"
	"github.com/abigotado/youtrack-agent-cli/internal/journal"
	"github.com/abigotado/youtrack-agent-cli/internal/profile"
	"github.com/abigotado/youtrack-agent-cli/internal/writepolicy"
)

type trapCredentials struct{ calls int }

func (store *trapCredentials) Exists(context.Context, string) (bool, error) {
	store.calls++
	return false, errors.New("credential trap called")
}

func (store *trapCredentials) Load(context.Context, string) (auth.Credential, error) {
	store.calls++
	return auth.Credential{}, errors.New("credential trap called")
}
func (store *trapCredentials) Save(context.Context, string, auth.Credential) error {
	store.calls++
	return errors.New("credential trap called")
}
func (store *trapCredentials) Delete(context.Context, string) error {
	store.calls++
	return errors.New("credential trap called")
}
func (store *trapCredentials) MigrateKeychain(context.Context, string) error {
	store.calls++
	return errors.New("credential trap called")
}

func TestMutationStatusAndExportPreserveFreshV2(t *testing.T) {
	service, credentials, transport := mutationService(t)
	journalDir := filepath.Join(t.TempDir(), "journal")
	service.Journal = journal.New(journalDir)
	created, err := service.PrepareMutationInfo(context.Background(), validPrepareInput(""))
	if err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(journalDir, created.PlanID+".json")
	before, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	status, err := service.MutationStatus(context.Background(), created.PlanID)
	if err != nil || status.Version != 2 || status.Revision != 1 || status.State != journal.StatePrepared {
		t.Fatalf("status of fresh v2 = %#v, %v", status, err)
	}
	exportPath := filepath.Join(t.TempDir(), "plan.json")
	exported, err := service.ExportMutation(context.Background(), created.PlanID, exportPath)
	if err != nil || exported.Version != 2 || exported.Revision != 1 {
		t.Fatalf("export of fresh v2 = %#v, %v", exported, err)
	}
	if _, err := os.Stat(exportPath); err != nil {
		t.Fatalf("export did not write plan: %v", err)
	}
	after, err := os.ReadFile(journalPath)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatalf("status/export changed authoritative v2: %v", err)
	}
	markerPath := filepath.Join(journalDir, created.PlanID+".v1-quarantine.json")
	if _, err := os.Lstat(markerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("status/export created quarantine marker: %v", err)
	}
	if credentials.calls != 0 || transport.calls != 0 {
		t.Fatalf("status/export contacted credentials=%d network=%d", credentials.calls, transport.calls)
	}
}

// Captured from the historical v1 MarshalIndent-plus-LF writer. This is an
// independent application-level fixture, not a projection of the live Record.
const applicationHistoricalV1Prepared = `{
  "version": 1,
  "revision": 1,
  "state": "prepared",
  "plan": {
    "schema_version": 1,
    "plan_id": "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA",
    "kind": "issue.update",
    "profile": {
      "name": "work",
      "instance": "https://acme.youtrack.cloud",
      "rest_base_url": "https://acme.youtrack.cloud/api",
      "oauth_issuer_url": "https://hub.example.test",
      "identity_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "credential_generation": "gen-1",
      "account": {
        "id": "1-2",
        "login": "alice"
      }
    },
    "policy": {
      "project": {
        "id": "0-1",
        "key": "APP"
      },
      "policy_revision": 1,
      "policy_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "schema_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "executor_assurance": "rest-best-effort",
      "authorized_capability": "issue-update",
      "notification_policy": "youtrack-default",
      "reconciliation_strategy": "bounded-exact-and-marker"
    },
    "operation": {
      "issue_update": {
        "request": {
          "issue_id": "APP-1",
          "set": {
            "summary": "new"
          }
        },
        "expected": {
          "issue_id": "APP-1",
          "issue_state_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
          "touched_fields_sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        }
      }
    },
    "request_sha256": "9b4a6652ef2500c4d1e59669cadf6dcc8dc2e77224684cd7433c8d49d844955b",
    "expected_sha256": "f17747d18c996141cb33aeba203a6635cffa8bd4fb178e14fb592af283ff77c9",
    "intent_sha256": "56635c16b12d2b5b4849a76fa936fc8f04550509c9afc4afa1fbd06a568da341"
  },
  "mutation_attempts": 0,
  "created_at": "2026-09-28T15:00:00Z",
  "updated_at": "2026-09-28T15:00:00Z"
}
`

func TestMutationStatusAndExportNeverMigrateLegacyJournal(t *testing.T) {
	service, credentials, transport := mutationService(t)
	journalDir := filepath.Join(t.TempDir(), "journal")
	service.Journal = journal.New(journalDir)
	if err := os.Mkdir(journalDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const planID = "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA"
	journalPath := filepath.Join(journalDir, planID+".json")
	before := []byte(applicationHistoricalV1Prepared)
	if _, err := journal.ClassifyLegacyV1(before); err != nil {
		t.Fatalf("historical v1 fixture is invalid: %v", err)
	}
	if err := os.WriteFile(journalPath, before, 0o600); err != nil {
		t.Fatal(err)
	}
	status, err := service.MutationStatus(context.Background(), planID)
	if err != nil || status.Version != 1 || status.Revision != 1 || status.State != journal.StatePrepared {
		t.Fatalf("status of historical v1 = %#v, %v", status, err)
	}
	exportPath := filepath.Join(t.TempDir(), "plan.json")
	exported, err := service.ExportMutation(context.Background(), planID, exportPath)
	if err != nil || exported.Version != 1 || exported.Revision != 1 {
		t.Fatalf("export of historical v1 = %#v, %v", exported, err)
	}
	if _, err := os.Stat(exportPath); err != nil {
		t.Fatalf("export did not write plan: %v", err)
	}
	after, err := os.ReadFile(journalPath)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatalf("status/export changed authoritative v1: %v", err)
	}
	markerPath := filepath.Join(journalDir, planID+".v1-quarantine.json")
	if _, err := os.Lstat(markerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("status/export created quarantine marker: %v", err)
	}
	if credentials.calls != 0 || transport.calls != 0 {
		t.Fatalf("status/export contacted credentials=%d network=%d", credentials.calls, transport.calls)
	}
}

type trapTransport struct{ calls int }

func (transport *trapTransport) RoundTrip(*http.Request) (*http.Response, error) {
	transport.calls++
	return nil, errors.New("network trap called")
}

type existingCredentials struct{ emptyCredentials }

func (*existingCredentials) Exists(context.Context, string) (bool, error) { return true, nil }

type trapBrowser struct{ calls int }

func (browser *trapBrowser) Open(context.Context, string) error {
	browser.calls++
	return errors.New("browser trap called")
}

type countingReader struct{ calls int }

func (reader *countingReader) Read([]byte) (int, error) {
	reader.calls++
	return 0, io.EOF
}

func mutationService(t *testing.T) (*Service, *trapCredentials, *trapTransport) {
	t.Helper()
	directory := t.TempDir()
	configDirectory := filepath.Join(directory, "config")
	profiles := profile.NewRegistry(filepath.Join(configDirectory, "profiles.json"))
	policies := writepolicy.NewRegistry(filepath.Join(configDirectory, "write-policies.json"))
	serviceURL := "https://tracker.example.test"
	mcpURL, err := endpoint.CanonicalMCPURL(serviceURL)
	if err != nil {
		t.Fatal(err)
	}
	value := profile.Profile{
		Name: "work", ServiceURL: serviceURL, RESTBaseURL: serviceURL + endpoint.RESTPath, MCPURL: mcpURL,
		OAuth: profile.OAuthConfig{
			IssuerURL: "https://hub.example.test", AuthorizationURL: "https://hub.example.test" + endpoint.OAuthAuthorizationPath,
			TokenURL: "https://hub.example.test" + endpoint.OAuthTokenPath, ClientID: "client", Scopes: []string{"YouTrack"},
			RedirectURI: "http://127.0.0.1:18987/oauth/callback",
		},
		ExpectedAccountID: "1-42", ExpectedLogin: "alice",
		Capabilities: []profile.Capability{profile.CapabilityRead, profile.CapabilityIssueUpdate},
		Executor:     profile.ExecutorRESTBestEffort, Assurance: profile.AssuranceBestEffort,
	}
	value, err = value.WithNewCredentialGeneration()
	if err != nil {
		t.Fatal(err)
	}
	if err := profiles.Add(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	if _, err := policies.Set(context.Background(), value, []writepolicy.Project{{ID: "0-1", Key: "APP"}}); err != nil {
		t.Fatal(err)
	}
	credentials := &trapCredentials{}
	transport := &trapTransport{}
	return &Service{
		Profiles: profiles, Policies: policies, Credentials: credentials,
		Journal: journal.New(filepath.Join(directory, "journal")), Approver: approval.Unsupported{}, HTTP: transport,
	}, credentials, transport
}

func validPrepareInput(outputPath string) MutationPrepareInput {
	return MutationPrepareInput{
		Profile: "work", Kind: "issue.update", Project: ProjectRef{ID: "0-1", Key: "APP"},
		SchemaSHA256: strings.Repeat("a", 64), OutputPath: outputPath,
		RequestJSON:  []byte(`{"issue_id":"APP-1","set":{"summary":"new"}}`),
		ExpectedJSON: []byte(`{"issue_id":"APP-1","issue_state_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","touched_fields_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}`),
	}
}

func TestPrepareMutationIsOfflineAndExportsExclusivePlan(t *testing.T) {
	service, credentials, transport := mutationService(t)
	path := filepath.Join(t.TempDir(), "plan.json")
	result, err := service.PrepareMutationInfo(context.Background(), validPrepareInput(path))
	if err != nil {
		t.Fatal(err)
	}
	if credentials.calls != 0 || transport.calls != 0 {
		t.Fatalf("offline prepare touched credentials=%d network=%d", credentials.calls, transport.calls)
	}
	if result.State != "prepared" || result.PlanID == "" || result.OutputPath != path {
		t.Fatalf("mutation result=%+v", result)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("plan mode=%v", info.Mode().Perm())
	}
}

func TestPrepareMutationPersistsEscapeHeavyPlanAboveFormerJournalLimit(t *testing.T) {
	service, credentials, transport := mutationService(t)
	fieldType := strings.Repeat("<", 128)
	literal := strings.Repeat("<", 8<<10)
	fields := `[{"field_id":"1","field_type":"` + fieldType + `","text_value":"` + literal +
		`"},{"field_id":"2","field_type":"` + fieldType + `","text_value":"` + literal +
		`"},{"field_id":"3","field_type":"` + fieldType + `","text_value":"` + literal + `"}]`
	request := []byte(`{"issue_id":"APP-1","set":{"summary":"` + strings.Repeat("<", 1024) +
		`","description":"` + strings.Repeat("<", 32<<10) + `","custom_fields":` + fields + `}}`)
	record, err := service.PrepareMutation(context.Background(), PrepareInput{
		Profile: "work", Kind: intent.KindIssueUpdate, Project: writepolicy.Project{ID: "0-1", Key: "APP"},
		SchemaSHA256: strings.Repeat("a", 64), RequestJSON: request,
		ExpectedJSON: []byte(`{"issue_id":"APP-1","issue_state_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","touched_fields_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := intent.CanonicalBytes(record.Plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(canonical) <= 256<<10 {
		t.Fatalf("canonical plan is %d bytes; regression no longer exercises the former journal limit", len(canonical))
	}
	stored, err := service.Journal.Get(context.Background(), record.Plan.PlanID)
	if err != nil || stored.Plan.IntentSHA256 != record.Plan.IntentSHA256 {
		t.Fatalf("stored plan=%#v err=%v", stored.Plan, err)
	}
	if credentials.calls != 0 || transport.calls != 0 {
		t.Fatalf("offline prepare touched credentials=%d network=%d", credentials.calls, transport.calls)
	}
}

func TestPrepareExportFailureKeepsAuthoritativeJournalRecord(t *testing.T) {
	service, _, _ := mutationService(t)
	directory := t.TempDir()
	result, err := service.PrepareMutationInfo(context.Background(), validPrepareInput(directory))
	if err == nil || result.PlanID == "" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	recorded, statusErr := service.MutationStatusInfo(context.Background(), result.PlanID)
	if statusErr != nil || recorded.State != "prepared" {
		t.Fatalf("recorded=%+v err=%v", recorded, statusErr)
	}
}

func TestPrepareMutationRequiresExactOperationCapability(t *testing.T) {
	service, credentials, transport := mutationService(t)
	input := validPrepareInput("")
	input.Kind = "issue.create"
	input.RequestJSON = []byte(`{"summary":"S","description":"","visibility":{"mode":"public"},"marker":"none"}`)
	input.ExpectedJSON = []byte(`{"project_state_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`)
	_, err := service.PrepareMutationInfo(context.Background(), input)
	var typed *errx.Error
	if !errors.As(err, &typed) || typed.Reason != "MUTATION_CAPABILITY_REQUIRED" {
		t.Fatalf("error=%v", err)
	}
	if credentials.calls != 0 || transport.calls != 0 {
		t.Fatalf("capability rejection touched credentials=%d network=%d", credentials.calls, transport.calls)
	}
}

func TestPrepareMutationRejectsIncompatibleProfileBeforeCapabilityOrSideEffects(t *testing.T) {
	directory := t.TempDir()
	profiles := profile.NewRegistry(filepath.Join(directory, "config", "profiles.json"))
	selected := profile.Profile{
		Name: "work", ServiceURL: "https://tracker.example.test:443", RESTBaseURL: "https://tracker.example.test:443/api",
		OAuth: profile.OAuthConfig{
			IssuerURL: "https://hub.example.test:443", AuthorizationURL: "https://hub.example.test:443/api/rest/oauth2/auth",
			TokenURL: "https://hub.example.test:443/api/rest/oauth2/token", ClientID: "client", Scopes: []string{"YouTrack"},
			RedirectURI: "http://127.0.0.1:18987/oauth/callback",
		},
		ExpectedAccountID: "1-42", ExpectedLogin: "alice", Capabilities: []profile.Capability{profile.CapabilityRead},
		Executor: profile.ExecutorRESTBestEffort, Assurance: profile.AssuranceBestEffort,
	}
	var err error
	selected.MCPURL, err = endpoint.CanonicalMCPURL(selected.ServiceURL)
	if err != nil {
		t.Fatal(err)
	}
	selected, err = selected.WithNewCredentialGeneration()
	if err != nil {
		t.Fatal(err)
	}
	if err := profiles.Add(context.Background(), selected); err != nil {
		t.Fatal(err)
	}
	policyDirectory := filepath.Join(directory, "policy")
	journalDirectory := filepath.Join(directory, "journal")
	exportPath := filepath.Join(directory, "exports", "plan.json")
	credentials := &trapCredentials{}
	transport := &trapTransport{}
	service := &Service{
		Profiles: profiles, Policies: writepolicy.NewRegistry(filepath.Join(policyDirectory, "write-policies.json")),
		Credentials: credentials, Journal: journal.New(journalDirectory), Approver: approval.Unsupported{}, HTTP: transport,
	}
	_, err = service.PrepareMutationInfo(context.Background(), validPrepareInput(exportPath))
	var typed *errx.Error
	if !errors.As(err, &typed) || typed.Code != errx.CodeUsage || typed.Reason != "MUTATION_PROFILE_INCOMPATIBLE" {
		t.Fatalf("error = %#v, want early profile compatibility rejection", err)
	}
	if !strings.Contains(typed.Hint, "canonical DNS or IPv4 HTTPS URLs") {
		t.Fatalf("compatibility hint = %q", typed.Hint)
	}
	if credentials.calls != 0 || transport.calls != 0 {
		t.Fatalf("compatibility rejection touched credentials=%d network=%d", credentials.calls, transport.calls)
	}
	for name, path := range map[string]string{
		"policy directory":  policyDirectory,
		"journal directory": journalDirectory,
		"export path":       exportPath,
	} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("%s was touched: %v", name, statErr)
		}
	}
}

func TestPrepareExportFailurePreservesPlanIDAndCanReexport(t *testing.T) {
	service, _, _ := mutationService(t)
	directory := t.TempDir()
	blocked := filepath.Join(directory, "already-exists.json")
	if err := os.WriteFile(blocked, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	record, err := service.PrepareMutationInfo(context.Background(), validPrepareInput(blocked))
	if err == nil || record.PlanID == "" || !strings.Contains(err.Error(), record.PlanID) {
		t.Fatalf("record=%#v err=%v", record, err)
	}
	var typed *errx.Error
	if !errors.As(err, &typed) || typed.Code != errx.CodeUsage || typed.Reason != "PLAN_EXPORT_FAILED" ||
		!strings.Contains(typed.Hint, "mutation export --plan-id "+record.PlanID) {
		t.Fatalf("export error contract=%#v", err)
	}
	if status, statusErr := service.MutationStatusInfo(context.Background(), record.PlanID); statusErr != nil || status.State != "prepared" {
		t.Fatalf("status=%#v err=%v", status, statusErr)
	}
	reexport := filepath.Join(directory, "reexport.json")
	exported, exportErr := service.ExportMutationInfo(context.Background(), record.PlanID, reexport)
	if exportErr != nil || exported.OutputPath != reexport {
		t.Fatalf("exported=%#v err=%v", exported, exportErr)
	}
	if info, statErr := os.Stat(reexport); statErr != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("reexport info=%v err=%v", info, statErr)
	}
}

func TestConfirmAndApplyFailClosedWithoutChangingPreparedState(t *testing.T) {
	service, _, _ := mutationService(t)
	result, err := service.PrepareMutationInfo(context.Background(), validPrepareInput(""))
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []struct {
		name string
		run  func() error
	}{
		{name: "confirm", run: func() error { return service.ConfirmMutation(context.Background(), result.PlanID) }},
		{name: "apply", run: func() error { return service.ApplyMutation(context.Background(), "work", result.PlanID) }},
	} {
		t.Run(operation.name, func(t *testing.T) {
			err := operation.run()
			var typed *errx.Error
			if !errors.As(err, &typed) || typed.Reason != "USER_PRESENCE_UNAVAILABLE" {
				t.Fatalf("error=%v", err)
			}
			current, statusErr := service.MutationStatusInfo(context.Background(), result.PlanID)
			if statusErr != nil || current.State != "prepared" || current.Revision != 1 {
				t.Fatalf("current=%+v err=%v", current, statusErr)
			}
		})
	}
}

func TestSaveProfileRefusesToOrphanBoundCredential(t *testing.T) {
	service, _, _ := mutationService(t)
	existing, err := service.GetProfile(context.Background(), "work")
	if err != nil {
		t.Fatal(err)
	}
	loginIntent, err := existing.LoginIntent()
	if err != nil {
		t.Fatal(err)
	}
	service.Credentials = &emptyCredentials{}
	_, err = service.SaveProfile(context.Background(), loginIntent, true)
	var typed *errx.Error
	if !errors.As(err, &typed) || typed.Reason != "PROFILE_AUTHENTICATED" {
		t.Fatalf("error=%v", err)
	}
	current, err := service.GetProfile(context.Background(), "work")
	if err != nil || current.CredentialGeneration != existing.CredentialGeneration {
		t.Fatalf("current=%+v err=%v", current, err)
	}
}

func TestCredentialReplacementConfirmationPrecedesOAuthSideEffects(t *testing.T) {
	service, _, transport := mutationService(t)
	service.Credentials = &existingCredentials{}
	browser := &trapBrowser{}
	_, err := service.LoginOAuth(context.Background(), "work", false, browser)
	if !errors.Is(err, auth.ErrOverwriteConfirmationRequired) {
		t.Fatalf("error=%v", err)
	}
	if browser.calls != 0 || transport.calls != 0 {
		t.Fatalf("preflight touched browser=%d network=%d", browser.calls, transport.calls)
	}
}

func TestCredentialReplacementConfirmationPrecedesTokenRead(t *testing.T) {
	service, _, transport := mutationService(t)
	service.Credentials = &existingCredentials{}
	reader := &countingReader{}
	_, err := service.ImportPermanentTokenReader(context.Background(), "work", reader, false)
	if !errors.Is(err, auth.ErrOverwriteConfirmationRequired) {
		t.Fatalf("error=%v", err)
	}
	if reader.calls != 0 || transport.calls != 0 {
		t.Fatalf("preflight touched reader=%d network=%d", reader.calls, transport.calls)
	}
}

func TestTranslateErrorPreservesStoreInvalidPlanUsage(t *testing.T) {
	service, credentials, transport := mutationService(t)
	record, err := service.PrepareMutation(context.Background(), PrepareInput{
		Profile: "work", Kind: intent.KindIssueUpdate, Project: writepolicy.Project{ID: "0-1", Key: "APP"},
		SchemaSHA256: strings.Repeat("a", 64),
		RequestJSON:  []byte(`{"issue_id":"APP-1","set":{"summary":"new"}}`),
		ExpectedJSON: []byte(`{"issue_id":"APP-1","issue_state_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","touched_fields_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	plan := record.Plan
	plan.Kind = intent.Kind("UNTRUSTED_SENTINEL")
	plan.Policy.AuthorizedCapability = ""
	if sourceErr := plan.Validate(); sourceErr == nil || !strings.Contains(sourceErr.Error(), "UNTRUSTED_SENTINEL") {
		t.Fatalf("invalid source plan did not exercise the sentinel-bearing validation path: %v", sourceErr)
	}
	_, storeErr := service.Journal.Create(context.Background(), plan)
	if !errors.Is(storeErr, intent.ErrInvalidPlan) {
		t.Fatalf("Store invalid plan error = %v", storeErr)
	}
	translated := TranslateError(storeErr, "work")
	var typed *errx.Error
	if !errors.As(translated, &typed) || typed.Code != errx.CodeUsage || typed.Reason != "USAGE" ||
		typed.Message != "input failed strict validation" || typed.Hint != "check the flags against --help" {
		t.Fatalf("translated Store error = %#v", translated)
	}
	if strings.Contains(translated.Error(), "UNTRUSTED_SENTINEL") ||
		strings.Contains(typed.Message, "UNTRUSTED_SENTINEL") || strings.Contains(typed.Hint, "UNTRUSTED_SENTINEL") {
		t.Fatalf("translated Store error exposed plan-controlled text: %v", translated)
	}
	if credentials.calls != 0 || transport.calls != 0 {
		t.Fatalf("offline invalid plan touched credentials=%d network=%d", credentials.calls, transport.calls)
	}
}

func TestTranslateErrorClassifiesIncompleteLogout(t *testing.T) {
	for _, cause := range []error{errors.New("registry unavailable"), context.Canceled, profile.ErrNotFound, profile.ErrCorruptRegistry, auth.ErrInteractionNotAllowed} {
		t.Run(cause.Error(), func(t *testing.T) {
			translated := TranslateError(errors.Join(auth.ErrLogoutIncomplete, cause), "work")
			var typed *errx.Error
			if !errors.As(translated, &typed) || typed.Code != errx.CodeConflict || typed.Reason != "LOGOUT_INCOMPLETE" {
				t.Fatalf("translated error = %#v", translated)
			}
			if !strings.Contains(typed.Hint, "inspect") {
				t.Fatalf("hint = %q", typed.Hint)
			}
		})
	}
}

type emptyCredentials struct{}

func (*emptyCredentials) Exists(context.Context, string) (bool, error) { return false, nil }
func (*emptyCredentials) Load(context.Context, string) (auth.Credential, error) {
	return auth.Credential{}, auth.ErrNotFound
}
func (*emptyCredentials) Save(context.Context, string, auth.Credential) error { return nil }
func (*emptyCredentials) Delete(context.Context, string) error                { return nil }
func (*emptyCredentials) MigrateKeychain(context.Context, string) error       { return nil }
