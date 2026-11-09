package application

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/auth"
	"github.com/abigotado/youtrack-agent-cli/internal/endpoint"
	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/oauth"
	"github.com/abigotado/youtrack-agent-cli/internal/output"
	"github.com/abigotado/youtrack-agent-cli/internal/profile"
)

type oauthCredentialStore struct {
	value     auth.Credential
	exists    bool
	saveCalls int
	saveErr   error
}

func (s *oauthCredentialStore) Exists(context.Context, string) (bool, error) { return s.exists, nil }
func (s *oauthCredentialStore) Load(context.Context, string) (auth.Credential, error) {
	if !s.exists {
		return auth.Credential{}, auth.ErrNotFound
	}
	return s.value, nil
}
func (s *oauthCredentialStore) Save(_ context.Context, _ string, value auth.Credential) error {
	s.saveCalls++
	if s.saveErr != nil {
		return s.saveErr
	}
	s.value = value
	s.exists = true
	return nil
}
func (s *oauthCredentialStore) Delete(context.Context, string) error {
	s.exists = false
	return nil
}
func (*oauthCredentialStore) MigrateKeychain(context.Context, string) error { return nil }

type callbackBrowser struct{}

func (callbackBrowser) Open(ctx context.Context, authorizationURL string) error {
	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		return err
	}
	callbackURL := parsed.Query().Get("redirect_uri") + "?code=authorization-code&state=" + url.QueryEscape(parsed.Query().Get("state"))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, callbackURL, nil)
	if err != nil {
		return err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != http.StatusOK {
		return errors.New("OAuth callback was rejected")
	}
	return nil
}

type oauthFlowTransport struct {
	scopeField string
	requests   int
}

func (transport *oauthFlowTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.requests++
	switch request.URL.Host {
	case "hub.example.test":
		body := `{"access_token":"access","refresh_token":"refresh","token_type":"Bearer","expires_in":3600` + transport.scopeField + `}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	case "tracker.example.test":
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"id":"1-42","login":"alice"}`)), Header: make(http.Header)}, nil
	default:
		return nil, errors.New("unexpected OAuth test origin")
	}
}

func oauthApplicationProfile(t *testing.T, authenticated bool) profile.Profile {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	serviceURL := "https://tracker.example.test"
	mcpURL, err := endpoint.CanonicalMCPURL(serviceURL)
	if err != nil {
		t.Fatal(err)
	}
	value := profile.Profile{
		Name: "work", ServiceURL: serviceURL, RESTBaseURL: serviceURL + endpoint.RESTPath, MCPURL: mcpURL,
		OAuth: profile.OAuthConfig{
			IssuerURL: "https://hub.example.test", AuthorizationURL: "https://hub.example.test" + endpoint.OAuthAuthorizationPath,
			TokenURL: "https://hub.example.test" + endpoint.OAuthTokenPath, ClientID: "client", Scopes: []string{"alpha", "beta"},
			RedirectURI: "http://" + address + "/oauth/callback",
		},
		ExpectedAccountID: "1-42", ExpectedLogin: "alice", Capabilities: []profile.Capability{profile.CapabilityRead},
		Executor: profile.ExecutorRESTBestEffort, Assurance: profile.AssuranceBestEffort,
	}
	if authenticated {
		value, err = value.WithNewCredentialGeneration()
		if err != nil {
			t.Fatal(err)
		}
	}
	return value
}

func oauthApplicationService(t *testing.T, selected profile.Profile, store *oauthCredentialStore, transport http.RoundTripper) *Service {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	registry := profile.NewRegistry(filepath.Join(directory, "profiles.json"))
	if err := registry.Add(t.Context(), selected); err != nil {
		t.Fatal(err)
	}
	return &Service{Profiles: registry, Credentials: store, HTTP: transport}
}

func TestCallbackIgnoresInvalidRequestBeforeValidCallback(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	issuer := "https://hub.example.test"
	state := strings.Repeat("s", 43)
	config := oauth.Config{
		IssuerURL: issuer, AuthorizationURL: issuer + endpoint.OAuthAuthorizationPath,
		TokenURL: issuer + endpoint.OAuthTokenPath, ClientID: "client", Scopes: []string{"YouTrack"},
		RedirectURI: "http://" + address + "/oauth/callback",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	callback, err := startCallback(ctx, config, state)
	if err != nil {
		t.Fatal(err)
	}
	defer callback.Close(ctx)
	for _, query := range []string{"?code=bad&state=wrong", "?error=access_denied&state=wrong"} {
		response, getErr := http.Get(config.RedirectURI + query)
		if getErr != nil {
			t.Fatal(getErr)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid callback status=%d", response.StatusCode)
		}
	}
	response, err := http.Get(config.RedirectURI + "?code=good&state=" + state)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	code, err := callback.Wait(ctx)
	if err != nil || code != "good" {
		t.Fatalf("code=%q err=%v", code, err)
	}
}

func TestLoginOAuthPersistsExactGrantedScopeSubset(t *testing.T) {
	selected := oauthApplicationProfile(t, false)
	store := &oauthCredentialStore{}
	transport := &oauthFlowTransport{scopeField: `,"scope":"beta"`}
	service := oauthApplicationService(t, selected, store, transport)

	loggedIn, err := service.LoginOAuth(t.Context(), selected.Name, false, callbackBrowser{})
	if err != nil {
		t.Fatal(err)
	}
	if store.saveCalls != 1 || !store.exists || !slices.Equal(store.value.OAuthScopes, []string{"beta"}) {
		t.Fatalf("stored credential scopes=%v saves=%d", store.value.OAuthScopes, store.saveCalls)
	}
	if loggedIn.CredentialGeneration == "" || auth.ValidateCredentialBinding(store.value, loggedIn) != nil {
		t.Fatalf("login binding is invalid: profile=%#v credential=%#v", loggedIn, store.value)
	}
}

func TestRefreshPersistsScopeWithoutReExpansion(t *testing.T) {
	for _, test := range []struct {
		name          string
		initialScopes []string
		wantScopes    []string
	}{
		{name: "modern subset", initialScopes: []string{"beta"}, wantScopes: []string{"beta"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			selected := oauthApplicationProfile(t, true)
			bound, err := auth.BindCredential(auth.Credential{
				Kind: auth.CredentialOAuth, AccessToken: "old-access", RefreshToken: "old-refresh", TokenType: "Bearer",
				AccessTokenExpiresAt: time.Unix(1_700_000_000, 0).UTC(), OAuthScopes: []string{"beta"},
			}, selected)
			if err != nil {
				t.Fatal(err)
			}
			bound.OAuthScopes = append([]string(nil), test.initialScopes...)
			store := &oauthCredentialStore{value: bound, exists: true}
			transport := &oauthFlowTransport{}
			service := oauthApplicationService(t, selected, store, transport)
			service.Now = func() time.Time { return time.Unix(1_700_000_100, 0).UTC() }

			status, err := service.AuthStatus(t.Context(), selected.Name, true)
			if err != nil || status.State != "valid" {
				t.Fatalf("status=%#v err=%v", status, err)
			}
			if store.saveCalls != 1 || !slices.Equal(store.value.OAuthScopes, test.wantScopes) {
				t.Fatalf("persisted scopes=%v saves=%d", store.value.OAuthScopes, store.saveCalls)
			}
		})
	}
}

func TestFailedRefreshKeepsStoredCredentialAndRequiresLogin(t *testing.T) {
	selected := oauthApplicationProfile(t, true)
	bound, err := auth.BindCredential(auth.Credential{
		Kind: auth.CredentialOAuth, AccessToken: "old-access", RefreshToken: "old-refresh", TokenType: "Bearer",
		AccessTokenExpiresAt: time.Unix(1_700_000_000, 0).UTC(), OAuthScopes: []string{"beta"},
	}, selected)
	if err != nil {
		t.Fatal(err)
	}
	store := &oauthCredentialStore{value: bound, exists: true}
	requests := 0
	transport := oauthDiagnosticTransport(func(*http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(strings.NewReader("server-secret-sentinel")), Header: make(http.Header)}, nil
	})
	service := oauthApplicationService(t, selected, store, transport)
	service.Now = func() time.Time { return time.Unix(1_700_000_100, 0).UTC() }

	_, err = service.AuthStatus(t.Context(), selected.Name, true)
	var typed *errx.Error
	if !errors.As(err, &typed) || typed.Code != errx.CodeAuth || typed.Reason != "OAUTH_TOKEN_EXCHANGE_FAILED" || typed.RetryAfter != 0 || typed.Message != "OAuth refresh failed" {
		t.Fatalf("refresh recovery=%#v, want classified failed request", typed)
	}
	if requests != 1 || store.saveCalls != 0 || !reflect.DeepEqual(store.value, bound) {
		t.Fatalf("refresh requests=%d saves=%d credential changed=%t", requests, store.saveCalls, !reflect.DeepEqual(store.value, bound))
	}
	var stdout bytes.Buffer
	if exit := (&output.Writer{Format: output.FormatJSON, Out: &stdout, Err: io.Discard}).Failure(TranslateError(err, selected.Name)); exit != errx.CodeAuth {
		t.Fatalf("rendered refresh exit=%d, want auth/5", exit)
	}
	var envelope output.Envelope
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error == nil || envelope.Error.Code != "OAUTH_TOKEN_EXCHANGE_FAILED" || envelope.Error.RetryAfter != "" || bytes.Contains(stdout.Bytes(), []byte(`"retry_after"`)) {
		t.Fatalf("failed refresh envelope=%+v", envelope)
	}
	assertRefreshRecoveryHint(t, envelope.Hint)
	if strings.Contains(stdout.String(), "server-secret-sentinel") {
		t.Fatalf("failed refresh envelope leaked untrusted response: %q", stdout.String())
	}
}

func TestCanceledInflightServiceRefreshRequiresOperatorRecovery(t *testing.T) {
	selected := oauthApplicationProfile(t, true)
	bound, err := auth.BindCredential(auth.Credential{
		Kind: auth.CredentialOAuth, AccessToken: "old-access", RefreshToken: "old-refresh", TokenType: "Bearer",
		AccessTokenExpiresAt: time.Unix(1_700_000_000, 0).UTC(), OAuthScopes: []string{"beta"},
	}, selected)
	if err != nil {
		t.Fatal(err)
	}
	store := &oauthCredentialStore{value: bound, exists: true}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	requests := 0
	transport := oauthDiagnosticTransport(func(*http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: http.StatusOK, Body: oauthCanceledBody{cancel: cancel}, Header: make(http.Header)}, nil
	})
	service := oauthApplicationService(t, selected, store, transport)
	service.Now = func() time.Time { return time.Unix(1_700_000_100, 0).UTC() }

	_, err = service.AuthStatus(ctx, selected.Name, true)
	if requests != 1 || store.saveCalls != 0 || !reflect.DeepEqual(store.value, bound) {
		t.Fatalf("requests=%d saves=%d credential unchanged=%t", requests, store.saveCalls, reflect.DeepEqual(store.value, bound))
	}
	var stdout bytes.Buffer
	if exit := (&output.Writer{Format: output.FormatJSON, Out: &stdout, Err: io.Discard}).Failure(TranslateError(err, selected.Name)); exit != errx.CodeAuth {
		t.Fatalf("in-flight refresh exit=%d, want auth/5", exit)
	}
	var envelope output.Envelope
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error == nil || envelope.Error.Code != "OAUTH_TOKEN_EXCHANGE_FAILED" || envelope.Error.RetryAfter != "" || bytes.Contains(stdout.Bytes(), []byte(`"retry_after"`)) {
		t.Fatalf("in-flight refresh envelope=%+v", envelope)
	}
	assertRefreshRecoveryHint(t, envelope.Hint)
}

func TestPreCanceledServiceRefreshDoesNotAttemptTokenRequest(t *testing.T) {
	for _, test := range []struct {
		name string
		make func(context.Context) (context.Context, context.CancelFunc)
		code string
	}{
		{name: "canceled", make: context.WithCancel, code: "CANCELED"},
		{name: "deadline", make: func(parent context.Context) (context.Context, context.CancelFunc) {
			return context.WithDeadline(parent, time.Now().Add(-time.Second))
		}, code: "TIMEOUT"},
	} {
		t.Run(test.name, func(t *testing.T) {
			selected := oauthApplicationProfile(t, true)
			bound, err := auth.BindCredential(auth.Credential{
				Kind: auth.CredentialOAuth, AccessToken: "old-access", RefreshToken: "old-refresh", TokenType: "Bearer",
				AccessTokenExpiresAt: time.Unix(1_700_000_000, 0).UTC(), OAuthScopes: []string{"beta"},
			}, selected)
			if err != nil {
				t.Fatal(err)
			}
			store := &oauthCredentialStore{value: bound, exists: true}
			requests := 0
			service := oauthApplicationService(t, selected, store, oauthDiagnosticTransport(func(*http.Request) (*http.Response, error) {
				requests++
				return nil, errors.New("unexpected token request")
			}))
			service.Now = func() time.Time { return time.Unix(1_700_000_100, 0).UTC() }
			ctx, cancel := test.make(t.Context())
			cancel()
			_, err = service.AuthStatus(ctx, selected.Name, true)
			if requests != 0 || store.saveCalls != 0 || !reflect.DeepEqual(store.value, bound) {
				t.Fatalf("requests=%d saves=%d credential unchanged=%t", requests, store.saveCalls, reflect.DeepEqual(store.value, bound))
			}
			var stdout bytes.Buffer
			if exit := (&output.Writer{Format: output.FormatJSON, Out: &stdout, Err: io.Discard}).Failure(TranslateError(err, selected.Name)); exit != errx.CodeRetryable {
				t.Fatalf("pre-attempt exit=%d, want retryable/6", exit)
			}
			var envelope output.Envelope
			if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Error == nil || envelope.Error.Code != test.code {
				t.Fatalf("pre-attempt envelope=%+v, want %s", envelope, test.code)
			}
		})
	}
}

func TestRefreshRejectsUnsafeTokenBeforePersistenceAndKeepsOldCredential(t *testing.T) {
	selected := oauthApplicationProfile(t, true)
	bound, err := auth.BindCredential(auth.Credential{
		Kind: auth.CredentialOAuth, AccessToken: "old-access", RefreshToken: "old-refresh", TokenType: "Bearer",
		AccessTokenExpiresAt: time.Unix(1_700_000_000, 0).UTC(), OAuthScopes: []string{"beta"},
	}, selected)
	if err != nil {
		t.Fatal(err)
	}
	store := &oauthCredentialStore{value: bound, exists: true}
	requests := 0
	transport := oauthDiagnosticTransport(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host != "hub.example.test" || request.Method != http.MethodPost {
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.Host)
		}
		requests++
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"access_token":"new-access-private-sentinel\nline","refresh_token":"new-refresh-private-sentinel","token_type":"Bearer","expires_in":3600}`)),
			Header:     make(http.Header),
		}, nil
	})
	service := oauthApplicationService(t, selected, store, transport)
	service.Now = func() time.Time { return time.Unix(1_700_000_100, 0).UTC() }
	var logs bytes.Buffer
	service.Logger = slog.New(slog.NewTextHandler(&logs, nil))

	_, err = service.AuthStatus(t.Context(), selected.Name, true)
	var typed *errx.Error
	if !errors.As(err, &typed) || typed.Code != errx.CodeAuth || typed.Reason != "OAUTH_TOKEN_EXCHANGE_FAILED" || typed.RetryAfter != 0 {
		t.Fatalf("pre-save recovery=%#v, want non-retryable auth/5", typed)
	}
	if typed.Message != "OAuth refresh failed" {
		t.Fatalf("parser rejection misstates failure stage: %q", typed.Message)
	}
	if requests != 1 || store.saveCalls != 0 || !store.exists || !reflect.DeepEqual(store.value, bound) {
		t.Fatalf("requests=%d saves=%d credential unchanged=%t", requests, store.saveCalls, reflect.DeepEqual(store.value, bound))
	}
	var stdout bytes.Buffer
	if exit := (&output.Writer{Format: output.FormatJSON, Out: &stdout, Err: io.Discard}).Failure(TranslateError(err, selected.Name)); exit != errx.CodeAuth {
		t.Fatalf("rendered exit=%d, want auth/5", exit)
	}
	var envelope output.Envelope
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error == nil || envelope.Error.Code != "OAUTH_TOKEN_EXCHANGE_FAILED" || envelope.Error.Message != typed.Message || envelope.Error.RetryAfter != "" || bytes.Contains(stdout.Bytes(), []byte(`"retry_after"`)) {
		t.Fatalf("pre-save failure envelope=%+v", envelope)
	}
	assertRefreshRecoveryHint(t, envelope.Hint)
	if strings.Contains(logs.String(), "binding rejected before persistence") {
		t.Fatalf("token parser rejection incorrectly claimed a binding failure: %q", logs.String())
	}
	for _, secret := range []string{"new-access-private-sentinel", "new-refresh-private-sentinel", "old-access", "old-refresh"} {
		if strings.Contains(stdout.String(), secret) || strings.Contains(logs.String(), secret) {
			t.Fatalf("pre-save error or log leaked token %q", secret)
		}
	}
}

func TestRefreshPreSaveBindingFailureIsFixedAndRedacted(t *testing.T) {
	const secret = "credential-private-sentinel"
	for _, test := range []struct {
		name     string
		cause    error
		category string
		action   string
	}{
		{name: "invalid token", cause: fmt.Errorf("%w: %s", auth.ErrInvalidToken, secret), category: "invalid_credential", action: "inspect local token validation and OAuth client configuration"},
		{name: "binding mismatch", cause: fmt.Errorf("%w: %s", auth.ErrCredentialBindingMismatch, secret), category: "binding_mismatch", action: "inspect and repair local profile/credential binding"},
		{name: "other", cause: errors.New(secret), category: "other", action: "inspect local post-refresh binding validation"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var logs bytes.Buffer
			failure := refreshPreSaveBindingFailure(test.cause, slog.New(slog.NewTextHandler(&logs, nil)))
			if failure.Code != errx.CodeAuth || failure.Reason != "OAUTH_TOKEN_EXCHANGE_FAILED" || failure.RetryAfter != 0 ||
				!strings.Contains(failure.Message, "before persistence") || strings.Contains(failure.Message, "uncertain") {
				t.Fatalf("pre-save binding failure=%#v, want fixed auth/5 before-persistence diagnosis", failure)
			}
			assertRefreshRecoveryHint(t, failure.Hint)
			if !strings.Contains(failure.Hint, test.action) {
				t.Fatalf("pre-save recovery %q missing safe action %q", failure.Hint, test.action)
			}
			if !strings.Contains(logs.String(), "binding rejected before persistence") || !strings.Contains(logs.String(), test.category) {
				t.Fatalf("pre-save log=%q, want fixed category %q", logs.String(), test.category)
			}
			var stdout bytes.Buffer
			if exit := (&output.Writer{Format: output.FormatJSON, Out: &stdout, Err: io.Discard}).Failure(failure); exit != errx.CodeAuth {
				t.Fatalf("pre-save binding exit=%d, want auth/5", exit)
			}
			var envelope output.Envelope
			if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Error == nil || envelope.Error.Code != "OAUTH_TOKEN_EXCHANGE_FAILED" || envelope.Error.RetryAfter != "" || !strings.Contains(envelope.Hint, test.action) || bytes.Contains(stdout.Bytes(), []byte(`"retry_after"`)) {
				t.Fatalf("pre-save binding envelope=%+v, want safe action %q", envelope, test.action)
			}
			if strings.Contains(logs.String(), secret) || strings.Contains(stdout.String(), secret) || strings.Contains(failure.Error(), secret) {
				t.Fatalf("pre-save binding leaked private cause: log=%q output=%q", logs.String(), stdout.String())
			}
		})
	}
}

func TestRotatedRefreshSaveFailureRequiresOperatorRecovery(t *testing.T) {
	const private = "keychain-private-sentinel"
	for _, test := range []struct {
		name     string
		saveErr  error
		category string
		action   string
	}{
		{name: "interaction blocked", saveErr: fmt.Errorf("%s: %w", private, auth.ErrInteractionNotAllowed), category: "interaction_blocked", action: "restore interactive Keychain access"},
		{name: "migration required", saveErr: fmt.Errorf("%s: %w", private, auth.ErrKeychainMigrationRequired), category: "migration_required", action: "inspect Keychain ACL and perform operator-approved migration if required"},
		{name: "migration canceled", saveErr: fmt.Errorf("%s: %w", private, auth.ErrKeychainMigrationCanceled), category: "user_canceled", action: "resolve canceled Keychain authorization"},
		{name: "context canceled", saveErr: fmt.Errorf("%s: %w", private, context.Canceled), category: "context_canceled", action: "inspect interrupted credential-store save"},
		{name: "deadline exceeded", saveErr: fmt.Errorf("%s: %w", private, context.DeadlineExceeded), category: "deadline_exceeded", action: "inspect timed-out credential-store save"},
		{name: "keychain status", saveErr: fmt.Errorf("%s: %w", private, &auth.StatusError{Operation: "private-operation-sentinel", Status: -25293}), category: "keychain_status_failure", action: "inspect Keychain availability and permissions"},
		{name: "other", saveErr: errors.New(private), category: "other", action: "inspect local credential-store save failure"},
	} {
		t.Run(test.name, func(t *testing.T) {
			selected := oauthApplicationProfile(t, true)
			bound, err := auth.BindCredential(auth.Credential{
				Kind: auth.CredentialOAuth, AccessToken: "old-access", RefreshToken: "old-refresh", TokenType: "Bearer",
				AccessTokenExpiresAt: time.Unix(1_700_000_000, 0).UTC(), OAuthScopes: []string{"beta"},
			}, selected)
			if err != nil {
				t.Fatal(err)
			}
			store := &oauthCredentialStore{value: bound, exists: true, saveErr: test.saveErr}
			requests := 0
			transport := oauthDiagnosticTransport(func(request *http.Request) (*http.Response, error) {
				if request.URL.Host != "hub.example.test" || request.Method != http.MethodPost {
					t.Fatalf("unexpected request: %s %s", request.Method, request.URL.Host)
				}
				requests++
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"access_token":"new-access-private-sentinel","refresh_token":"new-refresh-private-sentinel","token_type":"Bearer","expires_in":3600}`)),
					Header:     make(http.Header),
				}, nil
			})
			service := oauthApplicationService(t, selected, store, transport)
			service.Now = func() time.Time { return time.Unix(1_700_000_100, 0).UTC() }
			var logs bytes.Buffer
			service.Logger = slog.New(slog.NewTextHandler(&logs, nil))

			_, err = service.AuthStatus(t.Context(), selected.Name, true)
			if err == nil {
				t.Fatal("rotated refresh unexpectedly succeeded after credential persistence failed")
			}
			if requests != 1 || store.saveCalls != 1 || !store.exists || !reflect.DeepEqual(store.value, bound) {
				t.Fatalf("requests=%d saves=%d credential unchanged=%t", requests, store.saveCalls, reflect.DeepEqual(store.value, bound))
			}
			translated := TranslateError(err, selected.Name)
			var typed *errx.Error
			if !errors.As(translated, &typed) || typed.Code != errx.CodeAuth || typed.Reason != "OAUTH_TOKEN_EXCHANGE_FAILED" || typed.RetryAfter != 0 {
				t.Fatalf("recovery=%#v, want non-retryable legacy OAuth auth error", typed)
			}
			if !strings.Contains(typed.Message, "persistence is uncertain") {
				t.Fatalf("post-save failure must disclose persistence uncertainty: %q", typed.Message)
			}
			assertRefreshRecoveryHint(t, typed.Hint)
			if !strings.Contains(typed.Hint, test.action) {
				t.Fatalf("persistence hint %q missing safe action %q", typed.Hint, test.action)
			}
			if !strings.Contains(logs.String(), "OAuth refresh credential persistence is uncertain") || !strings.Contains(logs.String(), "category="+test.category) {
				t.Fatalf("refresh persistence log=%q, want fixed category %q", logs.String(), test.category)
			}
			var stdout bytes.Buffer
			if exit := (&output.Writer{Format: output.FormatJSON, Out: &stdout, Err: io.Discard}).Failure(translated); exit != errx.CodeAuth {
				t.Fatalf("rendered exit=%d, want auth/5", exit)
			}
			var envelope output.Envelope
			if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Error == nil || envelope.Error.Code != "OAUTH_TOKEN_EXCHANGE_FAILED" || envelope.Error.RetryAfter != "" || bytes.Contains(stdout.Bytes(), []byte(`"retry_after"`)) {
				t.Fatalf("unsafe OAuth failure envelope: %+v", envelope)
			}
			assertRefreshRecoveryHint(t, envelope.Hint)
			if !strings.Contains(envelope.Hint, test.action) {
				t.Fatalf("persistence envelope hint %q missing safe action %q", envelope.Hint, test.action)
			}
			for _, secret := range []string{private, "private-operation-sentinel", "-25293", "new-access-private-sentinel", "new-refresh-private-sentinel", "old-access", "old-refresh", selected.Name} {
				if strings.Contains(stdout.String(), secret) || strings.Contains(logs.String(), secret) {
					t.Fatalf("OAuth failure envelope or log leaked private data %q", secret)
				}
			}
			for _, key := range []string{"cause=", "status=", "profile=", "token="} {
				if strings.Contains(logs.String(), key) {
					t.Fatalf("OAuth persistence log contains unsafe attribute %q: %q", key, logs.String())
				}
			}
		})
	}
}

func TestLoginOAuthClassifiesRejectedTokenExchange(t *testing.T) {
	selected := oauthApplicationProfile(t, false)
	store := &oauthCredentialStore{}
	requests := 0
	transport := oauthDiagnosticTransport(func(*http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(strings.NewReader("server-secret-sentinel")), Header: make(http.Header)}, nil
	})
	service := oauthApplicationService(t, selected, store, transport)
	_, err := service.LoginOAuth(t.Context(), selected.Name, false, callbackBrowser{})
	if !errors.Is(err, oauth.ErrTokenExchange) {
		t.Fatalf("login error=%v, want classified exchange failure", err)
	}
	translated := TranslateError(err, selected.Name)
	var contract *errx.Error
	if !errors.As(translated, &contract) || contract.Reason != "OAUTH_TOKEN_REQUEST_REJECTED" || contract.Code != errx.CodeAuth {
		t.Fatalf("login recovery=%v, want rejected token request", translated)
	}
	if requests != 1 || store.saveCalls != 0 || store.exists {
		t.Fatalf("token requests=%d credential saves=%d exists=%t", requests, store.saveCalls, store.exists)
	}
}

func TestFailedReloginPreservesExistingCredential(t *testing.T) {
	selected := oauthApplicationProfile(t, true)
	bound, err := auth.BindCredential(auth.Credential{
		Kind: auth.CredentialOAuth, AccessToken: "old-access", RefreshToken: "old-refresh", TokenType: "Bearer",
		AccessTokenExpiresAt: time.Unix(1_700_000_000, 0).UTC(), OAuthScopes: []string{"beta"},
	}, selected)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		status int
		body   string
		code   string
	}{
		{name: "rejected request", status: http.StatusBadRequest, body: "server-secret-sentinel", code: "OAUTH_TOKEN_REQUEST_REJECTED"},
		{name: "invalid response", status: http.StatusOK, body: `{"access_token":"new-private-sentinel\nline","refresh_token":"new-refresh","token_type":"Bearer","expires_in":3600}`, code: "OAUTH_TOKEN_RESPONSE_INVALID"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &oauthCredentialStore{value: bound, exists: true}
			requests := 0
			transport := oauthDiagnosticTransport(func(*http.Request) (*http.Response, error) {
				requests++
				return &http.Response{StatusCode: test.status, Body: io.NopCloser(strings.NewReader(test.body)), Header: make(http.Header)}, nil
			})
			service := oauthApplicationService(t, selected, store, transport)
			_, err := service.LoginOAuth(t.Context(), selected.Name, true, callbackBrowser{})
			var typed *errx.Error
			if !errors.As(TranslateError(err, selected.Name), &typed) || typed.Reason != test.code || typed.Code != errx.CodeAuth {
				t.Fatalf("re-login recovery=%v, want %s auth/5", err, test.code)
			}
			if requests != 1 || store.saveCalls != 0 || !store.exists || !reflect.DeepEqual(store.value, bound) {
				t.Fatalf("token requests=%d saves=%d exists=%t credential unchanged=%t", requests, store.saveCalls, store.exists, reflect.DeepEqual(store.value, bound))
			}
		})
	}
}

func TestLoginOAuthRejectsUnsafeTokenWithoutAccountReadOrPersistence(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
	}{
		{
			name: "access token with escaped LF",
			body: `{"access_token":"access-private-sentinel\nline","refresh_token":"refresh","token_type":"Bearer","expires_in":3600}`,
		},
		{
			name: "refresh token with escaped NUL",
			body: `{"access_token":"access","refresh_token":"refresh-private-sentinel\u0000end","token_type":"Bearer","expires_in":3600}`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			selected := oauthApplicationProfile(t, false)
			store := &oauthCredentialStore{}
			tokenRequests, accountRequests := 0, 0
			transport := oauthDiagnosticTransport(func(request *http.Request) (*http.Response, error) {
				switch request.URL.Host {
				case "hub.example.test":
					tokenRequests++
					if request.Method != http.MethodPost {
						t.Fatalf("token method=%s, want POST", request.Method)
					}
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(test.body)), Header: make(http.Header)}, nil
				case "tracker.example.test":
					accountRequests++
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"id":"1-42","login":"alice"}`)), Header: make(http.Header)}, nil
				default:
					t.Fatalf("unexpected OAuth origin: %s", request.URL.Host)
					return nil, errors.New("unexpected OAuth origin")
				}
			})
			service := oauthApplicationService(t, selected, store, transport)
			_, err := service.LoginOAuth(t.Context(), selected.Name, false, callbackBrowser{})
			translated := TranslateError(err, selected.Name)
			var typed *errx.Error
			if !errors.As(translated, &typed) || typed.Code != errx.CodeAuth || typed.Reason != "OAUTH_TOKEN_RESPONSE_INVALID" || typed.RetryAfter != 0 {
				t.Fatalf("login failure=%#v, want invalid token response auth/5", typed)
			}
			if tokenRequests != 1 || accountRequests != 0 || store.saveCalls != 0 || store.exists {
				t.Fatalf("token requests=%d account reads=%d credential saves=%d exists=%t", tokenRequests, accountRequests, store.saveCalls, store.exists)
			}
			var stdout bytes.Buffer
			if exit := (&output.Writer{Format: output.FormatJSON, Out: &stdout, Err: io.Discard}).Failure(translated); exit != errx.CodeAuth {
				t.Fatalf("invalid login response exit=%d, want auth/5", exit)
			}
			var envelope output.Envelope
			if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Error == nil || envelope.Error.Code != "OAUTH_TOKEN_RESPONSE_INVALID" || envelope.Error.RetryAfter != "" {
				t.Fatalf("invalid login response envelope=%+v", envelope)
			}
			for _, secret := range []string{"access-private-sentinel", "refresh-private-sentinel"} {
				if strings.Contains(stdout.String(), secret) || strings.Contains(err.Error(), secret) {
					t.Fatalf("invalid login response leaked token %q", secret)
				}
			}
		})
	}
}
