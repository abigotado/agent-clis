package application

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/endpoint"
	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/oauth"
	"github.com/abigotado/youtrack-agent-cli/internal/oauthrecovery"
	"github.com/abigotado/youtrack-agent-cli/internal/output"
)

type oauthDiagnosticTransport func(*http.Request) (*http.Response, error)

func (transport oauthDiagnosticTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

type oauthCanceledBody struct{ cancel context.CancelFunc }

func (body oauthCanceledBody) Read([]byte) (int, error) {
	body.cancel()
	return 0, context.Canceled
}
func (oauthCanceledBody) Close() error { return nil }

func TestOAuthTokenDiagnosticsKeepV1EnvelopeAndRecoveryExit(t *testing.T) {
	const sentinel = "server-secret-sentinel"
	tests := []struct {
		name      string
		status    int
		body      string
		location  string
		transport error
		code      string
		exit      errx.Code
	}{
		{name: "transport", transport: errors.New("transport-secret-sentinel"), code: "OAUTH_TOKEN_ENDPOINT_UNAVAILABLE", exit: errx.CodeRetryable},
		{name: "TLS trust failure", transport: x509.UnknownAuthorityError{}, code: "OAUTH_TOKEN_TRANSPORT_REJECTED", exit: errx.CodeAuth},
		{name: "request timeout", status: http.StatusRequestTimeout, body: sentinel, code: "OAUTH_TOKEN_ENDPOINT_UNAVAILABLE", exit: errx.CodeRetryable},
		{name: "rate limited", status: http.StatusTooManyRequests, body: sentinel, code: "OAUTH_TOKEN_ENDPOINT_UNAVAILABLE", exit: errx.CodeRetryable},
		{name: "server error", status: http.StatusInternalServerError, body: sentinel, code: "OAUTH_TOKEN_ENDPOINT_UNAVAILABLE", exit: errx.CodeRetryable},
		{name: "service unavailable", status: http.StatusServiceUnavailable, body: sentinel, code: "OAUTH_TOKEN_ENDPOINT_UNAVAILABLE", exit: errx.CodeRetryable},
		{name: "rejected", status: http.StatusBadRequest, body: sentinel, code: "OAUTH_TOKEN_REQUEST_REJECTED", exit: errx.CodeAuth},
		{name: "invalid response", status: http.StatusOK, body: `{"access_token":"` + sentinel + `"`, code: "OAUTH_TOKEN_RESPONSE_INVALID", exit: errx.CodeAuth},
		{name: "redirect refused", status: http.StatusFound, body: sentinel, location: "https://other.example.test/secret-sentinel", code: "OAUTH_TOKEN_REDIRECT_REFUSED", exit: errx.CodeAuth},
		{name: "malformed redirect refused", status: http.StatusFound, body: sentinel, location: "http://[secret-sentinel", code: "OAUTH_TOKEN_REDIRECT_REFUSED", exit: errx.CodeAuth},
		{name: "redirect without location refused", status: http.StatusFound, body: sentinel, code: "OAUTH_TOKEN_REDIRECT_REFUSED", exit: errx.CodeAuth},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issuer := "https://hub.example.test"
			config := oauth.Config{
				IssuerURL: issuer, AuthorizationURL: issuer + endpoint.OAuthAuthorizationPath,
				TokenURL: issuer + endpoint.OAuthTokenPath, ClientID: "client", Scopes: []string{"YouTrack"},
				RedirectURI: "http://127.0.0.1:18987/oauth/callback",
			}
			calls := 0
			transport := oauthDiagnosticTransport(func(*http.Request) (*http.Response, error) {
				calls++
				if test.transport != nil {
					return nil, test.transport
				}
				header := make(http.Header)
				header.Set("X-Secret", sentinel)
				if test.status == http.StatusServiceUnavailable || test.status == http.StatusTooManyRequests {
					header.Set("Retry-After", "120")
				}
				if test.location != "" {
					header.Set("Location", test.location)
				}
				return &http.Response{StatusCode: test.status, Body: io.NopCloser(strings.NewReader(test.body)), Header: header}, nil
			})
			client, err := oauth.NewClient(config, transport)
			if err != nil {
				t.Fatal(err)
			}
			session, err := oauth.NewSession(strings.NewReader(strings.Repeat("v", 64)))
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Exchange(t.Context(), "authorization-code-secret-sentinel", session.Verifier)
			if !errors.Is(err, oauth.ErrTokenExchange) {
				t.Fatalf("OAuth error=%v", err)
			}
			translated := TranslateError(err, "work")
			if errx.ExitCode(translated) != test.exit {
				t.Fatalf("exit=%d, want %d", errx.ExitCode(translated), test.exit)
			}
			var stdout, stderr bytes.Buffer
			writer := &output.Writer{Format: output.FormatJSON, Out: &stdout, Err: &stderr}
			if exit := writer.Failure(translated); exit != test.exit {
				t.Fatalf("rendered exit=%d, want %d", exit, test.exit)
			}
			if calls != 1 || stderr.Len() != 0 || !bytes.HasSuffix(stdout.Bytes(), []byte("\n")) {
				t.Fatalf("requests=%d stderr=%q stdout=%q", calls, stderr.String(), stdout.String())
			}
			var envelope output.Envelope
			if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.OK || envelope.V != 1 || envelope.Error == nil || envelope.Error.Code != test.code || envelope.Error.Message == "" || envelope.Hint == "" {
				t.Fatalf("envelope=%+v", envelope)
			}
			if strings.Contains(envelope.Hint, "--yes") {
				t.Fatalf("machine hint bypasses explicit replacement approval: %q", envelope.Hint)
			}
			if test.code == "OAUTH_TOKEN_ENDPOINT_UNAVAILABLE" && bytes.Contains(stdout.Bytes(), []byte(`"retry_after"`)) {
				t.Fatalf("endpoint-unavailable envelope advertised a replay delay: %q", stdout.String())
			}
			if test.code == "OAUTH_TOKEN_ENDPOINT_UNAVAILABLE" && (!strings.Contains(envelope.Hint, "fresh authorization code") || !strings.Contains(envelope.Hint, "back off")) {
				t.Fatalf("retryable recovery must start a fresh login after backoff: %q", envelope.Hint)
			}
			if test.status != 0 && !strings.Contains(envelope.Error.Message, fmt.Sprintf("HTTP %d", test.status)) {
				t.Fatalf("status missing from safe message: %q", envelope.Error.Message)
			}
			if test.status == 0 && strings.Contains(envelope.Error.Message, "HTTP 0") {
				t.Fatalf("transport failure invented HTTP status: %q", envelope.Error.Message)
			}
			if strings.Contains(stdout.String(), "secret-sentinel") || strings.Contains(stdout.String(), "other.example.test") {
				t.Fatalf("v1 envelope leaked untrusted OAuth content: %q", stdout.String())
			}
		})
	}
}

func TestOAuthInvalidSuccessfulResponsesRequireFreshCodeWithoutReplay(t *testing.T) {
	const sentinel = "server-private-sentinel"
	for _, test := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "malformed HTTP 200", status: http.StatusOK, body: `{"access_token":"` + sentinel + `"`},
		{name: "oversized HTTP 200", status: http.StatusOK, body: strings.Repeat(sentinel, 4097)},
		{name: "unexpected HTTP 201", status: http.StatusCreated, body: sentinel},
		{name: "unexpected HTTP 204", status: http.StatusNoContent, body: sentinel},
	} {
		t.Run(test.name, func(t *testing.T) {
			issuer := "https://hub.example.test"
			calls := 0
			client, err := oauth.NewClient(oauth.Config{
				IssuerURL: issuer, AuthorizationURL: issuer + endpoint.OAuthAuthorizationPath,
				TokenURL: issuer + endpoint.OAuthTokenPath, ClientID: "client", Scopes: []string{"YouTrack"},
				RedirectURI: "http://127.0.0.1:18987/oauth/callback",
			}, oauthDiagnosticTransport(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.Method != http.MethodPost || request.URL.Host != "hub.example.test" {
					t.Fatalf("token request escaped fixed endpoint: %s %s", request.Method, request.URL.Host)
				}
				return &http.Response{
					StatusCode: test.status,
					Body:       io.NopCloser(strings.NewReader(test.body)),
					Header:     http.Header{"Retry-After": {"120"}, "X-Secret": {sentinel}},
				}, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			session, err := oauth.NewSession(strings.NewReader(strings.Repeat("v", 64)))
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Exchange(t.Context(), "authorization-code-private-sentinel", session.Verifier)
			if calls != 1 || !errors.Is(err, oauth.ErrTokenExchange) {
				t.Fatalf("token requests=%d failure=%v, want one invalid-response attempt", calls, err)
			}
			translated := TranslateError(err, "work")
			var stdout bytes.Buffer
			if exit := (&output.Writer{Format: output.FormatJSON, Out: &stdout, Err: io.Discard}).Failure(translated); exit != errx.CodeAuth {
				t.Fatalf("invalid response exit=%d, want auth/5", exit)
			}
			var envelope output.Envelope
			if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.OK || envelope.V != 1 || envelope.Error == nil || envelope.Error.Code != "OAUTH_TOKEN_RESPONSE_INVALID" || envelope.Error.RetryAfter != "" || bytes.Contains(stdout.Bytes(), []byte(`"retry_after"`)) {
				t.Fatalf("invalid response envelope=%+v", envelope)
			}
			if !strings.Contains(envelope.Error.Message, fmt.Sprintf("HTTP %d", test.status)) || !strings.Contains(envelope.Hint, "fresh interactive auth login") || !strings.Contains(envelope.Hint, "new authorization code") || !strings.Contains(envelope.Hint, "do not replay") || strings.Contains(envelope.Hint, "--yes") {
				t.Fatalf("invalid response recovery=%+v, hint=%q", envelope.Error, envelope.Hint)
			}
			if strings.Contains(stdout.String(), sentinel) || strings.Contains(stdout.String(), "authorization-code-private-sentinel") || strings.Contains(err.Error(), sentinel) {
				t.Fatal("invalid response leaked untrusted server content or authorization code")
			}
		})
	}
}

func TestOAuthTokenContractTableMatchesRenderedDiagnostics(t *testing.T) {
	documentation := []struct {
		path      string
		codeField int
		exitField int
	}{
		{path: "../../docs/contract.md", codeField: 1, exitField: 2},
		{path: "../../assets/skills/youtrack-agent/reference/contract.md", codeField: 1, exitField: 2},
	}
	catalog := make(map[string]oauthrecovery.Descriptor)
	for _, descriptor := range oauthrecovery.Catalog() {
		if _, duplicate := catalog[descriptor.Reason]; duplicate {
			t.Fatalf("duplicate recovery code %q", descriptor.Reason)
		}
		catalog[descriptor.Reason] = descriptor
	}
	for _, document := range documentation {
		raw, err := os.ReadFile(document.path)
		if err != nil {
			t.Fatal(err)
		}
		section := string(raw)
		var found bool
		_, section, found = strings.Cut(section, "## OAuth token errors")
		if !found {
			t.Fatal("generated contract has no OAuth token errors section")
		}
		if next := strings.Index(section, "\n## "); next >= 0 {
			section = section[:next]
		}
		rows := make(map[string]errx.Code)
		for _, line := range strings.Split(section, "\n") {
			if !strings.HasPrefix(line, "| ") || !strings.Contains(line, "`OAUTH_TOKEN_") {
				continue
			}
			fields := strings.Split(line, "|")
			if len(fields) != 5 {
				t.Fatalf("malformed OAuth row in %s: %q", document.path, line)
			}
			code := strings.Trim(strings.TrimSpace(fields[document.codeField]), "`")
			if !strings.HasPrefix(code, "OAUTH_TOKEN_") {
				t.Fatalf("OAuth code in wrong column of %s: %q", document.path, line)
			}
			if _, duplicate := rows[code]; duplicate {
				t.Fatalf("duplicate OAuth code %q in %s", code, document.path)
			}
			exitText := strings.Fields(strings.TrimSpace(fields[document.exitField]))
			if len(exitText) == 0 {
				t.Fatalf("missing OAuth exit for %q in %s", code, document.path)
			}
			exit, err := strconv.Atoi(exitText[0])
			if err != nil {
				t.Fatalf("invalid OAuth exit for %q in %s: %v", code, document.path, err)
			}
			descriptor, found := catalog[code]
			if !found || strings.TrimSpace(fields[3]) != descriptor.Recovery {
				t.Fatalf("generated OAuth recovery for %q in %s differs from catalog", code, document.path)
			}
			rows[code] = errx.Code(exit)
		}
		if len(rows) != len(catalog) {
			t.Fatalf("OAuth rows in %s=%d, want %d", document.path, len(rows), len(catalog))
		}
		for code, descriptor := range catalog {
			if got, exists := rows[code]; !exists || got != descriptor.Exit {
				t.Fatalf("OAuth code %s in %s: exit=%d exists=%v, want %d", code, document.path, got, exists, descriptor.Exit)
			}
		}
	}
	for _, path := range []string{"../../docs/oauth-errors.md", "../../docs/homebrew.md"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(raw, []byte("contract.md#oauth-token-errors-standard-macos-cli-planned-v020")) {
			t.Fatalf("%s does not link canonical generated OAuth recovery table", path)
		}
		if !bytes.Contains(raw, []byte("`devel`")) || !bytes.Contains(raw, []byte("`v0.2.0`")) {
			t.Fatalf("%s does not distinguish source checkout from planned tagged release", path)
		}
		if path == "../../docs/oauth-errors.md" {
			oldCodes := []string{
				"CREDENTIAL_BINDING_MISMATCH", "USAGE", "KEYCHAIN_INTERACTION_REQUIRED",
				"CONFIRMATION_REQUIRED", "INTERNAL", "CANCELED",
			}
			for _, oldCode := range oldCodes {
				found := false
				for _, line := range strings.Split(string(raw), "\n") {
					if strings.HasPrefix(line, "| ") && strings.Contains(line, "`"+oldCode+"`") && strings.Contains(line, "`"+oauthrecovery.Legacy().Reason+"` / 5") {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("%s omits old-to-new refresh mapping for %s", path, oldCode)
				}
			}
		}
	}

	tests := []struct {
		name      string
		code      string
		status    int
		body      string
		transport error
		refresh   bool
	}{
		{name: "unavailable", code: "OAUTH_TOKEN_ENDPOINT_UNAVAILABLE", status: http.StatusServiceUnavailable},
		{name: "transport rejected", code: "OAUTH_TOKEN_TRANSPORT_REJECTED", transport: x509.UnknownAuthorityError{}},
		{name: "request rejected", code: "OAUTH_TOKEN_REQUEST_REJECTED", status: http.StatusBadRequest},
		{name: "response invalid", code: "OAUTH_TOKEN_RESPONSE_INVALID", status: http.StatusOK, body: `{"invalid":true}`},
		{name: "redirect refused", code: "OAUTH_TOKEN_REDIRECT_REFUSED", status: http.StatusFound},
		{name: "request interrupted", code: "OAUTH_TOKEN_REQUEST_INTERRUPTED", transport: context.Canceled},
		{name: "legacy refresh", code: "OAUTH_TOKEN_EXCHANGE_FAILED", status: http.StatusServiceUnavailable, refresh: true},
	}
	seen := make(map[string]bool)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issuer := "https://hub.example.test"
			client, err := oauth.NewClient(oauth.Config{
				IssuerURL: issuer, AuthorizationURL: issuer + endpoint.OAuthAuthorizationPath,
				TokenURL: issuer + endpoint.OAuthTokenPath, ClientID: "client", Scopes: []string{"YouTrack"},
				RedirectURI: "http://127.0.0.1:18987/oauth/callback",
			}, oauthDiagnosticTransport(func(*http.Request) (*http.Response, error) {
				if test.transport != nil {
					return nil, test.transport
				}
				return &http.Response{StatusCode: test.status, Body: io.NopCloser(strings.NewReader(test.body)), Header: make(http.Header)}, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			if test.refresh {
				_, err = client.Refresh(t.Context(), oauth.TokenSet{RefreshToken: "refresh", Scopes: []string{"YouTrack"}})
			} else {
				session, sessionErr := oauth.NewSession(strings.NewReader(strings.Repeat("v", 64)))
				if sessionErr != nil {
					t.Fatal(sessionErr)
				}
				_, err = client.Exchange(t.Context(), "code", session.Verifier)
			}
			if err == nil {
				t.Fatal("OAuth token request unexpectedly succeeded")
			}
			translated := TranslateError(err, "work")
			var stdout bytes.Buffer
			exit := (&output.Writer{Format: output.FormatJSON, Out: &stdout, Err: io.Discard}).Failure(translated)
			var envelope output.Envelope
			if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Error == nil || envelope.Error.Code != test.code {
				t.Fatalf("OAuth envelope=%+v, want code %q", envelope, test.code)
			}
			descriptor, found := catalog[envelope.Error.Code]
			if !found || exit != descriptor.Exit || errx.ExitCode(translated) != descriptor.Exit {
				t.Fatalf("OAuth code=%q exit=%d translated exit=%d catalog exit=%d found=%v", envelope.Error.Code, exit, errx.ExitCode(translated), descriptor.Exit, found)
			}
			if test.refresh {
				if !strings.Contains(envelope.Hint, descriptor.Hint) {
					t.Fatalf("OAuth refresh hint does not include legacy descriptor recovery: %q", envelope.Hint)
				}
			} else if envelope.Hint != descriptor.Hint {
				t.Fatalf("OAuth code=%q hint=%q, want catalog hint=%q", envelope.Error.Code, envelope.Hint, descriptor.Hint)
			}
			if seen[envelope.Error.Code] {
				t.Fatalf("runtime scenario duplicated OAuth code %q", envelope.Error.Code)
			}
			seen[envelope.Error.Code] = true
		})
	}
	if len(catalog) != len(tests) || len(seen) != len(tests) {
		t.Fatalf("OAuth catalog rows=%d runtime codes=%d, want exactly %d each", len(catalog), len(seen), len(tests))
	}
}

type oauthFailingBody struct{ err error }

func (body oauthFailingBody) Read([]byte) (int, error) { return 0, body.err }
func (oauthFailingBody) Close() error                  { return nil }

func TestOAuthCancellationBeforeRequestAttemptKeepsGenericError(t *testing.T) {
	for _, grant := range []struct {
		name    string
		refresh bool
	}{{name: "exchange"}, {name: "refresh", refresh: true}} {
		t.Run(grant.name, func(t *testing.T) {
			for _, cause := range []struct {
				name string
				make func(context.Context) (context.Context, context.CancelFunc)
				code string
			}{
				{name: "canceled", make: context.WithCancel, code: "CANCELED"},
				{name: "deadline", make: func(parent context.Context) (context.Context, context.CancelFunc) {
					return context.WithDeadline(parent, time.Now().Add(-time.Second))
				}, code: "TIMEOUT"},
			} {
				t.Run(cause.name, func(t *testing.T) {
					calls := 0
					issuer := "https://hub.example.test"
					client, err := oauth.NewClient(oauth.Config{
						IssuerURL: issuer, AuthorizationURL: issuer + endpoint.OAuthAuthorizationPath,
						TokenURL: issuer + endpoint.OAuthTokenPath, ClientID: "client", Scopes: []string{"YouTrack"},
						RedirectURI: "http://127.0.0.1:18987/oauth/callback",
					}, oauthDiagnosticTransport(func(*http.Request) (*http.Response, error) {
						calls++
						return nil, errors.New("unexpected token request")
					}))
					if err != nil {
						t.Fatal(err)
					}
					ctx, cancel := cause.make(t.Context())
					cancel()
					if grant.refresh {
						_, err = client.Refresh(ctx, oauth.TokenSet{RefreshToken: "old-refresh", Scopes: []string{"YouTrack"}})
					} else {
						session, sessionErr := oauth.NewSession(strings.NewReader(strings.Repeat("v", 64)))
						if sessionErr != nil {
							t.Fatal(sessionErr)
						}
						_, err = client.Exchange(ctx, "authorization-code", session.Verifier)
					}
					if calls != 0 {
						t.Fatalf("pre-attempt cancellation made %d requests", calls)
					}
					translated := TranslateError(err, "work")
					if errx.ExitCode(translated) != errx.CodeRetryable {
						t.Fatalf("pre-attempt cancellation exit=%d", errx.ExitCode(translated))
					}
					var stdout bytes.Buffer
					if exit := (&output.Writer{Format: output.FormatJSON, Out: &stdout, Err: io.Discard}).Failure(translated); exit != errx.CodeRetryable {
						t.Fatalf("rendered exit=%d", exit)
					}
					var envelope output.Envelope
					if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
						t.Fatal(err)
					}
					if envelope.Error == nil || envelope.Error.Code != cause.code {
						t.Fatalf("pre-attempt envelope=%+v, want %s", envelope, cause.code)
					}
				})
			}
		})
	}
}

func TestOAuthExchangeCancellationAfterRequestAttemptRequiresFreshLogin(t *testing.T) {
	for _, stage := range []string{"round trip", "response body"} {
		t.Run(stage, func(t *testing.T) {
			for _, cause := range []struct {
				name string
				err  error
			}{{name: "canceled", err: context.Canceled}, {name: "deadline", err: context.DeadlineExceeded}} {
				t.Run(cause.name, func(t *testing.T) {
					issuer := "https://hub.example.test"
					calls := 0
					client, err := oauth.NewClient(oauth.Config{
						IssuerURL: issuer, AuthorizationURL: issuer + endpoint.OAuthAuthorizationPath,
						TokenURL: issuer + endpoint.OAuthTokenPath, ClientID: "client", Scopes: []string{"YouTrack"},
						RedirectURI: "http://127.0.0.1:18987/oauth/callback",
					}, oauthDiagnosticTransport(func(*http.Request) (*http.Response, error) {
						calls++
						if stage == "round trip" {
							return nil, cause.err
						}
						return &http.Response{StatusCode: http.StatusOK, Body: oauthFailingBody{err: cause.err}, Header: make(http.Header)}, nil
					}))
					if err != nil {
						t.Fatal(err)
					}
					session, err := oauth.NewSession(strings.NewReader(strings.Repeat("v", 64)))
					if err != nil {
						t.Fatal(err)
					}
					_, err = client.Exchange(t.Context(), "authorization-code", session.Verifier)
					if calls != 1 || errors.Is(err, cause.err) {
						t.Fatalf("requests=%d OAuth failure=%v, want a safe one-attempt result", calls, err)
					}
					translated := TranslateError(err, "work")
					if errx.ExitCode(translated) != errx.CodeAuth {
						t.Fatalf("post-attempt exit=%d, want auth/5", errx.ExitCode(translated))
					}
					var stdout bytes.Buffer
					if exit := (&output.Writer{Format: output.FormatJSON, Out: &stdout, Err: io.Discard}).Failure(translated); exit != errx.CodeAuth {
						t.Fatalf("rendered exit=%d, want auth/5", exit)
					}
					var envelope output.Envelope
					if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
						t.Fatal(err)
					}
					if envelope.Error == nil || envelope.Error.Code != "OAUTH_TOKEN_REQUEST_INTERRUPTED" || envelope.Error.RetryAfter != "" || !strings.Contains(envelope.Hint, "fresh authorization code") || !strings.Contains(envelope.Hint, "do not replay") || bytes.Contains(stdout.Bytes(), []byte(`"retry_after"`)) {
						t.Fatalf("post-attempt envelope=%+v", envelope)
					}
				})
			}
		})
	}
}

func TestUntypedOAuthFailureRetainsPublishedRecovery(t *testing.T) {
	translated := TranslateError(oauth.ErrTokenExchange, "work")
	var typed *errx.Error
	if !errors.As(translated, &typed) || typed.Code != errx.CodeAuth || typed.Reason != "OAUTH_TOKEN_EXCHANGE_FAILED" {
		t.Fatalf("translation=%#v", typed)
	}
	if !strings.Contains(typed.Hint, "correct invalid local exchange input") || !strings.Contains(typed.Hint, "if refresh was attempted") {
		t.Fatalf("untyped failure needs conditional recovery: %q", typed.Hint)
	}
	assertRefreshRecoveryHint(t, typed.Hint)
}

func assertRefreshRecoveryHint(t *testing.T, hint string) {
	t.Helper()
	for _, required := range []string{"stop auth-dependent commands", "operator", "login", "do not retry refresh"} {
		if !strings.Contains(hint, required) {
			t.Fatalf("refresh hint %q missing %q", hint, required)
		}
	}
	if !strings.Contains(hint, "approv") && !strings.Contains(hint, "consent") {
		t.Fatalf("refresh hint must require operator approval for credential replacement: %q", hint)
	}
	if strings.Contains(hint, "--yes") {
		t.Fatalf("refresh hint must not suggest unattended credential replacement: %q", hint)
	}
}

func TestBareOAuthTokenFailureKeepsSafeNonemptyMachineHint(t *testing.T) {
	translated := TranslateError(&oauth.TokenFailure{}, "work")
	if errx.ExitCode(translated) != errx.CodeAuth {
		t.Fatalf("bare token failure exit=%d, want auth/5", errx.ExitCode(translated))
	}
	var stdout bytes.Buffer
	if exit := (&output.Writer{Format: output.FormatJSON, Out: &stdout, Err: io.Discard}).Failure(translated); exit != errx.CodeAuth {
		t.Fatalf("bare token failure rendered exit=%d, want auth/5", exit)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(stdout.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	if _, present := fields["hint"]; !present {
		t.Fatalf("bare token failure omitted machine hint: %q", stdout.String())
	}
	var envelope output.Envelope
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.OK || envelope.Error == nil || envelope.Error.Code != "OAUTH_TOKEN_EXCHANGE_FAILED" || envelope.Hint == "" || envelope.Error.RetryAfter != "" || bytes.Contains(stdout.Bytes(), []byte(`"retry_after"`)) {
		t.Fatalf("bare token failure envelope=%+v", envelope)
	}
	assertRefreshRecoveryHint(t, envelope.Hint)
	if strings.Contains(stdout.String(), "--yes") || strings.Contains(stdout.String(), "work") {
		t.Fatalf("bare token failure leaked unsafe recovery or profile: %q", stdout.String())
	}
}

func TestTypedNilOAuthTokenFailureUsesSafeLegacyRecovery(t *testing.T) {
	var failure *oauth.TokenFailure
	translated := TranslateError(failure, "work")
	var typed *errx.Error
	if !errors.As(translated, &typed) || typed.Reason != oauthrecovery.Legacy().Reason || typed.Code != oauthrecovery.Legacy().Exit {
		t.Fatalf("typed-nil token failure translated as %#v", typed)
	}
	if !strings.Contains(typed.Hint, oauthrecovery.Legacy().Hint) {
		t.Fatalf("typed-nil token failure lost safe operator recovery: %q", typed.Hint)
	}
}

func TestRefreshFailureKeepsLegacyNonRetryableEnvelope(t *testing.T) {
	issuer := "https://hub.example.test"
	client, err := oauth.NewClient(oauth.Config{
		IssuerURL: issuer, AuthorizationURL: issuer + endpoint.OAuthAuthorizationPath,
		TokenURL: issuer + endpoint.OAuthTokenPath, ClientID: "client", Scopes: []string{"YouTrack"},
		RedirectURI: "http://127.0.0.1:18987/oauth/callback",
	}, oauthDiagnosticTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(strings.NewReader("server-secret-sentinel")), Header: make(http.Header)}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Refresh(t.Context(), oauth.TokenSet{AccessToken: "old-access", RefreshToken: "old-refresh", TokenType: "Bearer", Scopes: []string{"YouTrack"}})
	if err != oauth.ErrTokenExchange {
		t.Fatalf("refresh error=%v, want published non-retryable sentinel", err)
	}
	translated := TranslateError(err, "work")
	if errx.ExitCode(translated) != errx.CodeAuth {
		t.Fatalf("refresh exit=%d, want auth", errx.ExitCode(translated))
	}
	var stdout bytes.Buffer
	if exit := (&output.Writer{Format: output.FormatJSON, Out: &stdout, Err: io.Discard}).Failure(translated); exit != errx.CodeAuth {
		t.Fatalf("rendered refresh exit=%d, want auth", exit)
	}
	var envelope output.Envelope
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error == nil || envelope.Error.Code != "OAUTH_TOKEN_EXCHANGE_FAILED" || envelope.Error.RetryAfter != "" || bytes.Contains(stdout.Bytes(), []byte(`"retry_after"`)) {
		t.Fatalf("refresh envelope violated non-retryable contract: %+v", envelope)
	}
	assertRefreshRecoveryHint(t, envelope.Hint)
	if strings.Contains(stdout.String(), "server-secret-sentinel") {
		t.Fatalf("refresh envelope leaked untrusted response: %q", stdout.String())
	}
}

func TestCanceledInflightRefreshKeepsLegacyNonRetryableEnvelope(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	issuer := "https://hub.example.test"
	client, err := oauth.NewClient(oauth.Config{
		IssuerURL: issuer, AuthorizationURL: issuer + endpoint.OAuthAuthorizationPath,
		TokenURL: issuer + endpoint.OAuthTokenPath, ClientID: "client", Scopes: []string{"YouTrack"},
		RedirectURI: "http://127.0.0.1:18987/oauth/callback",
	}, oauthDiagnosticTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: oauthCanceledBody{cancel: cancel}, Header: make(http.Header)}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Refresh(ctx, oauth.TokenSet{RefreshToken: "old-refresh", Scopes: []string{"YouTrack"}})
	if err != oauth.ErrTokenExchange {
		t.Fatalf("in-flight refresh error=%v, want non-retryable legacy sentinel", err)
	}
	translated := TranslateError(err, "work")
	var typed *errx.Error
	if !errors.As(translated, &typed) || typed.Code != errx.CodeAuth || typed.Reason != "OAUTH_TOKEN_EXCHANGE_FAILED" || typed.RetryAfter != 0 {
		t.Fatalf("in-flight refresh recovery=%#v, want auth/5 with re-login hint", typed)
	}
	assertRefreshRecoveryHint(t, typed.Hint)
	var stdout bytes.Buffer
	if exit := (&output.Writer{Format: output.FormatJSON, Out: &stdout, Err: io.Discard}).Failure(translated); exit != errx.CodeAuth {
		t.Fatalf("rendered exit=%d, want auth/5", exit)
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

func TestRefreshHTTP200ReadErrorKeepsLegacyNonRetryableEnvelope(t *testing.T) {
	issuer := "https://hub.example.test"
	calls := 0
	client, err := oauth.NewClient(oauth.Config{
		IssuerURL: issuer, AuthorizationURL: issuer + endpoint.OAuthAuthorizationPath,
		TokenURL: issuer + endpoint.OAuthTokenPath, ClientID: "client", Scopes: []string{"YouTrack"},
		RedirectURI: "http://127.0.0.1:18987/oauth/callback",
	}, oauthDiagnosticTransport(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusOK, Body: oauthFailingBody{err: errors.New("body-secret-sentinel")}, Header: make(http.Header)}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Refresh(t.Context(), oauth.TokenSet{RefreshToken: "old-refresh", Scopes: []string{"YouTrack"}})
	if calls != 1 || err != oauth.ErrTokenExchange {
		t.Fatalf("refresh requests=%d failure=%v, want one non-retryable legacy failure", calls, err)
	}
	var stdout bytes.Buffer
	if exit := (&output.Writer{Format: output.FormatJSON, Out: &stdout, Err: io.Discard}).Failure(TranslateError(err, "work")); exit != errx.CodeAuth {
		t.Fatalf("HTTP 200 refresh read-error exit=%d, want auth/5", exit)
	}
	var envelope output.Envelope
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error == nil || envelope.Error.Code != "OAUTH_TOKEN_EXCHANGE_FAILED" || envelope.Error.RetryAfter != "" || bytes.Contains(stdout.Bytes(), []byte(`"retry_after"`)) {
		t.Fatalf("HTTP 200 refresh read-error envelope=%+v", envelope)
	}
	assertRefreshRecoveryHint(t, envelope.Hint)
	if strings.Contains(stdout.String(), "body-secret-sentinel") {
		t.Fatal("HTTP 200 refresh read-error leaked untrusted body error")
	}
}

func TestOAuthHTTP200BodyFailuresRequireFreshCodeWithoutReplay(t *testing.T) {
	tests := []struct {
		name  string
		cause error
	}{
		{name: "body read failure", cause: errors.New("server-secret-sentinel")},
		{name: "canceled read", cause: context.Canceled},
		{name: "deadline read", cause: context.DeadlineExceeded},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issuer := "https://hub.example.test"
			calls := 0
			client, err := oauth.NewClient(oauth.Config{
				IssuerURL: issuer, AuthorizationURL: issuer + endpoint.OAuthAuthorizationPath,
				TokenURL: issuer + endpoint.OAuthTokenPath, ClientID: "client", Scopes: []string{"YouTrack"},
				RedirectURI: "http://127.0.0.1:18987/oauth/callback",
			}, oauthDiagnosticTransport(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: http.StatusOK, Body: oauthFailingBody{err: test.cause}, Header: make(http.Header)}, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			session, err := oauth.NewSession(strings.NewReader(strings.Repeat("v", 64)))
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Exchange(t.Context(), "authorization-code", session.Verifier)
			translated := TranslateError(err, "work")
			var stdout bytes.Buffer
			if exit := (&output.Writer{Format: output.FormatJSON, Out: &stdout, Err: io.Discard}).Failure(translated); exit != errx.CodeAuth {
				t.Fatalf("interrupted response exit=%d, want auth/5", exit)
			}
			var envelope output.Envelope
			if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if calls != 1 || envelope.Error == nil || envelope.Error.Code != "OAUTH_TOKEN_REQUEST_INTERRUPTED" || envelope.Error.Message != "OAuth token response interrupted (HTTP 200)" || envelope.Error.RetryAfter != "" || bytes.Contains(stdout.Bytes(), []byte(`"retry_after"`)) {
				t.Fatalf("HTTP 200 failure=%+v, requests=%d, want one non-replayable interrupted response", envelope, calls)
			}
			if !strings.Contains(envelope.Hint, "fresh authorization code") || !strings.Contains(envelope.Hint, "do not replay") {
				t.Fatalf("HTTP 200 failure lacks fresh-code/no-replay recovery: %q", envelope.Hint)
			}
			if strings.Contains(stdout.String(), "server-secret-sentinel") {
				t.Fatalf("HTTP 200 failure leaked body error: %q", stdout.String())
			}
		})
	}
}
