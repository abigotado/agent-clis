package oauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/abigotado/youtrack-agent-cli/internal/endpoint"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }

func testConfig() Config {
	issuer := "https://hub.example.test"
	return Config{IssuerURL: issuer, AuthorizationURL: issuer + endpoint.OAuthAuthorizationPath, TokenURL: issuer + endpoint.OAuthTokenPath, ClientID: "client", Scopes: []string{"YouTrack"}, RedirectURI: "http://127.0.0.1:18987/oauth/callback"}
}

func TestPKCEAndCallback(t *testing.T) {
	session, err := NewSession(strings.NewReader(strings.Repeat("a", 64)))
	if err != nil || session.State == "" || session.Verifier == "" || session.Challenge == session.Verifier {
		t.Fatalf("session=%#v err=%v", session, err)
	}
	authURL, err := AuthorizationURL(testConfig(), session)
	if err != nil || !strings.Contains(authURL, "code_challenge_method=S256") {
		t.Fatalf("URL=%q err=%v", authURL, err)
	}
	code, err := ParseCallback(testConfig(), testConfig().RedirectURI+"?code=code-value&state="+session.State, session.State)
	if err != nil || code != "code-value" {
		t.Fatalf("code=%q err=%v", code, err)
	}
	if _, err := ParseCallback(testConfig(), testConfig().RedirectURI+"?code=x&state=wrong", session.State); !errors.Is(err, ErrInvalidCallback) {
		t.Fatalf("state error=%v", err)
	}
	if _, err := ParseCallback(testConfig(), testConfig().RedirectURI+"?error=access_denied&state=wrong", session.State); !errors.Is(err, ErrInvalidCallback) {
		t.Fatalf("denial with wrong state error=%v", err)
	}
	if _, err := ParseCallback(testConfig(), testConfig().RedirectURI+"?error=access_denied&state="+session.State, session.State); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("denial with valid state error=%v", err)
	}
}

func TestExchangeAndRefreshRotation(t *testing.T) {
	var bodies []string
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		raw, _ := io.ReadAll(request.Body)
		bodies = append(bodies, string(raw))
		response := `{"access_token":"access","refresh_token":"refresh","token_type":"Bearer","expires_in":3600,"scope":"YouTrack"}`
		if len(bodies) == 2 {
			response = `{"access_token":"next","refresh_token":"rotated","token_type":"bearer","expires_in":3600}`
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(response)), Header: make(http.Header)}, nil
	})
	client, err := NewClient(testConfig(), transport)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return time.Unix(100, 0) }
	session, err := NewSession(strings.NewReader(strings.Repeat("v", 64)))
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := client.Exchange(t.Context(), "code", session.Verifier)
	if err != nil || tokens.RefreshToken != "refresh" {
		t.Fatalf("tokens=%#v err=%v", tokens, err)
	}
	tokens, err = client.Refresh(t.Context(), tokens)
	if err != nil || tokens.RefreshToken != "rotated" || !strings.Contains(bodies[1], "grant_type=refresh_token") {
		t.Fatalf("tokens=%#v err=%v bodies=%v", tokens, err, bodies)
	}
}

func TestExchangeTreatsGrantedScopesAsStrictSubset(t *testing.T) {
	config := testConfig()
	config.Scopes = []string{"alpha", "beta", "gamma"}
	tests := []struct {
		name       string
		scopeField string
		want       []string
		wantErr    bool
	}{
		{name: "reordered subset", scopeField: `,"scope":"gamma alpha"`, want: []string{"alpha", "gamma"}},
		{name: "single subset", scopeField: `,"scope":"beta"`, want: []string{"beta"}},
		{name: "omitted means requested", want: []string{"alpha", "beta", "gamma"}},
		{name: "present empty is malformed", scopeField: `,"scope":""`, wantErr: true},
		{name: "present null is malformed", scopeField: `,"scope":null`, wantErr: true},
		{name: "double separator is malformed", scopeField: `,"scope":"alpha  beta"`, wantErr: true},
		{name: "tab separator is malformed", scopeField: `,"scope":"alpha\tbeta"`, wantErr: true},
		{name: "newline separator is malformed", scopeField: `,"scope":"alpha\nbeta"`, wantErr: true},
		{name: "leading separator is malformed", scopeField: `,"scope":" alpha"`, wantErr: true},
		{name: "duplicate is malformed", scopeField: `,"scope":"alpha alpha"`, wantErr: true},
		{name: "escalated scope", scopeField: `,"scope":"admin"`, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session, err := NewSession(strings.NewReader(strings.Repeat("v", 64)))
			if err != nil {
				t.Fatal(err)
			}
			transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
				body := `{"access_token":"access","refresh_token":"refresh","token_type":"Bearer","expires_in":3600` + test.scopeField + `}`
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
			})
			client, err := NewClient(config, transport)
			if err != nil {
				t.Fatal(err)
			}
			tokens, err := client.Exchange(t.Context(), "code", session.Verifier)
			if test.wantErr {
				if !errors.Is(err, ErrTokenExchange) {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if err != nil || !slices.Equal(tokens.Scopes, test.want) {
				t.Fatalf("scopes=%v err=%v", tokens.Scopes, err)
			}
		})
	}
}

func TestRefreshPreservesOrNarrowsCurrentGrant(t *testing.T) {
	config := testConfig()
	config.Scopes = []string{"alpha", "beta", "gamma"}
	tests := []struct {
		name       string
		scopeField string
		want       []string
		wantErr    bool
	}{
		{name: "omitted scope preserves current grant", want: []string{"alpha", "gamma"}},
		{name: "explicit narrowing", scopeField: `,"scope":"gamma"`, want: []string{"gamma"}},
		{name: "cannot re-expand from current grant", scopeField: `,"scope":"alpha beta gamma"`, wantErr: true},
		{name: "present empty is malformed", scopeField: `,"scope":""`, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
				raw, err := io.ReadAll(request.Body)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(raw), "grant_type=refresh_token") {
					t.Fatalf("refresh form = %q", raw)
				}
				body := `{"access_token":"next","token_type":"Bearer","expires_in":3600` + test.scopeField + `}`
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
			})
			client, err := NewClient(config, transport)
			if err != nil {
				t.Fatal(err)
			}
			current := TokenSet{AccessToken: "old", RefreshToken: "refresh", TokenType: "Bearer", Scopes: []string{"alpha", "gamma"}}
			tokens, err := client.Refresh(t.Context(), current)
			if test.wantErr {
				if !errors.Is(err, ErrTokenExchange) {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if err != nil || tokens.RefreshToken != current.RefreshToken || !slices.Equal(tokens.Scopes, test.want) {
				t.Fatalf("tokens=%#v err=%v", tokens, err)
			}
		})
	}
}

func TestTokenResponseIsBoundedAndErrorsAreRedacted(t *testing.T) {
	sentinel := "server-secret-sentinel"
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 400, Body: io.NopCloser(strings.NewReader(sentinel)), Header: make(http.Header)}, nil
	})
	client, err := NewClient(testConfig(), transport)
	if err != nil {
		t.Fatal(err)
	}
	session, sessionErr := NewSession(strings.NewReader(strings.Repeat("v", 64)))
	if sessionErr != nil {
		t.Fatal(sessionErr)
	}
	_, err = client.Exchange(t.Context(), "code", session.Verifier)
	if !errors.Is(err, ErrTokenExchange) || strings.Contains(err.Error(), sentinel) {
		t.Fatalf("error=%v", err)
	}
}

type failingTokenBody struct{}

func (failingTokenBody) Read([]byte) (int, error) { return 0, errors.New("body-secret-sentinel") }
func (failingTokenBody) Close() error             { return nil }

type cancelingTokenBody struct{ cancel context.CancelFunc }

func (body cancelingTokenBody) Read([]byte) (int, error) {
	body.cancel()
	return 0, context.Canceled
}
func (cancelingTokenBody) Close() error { return nil }

type countedTokenBody struct {
	reader io.Reader
	read   int
}

func (body *countedTokenBody) Read(buffer []byte) (int, error) {
	count, err := body.reader.Read(buffer)
	body.read += count
	return count, err
}

func (*countedTokenBody) Close() error { return nil }

func tokenGrantError(t *testing.T, refresh bool, transport http.RoundTripper) error {
	t.Helper()
	client, err := NewClient(testConfig(), transport)
	if err != nil {
		t.Fatal(err)
	}
	if refresh {
		_, err = client.Refresh(t.Context(), TokenSet{AccessToken: "access-secret-sentinel", RefreshToken: "refresh-secret-sentinel", TokenType: "Bearer", Scopes: []string{"YouTrack"}})
		return err
	}
	session, err := NewSession(strings.NewReader(strings.Repeat("v", 64)))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Exchange(t.Context(), "code-secret-sentinel", session.Verifier)
	return err
}

func TestTokenFailuresClassifyExchangeAndKeepRefreshNonRetryable(t *testing.T) {
	const sentinel = "server-secret-sentinel"
	tests := []struct {
		name       string
		status     int
		body       string
		location   string
		bodyError  bool
		transport  error
		want       TokenFailureCategory
		wantStatus int
	}{
		{name: "transport", transport: errors.New("transport-secret-sentinel"), want: TokenEndpointUnavailable},
		{name: "TLS verification", transport: &tls.CertificateVerificationError{Err: errors.New("certificate-secret-sentinel")}, want: TokenTransportRejected},
		{name: "invalid certificate", transport: x509.CertificateInvalidError{Reason: x509.Expired, Detail: "certificate-secret-sentinel"}, want: TokenTransportRejected},
		{name: "unknown authority", transport: x509.UnknownAuthorityError{}, want: TokenTransportRejected},
		{name: "hostname mismatch", transport: x509.HostnameError{Certificate: &x509.Certificate{DNSNames: []string{"safe.example.test"}}, Host: "host-secret-sentinel"}, want: TokenTransportRejected},
		{name: "system roots", transport: x509.SystemRootsError{Err: errors.New("roots-secret-sentinel")}, want: TokenTransportRejected},
		{name: "DNS name not found", transport: &net.DNSError{Name: "dns-secret-sentinel", IsNotFound: true}, want: TokenTransportRejected},
		{name: "transient DNS failure", transport: &net.DNSError{Name: "dns-secret-sentinel", IsNotFound: false, IsTemporary: true}, want: TokenEndpointUnavailable},
		{name: "scheme mismatch", transport: http.ErrSchemeMismatch, want: TokenTransportRejected},
		{name: "timeout status", status: http.StatusRequestTimeout, body: sentinel, want: TokenEndpointUnavailable, wantStatus: http.StatusRequestTimeout},
		{name: "rate limit", status: http.StatusTooManyRequests, body: sentinel, want: TokenEndpointUnavailable, wantStatus: http.StatusTooManyRequests},
		{name: "server error", status: http.StatusServiceUnavailable, body: sentinel, want: TokenEndpointUnavailable, wantStatus: http.StatusServiceUnavailable},
		{name: "rejected", status: http.StatusBadRequest, body: sentinel, want: TokenRequestRejected, wantStatus: http.StatusBadRequest},
		{name: "unauthorized", status: http.StatusUnauthorized, body: sentinel, want: TokenRequestRejected, wantStatus: http.StatusUnauthorized},
		{name: "forbidden", status: http.StatusForbidden, body: sentinel, want: TokenRequestRejected, wantStatus: http.StatusForbidden},
		{name: "redirect", status: http.StatusFound, body: sentinel, location: "https://other.example.test/secret-sentinel", want: TokenRedirectRefused, wantStatus: http.StatusFound},
		{name: "redirect with malformed location", status: http.StatusFound, body: sentinel, location: "http://[secret-sentinel", want: TokenRedirectRefused, wantStatus: http.StatusFound},
		{name: "redirect without location", status: http.StatusFound, body: sentinel, want: TokenRedirectRefused, wantStatus: http.StatusFound},
		{name: "unexpected informational", status: http.StatusProcessing, body: sentinel, want: TokenResponseInvalid, wantStatus: http.StatusProcessing},
		{name: "unexpected success", status: http.StatusCreated, body: sentinel, want: TokenResponseInvalid, wantStatus: http.StatusCreated},
		{name: "malformed JSON", status: http.StatusOK, body: `{"access_token":"` + sentinel + `"`, want: TokenResponseInvalid, wantStatus: http.StatusOK},
		{name: "untrusted expiry", status: http.StatusOK, body: `{"access_token":"access","refresh_token":"refresh","token_type":"Bearer","expires_in":"` + sentinel + `"}`, want: TokenResponseInvalid, wantStatus: http.StatusOK},
		{name: "missing access", status: http.StatusOK, body: `{"refresh_token":"refresh","token_type":"Bearer","expires_in":3600}`, want: TokenResponseInvalid, wantStatus: http.StatusOK},
		{name: "body read error", status: http.StatusOK, bodyError: true, want: TokenRequestInterrupted, wantStatus: http.StatusOK},
		{name: "known rejection beats body error", status: http.StatusBadRequest, bodyError: true, want: TokenRequestRejected, wantStatus: http.StatusBadRequest},
		{name: "known retryable beats body error", status: http.StatusTooManyRequests, bodyError: true, want: TokenEndpointUnavailable, wantStatus: http.StatusTooManyRequests},
	}
	for _, grant := range []struct {
		name    string
		refresh bool
	}{{name: "exchange"}, {name: "refresh", refresh: true}} {
		t.Run(grant.name, func(t *testing.T) {
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					calls := 0
					transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
						calls++
						if test.transport != nil {
							return nil, test.transport
						}
						var body io.ReadCloser = io.NopCloser(strings.NewReader(test.body))
						if test.bodyError {
							body = failingTokenBody{}
						}
						header := make(http.Header)
						if test.location != "" {
							header.Set("Location", test.location)
						}
						return &http.Response{StatusCode: test.status, Body: body, Header: header}, nil
					})
					err := tokenGrantError(t, grant.refresh, transport)
					if !errors.Is(err, ErrTokenExchange) {
						t.Fatalf("error does not preserve ErrTokenExchange: %v", err)
					}
					var failure *TokenFailure
					if grant.refresh {
						if errors.As(err, &failure) || err != ErrTokenExchange {
							t.Fatalf("refresh failure=%v, want legacy non-retryable sentinel", err)
						}
					} else if !errors.As(err, &failure) || failure.Category() != test.want || failure.HTTPStatus() != test.wantStatus {
						t.Fatalf("failure=%#v, want category=%v status=%d", failure, test.want, test.wantStatus)
					}
					if calls != 1 {
						t.Fatalf("token requests=%d, want one fixed-origin request", calls)
					}
					for _, representation := range []string{err.Error(), fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err)} {
						if strings.Contains(representation, "secret-sentinel") || strings.Contains(representation, "other.example.test") {
							t.Fatalf("OAuth failure leaked untrusted content: %q", representation)
						}
						if test.wantStatus == 0 && strings.Contains(representation, "HTTP 0") {
							t.Fatalf("OAuth failure invented an HTTP status: %q", representation)
						}
					}
					encoded, encodeErr := json.Marshal(err)
					if encodeErr != nil || strings.Contains(string(encoded), "secret-sentinel") {
						t.Fatalf("OAuth failure JSON=%s, err=%v", encoded, encodeErr)
					}
					var logline bytes.Buffer
					slog.New(slog.NewJSONHandler(&logline, nil)).Error("OAuth token failure", "error", err)
					if strings.Contains(logline.String(), "secret-sentinel") || strings.Contains(logline.String(), "other.example.test") {
						t.Fatalf("OAuth failure log leaked untrusted content: %q", logline.String())
					}
				})
			}
		})
	}
}

func TestTokenResponsesRejectEscapedControlCharactersInCredentials(t *testing.T) {
	for _, grant := range []struct {
		name    string
		refresh bool
	}{{name: "exchange"}, {name: "refresh", refresh: true}} {
		t.Run(grant.name, func(t *testing.T) {
			for _, field := range []string{"access_token", "refresh_token"} {
				t.Run(field, func(t *testing.T) {
					for _, control := range []struct {
						name    string
						escaped string
					}{
						{name: "NUL", escaped: `\u0000`},
						{name: "CR", escaped: `\r`},
						{name: "LF", escaped: `\n`},
					} {
						t.Run(control.name, func(t *testing.T) {
							const sentinel = "token-private-sentinel"
							access, refresh := sentinel, "refresh"
							if field == "access_token" {
								access += control.escaped
							} else {
								refresh = sentinel + control.escaped
							}
							body := `{"access_token":"` + access + `","refresh_token":"` + refresh + `","token_type":"Bearer","expires_in":3600}`
							calls := 0
							transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
								calls++
								if request.Method != http.MethodPost || request.URL.Host != "hub.example.test" {
									t.Fatalf("unexpected token endpoint: %s %s", request.Method, request.URL.Host)
								}
								return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
							})
							err := tokenGrantError(t, grant.refresh, transport)
							if calls != 1 {
								t.Fatalf("token requests=%d, want exactly one", calls)
							}
							if grant.refresh {
								if err != ErrTokenExchange {
									t.Fatalf("refresh failure=%v, want legacy auth failure", err)
								}
							} else {
								var failure *TokenFailure
								if !errors.As(err, &failure) || failure.Category() != TokenResponseInvalid || failure.HTTPStatus() != http.StatusOK {
									t.Fatalf("exchange failure=%v, want invalid HTTP 200 token response", err)
								}
							}
							if strings.Contains(err.Error(), sentinel) {
								t.Fatalf("token failure leaked credential: %q", err.Error())
							}
						})
					}
				})
			}
		})
	}
}

func TestTokenResponsesRejectRawInvalidUTF8BeforeJSONDecoding(t *testing.T) {
	for _, grant := range []struct {
		name    string
		refresh bool
	}{{name: "exchange"}, {name: "refresh", refresh: true}} {
		t.Run(grant.name, func(t *testing.T) {
			for _, field := range []string{"access_token", "refresh_token"} {
				t.Run(field, func(t *testing.T) {
					// Build raw response bytes directly: json.Marshal would replace or
					// escape the invalid byte and stop testing the wire boundary.
					prefix := `{"access_token":"valid-access","refresh_token":"valid-refresh","token_type":"Bearer","expires_in":3600}`
					marker := `valid-access`
					if field == "refresh_token" {
						marker = `valid-refresh`
					}
					broken := append([]byte("private-sentinel"), 0xff)
					body := bytes.Replace([]byte(prefix), []byte(marker), broken, 1)
					if utf8.Valid(body) {
						t.Fatal("fixture must contain raw invalid UTF-8")
					}
					calls := 0
					transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
						calls++
						return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
					})
					err := tokenGrantError(t, grant.refresh, transport)
					if calls != 1 {
						t.Fatalf("token requests=%d, want one", calls)
					}
					if grant.refresh {
						if err != ErrTokenExchange {
							t.Fatalf("refresh error=%v, want non-retryable legacy sentinel", err)
						}
					} else {
						var failure *TokenFailure
						if !errors.As(err, &failure) || failure.Category() != TokenResponseInvalid || failure.HTTPStatus() != http.StatusOK {
							t.Fatalf("exchange error=%v, want invalid HTTP 200 response", err)
						}
					}
					if strings.Contains(err.Error(), "private-sentinel") || strings.ContainsRune(err.Error(), '\ufffd') || strings.Contains(err.Error(), "\\xff") || bytes.Contains([]byte(err.Error()), []byte{0xff}) {
						t.Fatalf("invalid token bytes leaked into error: %q", err.Error())
					}
				})
			}
		})
	}
}

type closingTokenBody struct {
	io.Reader
	closes int
}

func (body *closingTokenBody) Close() error {
	body.closes++
	return nil
}

func TestTokenRedirectResponsesAreClosedWithoutFollowing(t *testing.T) {
	for _, grant := range []struct {
		name    string
		refresh bool
	}{{name: "exchange"}, {name: "refresh", refresh: true}} {
		t.Run(grant.name, func(t *testing.T) {
			for _, location := range []struct {
				name  string
				value string
			}{
				{name: "valid location", value: "https://other.example.test/secret-sentinel"},
				{name: "malformed location", value: "http://[secret-sentinel"},
				{name: "missing location"},
			} {
				t.Run(location.name, func(t *testing.T) {
					body := &closingTokenBody{Reader: strings.NewReader("response-secret-sentinel")}
					calls := 0
					transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
						calls++
						if request.URL.Host != "hub.example.test" {
							t.Fatalf("OAuth request escaped fixed origin: %q", request.URL.Host)
						}
						header := make(http.Header)
						if location.value != "" {
							header.Set("Location", location.value)
						}
						return &http.Response{StatusCode: http.StatusFound, Body: body, Header: header}, nil
					})
					err := tokenGrantError(t, grant.refresh, transport)
					if calls != 1 || body.closes != 1 {
						t.Fatalf("token requests=%d response closes=%d, want exactly one each", calls, body.closes)
					}
					if grant.refresh {
						if err != ErrTokenExchange {
							t.Fatalf("refresh failure=%v, want legacy sentinel", err)
						}
					} else {
						var failure *TokenFailure
						if !errors.As(err, &failure) || failure.Category() != TokenRedirectRefused || failure.HTTPStatus() != http.StatusFound {
							t.Fatalf("exchange failure=%v, want redirect refusal with HTTP 302", err)
						}
					}
					if strings.Contains(err.Error(), "secret-sentinel") || strings.Contains(err.Error(), "other.example.test") {
						t.Fatalf("redirect failure leaked untrusted content: %q", err.Error())
					}
				})
			}
		})
	}
}

func TestToken307And308NeverFollowLocation(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			for _, location := range []string{"https://other.example.test/secret-sentinel", "http://[secret-sentinel"} {
				t.Run(location, func(t *testing.T) {
					body := &closingTokenBody{Reader: strings.NewReader("response-secret-sentinel")}
					calls := 0
					transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
						calls++
						if request.URL.Host != "hub.example.test" {
							t.Fatalf("OAuth request escaped fixed origin: %q", request.URL.Host)
						}
						return &http.Response{StatusCode: status, Body: body, Header: http.Header{"Location": {location}}}, nil
					})
					client, err := NewClient(testConfig(), transport)
					if err != nil {
						t.Fatal(err)
					}
					// Removing the fallback makes this test fail if the primary
					// transport ever lets Location reach http.Client.
					client.http.CheckRedirect = nil
					session, err := NewSession(strings.NewReader(strings.Repeat("v", 64)))
					if err != nil {
						t.Fatal(err)
					}
					_, err = client.Exchange(t.Context(), "code", session.Verifier)
					var failure *TokenFailure
					if !errors.As(err, &failure) || failure.Category() != TokenRedirectRefused || failure.HTTPStatus() != status {
						t.Fatalf("OAuth failure=%v, want redirect refusal with HTTP %d", err, status)
					}
					if calls != 1 || body.closes != 1 || strings.Contains(err.Error(), "secret-sentinel") {
						t.Fatalf("requests=%d closes=%d failure=%v, want one safe refusal", calls, body.closes, err)
					}
				})
			}
		})
	}
}

func TestTokenCheckRedirectFallbackRefusesAndCloses(t *testing.T) {
	client, err := NewClient(testConfig(), roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("wrapped transport was unexpectedly used")
		return nil, errors.New("unexpected request")
	}))
	if err != nil {
		t.Fatal(err)
	}
	body := &closingTokenBody{Reader: strings.NewReader("response-secret-sentinel")}
	calls := 0
	// Bypass only the Location-stripping wrapper to exercise the independent
	// http.Client.CheckRedirect safeguard on the actual token exchange path.
	client.http.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.URL.Host != "hub.example.test" {
			t.Fatalf("OAuth request escaped fixed origin: %q", request.URL.Host)
		}
		return &http.Response{StatusCode: http.StatusFound, Body: body, Header: http.Header{"Location": {"https://other.example.test/secret-sentinel"}}}, nil
	})
	session, err := NewSession(strings.NewReader(strings.Repeat("v", 64)))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Exchange(t.Context(), "code", session.Verifier)
	var failure *TokenFailure
	if !errors.As(err, &failure) || failure.Category() != TokenRedirectRefused || failure.HTTPStatus() != http.StatusFound {
		t.Fatalf("fallback failure=%v, want redirect refusal with HTTP 302", err)
	}
	if calls != 1 || body.closes != 1 || strings.Contains(err.Error(), "secret-sentinel") {
		t.Fatalf("requests=%d closes=%d failure=%v, want one safe refusal", calls, body.closes, err)
	}
}

func TestTokenTransportClosesResponseWhenReturningError(t *testing.T) {
	for _, refresh := range []bool{false, true} {
		name := "exchange"
		if refresh {
			name = "refresh"
		}
		t.Run(name, func(t *testing.T) {
			body := &closingTokenBody{Reader: strings.NewReader("response-secret-sentinel")}
			calls := 0
			transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: http.StatusFound, Body: body, Header: http.Header{"Location": {"http://[secret-sentinel"}}}, errors.New("transport-secret-sentinel")
			})
			err := tokenGrantError(t, refresh, transport)
			if calls != 1 || body.closes != 1 {
				t.Fatalf("token requests=%d response closes=%d, want exactly one each", calls, body.closes)
			}
			if !errors.Is(err, ErrTokenExchange) || strings.Contains(err.Error(), "secret-sentinel") {
				t.Fatalf("OAuth failure=%v", err)
			}
		})
	}
}

func TestTokenRequestAttemptCancellationDoesNotExposeContextError(t *testing.T) {
	for _, grant := range []struct {
		name    string
		refresh bool
	}{{name: "exchange"}, {name: "refresh", refresh: true}} {
		t.Run(grant.name, func(t *testing.T) {
			for _, cause := range []struct {
				name string
				err  error
			}{{name: "canceled", err: context.Canceled}, {name: "deadline", err: context.DeadlineExceeded}} {
				t.Run(cause.name, func(t *testing.T) {
					calls := 0
					transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
						calls++
						return nil, cause.err
					})
					err := tokenGrantError(t, grant.refresh, transport)
					if calls != 1 || !errors.Is(err, ErrTokenExchange) || errors.Is(err, cause.err) {
						t.Fatalf("token requests=%d failure=%v, want one attempt and safe OAuth recovery", calls, err)
					}
					if grant.refresh {
						if err != ErrTokenExchange {
							t.Fatalf("refresh failure=%v, want legacy sentinel", err)
						}
					} else {
						var failure *TokenFailure
						if !errors.As(err, &failure) || failure.Category() != TokenRequestInterrupted || failure.HTTPStatus() != 0 {
							t.Fatalf("exchange failure=%v, want status-free request interruption", err)
						}
					}
				})
			}
		})
	}
}

func TestTokenResponseReadBoundAppliesToBothGrants(t *testing.T) {
	for _, refresh := range []bool{false, true} {
		name := "exchange"
		if refresh {
			name = "refresh"
		}
		t.Run(name, func(t *testing.T) {
			body := &countedTokenBody{reader: strings.NewReader(strings.Repeat("x", maxTokenResponseBytes*4))}
			transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: body, Header: make(http.Header)}, nil
			})
			err := tokenGrantError(t, refresh, transport)
			var failure *TokenFailure
			if refresh {
				if err != ErrTokenExchange || errors.As(err, &failure) {
					t.Fatalf("refresh failure=%v, want legacy non-retryable sentinel", err)
				}
			} else if !errors.As(err, &failure) || failure.Category() != TokenResponseInvalid || failure.HTTPStatus() != http.StatusOK {
				t.Fatalf("failure=%#v", failure)
			}
			if body.read != maxTokenResponseBytes+1 {
				t.Fatalf("read %d bytes, want bounded read of %d", body.read, maxTokenResponseBytes+1)
			}
		})
	}
}

func TestRefreshCancellationBeforeDispatchKeepsCancellation(t *testing.T) {
	calls := 0
	client, err := NewClient(testConfig(), roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("unexpected refresh dispatch")
	}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = client.Refresh(ctx, TokenSet{RefreshToken: "refresh", Scopes: []string{"YouTrack"}})
	if !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("pre-dispatch cancellation error=%v requests=%d", err, calls)
	}
}

func TestExchangeCancellationAfterDispatchRequiresFreshLogin(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	client, err := NewClient(testConfig(), roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: cancelingTokenBody{cancel: cancel}, Header: make(http.Header)}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	session, err := NewSession(strings.NewReader(strings.Repeat("v", 64)))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Exchange(ctx, "code", session.Verifier)
	var failure *TokenFailure
	if !errors.As(err, &failure) || failure.Category() != TokenRequestInterrupted || failure.HTTPStatus() != http.StatusOK || errors.Is(err, context.Canceled) {
		t.Fatalf("post-dispatch exchange cancellation=%v, want response-interrupted recovery", err)
	}
	if !strings.Contains(err.Error(), "response interrupted") || strings.Contains(err.Error(), "endpoint unavailable (HTTP 200)") {
		t.Fatalf("misleading interrupted-response error=%q", err.Error())
	}
}

func TestExchangeCancellationBeforeDispatchKeepsCancellation(t *testing.T) {
	calls := 0
	client, err := NewClient(testConfig(), roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("unexpected exchange dispatch")
	}))
	if err != nil {
		t.Fatal(err)
	}
	session, err := NewSession(strings.NewReader(strings.Repeat("v", 64)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = client.Exchange(ctx, "code", session.Verifier)
	if !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("pre-dispatch exchange cancellation error=%v requests=%d", err, calls)
	}
}

func TestRefreshCancellationAfterDispatchKeepsLegacyAuthRecovery(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	client, err := NewClient(testConfig(), roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: cancelingTokenBody{cancel: cancel}, Header: make(http.Header)}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Refresh(ctx, TokenSet{RefreshToken: "refresh", Scopes: []string{"YouTrack"}})
	if err != ErrTokenExchange {
		t.Fatalf("post-dispatch refresh cancellation=%v, want legacy auth recovery", err)
	}
}

func TestTokenSetCannotEnterFormattingOrJSON(t *testing.T) {
	tokens := TokenSet{AccessToken: "access-sentinel", RefreshToken: "refresh-sentinel"}
	if formatted := fmt.Sprintf("%v", tokens); strings.Contains(formatted, "sentinel") {
		t.Fatalf("format exposed token: %q", formatted)
	}
	raw, err := json.Marshal(tokens)
	if err != nil || strings.Contains(string(raw), "sentinel") {
		t.Fatalf("JSON exposed token: %s, %v", raw, err)
	}
}
