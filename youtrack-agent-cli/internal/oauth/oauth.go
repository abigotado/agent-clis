// Package oauth implements the network-safe parts of public-client OAuth:
// PKCE, callback verification, and bounded fixed-endpoint token requests. It
// does not open browsers or run a callback listener.
package oauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/abigotado/youtrack-agent-cli/internal/endpoint"
)

const maxTokenResponseBytes = 64 << 10

var (
	ErrInvalidConfig       = errors.New("invalid OAuth configuration")
	ErrInvalidCallback     = errors.New("invalid OAuth callback")
	ErrAuthorizationDenied = errors.New("OAuth authorization was denied")
	ErrTokenExchange       = errors.New("OAuth token exchange failed")
	errRedirectRefused     = errors.New("OAuth token redirect refused")
)

// TokenFailureCategory identifies a safe, fixed recovery path for a token
// request. It does not retain the server response or the underlying error.
type TokenFailureCategory uint8

const (
	TokenEndpointUnavailable TokenFailureCategory = iota + 1
	TokenRequestRejected
	TokenResponseInvalid
	TokenRedirectRefused
	TokenTransportRejected
	TokenRequestInterrupted
	TokenFailureCategoryCount
)

// TokenFailure carries only a fixed category and the HTTP status, when one
// exists. In particular, it never retains a response body, URL, or token.
type TokenFailure struct {
	category TokenFailureCategory
	status   int
}

func (failure *TokenFailure) Category() TokenFailureCategory { return failure.category }
func (failure *TokenFailure) HTTPStatus() int                { return failure.status }
func (failure *TokenFailure) Unwrap() error                  { return ErrTokenExchange }

func (failure *TokenFailure) Error() string {
	message := "OAuth token exchange failed"
	switch failure.category {
	case TokenEndpointUnavailable:
		message = "OAuth token endpoint unavailable"
	case TokenRequestRejected:
		message = "OAuth token request rejected"
	case TokenResponseInvalid:
		message = "OAuth token response invalid"
	case TokenRedirectRefused:
		message = "OAuth token redirect refused"
	case TokenTransportRejected:
		message = "OAuth token transport configuration rejected"
	case TokenRequestInterrupted:
		message = "OAuth token request interrupted"
		if failure.status == http.StatusOK {
			message = "OAuth token response interrupted"
		}
	}
	if failure.status != 0 {
		return fmt.Sprintf("%s (HTTP %d)", message, failure.status)
	}
	return message
}

func tokenFailure(category TokenFailureCategory, status int) error {
	return &TokenFailure{category: category, status: status}
}

type Config struct {
	IssuerURL        string
	AuthorizationURL string
	TokenURL         string
	ClientID         string
	Scopes           []string
	RedirectURI      string
}

type Session struct {
	State     string
	Verifier  string
	Challenge string
}

type TokenSet struct {
	AccessToken  string    `json:"-"`
	RefreshToken string    `json:"-"`
	TokenType    string    `json:"-"`
	ExpiresAt    time.Time `json:"-"`
	Scopes       []string  `json:"-"`
}

func (TokenSet) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, "<redacted>") }
func (TokenSet) LogValue() slog.Value           { return slog.StringValue("<redacted>") }

func NewSession(random io.Reader) (Session, error) {
	if random == nil {
		random = rand.Reader
	}
	state, err := randomValue(random)
	if err != nil {
		return Session{}, fmt.Errorf("generate OAuth state: %w", err)
	}
	verifier, err := randomValue(random)
	if err != nil {
		return Session{}, fmt.Errorf("generate PKCE verifier: %w", err)
	}
	digest := sha256.Sum256([]byte(verifier))
	return Session{State: state, Verifier: verifier, Challenge: base64.RawURLEncoding.EncodeToString(digest[:])}, nil
}

func randomValue(source io.Reader) (string, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(source, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func AuthorizationURL(config Config, session Session) (string, error) {
	if err := validateConfig(config); err != nil {
		return "", err
	}
	if !validSession(session) {
		return "", fmt.Errorf("%w: session is incomplete", ErrInvalidConfig)
	}
	parsed, _ := url.Parse(config.AuthorizationURL)
	query := url.Values{}
	query.Set("response_type", "code")
	query.Set("client_id", config.ClientID)
	query.Set("redirect_uri", config.RedirectURI)
	query.Set("scope", strings.Join(config.Scopes, " "))
	query.Set("state", session.State)
	query.Set("access_type", "offline")
	query.Set("code_challenge", session.Challenge)
	query.Set("code_challenge_method", "S256")
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func validSession(session Session) bool {
	state, stateErr := base64.RawURLEncoding.DecodeString(session.State)
	verifier, verifierErr := base64.RawURLEncoding.DecodeString(session.Verifier)
	digest := sha256.Sum256([]byte(session.Verifier))
	return stateErr == nil && verifierErr == nil && len(state) == 32 && len(verifier) == 32 &&
		session.Challenge == base64.RawURLEncoding.EncodeToString(digest[:])
}

func ParseCallback(config Config, callbackURL, expectedState string) (string, error) {
	if err := validateConfig(config); err != nil {
		return "", err
	}
	expected, _ := url.Parse(config.RedirectURI)
	actual, err := url.Parse(callbackURL)
	if err != nil || actual.Scheme != expected.Scheme || actual.Host != expected.Host || actual.Path != expected.Path || actual.Fragment != "" || actual.User != nil {
		return "", ErrInvalidCallback
	}
	query, err := url.ParseQuery(actual.RawQuery)
	if err != nil {
		return "", ErrInvalidCallback
	}
	for key, values := range query {
		if (key != "code" && key != "state" && key != "error" && key != "error_description") || len(values) != 1 {
			return "", ErrInvalidCallback
		}
	}
	states := query["state"]
	if len(states) != 1 || len(states[0]) != len(expectedState) || subtle.ConstantTimeCompare([]byte(states[0]), []byte(expectedState)) != 1 {
		return "", ErrInvalidCallback
	}
	if query.Get("error") != "" {
		return "", ErrAuthorizationDenied
	}
	if query.Get("error_description") != "" {
		return "", ErrInvalidCallback
	}
	code := query["code"]
	if len(code) != 1 || code[0] == "" || len(code[0]) > 8192 {
		return "", ErrInvalidCallback
	}
	return code[0], nil
}

type Client struct {
	config Config
	http   *http.Client
	now    func() time.Time
}

// tokenTransport prevents http.Client from parsing or following an untrusted
// Location, including malformed values that fail before CheckRedirect runs.
type tokenTransport struct{ base http.RoundTripper }

func (transport tokenTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.base.RoundTrip(request)
	if err != nil {
		if response != nil && response.Body != nil {
			// A response accompanied by an error cannot be used. Closing it here
			// avoids retaining a token response body; a close failure is not useful.
			_ = response.Body.Close()
		}
		return nil, err
	}
	if response == nil || response.StatusCode < 300 || response.StatusCode >= 400 {
		return response, nil
	}
	safeResponse := *response
	safeResponse.Header = response.Header.Clone()
	for key := range safeResponse.Header {
		if strings.EqualFold(key, "Location") {
			delete(safeResponse.Header, key)
		}
	}
	return &safeResponse, nil
}

func NewClient(config Config, transport http.RoundTripper) (*Client, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	if transport == nil {
		transport = http.DefaultTransport
	}
	// Keep CheckRedirect as defense in depth if a Location reaches http.Client:
	// refusing a redirect can return both the response and a wrapped error.
	return &Client{config: config, http: &http.Client{Transport: tokenTransport{base: transport}, CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirectRefused }}, now: time.Now}, nil
}

func (client *Client) Exchange(ctx context.Context, code, verifier string) (TokenSet, error) {
	if code == "" || len(code) > 8192 || !validVerifier(verifier) {
		return TokenSet{}, ErrTokenExchange
	}
	if err := ctx.Err(); err != nil {
		return TokenSet{}, err
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {client.config.RedirectURI}, "client_id": {client.config.ClientID}, "code_verifier": {verifier}}
	return client.request(ctx, form, "", client.config.Scopes)
}

func validVerifier(verifier string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(verifier)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == verifier
}

func (client *Client) Refresh(ctx context.Context, current TokenSet) (TokenSet, error) {
	if current.RefreshToken == "" || len(current.RefreshToken) > 8192 || !validGrantedScopes(current.Scopes, client.config.Scopes) {
		return TokenSet{}, ErrTokenExchange
	}
	if err := ctx.Err(); err != nil {
		return TokenSet{}, err
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {current.RefreshToken}, "client_id": {client.config.ClientID}}
	tokens, err := client.request(ctx, form, current.RefreshToken, current.Scopes)
	if err != nil {
		// A failed refresh may already have rotated the server-side token. Keep
		// the published non-retryable recovery until a durable refresh fence exists.
		return TokenSet{}, ErrTokenExchange
	}
	return tokens, nil
}

func permanentTokenTransportError(err error) bool {
	var verification *tls.CertificateVerificationError
	var invalidCertificate x509.CertificateInvalidError
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var systemRoots x509.SystemRootsError
	var dns *net.DNSError
	return errors.As(err, &verification) || errors.As(err, &invalidCertificate) ||
		errors.As(err, &unknownAuthority) || errors.As(err, &hostname) ||
		errors.As(err, &systemRoots) || (errors.As(err, &dns) && dns.IsNotFound) ||
		errors.Is(err, http.ErrSchemeMismatch)
}

func (client *Client) request(ctx context.Context, form url.Values, previousRefresh string, allowedScopes []string) (TokenSet, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.config.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenSet{}, ErrTokenExchange
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.http.Do(request)
	if err != nil {
		if errors.Is(err, errRedirectRefused) {
			status := 0
			if response != nil {
				status = response.StatusCode
			}
			return TokenSet{}, tokenFailure(TokenRedirectRefused, status)
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return TokenSet{}, tokenFailure(TokenRequestInterrupted, 0)
		}
		if permanentTokenTransportError(err) {
			return TokenSet{}, tokenFailure(TokenTransportRejected, 0)
		}
		return TokenSet{}, tokenFailure(TokenEndpointUnavailable, 0)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		switch {
		case response.StatusCode >= 300 && response.StatusCode < 400:
			return TokenSet{}, tokenFailure(TokenRedirectRefused, response.StatusCode)
		case response.StatusCode == http.StatusRequestTimeout, response.StatusCode == http.StatusTooManyRequests, response.StatusCode >= 500 && response.StatusCode < 600:
			return TokenSet{}, tokenFailure(TokenEndpointUnavailable, response.StatusCode)
		case response.StatusCode >= 400 && response.StatusCode < 500:
			return TokenSet{}, tokenFailure(TokenRequestRejected, response.StatusCode)
		default:
			return TokenSet{}, tokenFailure(TokenResponseInvalid, response.StatusCode)
		}
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxTokenResponseBytes+1))
	if err != nil {
		// After HTTP 200, an unreadable response leaves one-time token
		// consumption uncertain regardless of the local read error. Never
		// advertise retry of that POST.
		return TokenSet{}, tokenFailure(TokenRequestInterrupted, response.StatusCode)
	}
	if len(raw) > maxTokenResponseBytes || !utf8.Valid(raw) {
		return TokenSet{}, tokenFailure(TokenResponseInvalid, response.StatusCode)
	}
	var wire struct {
		AccessToken  string          `json:"access_token"`
		RefreshToken string          `json:"refresh_token"`
		TokenType    string          `json:"token_type"`
		ExpiresIn    json.Number     `json:"expires_in"`
		Scope        json.RawMessage `json:"scope"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&wire); err != nil {
		return TokenSet{}, tokenFailure(TokenResponseInvalid, response.StatusCode)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return TokenSet{}, tokenFailure(TokenResponseInvalid, response.StatusCode)
	}
	seconds, err := strconv.ParseInt(string(wire.ExpiresIn), 10, 64)
	if err != nil || seconds <= 0 || seconds > int64((365*24*time.Hour)/time.Second) || !validTokenValue(wire.AccessToken) || !strings.EqualFold(wire.TokenType, "Bearer") {
		return TokenSet{}, tokenFailure(TokenResponseInvalid, response.StatusCode)
	}
	refresh := wire.RefreshToken
	if refresh == "" {
		refresh = previousRefresh
	}
	if !validTokenValue(refresh) {
		return TokenSet{}, tokenFailure(TokenResponseInvalid, response.StatusCode)
	}
	grantedScopes, err := grantedScopes(wire.Scope, allowedScopes)
	if err != nil {
		return TokenSet{}, tokenFailure(TokenResponseInvalid, response.StatusCode)
	}
	return TokenSet{AccessToken: wire.AccessToken, RefreshToken: refresh, TokenType: "Bearer", ExpiresAt: client.now().Add(time.Duration(seconds) * time.Second).UTC(), Scopes: grantedScopes}, nil
}

// Match auth.ValidateToken before handing a response to the credential store,
// without making the network-only OAuth package depend on credential storage.
func validTokenValue(token string) bool {
	return token != "" && len(token) <= 8192 && utf8.ValidString(token) && !strings.ContainsAny(token, "\x00\r\n")
}

func grantedScopes(raw json.RawMessage, allowed []string) ([]string, error) {
	if len(raw) == 0 {
		return append([]string(nil), allowed...), nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || value == "" {
		return nil, ErrTokenExchange
	}
	granted := strings.Split(value, " ")
	for _, scope := range granted {
		if !validScopeToken(scope) {
			return nil, ErrTokenExchange
		}
	}
	slices.Sort(granted)
	if !validGrantedScopes(granted, allowed) {
		return nil, ErrTokenExchange
	}
	return granted, nil
}

func validScopeToken(scope string) bool {
	if scope == "" || len(scope) > 128 {
		return false
	}
	for index := 0; index < len(scope); index++ {
		character := scope[index]
		if character == 0x21 || character >= 0x23 && character <= 0x5b || character >= 0x5d && character <= 0x7e {
			continue
		}
		return false
	}
	return true
}

func validGrantedScopes(granted, allowed []string) bool {
	if len(granted) == 0 {
		return false
	}
	allowedIndex := 0
	previous := ""
	for _, scope := range granted {
		if scope == "" || scope <= previous {
			return false
		}
		for allowedIndex < len(allowed) && allowed[allowedIndex] < scope {
			allowedIndex++
		}
		if allowedIndex == len(allowed) || allowed[allowedIndex] != scope {
			return false
		}
		previous = scope
		allowedIndex++
	}
	return true
}

func validateConfig(config Config) error {
	if err := endpoint.ValidateOAuthTopology(config.IssuerURL, config.AuthorizationURL, config.TokenURL); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	if config.ClientID == "" || len(config.ClientID) > 256 || strings.ContainsAny(config.ClientID, "\x00\r\n\t ") {
		return ErrInvalidConfig
	}
	if len(config.Scopes) == 0 || len(config.Scopes) > 32 {
		return ErrInvalidConfig
	}
	for index, scope := range config.Scopes {
		if !validScopeToken(scope) || (index > 0 && scope <= config.Scopes[index-1]) {
			return ErrInvalidConfig
		}
	}
	if err := endpoint.ValidateLoopbackRedirect(config.RedirectURI); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	return nil
}
