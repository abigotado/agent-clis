package application

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/abigotado/youtrack-agent-cli/internal/auth"
	"github.com/abigotado/youtrack-agent-cli/internal/endpoint"
	"github.com/abigotado/youtrack-agent-cli/internal/oauth"
)

func TestTokenResponseValidationMatchesCredentialStoreForBothFields(t *testing.T) {
	corpus := []struct {
		name       string
		value      string
		rawInvalid bool
	}{
		{name: "empty"},
		{name: "normal", value: "token-value_123"},
		{name: "max bytes", value: strings.Repeat("a", auth.MaxTokenBytes)},
		{name: "over max bytes", value: strings.Repeat("a", auth.MaxTokenBytes+1)},
		{name: "leading NUL", value: "\x00abc"},
		{name: "middle NUL", value: "a\x00bc"},
		{name: "trailing NUL", value: "abc\x00"},
		{name: "leading CR", value: "\rabc"},
		{name: "middle CR", value: "a\rbc"},
		{name: "trailing CR", value: "abc\r"},
		{name: "leading LF", value: "\nabc"},
		{name: "middle LF", value: "a\nbc"},
		{name: "trailing LF", value: "abc\n"},
		{name: "allowed control", value: "a\x01\t\x7fb"},
		{name: "unicode", value: "a雪☃🙂b"},
		{name: "leading invalid UTF-8", value: string([]byte{0xff, 'a'}), rawInvalid: true},
		{name: "middle invalid UTF-8", value: string([]byte{'a', 0xff, 'b'}), rawInvalid: true},
		{name: "trailing invalid UTF-8", value: string([]byte{'a', 0xff}), rawInvalid: true},
	}
	issuer := "https://hub.example.test"
	config := oauth.Config{
		IssuerURL: issuer, AuthorizationURL: issuer + endpoint.OAuthAuthorizationPath,
		TokenURL: issuer + endpoint.OAuthTokenPath, ClientID: "client", Scopes: []string{"YouTrack"},
		RedirectURI: "http://127.0.0.1:18987/oauth/callback",
	}
	for _, field := range []string{"access_token", "refresh_token"} {
		t.Run(field, func(t *testing.T) {
			for _, sample := range corpus {
				t.Run(sample.name, func(t *testing.T) {
					var body []byte
					if sample.rawInvalid {
						// json.Marshal normalizes malformed UTF-8. Construct wire
						// bytes directly so this case tests the HTTP boundary.
						marker := "valid-access"
						if field == "refresh_token" {
							marker = "valid-refresh"
						}
						body = bytes.Replace([]byte(`{"access_token":"valid-access","refresh_token":"valid-refresh","token_type":"Bearer","expires_in":3600}`), []byte(marker), []byte(sample.value), 1)
						if utf8.Valid(body) {
							t.Fatal("fixture must contain raw invalid UTF-8")
						}
					} else {
						wire := map[string]any{
							"access_token": "valid-access", "refresh_token": "valid-refresh",
							"token_type": "Bearer", "expires_in": 3600,
						}
						wire[field] = sample.value
						var err error
						body, err = json.Marshal(wire)
						if err != nil {
							t.Fatal(err)
						}
					}
					calls := 0
					client, err := oauth.NewClient(config, oauthDiagnosticTransport(func(*http.Request) (*http.Response, error) {
						calls++
						return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
					}))
					if err != nil {
						t.Fatal(err)
					}
					session, err := oauth.NewSession(strings.NewReader(strings.Repeat("v", 64)))
					if err != nil {
						t.Fatal(err)
					}
					tokens, exchangeErr := client.Exchange(t.Context(), "code", session.Verifier)
					wantAccepted := auth.ValidateToken(sample.value) == nil
					if gotAccepted := exchangeErr == nil; gotAccepted != wantAccepted {
						t.Fatalf("credential validation accepted=%t exchange accepted=%t (length=%d)", wantAccepted, gotAccepted, len(sample.value))
					}
					if calls != 1 {
						t.Fatalf("token requests=%d, want one", calls)
					}
					if wantAccepted {
						got := tokens.AccessToken
						if field == "refresh_token" {
							got = tokens.RefreshToken
						}
						if got != sample.value {
							t.Fatal("accepted token value changed")
						}
					} else {
						var failure *oauth.TokenFailure
						if !errors.As(exchangeErr, &failure) || failure.Category() != oauth.TokenResponseInvalid || failure.HTTPStatus() != http.StatusOK {
							t.Fatalf("invalid token classified as %v, want invalid HTTP 200 response", exchangeErr)
						}
					}
				})
			}
		})
	}
}
