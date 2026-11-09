// Package auth owns secret storage and profile binding without exposing token
// material through JSON, formatting, or structured logs.
package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/abigotado/youtrack-agent-cli/internal/profile"
)

const (
	KeychainService = "youtrack-agent-cli"
	MaxTokenBytes   = 8192
	// encoding/json can expand one permitted token byte to a six-byte \u00XX
	// escape. Bound the durable payload by the worst case, not raw token size.
	maxStoredCredentialBytes  = (MaxTokenBytes * 2 * 6) + (32 * 128) + 8192
	credentialPayloadPrefixV1 = "youtrack-agent-cli:credential:v1\x00"
	credentialPayloadPrefixV2 = "youtrack-agent-cli:credential:v2\x00"
	credentialPayloadPrefix   = credentialPayloadPrefixV2
)

var (
	ErrNotFound                      = errors.New("credential not found")
	ErrUnsupported                   = errors.New("native credential store is unsupported on this platform")
	ErrInteractionNotAllowed         = errors.New("credential store requires user interaction")
	ErrKeychainMigrationRequired     = errors.New("keychain access policy requires migration")
	ErrInvalidToken                  = errors.New("invalid token")
	ErrOverwriteConfirmationRequired = errors.New("credential overwrite requires confirmation")
	ErrKeychainEntryNotFound         = errors.New("keychain entry not found")
	ErrKeychainMigrationBlocked      = errors.New("keychain migration requires an interactive session")
	ErrKeychainMigrationCanceled     = errors.New("keychain migration was canceled")
	ErrKeychainMigrationUnavailable  = errors.New("keychain migration is unavailable")
	ErrCredentialBindingMismatch     = errors.New("credential binding does not match profile")
	ErrProfileChangedDuringLogin     = errors.New("profile changed during login")
	ErrLogoutIncomplete              = errors.New("logout removed the credential but could not remove profile metadata")
)

type CredentialKind string

const (
	CredentialOAuth          CredentialKind = "oauth"
	CredentialPermanentToken CredentialKind = "permanent-token"
)

type Credential struct {
	Kind                 CredentialKind       `json:"-"`
	PermanentToken       string               `json:"-"`
	AccessToken          string               `json:"-"`
	RefreshToken         string               `json:"-"`
	TokenType            string               `json:"-"`
	AccessTokenExpiresAt time.Time            `json:"-"`
	OAuthScopes          []string             `json:"-"`
	ProfileIdentity      string               `json:"-"`
	Generation           string               `json:"-"`
	Capabilities         []profile.Capability `json:"-"`
	legacyOAuthScopes    bool
}

func (Credential) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, "<redacted>") }
func (Credential) LogValue() slog.Value           { return slog.StringValue("<redacted>") }

func (c Credential) Validate() error {
	switch c.Kind {
	case CredentialPermanentToken:
		if err := ValidateToken(c.PermanentToken); err != nil {
			return err
		}
		if c.AccessToken != "" || c.RefreshToken != "" || c.TokenType != "" || !c.AccessTokenExpiresAt.IsZero() || len(c.OAuthScopes) != 0 {
			return fmt.Errorf("%w: permanent-token credential contains OAuth fields", ErrInvalidToken)
		}
	case CredentialOAuth:
		if err := ValidateToken(c.AccessToken); err != nil {
			return err
		}
		if err := ValidateToken(c.RefreshToken); err != nil {
			return err
		}
		if c.TokenType != "Bearer" || c.AccessTokenExpiresAt.IsZero() {
			return fmt.Errorf("%w: OAuth credential metadata is invalid", ErrInvalidToken)
		}
		if c.PermanentToken != "" {
			return fmt.Errorf("%w: OAuth credential contains a permanent token", ErrInvalidToken)
		}
		if len(c.OAuthScopes) != 0 {
			if err := profile.ValidateScopes(c.OAuthScopes); err != nil {
				return fmt.Errorf("%w: OAuth credential scopes are invalid", ErrInvalidToken)
			}
		}
	default:
		return fmt.Errorf("%w: credential kind is invalid", ErrInvalidToken)
	}
	if c.ProfileIdentity == "" && c.Generation == "" && len(c.Capabilities) == 0 {
		if c.legacyOAuthScopes {
			return fmt.Errorf("%w: legacy OAuth scope state is not bound", ErrInvalidToken)
		}
		return nil
	}
	if !validProfileIdentity(c.ProfileIdentity) {
		return errors.New("invalid credential profile identity binding")
	}
	if err := profile.ValidateCredentialGeneration(c.Generation); err != nil {
		return fmt.Errorf("invalid credential generation binding: %w", err)
	}
	if err := profile.ValidateCapabilities(c.Capabilities); err != nil {
		return fmt.Errorf("invalid credential capability binding: %w", err)
	}
	return nil
}

func (c Credential) BearerToken(now time.Time) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	if c.Kind == CredentialPermanentToken {
		return c.PermanentToken, nil
	}
	if !now.Before(c.AccessTokenExpiresAt) {
		return "", fmt.Errorf("%w: OAuth access token is expired", ErrInvalidToken)
	}
	return c.AccessToken, nil
}

func BindCredential(c Credential, p profile.Profile) (Credential, error) {
	if err := p.Validate(); err != nil {
		return Credential{}, err
	}
	if p.CredentialGeneration == "" {
		return Credential{}, ErrCredentialBindingMismatch
	}
	if c.ProfileIdentity != "" || c.Generation != "" || len(c.Capabilities) != 0 {
		return Credential{}, ErrCredentialBindingMismatch
	}
	if err := c.Validate(); err != nil {
		return Credential{}, err
	}
	if c.Kind == CredentialOAuth {
		if len(c.OAuthScopes) == 0 {
			c.OAuthScopes = append([]string(nil), p.OAuth.Scopes...)
		}
		if !scopeSubset(c.OAuthScopes, p.OAuth.Scopes) {
			return Credential{}, ErrCredentialBindingMismatch
		}
	}
	c.ProfileIdentity = profile.CredentialIdentity(p)
	c.Generation = p.CredentialGeneration
	c.Capabilities = append([]profile.Capability(nil), p.Capabilities...)
	return c, nil
}

func ValidateCredentialBinding(c Credential, p profile.Profile) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := p.Validate(); err != nil {
		return err
	}
	if p.CredentialGeneration == "" || c.ProfileIdentity != profile.CredentialIdentity(p) || c.Generation != p.CredentialGeneration || !slices.Equal(c.Capabilities, p.Capabilities) {
		return ErrCredentialBindingMismatch
	}
	if c.Kind == CredentialOAuth {
		if len(c.OAuthScopes) == 0 && !c.legacyOAuthScopes {
			return ErrCredentialBindingMismatch
		}
		if len(c.OAuthScopes) != 0 && !scopeSubset(c.OAuthScopes, p.OAuth.Scopes) {
			return ErrCredentialBindingMismatch
		}
	}
	return nil
}

type credentialPayload struct {
	Version              int                  `json:"version"`
	Kind                 CredentialKind       `json:"kind"`
	ProfileIdentity      string               `json:"profile_identity"`
	Generation           string               `json:"generation"`
	Capabilities         []profile.Capability `json:"capabilities"`
	PermanentToken       string               `json:"permanent_token,omitempty"`
	AccessToken          string               `json:"access_token,omitempty"`
	RefreshToken         string               `json:"refresh_token,omitempty"`
	TokenType            string               `json:"token_type,omitempty"`
	AccessTokenExpiresAt *time.Time           `json:"access_token_expires_at,omitempty"`
	OAuthScopes          []string             `json:"oauth_scopes,omitempty"`
}

func encodeCredentialValue(c Credential) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if c.ProfileIdentity == "" {
		return nil, ErrCredentialBindingMismatch
	}
	if c.Kind == CredentialOAuth && len(c.OAuthScopes) == 0 && !c.legacyOAuthScopes {
		return nil, ErrCredentialBindingMismatch
	}
	payloadVersion := 2
	payloadPrefix := credentialPayloadPrefixV2
	if c.Kind == CredentialOAuth && c.legacyOAuthScopes && len(c.OAuthScopes) == 0 {
		// Preserve a decoded v1 credential byte contract when transaction
		// compensation must restore it before the service can infer the legacy
		// grant from its bound profile during an ordinary refresh.
		payloadVersion = 1
		payloadPrefix = credentialPayloadPrefixV1
	}
	payload := credentialPayload{Version: payloadVersion, Kind: c.Kind, ProfileIdentity: c.ProfileIdentity, Generation: c.Generation,
		Capabilities: append([]profile.Capability(nil), c.Capabilities...), PermanentToken: c.PermanentToken,
		AccessToken: c.AccessToken, RefreshToken: c.RefreshToken, TokenType: c.TokenType,
		OAuthScopes: append([]string(nil), c.OAuthScopes...)}
	if !c.AccessTokenExpiresAt.IsZero() {
		expires := c.AccessTokenExpiresAt.UTC()
		payload.AccessTokenExpiresAt = &expires
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode credential payload: %w", err)
	}
	value := append([]byte(payloadPrefix), raw...)
	if len(value) > maxStoredCredentialBytes {
		return nil, errors.New("stored credential payload exceeds its bound")
	}
	return value, nil
}

func decodeCredentialValue(value []byte) (Credential, error) {
	if len(value) == 0 || len(value) > maxStoredCredentialBytes {
		return Credential{}, errors.New("stored credential payload is invalid")
	}
	prefixVersion := 0
	payloadOffset := 0
	switch {
	case bytes.HasPrefix(value, []byte(credentialPayloadPrefixV1)):
		prefixVersion = 1
		payloadOffset = len(credentialPayloadPrefixV1)
	case bytes.HasPrefix(value, []byte(credentialPayloadPrefixV2)):
		prefixVersion = 2
		payloadOffset = len(credentialPayloadPrefixV2)
	default:
		return Credential{}, errors.New("stored credential payload is invalid")
	}
	payloadBytes := value[payloadOffset:]
	decoder := json.NewDecoder(bytes.NewReader(payloadBytes))
	decoder.DisallowUnknownFields()
	var payload credentialPayload
	if err := decoder.Decode(&payload); err != nil {
		return Credential{}, errors.New("stored credential payload is invalid")
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Credential{}, errors.New("stored credential payload has trailing data")
	}
	if payload.Version != prefixVersion || (payload.Version != 1 && payload.Version != 2) {
		return Credential{}, errors.New("stored credential payload version is unsupported")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payloadBytes, &fields); err != nil {
		return Credential{}, errors.New("stored credential payload is invalid")
	}
	_, oauthScopesPresent := fields["oauth_scopes"]
	if payload.Version == 1 && oauthScopesPresent {
		return Credential{}, errors.New("stored credential payload is invalid")
	}
	credential := Credential{Kind: payload.Kind, ProfileIdentity: payload.ProfileIdentity, Generation: payload.Generation,
		Capabilities: append([]profile.Capability(nil), payload.Capabilities...), PermanentToken: payload.PermanentToken,
		AccessToken: payload.AccessToken, RefreshToken: payload.RefreshToken, TokenType: payload.TokenType,
		OAuthScopes: append([]string(nil), payload.OAuthScopes...)}
	credential.legacyOAuthScopes = payload.Version == 1 && credential.Kind == CredentialOAuth
	if payload.AccessTokenExpiresAt != nil {
		credential.AccessTokenExpiresAt = payload.AccessTokenExpiresAt.UTC()
	}
	if err := credential.Validate(); err != nil {
		return Credential{}, errors.New("stored credential payload is invalid")
	}
	if payload.Version == 2 && credential.Kind == CredentialOAuth && (!oauthScopesPresent || len(credential.OAuthScopes) == 0) {
		return Credential{}, errors.New("stored credential payload is invalid")
	}
	if payload.Version == 2 && credential.Kind != CredentialOAuth && oauthScopesPresent {
		return Credential{}, errors.New("stored credential payload is invalid")
	}
	return credential, nil
}

func scopeSubset(granted, allowed []string) bool {
	allowedIndex := 0
	for _, scope := range granted {
		for allowedIndex < len(allowed) && allowed[allowedIndex] < scope {
			allowedIndex++
		}
		if allowedIndex == len(allowed) || allowed[allowedIndex] != scope {
			return false
		}
		allowedIndex++
	}
	return true
}

func validProfileIdentity(identity string) bool {
	if len(identity) != 64 || identity != strings.ToLower(identity) {
		return false
	}
	decoded, err := hex.DecodeString(identity)
	return err == nil && len(decoded) == sha256.Size
}

type CredentialStore interface {
	Exists(context.Context, string) (bool, error)
	Load(context.Context, string) (Credential, error)
	Save(context.Context, string, Credential) error
	Delete(context.Context, string) error
}

type CredentialAccessStore interface {
	CredentialStore
	MigrateKeychain(context.Context, string) error
}

type StatusError struct {
	Operation string
	Status    int64
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("keychain %s failed with OSStatus %d", e.Operation, e.Status)
}

func ValidateToken(token string) error {
	if token == "" {
		return fmt.Errorf("%w: token is empty", ErrInvalidToken)
	}
	if len(token) > MaxTokenBytes {
		return fmt.Errorf("%w: token exceeds %d bytes", ErrInvalidToken, MaxTokenBytes)
	}
	if !utf8.ValidString(token) {
		return fmt.Errorf("%w: token is not valid UTF-8", ErrInvalidToken)
	}
	for _, character := range token {
		if character == '\x00' || character == '\r' || character == '\n' {
			return fmt.Errorf("%w: token contains a prohibited control character", ErrInvalidToken)
		}
	}
	return nil
}
