package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/endpoint"
	"github.com/abigotado/youtrack-agent-cli/internal/profile"
)

func authTestProfile(t *testing.T) profile.Profile {
	t.Helper()
	service := "https://tracker.example.test"
	mcp, err := endpoint.CanonicalMCPURL(service)
	if err != nil {
		t.Fatal(err)
	}
	issuer := "https://hub.example.test"
	value := profile.Profile{Name: "work", ServiceURL: service, RESTBaseURL: service + "/api", MCPURL: mcp,
		OAuth: profile.OAuthConfig{IssuerURL: issuer, AuthorizationURL: issuer + endpoint.OAuthAuthorizationPath, TokenURL: issuer + endpoint.OAuthTokenPath,
			ClientID: "client", Scopes: []string{"YouTrack"}, RedirectURI: "http://127.0.0.1:18987/oauth/callback"},
		ExpectedAccountID: "1-42", ExpectedLogin: "alice", Capabilities: []profile.Capability{profile.CapabilityRead, profile.CapabilityIssueUpdate},
		Executor: profile.ExecutorRESTBestEffort, Assurance: profile.AssuranceBestEffort}
	bound, err := value.WithNewCredentialGeneration()
	if err != nil {
		t.Fatal(err)
	}
	return bound
}

func TestCredentialPayloadRoundTripKindsAndRedaction(t *testing.T) {
	selected := authTestProfile(t)
	credentials := []Credential{
		{Kind: CredentialPermanentToken, PermanentToken: "permanent-sentinel"},
		{Kind: CredentialOAuth, AccessToken: "access-sentinel", RefreshToken: "refresh-sentinel", TokenType: "Bearer", AccessTokenExpiresAt: time.Now().Add(time.Hour).UTC(), OAuthScopes: []string{"YouTrack"}},
	}
	for _, candidate := range credentials {
		bound, err := BindCredential(candidate, selected)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := encodeCredentialValue(bound)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeCredentialValue(encoded)
		if err != nil || ValidateCredentialBinding(decoded, selected) != nil {
			t.Fatalf("decode error=%v credential=%v", err, decoded)
		}
		for _, secret := range []string{candidate.PermanentToken, candidate.AccessToken, candidate.RefreshToken} {
			if secret == "" {
				continue
			}
			if strings.Contains(fmt.Sprintf("%v", decoded), secret) {
				t.Fatal("format exposed secret")
			}
			raw, err := json.Marshal(decoded)
			if err != nil || strings.Contains(string(raw), secret) {
				t.Fatal("JSON exposed secret")
			}
		}
	}
}

func TestInvalidUTF8TokenRejectedBeforeCredentialSerialization(t *testing.T) {
	selected := authTestProfile(t)
	baseOAuth, err := BindCredential(Credential{
		Kind: CredentialOAuth, AccessToken: "valid-access", RefreshToken: "valid-refresh",
		TokenType: "Bearer", AccessTokenExpiresAt: time.Now().Add(time.Hour).UTC(),
		OAuthScopes: []string{"YouTrack"},
	}, selected)
	if err != nil {
		t.Fatal(err)
	}
	basePermanent, err := BindCredential(Credential{Kind: CredentialPermanentToken, PermanentToken: "valid-permanent"}, selected)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*Credential, string)
		base   Credential
	}{
		{name: "access", base: baseOAuth, mutate: func(c *Credential, value string) { c.AccessToken = value }},
		{name: "refresh", base: baseOAuth, mutate: func(c *Credential, value string) { c.RefreshToken = value }},
		{name: "permanent", base: basePermanent, mutate: func(c *Credential, value string) { c.PermanentToken = value }},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := string([]byte{'a', 0xff, 'b'})
			if err := ValidateToken(invalid); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("ValidateToken accepted malformed UTF-8: %v", err)
			}
			candidate := test.base
			test.mutate(&candidate, invalid)
			encoded, err := encodeCredentialValue(candidate)
			if !errors.Is(err, ErrInvalidToken) || len(encoded) != 0 {
				t.Fatalf("credential reached serialization with malformed UTF-8: err=%v bytes=%d", err, len(encoded))
			}
		})
	}
}

func TestCredentialPayloadV2PersistsOAuthGrant(t *testing.T) {
	selected := authTestProfile(t)
	selected.OAuth.Scopes = []string{"YouTrack", "YouTrack-Admin"}
	slices.Sort(selected.OAuth.Scopes)
	bound, err := BindCredential(Credential{
		Kind: CredentialOAuth, AccessToken: "access", RefreshToken: "refresh",
		TokenType: "Bearer", AccessTokenExpiresAt: time.Unix(1_800_000_000, 0).UTC(),
		OAuthScopes: []string{"YouTrack"},
	}, selected)
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := encodeCredentialValue(bound)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(encoded), credentialPayloadPrefixV2) || !strings.Contains(string(encoded), `"version":2`) {
		t.Fatalf("encoded payload is not v2: %q", encoded)
	}
	decoded, err := decodeCredentialValue(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(decoded.OAuthScopes, []string{"YouTrack"}) || decoded.AccessTokenExpiresAt != bound.AccessTokenExpiresAt {
		t.Fatalf("decoded credential = %#v", decoded)
	}
}

func TestCredentialPayloadV2SupportsMaximumCanonicalScopeSet(t *testing.T) {
	selected := authTestProfile(t)
	selected.OAuth.Scopes = make([]string, 32)
	for index := range selected.OAuth.Scopes {
		selected.OAuth.Scopes[index] = fmt.Sprintf("scope-%02d-%s", index, strings.Repeat("x", 119))
		if len(selected.OAuth.Scopes[index]) != 128 {
			t.Fatalf("scope length = %d", len(selected.OAuth.Scopes[index]))
		}
	}
	bound, err := BindCredential(Credential{
		Kind: CredentialOAuth, AccessToken: strings.Repeat("\x01", MaxTokenBytes),
		RefreshToken: strings.Repeat("\x02", MaxTokenBytes), TokenType: "Bearer",
		AccessTokenExpiresAt: time.Unix(1_800_000_000, 0).UTC(),
		OAuthScopes:          append([]string(nil), selected.OAuth.Scopes...),
	}, selected)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := encodeCredentialValue(bound)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeCredentialValue(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(decoded.OAuthScopes, selected.OAuth.Scopes) {
		t.Fatalf("scope count = %d, want %d", len(decoded.OAuthScopes), len(selected.OAuth.Scopes))
	}
}

func TestCredentialPayloadStrictVersionMigration(t *testing.T) {
	selected := authTestProfile(t)
	identity := profile.CredentialIdentity(selected)
	legacyOAuth := fmt.Sprintf(
		`{"version":1,"kind":"oauth","profile_identity":%q,"generation":%q,"capabilities":["read","issue-update"],"access_token":"access","refresh_token":"refresh","token_type":"Bearer","access_token_expires_at":"2030-01-01T00:00:00Z"}`,
		identity,
		selected.CredentialGeneration,
	)
	decoded, err := decodeCredentialValue(append([]byte(credentialPayloadPrefixV1), legacyOAuth...))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Kind != CredentialOAuth || decoded.OAuthScopes != nil {
		t.Fatalf("legacy credential = %#v", decoded)
	}
	if err := ValidateCredentialBinding(decoded, selected); err != nil {
		t.Fatalf("decoded v1 OAuth credential lost its migration eligibility: %v", err)
	}
	restored, err := encodeCredentialValue(decoded)
	if err != nil || !strings.HasPrefix(string(restored), credentialPayloadPrefixV1) {
		t.Fatalf("legacy rollback encoding = %q, %v", restored, err)
	}
	migrated := decoded
	migrated.OAuthScopes = append([]string(nil), selected.OAuth.Scopes...)
	migratedValue, err := encodeCredentialValue(migrated)
	if err != nil || !strings.HasPrefix(string(migratedValue), credentialPayloadPrefixV2) {
		t.Fatalf("migrated encoding = %q, %v", migratedValue, err)
	}
	migratedDecoded, err := decodeCredentialValue(migratedValue)
	if err != nil || !slices.Equal(migratedDecoded.OAuthScopes, selected.OAuth.Scopes) {
		t.Fatalf("migrated credential = %#v, %v", migratedDecoded, err)
	}

	tests := []struct {
		name   string
		prefix string
		body   string
	}{
		{name: "prefix and body mismatch", prefix: credentialPayloadPrefixV2, body: legacyOAuth},
		{name: "v1 adds scopes", prefix: credentialPayloadPrefixV1, body: strings.TrimSuffix(legacyOAuth, "}") + `,"oauth_scopes":["YouTrack"]}`},
		{name: "v1 adds null scopes", prefix: credentialPayloadPrefixV1, body: strings.TrimSuffix(legacyOAuth, "}") + `,"oauth_scopes":null}`},
		{name: "v2 oauth omits scopes", prefix: credentialPayloadPrefixV2, body: strings.Replace(legacyOAuth, `"version":1`, `"version":2`, 1)},
		{name: "v2 oauth empty scopes", prefix: credentialPayloadPrefixV2, body: strings.TrimSuffix(strings.Replace(legacyOAuth, `"version":1`, `"version":2`, 1), "}") + `,"oauth_scopes":[]}`},
		{name: "v2 oauth null scopes", prefix: credentialPayloadPrefixV2, body: strings.TrimSuffix(strings.Replace(legacyOAuth, `"version":1`, `"version":2`, 1), "}") + `,"oauth_scopes":null}`},
		{name: "v2 oauth duplicate scopes", prefix: credentialPayloadPrefixV2, body: strings.TrimSuffix(strings.Replace(legacyOAuth, `"version":1`, `"version":2`, 1), "}") + `,"oauth_scopes":["YouTrack","YouTrack"]}`},
		{name: "v2 oauth malformed scope", prefix: credentialPayloadPrefixV2, body: strings.TrimSuffix(strings.Replace(legacyOAuth, `"version":1`, `"version":2`, 1), "}") + `,"oauth_scopes":["You Track"]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodeCredentialValue(append([]byte(test.prefix), test.body...)); err == nil {
				t.Fatal("malformed stored credential was accepted")
			}
		})
	}
}

func TestCredentialPayloadV2PermanentTokenRejectsOAuthScopeField(t *testing.T) {
	selected := authTestProfile(t)
	base := fmt.Sprintf(
		`{"version":2,"kind":"permanent-token","profile_identity":%q,"generation":%q,"capabilities":["read","issue-update"],"permanent_token":"token"`,
		profile.CredentialIdentity(selected),
		selected.CredentialGeneration,
	)
	for _, value := range []string{"[]", "null", `["YouTrack"]`} {
		t.Run(value, func(t *testing.T) {
			raw := append([]byte(credentialPayloadPrefixV2), []byte(base+`,"oauth_scopes":`+value+`}`)...)
			if _, err := decodeCredentialValue(raw); err == nil {
				t.Fatalf("permanent-token payload accepted oauth_scopes=%s", value)
			}
		})
	}
}

func TestOAuthCredentialBindingRequiresCanonicalGrantedSubset(t *testing.T) {
	selected := authTestProfile(t)
	selected.OAuth.Scopes = []string{"Read", "Write"}
	base := Credential{
		Kind: CredentialOAuth, AccessToken: "access", RefreshToken: "refresh",
		TokenType: "Bearer", AccessTokenExpiresAt: time.Unix(1_800_000_000, 0).UTC(),
	}
	for _, test := range []struct {
		name   string
		scopes []string
		ok     bool
	}{
		{name: "subset", scopes: []string{"Read"}, ok: true},
		{name: "complete", scopes: []string{"Read", "Write"}, ok: true},
		{name: "escalation", scopes: []string{"Admin"}},
		{name: "unsorted", scopes: []string{"Write", "Read"}},
		{name: "duplicate", scopes: []string{"Read", "Read"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			candidate.OAuthScopes = append([]string(nil), test.scopes...)
			bound, err := BindCredential(candidate, selected)
			if test.ok {
				if err != nil || !slices.Equal(bound.OAuthScopes, test.scopes) {
					t.Fatalf("bound=%#v err=%v", bound, err)
				}
				return
			}
			if !errors.Is(err, ErrCredentialBindingMismatch) && !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("error = %v", err)
			}
		})
	}

	bound, err := BindCredential(base, selected)
	if err != nil || !slices.Equal(bound.OAuthScopes, selected.OAuth.Scopes) {
		t.Fatalf("new nil grant did not migrate at binding: %#v, %v", bound, err)
	}
	bound.OAuthScopes = nil
	if err := ValidateCredentialBinding(bound, selected); !errors.Is(err, ErrCredentialBindingMismatch) {
		t.Fatalf("modern bound credential accepted nil grant: %v", err)
	}
}

func TestCredentialBindingFailsClosed(t *testing.T) {
	selected := authTestProfile(t)
	bound, err := BindCredential(Credential{Kind: CredentialPermanentToken, PermanentToken: "sentinel"}, selected)
	if err != nil {
		t.Fatal(err)
	}
	changed := selected
	changed.ExpectedLogin = "bob"
	if err := ValidateCredentialBinding(bound, changed); err != ErrCredentialBindingMismatch {
		t.Fatalf("binding error=%v", err)
	}
}

func TestCredentialPayloadRejectsLegacyAndUnknown(t *testing.T) {
	for _, raw := range [][]byte{[]byte("legacy-token"), append([]byte(credentialPayloadPrefix), []byte(`{"version":1,"unknown":true}`)...)} {
		if _, err := decodeCredentialValue(raw); err == nil {
			t.Fatalf("decode accepted %q", raw)
		}
	}
}
