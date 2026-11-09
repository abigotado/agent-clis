package profile

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/endpoint"
)

func testProfile(name string) Profile {
	service := "https://tracker.example.test/youtrack"
	mcp, err := endpoint.CanonicalMCPURL(service)
	if err != nil {
		panic(err)
	}
	issuer := "https://hub.example.test/hub"
	return Profile{
		Name: name, ServiceURL: service, RESTBaseURL: service + endpoint.RESTPath, MCPURL: mcp,
		OAuth: OAuthConfig{IssuerURL: issuer, AuthorizationURL: issuer + endpoint.OAuthAuthorizationPath,
			TokenURL: issuer + endpoint.OAuthTokenPath, ClientID: "youtrack-agent-cli", Scopes: []string{"YouTrack"}, RedirectURI: "http://127.0.0.1:18987/oauth/callback"},
		ExpectedAccountID: "1-42", ExpectedLogin: "alice",
		Capabilities: []Capability{CapabilityRead, CapabilityIssueCreate, CapabilityIssueUpdate, CapabilityCommentAdd},
		Executor:     ExecutorRESTBestEffort, Assurance: AssuranceBestEffort,
	}
}

func TestProfileValidation(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Profile)
		ok     bool
	}{
		{name: "valid", ok: true},
		{name: "bare MCP", change: func(p *Profile) { p.MCPURL = p.ServiceURL + "/mcp" }},
		{name: "REST mismatch", change: func(p *Profile) { p.RESTBaseURL = "https://other.example.test/api" }},
		{name: "OAuth mismatch", change: func(p *Profile) { p.OAuth.TokenURL = "https://other.example.test/token" }},
		{name: "unsafe redirect", change: func(p *Profile) { p.OAuth.RedirectURI = "http://localhost:18987/oauth/callback" }},
		{name: "unsorted scopes", change: func(p *Profile) { p.OAuth.Scopes = []string{"z", "a"} }},
		{name: "missing account", change: func(p *Profile) { p.ExpectedAccountID = "" }},
		{name: "bad capability order", change: func(p *Profile) {
			p.Capabilities = []Capability{CapabilityRead, CapabilityIssueUpdate, CapabilityIssueCreate}
		}},
		{name: "mismatched assurance", change: func(p *Profile) { p.Assurance = AssuranceStrictAtomic }},
		{name: "future atomic pair", change: func(p *Profile) { p.Executor = ExecutorCustomMCPAtomic; p.Assurance = AssuranceStrictAtomic }, ok: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := testProfile("work")
			if test.change != nil {
				test.change(&value)
			}
			err := value.Validate()
			if test.ok && err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if !test.ok && !errors.Is(err, ErrInvalidProfile) {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestCredentialIdentityBindsFullProfile(t *testing.T) {
	base, err := testProfile("work").WithNewCredentialGeneration()
	if err != nil {
		t.Fatal(err)
	}
	wantDifferent := base
	wantDifferent.OAuth.ClientID = "other"
	if CredentialIdentity(base) == CredentialIdentity(wantDifferent) {
		t.Fatal("OAuth client ID was not bound")
	}
	wantDifferent = base
	wantDifferent.ExpectedAccountID = "1-43"
	if CredentialIdentity(base) == CredentialIdentity(wantDifferent) {
		t.Fatal("account was not bound")
	}
	wantDifferent = base
	wantDifferent.Executor = ExecutorCustomMCPAtomic
	if CredentialIdentity(base) == CredentialIdentity(wantDifferent) {
		t.Fatal("executor was not bound")
	}
}

func TestSelectionIdentityExcludesCredentialGenerationButBindsTopology(t *testing.T) {
	base, err := testProfile("work").WithNewCredentialGeneration()
	if err != nil {
		t.Fatal(err)
	}
	rotated := base
	rotated.CredentialGeneration = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if SelectionIdentity(base) != SelectionIdentity(rotated) {
		t.Fatal("credential generation changed saved-default identity")
	}
	for _, change := range []func(*Profile){
		func(value *Profile) { value.ExpectedAccountID = "1-43" },
		func(value *Profile) { value.ServiceURL = "https://other.example.test/youtrack" },
		func(value *Profile) { value.Capabilities = []Capability{CapabilityRead} },
	} {
		changed := base
		change(&changed)
		if SelectionIdentity(base) == SelectionIdentity(changed) {
			t.Fatal("saved-default identity did not bind profile topology")
		}
	}
}

func TestProfileStrictJSONAndGeneration(t *testing.T) {
	value := testProfile("work")
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Profile
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := string(raw[:len(raw)-1]) + `,"unknown":true}`
	if err := json.Unmarshal([]byte(bad), &decoded); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("unknown field error = %v", err)
	}
	bound, err := value.WithNewCredentialGeneration()
	if err != nil || ValidateCredentialGeneration(bound.CredentialGeneration) != nil {
		t.Fatalf("generation = %q, err = %v", bound.CredentialGeneration, err)
	}
	if _, err := bound.WithNewCredentialGeneration(); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("second generation error = %v", err)
	}
}
