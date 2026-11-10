package endpoint

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApprovalURLSharedCorpus(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "gate1a", "approval-url-corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Valid   []string `json:"valid"`
		Invalid []string `json:"invalid"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range corpus.Valid {
		if err := ValidateApprovalURL(candidate); err != nil {
			t.Errorf("valid shared URL %q: %v", candidate, err)
		}
	}
	for _, candidate := range corpus.Invalid {
		if err := ValidateApprovalURL(candidate); !errors.Is(err, ErrInvalidEndpoint) {
			t.Errorf("invalid shared URL %q error = %v", candidate, err)
		}
	}
}

func TestValidateApprovalURLLanguageNeutralGrammar(t *testing.T) {
	valid := []string{
		"https://acme.youtrack.cloud",
		"https://tracker.example:8443/youtrack",
		"https://192.0.2.10/yt_A-1",
		"https://example/UPPER~ok!$&'()*+,;=:@",
	}
	for _, candidate := range valid {
		t.Run("valid "+candidate, func(t *testing.T) {
			if err := ValidateApprovalURL(candidate); err != nil {
				t.Fatalf("ValidateApprovalURL(%q) error = %v", candidate, err)
			}
		})
	}

	invalid := []string{
		"HTTPS://acme.youtrack.cloud",
		"https://Acme.youtrack.cloud",
		"https://acme.youtrack.cloud:443",
		"https://acme.youtrack.cloud:0443",
		"https://acme.youtrack.cloud:+80",
		"https://acme.youtrack.cloud:0",
		"https://acme.youtrack.cloud:65536",
		"https://01.2.3.4",
		"https://256.2.3.4",
		"https://[2001:db8::1]",
		"https://münchen.example",
		"https://-bad.example",
		"https://bad-.example",
		"https://bad..example",
		"https://acme.youtrack.cloud/",
		"https://acme.youtrack.cloud/a//b",
		"https://acme.youtrack.cloud/a/./b",
		"https://acme.youtrack.cloud/a/../b",
		"https://acme.youtrack.cloud/a%20b",
		"https://acme.youtrack.cloud/a\\b",
		"https://user@acme.youtrack.cloud",
		"https://acme.youtrack.cloud/path?x=1",
		"https://acme.youtrack.cloud/path#fragment",
		"https://" + strings.Repeat("a", 64) + ".example",
		"https://" + strings.Repeat("a", MaxURLLength),
	}
	for _, candidate := range invalid {
		t.Run("invalid "+candidate, func(t *testing.T) {
			if err := ValidateApprovalURL(candidate); !errors.Is(err, ErrInvalidEndpoint) {
				t.Fatalf("ValidateApprovalURL(%q) error = %v, want ErrInvalidEndpoint", candidate, err)
			}
		})
	}
}

func TestStrictApprovalGrammarDoesNotNarrowExistingServiceURLs(t *testing.T) {
	for _, candidate := range []string{
		"https://tracker.example:443",
		"https://[2001:db8::1]",
	} {
		if err := ValidateServiceURL(candidate); err != nil {
			t.Fatalf("ValidateServiceURL(%q) compatibility error = %v", candidate, err)
		}
		if err := ValidateApprovalURL(candidate); !errors.Is(err, ErrInvalidEndpoint) {
			t.Fatalf("ValidateApprovalURL(%q) error = %v, want ErrInvalidEndpoint", candidate, err)
		}
	}
}

func TestValidateServiceTopology(t *testing.T) {
	service := "https://tracker.example.test/youtrack"
	mcp, err := CanonicalMCPURL(service)
	if err != nil {
		t.Fatalf("CanonicalMCPURL() error = %v", err)
	}
	tests := []struct {
		name string
		fn   func() error
		ok   bool
	}{
		{name: "service with base path", fn: func() error { return ValidateServiceURL(service) }, ok: true},
		{name: "root service", fn: func() error { return ValidateServiceURL("https://tracker.example.test") }, ok: true},
		{name: "REST derived exactly", fn: func() error { return ValidateRESTBaseURL(service, service+"/api") }, ok: true},
		{name: "MCP exact allowlist", fn: func() error { return ValidateMCPURL(service, mcp) }, ok: true},
		{name: "HTTP rejected", fn: func() error { return ValidateServiceURL("http://tracker.example.test") }},
		{name: "userinfo rejected", fn: func() error { return ValidateServiceURL("https://user@tracker.example.test") }},
		{name: "query rejected", fn: func() error { return ValidateServiceURL("https://tracker.example.test?x=1") }},
		{name: "trailing slash rejected", fn: func() error { return ValidateServiceURL("https://tracker.example.test/") }},
		{name: "dot segment rejected", fn: func() error { return ValidateServiceURL("https://tracker.example.test/./youtrack") }},
		{name: "parent segment rejected", fn: func() error { return ValidateServiceURL("https://tracker.example.test/youtrack/../other") }},
		{name: "REST other origin rejected", fn: func() error { return ValidateRESTBaseURL(service, "https://other.example.test/api") }},
		{name: "bare MCP rejected", fn: func() error { return ValidateMCPURL(service, service+"/mcp") }},
		{name: "ignoreTools rejected", fn: func() error { return ValidateMCPURL(service, service+"/mcp?ignoreTools=create_issue") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.fn()
			if test.ok && err != nil {
				t.Fatalf("validation error = %v", err)
			}
			if !test.ok && !errors.Is(err, ErrInvalidEndpoint) {
				t.Fatalf("validation error = %v, want ErrInvalidEndpoint", err)
			}
		})
	}
}

func TestValidateMCPURLFailsClosedOnToolChanges(t *testing.T) {
	service := "https://tracker.example.test"
	canonical, err := CanonicalMCPURL(service)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(canonical)
	if err != nil {
		t.Fatal(err)
	}
	queries := []url.Values{
		{"tools": {"get_issue"}, "enableToolOutputSchema": {"true"}},
		{"tools": {"get_current_user,search_issues,get_issue,get_issue_comments,get_project,get_issue_fields_schema,update_issue"}, "enableToolOutputSchema": {"true"}},
		{"tools": {"get_current_user,search_issues,get_issue,get_issue_comments,get_project,get_issue_fields_schema"}},
		{"tools": {"get_current_user,search_issues,get_issue,get_issue_comments,get_project,get_issue_fields_schema"}, "enableToolOutputSchema": {"false"}},
	}
	for _, query := range queries {
		candidate := *parsed
		candidate.RawQuery = query.Encode()
		if err := ValidateMCPURL(service, candidate.String()); !errors.Is(err, ErrInvalidEndpoint) {
			t.Fatalf("ValidateMCPURL(%q) error = %v", candidate.String(), err)
		}
	}
}

func TestReadOnlyMCPToolsReturnsDefensiveCopy(t *testing.T) {
	service := "https://tracker.example.test"
	want, err := CanonicalMCPURL(service)
	if err != nil {
		t.Fatal(err)
	}
	tools := ReadOnlyMCPTools()
	tools[0] = "update_issue"
	got, err := CanonicalMCPURL(service)
	if err != nil || got != want {
		t.Fatalf("canonical URL changed through exposed copy: got=%q err=%v", got, err)
	}
}

func TestValidateOAuthTopologyAndRedirect(t *testing.T) {
	issuer := "https://hub.example.test/hub"
	if err := ValidateOAuthTopology(issuer, issuer+OAuthAuthorizationPath, issuer+OAuthTokenPath); err != nil {
		t.Fatalf("ValidateOAuthTopology() error = %v", err)
	}
	if err := ValidateOAuthTopology(issuer, "https://lookalike.example.test/api/rest/oauth2/auth", issuer+OAuthTokenPath); !errors.Is(err, ErrInvalidEndpoint) {
		t.Fatalf("wrong authorization endpoint error = %v", err)
	}
	for _, redirect := range []string{"http://127.0.0.1:18987/oauth/callback", "http://[::1]:18987/oauth/callback"} {
		if err := ValidateLoopbackRedirect(redirect); err != nil {
			t.Fatalf("ValidateLoopbackRedirect(%q) error = %v", redirect, err)
		}
	}
	for _, redirect := range []string{
		"https://127.0.0.1:18987/oauth/callback",
		"http://localhost:18987/oauth/callback",
		"http://127.0.0.1/oauth/callback",
		"http://127.0.0.1:18987/oauth/callback?code=x",
	} {
		if err := ValidateLoopbackRedirect(redirect); !errors.Is(err, ErrInvalidEndpoint) {
			t.Fatalf("ValidateLoopbackRedirect(%q) error = %v", redirect, err)
		}
	}
}
