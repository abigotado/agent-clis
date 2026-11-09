package writepolicy

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/endpoint"
	"github.com/abigotado/youtrack-agent-cli/internal/profile"
)

func policyProfile(name string) profile.Profile {
	service := "https://tracker.example.test"
	mcp, err := endpoint.CanonicalMCPURL(service)
	if err != nil {
		panic(err)
	}
	issuer := "https://hub.example.test"
	value := profile.Profile{
		Name: name, ServiceURL: service, RESTBaseURL: service + "/api", MCPURL: mcp,
		OAuth: profile.OAuthConfig{IssuerURL: issuer, AuthorizationURL: issuer + endpoint.OAuthAuthorizationPath,
			TokenURL: issuer + endpoint.OAuthTokenPath, ClientID: "client", Scopes: []string{"YouTrack"}, RedirectURI: "http://127.0.0.1:18987/oauth/callback"},
		ExpectedAccountID: "1-42", ExpectedLogin: "alice",
		Capabilities: []profile.Capability{profile.CapabilityRead, profile.CapabilityIssueUpdate},
		Executor:     profile.ExecutorRESTBestEffort, Assurance: profile.AssuranceBestEffort,
	}
	bound, err := value.WithNewCredentialGeneration()
	if err != nil {
		panic(err)
	}
	return bound
}

func TestCanonicalProjects(t *testing.T) {
	got, err := CanonicalProjects([]Project{{ID: "0-2", Key: "APP"}, {ID: "0-1", Key: "CORE"}, {ID: "0-2", Key: "APP"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != (Project{ID: "0-1", Key: "CORE"}) {
		t.Fatalf("projects=%#v", got)
	}
	for _, input := range [][]Project{
		{}, {{ID: "0-1", Key: "lower"}}, {{ID: "0-1", Key: "A"}, {ID: "0-1", Key: "B"}}, {{ID: "0-1", Key: "A"}, {ID: "0-2", Key: "A"}},
	} {
		if _, err := CanonicalProjects(input); !errors.Is(err, ErrInvalid) {
			t.Fatalf("CanonicalProjects(%#v) error=%v", input, err)
		}
	}
}

func TestRegistryBindsFullProfileAndExactProjectPair(t *testing.T) {
	registry := NewRegistry(filepath.Join(t.TempDir(), "config", "write-policies.json"))
	selected := policyProfile("work")
	policy, err := registry.Set(context.Background(), selected, []Project{{ID: "0-1", Key: "CORE"}})
	if err != nil || policy.Identity != profile.CredentialIdentity(selected) || policy.Revision != 1 {
		t.Fatalf("Set()=%#v err=%v", policy, err)
	}
	updated, err := registry.Set(context.Background(), selected, []Project{{ID: "0-1", Key: "CORE"}})
	if err != nil || updated.Revision != 2 {
		t.Fatalf("second Set()=%#v err=%v", updated, err)
	}
	if _, err := registry.RequireProject(context.Background(), selected, "0-1", "CORE"); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.RequireProject(context.Background(), selected, "0-1", "OTHER"); !errors.Is(err, ErrProjectDenied) {
		t.Fatalf("wrong key error=%v", err)
	}
	changed := selected
	changed.ExpectedAccountID = "1-43"
	if _, err := registry.GetBound(context.Background(), changed); !errors.Is(err, ErrStale) {
		t.Fatalf("changed identity error=%v", err)
	}
}

func TestRegistryRequiresAuthenticatedMutationProfile(t *testing.T) {
	registry := NewRegistry(filepath.Join(t.TempDir(), "config", "write-policies.json"))
	selected := policyProfile("work")
	selected.CredentialGeneration = ""
	if _, err := registry.Set(context.Background(), selected, []Project{{ID: "0-1", Key: "CORE"}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing generation error=%v", err)
	}
	selected = policyProfile("work")
	selected.Capabilities = []profile.Capability{profile.CapabilityRead}
	if _, err := registry.Set(context.Background(), selected, []Project{{ID: "0-1", Key: "CORE"}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("read-only error=%v", err)
	}
}
