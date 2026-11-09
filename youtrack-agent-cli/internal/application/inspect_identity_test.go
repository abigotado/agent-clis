package application

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/auth"
	"github.com/abigotado/youtrack-agent-cli/internal/endpoint"
	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/profile"
)

type fixedCredentials struct{ value auth.Credential }

func (*fixedCredentials) Exists(context.Context, string) (bool, error) { return true, nil }
func (store *fixedCredentials) Load(context.Context, string) (auth.Credential, error) {
	return store.value, nil
}
func (*fixedCredentials) Save(context.Context, string, auth.Credential) error { return nil }
func (*fixedCredentials) Delete(context.Context, string) error                { return nil }
func (*fixedCredentials) MigrateKeychain(context.Context, string) error       { return nil }

func TestInspectVerifiesCurrentAccountBeforeEveryTargetRead(t *testing.T) {
	tests := []struct {
		name       string
		targetPath string
		response   string
		invoke     func(context.Context, *Service) error
	}{
		{
			name: "issue", targetPath: "/api/issues/APP-1",
			response: `{"id":"2-1","idReadable":"APP-1","summary":"S","project":{"id":"0-1","shortName":"APP","name":"App","archived":false},"created":1,"updated":2,"commentsCount":0,"customFields":[]}`,
			invoke: func(ctx context.Context, service *Service) error {
				_, _, err := service.InspectIssue(ctx, "work", "APP-1")
				return err
			},
		},
		{
			name: "comments", targetPath: "/api/issues/APP-1/comments", response: `[]`,
			invoke: func(ctx context.Context, service *Service) error {
				_, _, _, err := service.InspectComments(ctx, "work", "APP-1", 10, 0)
				return err
			},
		},
		{
			name: "project", targetPath: "/api/admin/projects/APP",
			response: `{"id":"0-1","shortName":"APP","name":"App","archived":false}`,
			invoke: func(ctx context.Context, service *Service) error {
				_, _, err := service.InspectProject(ctx, "work", "APP")
				return err
			},
		},
		{
			name: "schema", targetPath: "/api/admin/projects/APP/customFields", response: `[]`,
			invoke: func(ctx context.Context, service *Service) error {
				_, _, _, err := service.InspectSchema(ctx, "work", "APP", 1, 0)
				return err
			},
		},
	}
	for _, test := range tests {
		for _, mismatch := range []bool{false, true} {
			name := "match"
			if mismatch {
				name = "mismatch"
			}
			t.Run(test.name+"/"+name, func(t *testing.T) {
				var paths []string
				server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					paths = append(paths, request.URL.Path)
					writer.Header().Set("Content-Type", "application/json")
					switch request.URL.Path {
					case "/api/users/me":
						login := "alice"
						if mismatch {
							login = "mallory"
						}
						_, _ = io.WriteString(writer, `{"id":"1-2","login":"`+login+`"}`)
					case test.targetPath:
						_, _ = io.WriteString(writer, test.response)
					default:
						t.Fatalf("unexpected path %s", request.URL.Path)
					}
				}))
				defer server.Close()
				service := inspectTestService(t, server)
				err := test.invoke(context.Background(), service)
				if mismatch {
					if err == nil || !reflect.DeepEqual(paths, []string{"/api/users/me"}) {
						t.Fatalf("err=%v paths=%v", err, paths)
					}
					return
				}
				if err != nil || !reflect.DeepEqual(paths, []string{"/api/users/me", test.targetPath}) {
					t.Fatalf("err=%v paths=%v", err, paths)
				}
			})
		}
	}
}

func TestInspectSchemaMinimumLimitOversizeIsNotReportedAsReducible(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/users/me":
			_, _ = io.WriteString(writer, `{"id":"1-2","login":"alice"}`)
		case "/api/admin/projects/APP/customFields":
			if request.URL.Query().Get("$top") != "2" {
				t.Fatalf("$top = %q", request.URL.Query().Get("$top"))
			}
			_, _ = writer.Write(bytes.Repeat([]byte("x"), (5<<20)+1))
		default:
			t.Fatalf("unexpected path %s", request.URL.Path)
		}
	}))
	defer server.Close()

	_, _, _, err := inspectTestService(t, server).InspectSchema(t.Context(), "work", "APP", 1, 0)
	var typed *errx.Error
	if !errors.As(err, &typed) || typed.Code != errx.CodeInternal || typed.Reason != "RESPONSE_TOO_LARGE" {
		t.Fatalf("error = %#v", err)
	}
	if !strings.Contains(typed.Hint, "do not retry unchanged") || strings.Contains(typed.Hint, "--limit") {
		t.Fatalf("hint = %q", typed.Hint)
	}
}

func inspectTestService(t *testing.T, server *httptest.Server) *Service {
	t.Helper()
	mcpURL, err := endpoint.CanonicalMCPURL(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	value := profile.Profile{
		Name: "work", ServiceURL: server.URL, RESTBaseURL: server.URL + endpoint.RESTPath, MCPURL: mcpURL,
		OAuth: profile.OAuthConfig{
			IssuerURL: "https://hub.example.test", AuthorizationURL: "https://hub.example.test" + endpoint.OAuthAuthorizationPath,
			TokenURL: "https://hub.example.test" + endpoint.OAuthTokenPath, ClientID: "client", Scopes: []string{"YouTrack"},
			RedirectURI: "http://127.0.0.1:18987/oauth/callback",
		},
		ExpectedAccountID: "1-2", ExpectedLogin: "alice", Capabilities: []profile.Capability{profile.CapabilityRead},
		Executor: profile.ExecutorRESTBestEffort, Assurance: profile.AssuranceBestEffort,
	}
	value, err = value.WithNewCredentialGeneration()
	if err != nil {
		t.Fatal(err)
	}
	registry := profile.NewRegistry(filepath.Join(t.TempDir(), "config", "profiles.json"))
	if err := registry.Add(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	credential, err := auth.BindCredential(auth.Credential{Kind: auth.CredentialPermanentToken, PermanentToken: "perm:TEST"}, value)
	if err != nil {
		t.Fatal(err)
	}
	return &Service{Profiles: registry, Credentials: &fixedCredentials{value: credential}, HTTP: server.Client().Transport}
}
