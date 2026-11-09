package application

import (
	"errors"
	"os"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/profile"
)

func defaultName(value string) *string { return &value }

func requireReason(t *testing.T, err error, want string) {
	t.Helper()
	var typed *errx.Error
	if !errors.As(err, &typed) || typed.Reason != want {
		t.Fatalf("error=%#v, want reason %q", err, want)
	}
}

func TestChangeProfileDefaultsBindsRolesAndDryRunDoesNotWrite(t *testing.T) {
	service, credentials, transport := mutationService(t)
	path := service.Profiles.DefaultsPath()

	preview, err := service.ChangeProfileDefaults(t.Context(), defaultName("work"), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Read.State != "valid" || preview.Read.ProfileName != "work" || preview.Write.State != "unset" {
		t.Fatalf("preview=%#v", preview)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dry run defaults file stat error=%v, want not exist", err)
	}

	updated, err := service.ChangeProfileDefaults(t.Context(), defaultName("work"), defaultName("work"), false)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Read.State != "valid" || updated.Write.State != "valid" || updated.Read.ProfileIdentitySHA256 == "" || updated.Write.ProfileIdentitySHA256 == "" {
		t.Fatalf("updated=%#v", updated)
	}
	if credentials.calls != 0 || transport.calls != 0 {
		t.Fatalf("defaults change touched credentials=%d network=%d", credentials.calls, transport.calls)
	}
}

func TestChangeProfileDefaultsRejectsWriteIneligibleProfileWithoutCreatingDefaults(t *testing.T) {
	service, credentials, transport := mutationService(t)
	readOnly, err := service.Profiles.Get(t.Context(), "work")
	if err != nil {
		t.Fatal(err)
	}
	readOnly.Name = "readonly"
	readOnly.Capabilities = []profile.Capability{profile.CapabilityRead}
	if err := service.Profiles.Add(t.Context(), readOnly); err != nil {
		t.Fatal(err)
	}
	_, err = service.ChangeProfileDefaults(t.Context(), nil, defaultName("readonly"), false)
	requireReason(t, err, "USAGE")
	if _, statErr := os.Stat(service.Profiles.DefaultsPath()); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("ineligible default created defaults file: %v", statErr)
	}
	if credentials.calls != 0 || transport.calls != 0 {
		t.Fatalf("eligibility check touched credentials=%d network=%d", credentials.calls, transport.calls)
	}
}

func TestChangeProfileDefaultsAcceptsEachOperatorWriteCapabilityAlone(t *testing.T) {
	for _, capability := range []profile.Capability{profile.CapabilityIssueCreate, profile.CapabilityIssueUpdate, profile.CapabilityCommentAdd} {
		t.Run(string(capability), func(t *testing.T) {
			service, _, _ := mutationService(t)
			writer, err := service.Profiles.Get(t.Context(), "work")
			if err != nil {
				t.Fatal(err)
			}
			writer.Name = "writer"
			writer.Capabilities = []profile.Capability{profile.CapabilityRead, capability}
			writer.Executor, writer.Assurance = profile.ExecutorRESTBestEffort, profile.AssuranceBestEffort
			if err := service.Profiles.Add(t.Context(), writer); err != nil {
				t.Fatal(err)
			}
			updated, err := service.ChangeProfileDefaults(t.Context(), nil, defaultName("writer"), false)
			if err != nil || updated.Write.State != "valid" || updated.Write.ProfileName != "writer" {
				t.Fatalf("write default=%#v err=%v", updated.Write, err)
			}
		})
	}
}

func TestProfileDefaultsShowAndResolveFailClosedForMissingAndStaleSlots(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, service *Service)
		state  string
	}{
		{
			name: "missing profile",
			mutate: func(t *testing.T, service *Service) {
				t.Helper()
				if err := service.Profiles.Remove(t.Context(), "work"); err != nil {
					t.Fatal(err)
				}
			},
			state: "missing_profile",
		},
		{
			name: "changed profile topology",
			mutate: func(t *testing.T, service *Service) {
				t.Helper()
				value, err := service.Profiles.Get(t.Context(), "work")
				if err != nil {
					t.Fatal(err)
				}
				value.ExpectedLogin = "bob"
				if err := service.Profiles.Put(t.Context(), value); err != nil {
					t.Fatal(err)
				}
			},
			state: "stale",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, credentials, transport := mutationService(t)
			if _, err := service.ChangeProfileDefaults(t.Context(), defaultName("work"), nil, false); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, service)
			info, err := service.GetProfileDefaults(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if info.Read.State != test.state {
				t.Fatalf("info=%#v, want read state %q", info, test.state)
			}
			_, _, err = service.ResolveSavedProfile(t.Context(), "read")
			requireReason(t, err, "PROFILE_DEFAULT_STALE")
			if credentials.calls != 0 || transport.calls != 0 {
				t.Fatalf("show/resolve touched credentials=%d network=%d", credentials.calls, transport.calls)
			}
		})
	}
}

func TestClearProfileDefaultsNeedsNoProfileCredentialOrNetwork(t *testing.T) {
	service, credentials, transport := mutationService(t)
	if _, err := service.ChangeProfileDefaults(t.Context(), defaultName("work"), defaultName("work"), false); err != nil {
		t.Fatal(err)
	}
	if err := service.Profiles.Remove(t.Context(), "work"); err != nil {
		t.Fatal(err)
	}
	cleared, err := service.ClearProfileDefaults(t.Context(), true, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if cleared.Read.State != "unset" || cleared.Write.State != "unset" {
		t.Fatalf("cleared=%#v", cleared)
	}
	if credentials.calls != 0 || transport.calls != 0 {
		t.Fatalf("clear touched credentials=%d network=%d", credentials.calls, transport.calls)
	}
}

func TestSavedDefaultGuardRejectsReplacementBeforeCredentialsOrHTTP(t *testing.T) {
	service, credentials, transport := mutationService(t)
	if _, err := service.ChangeProfileDefaults(t.Context(), defaultName("work"), nil, false); err != nil {
		t.Fatal(err)
	}
	guarded, name, err := service.ResolveSavedProfile(t.Context(), "read")
	if err != nil || name != "work" {
		t.Fatalf("ResolveSavedProfile() name=%q err=%v", name, err)
	}
	replacement, err := service.Profiles.Get(t.Context(), name)
	if err != nil {
		t.Fatal(err)
	}
	replacement.ExpectedLogin = "bob"
	if err := service.Profiles.Put(t.Context(), replacement); err != nil {
		t.Fatal(err)
	}
	_, _, err = service.InspectIssue(guarded, name, "APP-1")
	requireReason(t, err, "PROFILE_DEFAULT_STALE")
	if credentials.calls != 0 || transport.calls != 0 {
		t.Fatalf("stale guarded read touched credentials=%d network=%d", credentials.calls, transport.calls)
	}
}
