package application

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/auth"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
)

// saveRecorder keeps every credential handed to Save, in order.
type saveRecorder struct {
	*oauthCredentialStore
	saved []auth.Credential
}

func (r *saveRecorder) Save(ctx context.Context, name string, value auth.Credential) error {
	r.saved = append(r.saved, value)
	return r.oauthCredentialStore.Save(ctx, name, value)
}

type refreshPrecheckFixture struct {
	service  *Service
	store    *oauthCredentialStore
	logs     *bytes.Buffer
	requests *int
}

func newRefreshPrecheckFixture(t *testing.T, expires time.Time, saveErr error) *refreshPrecheckFixture {
	t.Helper()
	selected := oauthApplicationProfile(t, true)
	bound, err := auth.BindCredential(auth.Credential{
		Kind: auth.CredentialOAuth, AccessToken: "old-access", RefreshToken: "old-refresh", TokenType: "Bearer",
		AccessTokenExpiresAt: expires, OAuthScopes: []string{"beta"},
	}, selected)
	if err != nil {
		t.Fatal(err)
	}
	store := &oauthCredentialStore{value: bound, exists: true, saveErr: saveErr}
	requests := 0
	transport := oauthDiagnosticTransport(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Host {
		case "hub.example.test":
		case "tracker.example.test":
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"id":"1-42","login":"alice"}`)), Header: make(http.Header)}, nil
		default:
			return nil, fmt.Errorf("unexpected origin %s", request.URL.Host)
		}
		requests++
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"access_token":"new-access-marker","refresh_token":"new-refresh-marker","token_type":"Bearer","expires_in":3600}`)),
			Header:     make(http.Header),
		}, nil
	})
	service := oauthApplicationService(t, selected, store, transport)
	service.Now = func() time.Time { return time.Unix(1_700_000_100, 0).UTC() }
	logs := &bytes.Buffer{}
	service.Logger = slog.New(slog.NewTextHandler(logs, nil))
	return &refreshPrecheckFixture{service: service, store: store, logs: logs, requests: &requests}
}

func TestRefreshPrecheckStopsBeforeTheTokenEndpoint(t *testing.T) {
	const marker = "precheck-private-marker"
	for _, test := range []struct {
		name   string
		err    error
		reason string
		exit   errx.Code
	}{
		{"store unavailable", auth.ErrCredentialStoreUnavailable, "CREDENTIAL_STORE_UNAVAILABLE", errx.CodePermission},
		{"store read only", auth.ErrCredentialStoreReadOnly, "CREDENTIAL_STORE_READ_ONLY", errx.CodePermission},
		{"store contended", auth.ErrCredentialStoreContended, "CREDENTIAL_STORE_CONTENDED", errx.CodeConflict},
		{"store internal", auth.ErrCredentialStoreInternal, "INTERNAL", errx.CodeInternal},
		{"interaction not allowed", auth.ErrInteractionNotAllowed, "KEYCHAIN_INTERACTION_REQUIRED", errx.CodeAuth},
		{"migration required", auth.ErrKeychainMigrationRequired, "CONFIRMATION_REQUIRED", errx.CodeConfirm},
		{"generic status error", &auth.StatusError{Operation: "private-operation-marker", Status: -25293}, "INTERNAL", errx.CodeInternal},
		{"context canceled", context.Canceled, "CANCELED", errx.CodeRetryable},
		{"deadline exceeded", context.DeadlineExceeded, "TIMEOUT", errx.CodeRetryable},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRefreshPrecheckFixture(t, time.Unix(1_700_000_000, 0).UTC(), fmt.Errorf("%s: %w", marker, test.err))

			_, err := fixture.service.AuthStatus(t.Context(), "work", true)
			if err == nil {
				t.Fatal("refresh unexpectedly succeeded after the pre-check Save failed")
			}
			if *fixture.requests != 0 || fixture.store.saveCalls != 1 {
				t.Fatalf("token requests=%d saves=%d, want 0 and 1", *fixture.requests, fixture.store.saveCalls)
			}
			var typed *errx.Error
			if !errors.As(TranslateError(err, "work"), &typed) || typed.Reason != test.reason || typed.Code != test.exit {
				t.Fatalf("recovery=%#v, want %s exit %d", typed, test.reason, test.exit)
			}
			if strings.Contains(typed.Message, "uncertain") || strings.Contains(typed.Hint, "uncertain") {
				t.Errorf("a pre-check failure redeemed nothing, yet reads as uncertain: %q %q", typed.Message, typed.Hint)
			}
			text := typed.Message + typed.Hint + fixture.logs.String()
			for _, secret := range []string{marker, "private-operation-marker", "-25293", "old-access", "old-refresh", "new-access-marker", "new-refresh-marker"} {
				if strings.Contains(text, secret) {
					t.Errorf("error or log exposes %q: %q", secret, text)
				}
			}
		})
	}
}

func TestRefreshPrecheckSucceedsThenSavesTheRotatedCredential(t *testing.T) {
	fixture := newRefreshPrecheckFixture(t, time.Unix(1_700_000_000, 0).UTC(), nil)
	recorder := &saveRecorder{oauthCredentialStore: fixture.store}
	fixture.service.Credentials = recorder

	status, err := fixture.service.AuthStatus(t.Context(), "work", true)
	if err != nil || status.State != "valid" {
		t.Fatalf("status=%#v err=%v", status, err)
	}
	if len(recorder.saved) != 2 || *fixture.requests != 1 {
		t.Fatalf("saves=%d token requests=%d, want 2 and 1", len(recorder.saved), *fixture.requests)
	}
	if first := recorder.saved[0]; first.AccessToken != "old-access" || first.RefreshToken != "old-refresh" {
		t.Errorf("pre-check Save must carry the unchanged credential, got access=%q refresh=%q", first.AccessToken, first.RefreshToken)
	}
	if second := recorder.saved[1]; second.AccessToken != "new-access-marker" || second.RefreshToken != "new-refresh-marker" {
		t.Errorf("second Save must carry the rotated credential, got access=%q refresh=%q", second.AccessToken, second.RefreshToken)
	}
}

func TestRefreshPrecheckKeepsPostRedemptionSaveFailureUncertain(t *testing.T) {
	const marker = "post-redeem-private-marker"
	fixture := newRefreshPrecheckFixture(t, time.Unix(1_700_000_000, 0).UTC(), fmt.Errorf("%s: %w", marker, auth.ErrCredentialStoreReadOnly))
	fixture.store.saveErrAfter = 1

	_, err := fixture.service.AuthStatus(t.Context(), "work", true)
	if *fixture.requests != 1 || fixture.store.saveCalls != 2 {
		t.Fatalf("token requests=%d saves=%d, want 1 and 2", *fixture.requests, fixture.store.saveCalls)
	}
	var typed *errx.Error
	if !errors.As(TranslateError(err, "work"), &typed) || typed.Reason != "OAUTH_TOKEN_EXCHANGE_FAILED" || typed.Code != errx.CodeAuth ||
		!strings.Contains(typed.Message, "persistence is uncertain") {
		t.Fatalf("recovery=%#v, want the unchanged persistence-uncertain auth/5", typed)
	}
	text := typed.Message + typed.Hint + fixture.logs.String()
	for _, secret := range []string{marker, "new-access-marker", "new-refresh-marker", "old-refresh"} {
		if strings.Contains(text, secret) {
			t.Errorf("error or log exposes %q", secret)
		}
	}
}

func TestRefreshNotDueDoesNoSaveAndNoTokenRequest(t *testing.T) {
	fixture := newRefreshPrecheckFixture(t, time.Unix(1_700_000_100, 0).Add(refreshSkew+time.Hour).UTC(), nil)

	status, err := fixture.service.AuthStatus(t.Context(), "work", true)
	if err != nil || status.State != "valid" {
		t.Fatalf("status=%#v err=%v", status, err)
	}
	if *fixture.requests != 0 || fixture.store.saveCalls != 0 {
		t.Fatalf("token requests=%d saves=%d, want 0 and 0", *fixture.requests, fixture.store.saveCalls)
	}
}
