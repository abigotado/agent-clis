package application

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/auth"
	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/oauth"
	"github.com/abigotado/youtrack-agent-cli/internal/profile"
	"github.com/abigotado/youtrack-agent-cli/internal/youtrack"
)

// Browser opens one public authorization URL without receiving credentials.
type Browser interface {
	Open(ctx context.Context, authorizationURL string) error
}

// SystemBrowser opens the macOS default browser through the fixed system tool.
type SystemBrowser struct{}

func (SystemBrowser) Open(ctx context.Context, authorizationURL string) error {
	if runtime.GOOS != "darwin" {
		return errx.Usage("interactive OAuth browser login is supported only on macOS in this release")
	}
	if err := exec.CommandContext(ctx, "/usr/bin/open", authorizationURL).Run(); err != nil {
		return fmt.Errorf("open OAuth authorization URL: %w", err)
	}
	return nil
}

// LoginOAuth runs one public-client Authorization Code + PKCE session, checks
// the exact expected account, and persists the rotated credential atomically.
func (s *Service) LoginOAuth(ctx context.Context, name string, replace bool, browser Browser) (profile.Profile, error) {
	value, err := s.GetProfile(ctx, name)
	if err != nil {
		return profile.Profile{}, err
	}
	loginIntent, err := value.LoginIntent()
	if err != nil {
		return profile.Profile{}, err
	}
	if err := s.requireCredentialReplacementConfirmation(ctx, name, replace); err != nil {
		return profile.Profile{}, err
	}
	config := oauthConfig(value)
	session, err := oauth.NewSession(nil)
	if err != nil {
		return profile.Profile{}, err
	}
	authorizationURL, err := oauth.AuthorizationURL(config, session)
	if err != nil {
		return profile.Profile{}, err
	}
	callback, err := startCallback(ctx, config, session.State)
	if err != nil {
		return profile.Profile{}, err
	}
	defer callback.Close(ctx)
	if browser == nil {
		browser = SystemBrowser{}
	}
	if err := browser.Open(ctx, authorizationURL); err != nil {
		return profile.Profile{}, err
	}
	code, err := callback.Wait(ctx)
	if err != nil {
		return profile.Profile{}, err
	}
	oauthClient, err := oauth.NewClient(config, s.HTTP)
	if err != nil {
		return profile.Profile{}, err
	}
	tokens, err := oauthClient.Exchange(ctx, code, session.Verifier)
	if err != nil {
		return profile.Profile{}, err
	}
	credential := auth.Credential{
		Kind: auth.CredentialOAuth, AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken,
		TokenType: tokens.TokenType, AccessTokenExpiresAt: tokens.ExpiresAt,
		OAuthScopes: append([]string(nil), tokens.Scopes...),
	}
	client, err := youtrack.New(youtrack.Config{RESTBaseURL: value.RESTBaseURL}, youtrack.Credential{Token: tokens.AccessToken}, youtrack.WithHTTPClient(&http.Client{Transport: s.HTTP}), youtrack.WithLogger(s.Logger))
	if err != nil {
		return profile.Profile{}, err
	}
	current, err := client.CurrentUser(ctx)
	if err != nil {
		return profile.Profile{}, err
	}
	if err := verifyAccount(value, current); err != nil {
		return profile.Profile{}, err
	}
	return auth.Login(ctx, s.Credentials, s.Profiles, loginIntent, credential, replace)
}

type callbackServer struct {
	server    *http.Server
	result    chan callbackResult
	once      sync.Once
	closeOnce sync.Once
	done      chan struct{}
	ctx       context.Context
}

type callbackResult struct {
	code string
	err  error
}

func startCallback(ctx context.Context, config oauth.Config, expectedState string) (*callbackServer, error) {
	redirect, err := url.Parse(config.RedirectURI)
	if err != nil {
		return nil, errx.Usage("OAuth redirect URI is invalid")
	}
	listener, err := net.Listen("tcp", redirect.Host)
	if err != nil {
		return nil, fmt.Errorf("listen on the configured OAuth loopback callback: %w", err)
	}
	callback := &callbackServer{result: make(chan callbackResult, 1), done: make(chan struct{}), ctx: ctx}
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.Host != redirect.Host || request.URL.Path != redirect.Path {
			http.NotFound(writer, request)
			return
		}
		actual := *redirect
		actual.RawQuery = request.URL.RawQuery
		code, parseErr := oauth.ParseCallback(config, actual.String(), expectedState)
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.Header().Set("Cache-Control", "no-store")
		if parseErr != nil {
			http.Error(writer, "Authorization failed. Return to the terminal.", http.StatusBadRequest)
			if errors.Is(parseErr, oauth.ErrAuthorizationDenied) {
				callback.once.Do(func() { callback.result <- callbackResult{err: parseErr} })
			}
			return
		}
		callback.once.Do(func() { callback.result <- callbackResult{code: code} })
		_, _ = writer.Write([]byte("Authorization received. You can close this window."))
	})
	callback.server = &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8 << 10}
	go func() {
		serveErr := callback.server.Serve(listener)
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			callback.once.Do(func() { callback.result <- callbackResult{err: fmt.Errorf("serve OAuth callback: %w", serveErr)} })
		}
	}()
	go func() {
		select {
		case <-ctx.Done():
			callback.Close(ctx)
		case <-callback.done:
		}
	}()
	return callback, nil
}

func (callback *callbackServer) Wait(ctx context.Context) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case result := <-callback.result:
		return result.code, result.err
	}
}

func (callback *callbackServer) Close(parent context.Context) {
	if callback == nil || callback.server == nil {
		return
	}
	if parent == nil {
		parent = callback.ctx
	}
	callback.closeOnce.Do(func() {
		close(callback.done)
		ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), time.Second)
		defer cancel()
		_ = callback.server.Shutdown(ctx)
	})
}
