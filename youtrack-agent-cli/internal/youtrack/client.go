// Package youtrack implements the fixed-origin YouTrack 2026.2 REST boundary.
//
// The package exposes only typed, field-minimal operations. It never accepts an
// arbitrary HTTP method, path, URL, or response shape from its caller.
package youtrack

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
)

const (
	maxReadAttempts         = 3
	maxRetryAfterDelay      = 30 * time.Second
	maxCompressedBodyBytes  = 4 << 20
	maxResponseBodyBytes    = 4 << 20
	maxDrainBodyBytes       = 64 << 10
	maxTokenBytes           = 16 << 10
	maxIdentifierBytes      = 128
	maxQueryBytes           = 4096
	maxCollectionPageSize   = 101 // one sentinel beyond the public 100-item page
	defaultCollectionLimit  = 25
	maxCustomFieldValueSize = 1 << 20
)

// Config pins the complete REST API base. For a service mounted at
// https://host/youtrack, RESTBaseURL is https://host/youtrack/api.
type Config struct {
	RESTBaseURL string
}

// Credential contains one OAuth access token or permanent YouTrack token.
// Both credential kinds use the Bearer authorization scheme.
type Credential struct {
	Token string `json:"-"`
}

// Format redacts the credential for every fmt verb.
func (Credential) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "<redacted>")
}

// LogValue prevents structured logging from reflecting token material.
func (Credential) LogValue() slog.Value { return slog.StringValue("<redacted>") }

// Client is a fixed-origin YouTrack REST client.
type Client struct {
	baseURL *url.URL
	token   string
	http    *http.Client
	log     *slog.Logger
	sleep   func(context.Context, time.Duration) error
	now     func() time.Time
}

// Option customizes a Client without allowing its fixed endpoint to change.
type Option func(*Client)

// WithHTTPClient injects an HTTP client while still refusing redirects and
// discarding cookie state.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(client *Client) {
		if httpClient == nil {
			return
		}
		clone := *httpClient
		clone.CheckRedirect = refuseRedirect
		clone.Jar = nil
		client.http = &clone
	}
}

// WithLogger installs a diagnostic logger. Logs contain operation names,
// attempt numbers, delays, and status codes only.
func WithLogger(logger *slog.Logger) Option {
	return func(client *Client) {
		if logger != nil {
			client.log = logger
		}
	}
}

// WithSleep replaces retry waiting for deterministic tests.
func WithSleep(sleep func(context.Context, time.Duration) error) Option {
	return func(client *Client) {
		if sleep != nil {
			client.sleep = sleep
		}
	}
}

// New validates and pins a YouTrack REST base before retaining credential
// material. The base must be an absolute HTTPS URL ending in /api.
func New(config Config, credential Credential, options ...Option) (*Client, error) {
	baseURL, err := validateRESTBaseURL(config.RESTBaseURL)
	if err != nil {
		return nil, errx.Usage("YouTrack REST base URL is invalid")
	}
	if err := validateToken(credential.Token); err != nil {
		return nil, err
	}

	client := &Client{
		baseURL: baseURL,
		token:   credential.Token,
		http: &http.Client{
			CheckRedirect: refuseRedirect,
		},
		log:   slog.New(discardHandler{}),
		sleep: sleepContext,
		now:   time.Now,
	}
	for _, option := range options {
		option(client)
	}
	return client, nil
}

type request struct {
	method        string
	path          string
	query         url.Values
	body          []byte
	operation     string
	write         bool
	pageReducible bool
}

func (client *Client) readJSON(ctx context.Context, request request, out any) error {
	request.method = http.MethodGet
	var lastErr error
	for attempt := 1; attempt <= maxReadAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return errx.Translate(err)
		}
		response, err := client.send(ctx, request)
		if err != nil {
			if ctx.Err() != nil {
				return errx.Translate(ctx.Err())
			}
			lastErr = errx.Retryable("NETWORK", 0, "could not reach YouTrack")
			if attempt == maxReadAttempts {
				return lastErr
			}
			delay := retryBackoff(attempt)
			if !retryDelayFitsContext(ctx, delay) {
				return lastErr
			}
			if err := client.sleep(ctx, delay); err != nil {
				return errx.Translate(err)
			}
			continue
		}

		delay, retry, translated := client.handleReadResponse(response, request, out)
		if translated == nil {
			return nil
		}
		lastErr = translated
		if !retry || attempt == maxReadAttempts {
			return translated
		}
		if delay <= 0 {
			delay = retryBackoff(attempt)
		}
		if !retryDelayFitsContext(ctx, delay) {
			return translated
		}
		client.log.Debug("retrying YouTrack read", "operation", request.operation, "attempt", attempt, "delay", delay)
		if err := client.sleep(ctx, delay); err != nil {
			return errx.Translate(err)
		}
	}
	return lastErr
}

func (client *Client) writeJSON(ctx context.Context, request request, out any) error {
	request.write = true
	response, err := client.send(ctx, request)
	if err != nil {
		return errx.WriteOutcomeUnknown(request.operation)
	}
	if response == nil || response.Body == nil {
		return errx.WriteOutcomeUnknown(request.operation)
	}
	defer closeAndDrain(response.Body)

	if response.StatusCode != http.StatusOK {
		return client.translateWriteStatus(response, request.operation)
	}
	body, tooLarge, readErr := readResponseBody(response)
	if readErr != nil || tooLarge || len(bytes.TrimSpace(body)) == 0 {
		return errx.WriteOutcomeUnknown(request.operation)
	}
	if err := decodeOneJSON(body, out); err != nil {
		return errx.WriteOutcomeUnknown(request.operation)
	}
	return nil
}

func (client *Client) send(ctx context.Context, request request) (*http.Response, error) {
	requestURL := *client.baseURL
	requestURL.Path = strings.TrimSuffix(client.baseURL.Path, "/") + request.path
	requestURL.RawPath = ""
	requestURL.RawQuery = request.query.Encode()

	var body io.Reader
	if request.write {
		body = &nonReplayableReader{reader: bytes.NewReader(request.body)}
	}
	httpRequest, err := http.NewRequestWithContext(ctx, request.method, requestURL.String(), body)
	if err != nil {
		return nil, errors.New("invalid YouTrack request")
	}
	if request.write {
		httpRequest.ContentLength = int64(len(request.body))
		httpRequest.Header.Set("Content-Type", "application/json")
	}
	httpRequest.Header.Set("Accept", "application/json")
	// Explicit gzip handling lets us enforce separate wire and decoded bounds.
	httpRequest.Header.Set("Accept-Encoding", "gzip")
	httpRequest.Header.Set("Authorization", "Bearer "+client.token)
	client.log.Debug("YouTrack request", "operation", request.operation)
	return client.http.Do(httpRequest)
}

func (client *Client) handleReadResponse(response *http.Response, request request, out any) (time.Duration, bool, error) {
	if response == nil || response.Body == nil {
		return 0, true, errx.Retryable("INVALID_RESPONSE", 0, "YouTrack returned no response")
	}
	defer closeAndDrain(response.Body)

	if response.StatusCode != http.StatusOK {
		return client.translateReadStatus(response, request.operation)
	}
	body, tooLarge, err := readResponseBody(response)
	if err != nil {
		return 0, false, errx.Internal("could not read the bounded YouTrack response")
	}
	if tooLarge {
		return 0, false, errx.ResponseTooLarge(request.operation, request.pageReducible, maxResponseBodyBytes)
	}
	if len(bytes.TrimSpace(body)) == 0 || decodeOneJSON(body, out) != nil {
		return 0, false, invalidReadResponse()
	}
	return 0, false, nil
}

func (client *Client) translateReadStatus(response *http.Response, operation string) (time.Duration, bool, error) {
	switch response.StatusCode {
	case http.StatusUnauthorized:
		return 0, false, errx.Auth("AUTHENTICATION_FAILED", "YouTrack rejected the credential")
	case http.StatusForbidden:
		return 0, false, errx.Permission("PERMISSION_DENIED", "the account cannot perform the requested YouTrack read")
	case http.StatusNotFound:
		return 0, false, errx.NotFound(resourceKind(operation), "requested", nil)
	case http.StatusTooManyRequests:
		delay, autoRetryAllowed := parseRetryAfter(response.Header.Get("Retry-After"), client.now())
		reportedDelay := delay
		if !autoRetryAllowed {
			reportedDelay = 0
		}
		rateLimitErr := errx.Retryable("RATE_LIMITED", reportedDelay, "YouTrack rate limited the read")
		if !autoRetryAllowed {
			rateLimitErr.WithHint("the server delay exceeds the 30s local cap; stop automatic retries and retry later")
		}
		return delay, autoRetryAllowed, rateLimitErr
	default:
		if response.StatusCode >= http.StatusInternalServerError {
			return 0, true, errx.Retryable("SERVER_ERROR", 0, "YouTrack is temporarily unavailable")
		}
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			return 0, false, errx.Internal("YouTrack redirect was refused")
		}
		return 0, false, errx.Internal("YouTrack returned unexpected HTTP status %d", response.StatusCode)
	}
}

func (client *Client) translateWriteStatus(response *http.Response, operation string) error {
	switch response.StatusCode {
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return errx.Usage("YouTrack rejected the %s request", operation)
	case http.StatusUnauthorized:
		return errx.Auth("AUTHENTICATION_FAILED", "YouTrack rejected the credential")
	case http.StatusForbidden:
		return errx.Permission("PERMISSION_DENIED", "the account cannot perform the requested YouTrack mutation")
	case http.StatusNotFound:
		return errx.Conflict("TARGET_CHANGED", "the YouTrack mutation target is no longer available")
	case http.StatusConflict, http.StatusPreconditionFailed:
		return errx.Conflict("PRECONDITION_FAILED", "YouTrack rejected stale mutation state")
	case http.StatusRequestEntityTooLarge:
		return errx.PayloadTooLarge(operation)
	case http.StatusTooManyRequests:
		return errx.WriteOutcomeUnknown(operation)
	default:
		return errx.WriteOutcomeUnknown(operation)
	}
}

func validateRESTBaseURL(raw string) (*url.URL, error) {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return nil, errors.New("REST base is empty or padded")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawPath != "" {
		return nil, errors.New("REST base must be an absolute HTTPS URL without credentials, query, or fragment")
	}
	if parsed.Path == "" || strings.HasSuffix(parsed.Path, "/") || path.Clean(parsed.Path) != parsed.Path ||
		!(parsed.Path == "/api" || strings.HasSuffix(parsed.Path, "/api")) {
		return nil, errors.New("REST base path must end in /api")
	}
	if raw != parsed.String() {
		return nil, errors.New("REST base must use its canonical URL spelling")
	}
	return parsed, nil
}

func validateToken(token string) error {
	if token == "" {
		return errx.Auth("MISSING_TOKEN", "YouTrack credential is missing")
	}
	if len(token) > maxTokenBytes || strings.ContainsAny(token, "\x00\r\n") {
		return errx.Auth("INVALID_TOKEN", "YouTrack credential is malformed")
	}
	return nil
}

func decodeOneJSON(body []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func readResponseBody(response *http.Response) ([]byte, bool, error) {
	encoding := strings.TrimSpace(response.Header.Get("Content-Encoding"))
	if encoding == "" || strings.EqualFold(encoding, "identity") {
		return readBounded(response.Body, maxResponseBodyBytes)
	}
	if !strings.EqualFold(encoding, "gzip") {
		return nil, false, errors.New("unsupported response content encoding")
	}
	compressed, tooLarge, err := readBounded(response.Body, maxCompressedBodyBytes)
	if err != nil || tooLarge {
		return nil, tooLarge, err
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, false, err
	}
	decompressed, tooLarge, readErr := readBounded(reader, maxResponseBodyBytes)
	closeErr := reader.Close()
	if readErr != nil {
		return nil, false, readErr
	}
	if closeErr != nil {
		return nil, false, closeErr
	}
	return decompressed, tooLarge, nil
}

func readBounded(reader io.Reader, limit int64) ([]byte, bool, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > limit {
		return data[:limit], true, nil
	}
	return data, false, nil
}

func closeAndDrain(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, maxDrainBodyBytes))
	_ = body.Close()
}

func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if seconds, err := strconv.ParseUint(value, 10, 64); err == nil {
		maximumSeconds := uint64(maxRetryAfterDelay / time.Second)
		if seconds > maximumSeconds {
			return maxRetryAfterDelay, false
		}
		return time.Duration(seconds) * time.Second, true
	} else if decimalDigits(value) {
		return maxRetryAfterDelay, false
	}
	when, err := http.ParseTime(value)
	if err != nil || !when.After(now) {
		return 0, true
	}
	delay := when.Sub(now)
	if delay > maxRetryAfterDelay {
		return maxRetryAfterDelay, false
	}
	return delay, true
}

func decimalDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func retryBackoff(attempt int) time.Duration {
	return time.Duration(attempt) * 250 * time.Millisecond
}

func retryDelayFitsContext(ctx context.Context, delay time.Duration) bool {
	if delay < 0 {
		return false
	}
	deadline, ok := ctx.Deadline()
	return !ok || time.Until(deadline) > delay
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func refuseRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

func invalidReadResponse() error {
	return errx.Internal("YouTrack returned an invalid read response")
}

func resourceKind(operation string) string {
	before, _, found := strings.Cut(operation, ".")
	if !found || before == "" {
		return "resource"
	}
	return strings.TrimSuffix(before, "s")
}

type nonReplayableReader struct {
	reader *bytes.Reader
}

func (reader *nonReplayableReader) Read(buffer []byte) (int, error) {
	return reader.reader.Read(buffer)
}

type discardHandler struct{}

func (discardHandler) Enabled(context.Context, slog.Level) bool   { return false }
func (discardHandler) Handle(context.Context, slog.Record) error  { return nil }
func (handler discardHandler) WithAttrs([]slog.Attr) slog.Handler { return handler }
func (handler discardHandler) WithGroup(string) slog.Handler      { return handler }
