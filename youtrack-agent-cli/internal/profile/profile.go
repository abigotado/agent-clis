// Package profile stores strict, non-secret YouTrack connection and identity
// metadata. It has no active-profile state and never reads credentials.
package profile

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/endpoint"
)

const (
	maxNameLength              = 64
	maxAccountValueLength      = 256
	credentialGenerationBytes  = 32
	credentialGenerationLength = 43
)

var (
	ErrProfileRequired     = errors.New("a profile is required for every invocation")
	ErrInvalidProfile      = errors.New("invalid profile")
	ErrNotFound            = errors.New("profile not found")
	ErrAlreadyExists       = errors.New("profile already exists")
	ErrCorruptRegistry     = errors.New("profile registry is corrupt")
	ErrInsecurePermissions = errors.New("profile registry has insecure permissions")
	ErrDefaultNotSet       = errors.New("profile default is not set")
	ErrDefaultStale        = errors.New("profile default identity is stale")

	namePattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	accountIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
	loginPattern      = regexp.MustCompile(`^[^\x00-\x20\x7f]+$`)
	clientIDPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
	scopeTokenPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)
)

// CommitError reports that an atomic profile rename succeeded but the
// following directory durability step failed.
type CommitError struct{ Err error }

func (e *CommitError) Error() string {
	return fmt.Sprintf("profile metadata committed but durability check failed: %v", e.Err)
}

func (e *CommitError) Unwrap() error { return e.Err }

func WasCommitted(err error) bool {
	var committed *CommitError
	return errors.As(err, &committed)
}

type Capability string

const (
	CapabilityRead          Capability = "read"
	CapabilityIssueCreate   Capability = "issue-create"
	CapabilityIssueUpdate   Capability = "issue-update"
	CapabilityCommentAdd    Capability = "comment-add"
	CapabilityCommentDelete Capability = "comment-delete"
	CapabilityIssueEdit     Capability = "issue-edit"
	CapabilityIssueLink     Capability = "issue-link"
)

type Executor string

const (
	ExecutorRESTBestEffort  Executor = "rest-best-effort"
	ExecutorCustomMCPAtomic Executor = "custom-mcp-atomic"
)

type Assurance string

const (
	AssuranceBestEffort   Assurance = "best-effort"
	AssuranceStrictAtomic Assurance = "strict-atomic"
)

// OAuthConfig contains public OAuth client metadata only. A client secret is
// intentionally unsupported because this binary is a public client.
type OAuthConfig struct {
	IssuerURL        string   `json:"issuer_url"`
	AuthorizationURL string   `json:"authorization_url"`
	TokenURL         string   `json:"token_url"`
	ClientID         string   `json:"client_id"`
	Scopes           []string `json:"scopes"`
	RedirectURI      string   `json:"redirect_uri"`
}

// Profile contains every non-secret value that constrains credential use.
// CredentialGeneration is absent before login and replaced on every login.
type Profile struct {
	Name                 string       `json:"name"`
	ServiceURL           string       `json:"service_url"`
	RESTBaseURL          string       `json:"rest_base_url"`
	MCPURL               string       `json:"mcp_url"`
	OAuth                OAuthConfig  `json:"oauth"`
	ExpectedAccountID    string       `json:"expected_account_id"`
	ExpectedLogin        string       `json:"expected_login"`
	CredentialGeneration string       `json:"credential_generation,omitempty"`
	Capabilities         []Capability `json:"capabilities"`
	Executor             Executor     `json:"executor"`
	Assurance            Assurance    `json:"assurance"`

	credentialGenerationPresent bool
}

// UnmarshalJSON rejects unknown fields and preserves a present null
// credential generation so malformed authenticated state cannot become an
// unauthenticated profile silently.
func (p *Profile) UnmarshalJSON(raw []byte) error {
	type wireProfile struct {
		Name                 string          `json:"name"`
		ServiceURL           string          `json:"service_url"`
		RESTBaseURL          string          `json:"rest_base_url"`
		MCPURL               string          `json:"mcp_url"`
		OAuth                OAuthConfig     `json:"oauth"`
		ExpectedAccountID    string          `json:"expected_account_id"`
		ExpectedLogin        string          `json:"expected_login"`
		CredentialGeneration json.RawMessage `json:"credential_generation"`
		Capabilities         []Capability    `json:"capabilities"`
		Executor             Executor        `json:"executor"`
		Assurance            Assurance       `json:"assurance"`
	}
	var wire wireProfile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return fmt.Errorf("%w: decode: %v", ErrInvalidProfile, err)
	}
	if err := requireDecodeEOF(decoder); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidProfile, err)
	}
	decoded := Profile{
		Name: wire.Name, ServiceURL: wire.ServiceURL, RESTBaseURL: wire.RESTBaseURL,
		MCPURL: wire.MCPURL, OAuth: wire.OAuth, ExpectedAccountID: wire.ExpectedAccountID,
		ExpectedLogin: wire.ExpectedLogin, Capabilities: wire.Capabilities,
		Executor: wire.Executor, Assurance: wire.Assurance,
	}
	if wire.CredentialGeneration != nil {
		decoded.credentialGenerationPresent = true
		if bytes.Equal(wire.CredentialGeneration, []byte("null")) {
			return fmt.Errorf("%w: credential_generation cannot be null", ErrInvalidProfile)
		}
		if err := json.Unmarshal(wire.CredentialGeneration, &decoded.CredentialGeneration); err != nil {
			return fmt.Errorf("%w: credential_generation must be a string", ErrInvalidProfile)
		}
	}
	*p = decoded
	return nil
}

func requireDecodeEOF(decoder *json.Decoder) error {
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

// CredentialIdentity hashes the complete canonical non-secret profile
// identity. Any endpoint, account, capability, executor, assurance, or
// credential-generation change invalidates bound credentials and policies.
func CredentialIdentity(value Profile) string {
	type identity struct {
		Version              int          `json:"version"`
		Name                 string       `json:"name"`
		ServiceURL           string       `json:"service_url"`
		RESTBaseURL          string       `json:"rest_base_url"`
		MCPURL               string       `json:"mcp_url"`
		OAuth                OAuthConfig  `json:"oauth"`
		ExpectedAccountID    string       `json:"expected_account_id"`
		ExpectedLogin        string       `json:"expected_login"`
		CredentialGeneration string       `json:"credential_generation"`
		Capabilities         []Capability `json:"capabilities"`
		Executor             Executor     `json:"executor"`
		Assurance            Assurance    `json:"assurance"`
	}
	canonical, _ := json.Marshal(identity{
		Version: 1, Name: value.Name, ServiceURL: value.ServiceURL,
		RESTBaseURL: value.RESTBaseURL, MCPURL: value.MCPURL, OAuth: value.OAuth,
		ExpectedAccountID: value.ExpectedAccountID, ExpectedLogin: value.ExpectedLogin,
		CredentialGeneration: value.CredentialGeneration,
		Capabilities:         append([]Capability(nil), value.Capabilities...),
		Executor:             value.Executor, Assurance: value.Assurance,
	})
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:])
}

// SelectionIdentity hashes the stable profile topology used for saved default
// selection. Credential generations rotate during login and must not invalidate
// a choice that is otherwise still bound to the same profile metadata.
func SelectionIdentity(value Profile) string {
	value.CredentialGeneration = ""
	value.credentialGenerationPresent = false
	return CredentialIdentity(value)
}

func RequireName(name string) error {
	if name == "" {
		return ErrProfileRequired
	}
	return ValidateName(name)
}

func ValidateName(name string) error {
	if name == "" || len(name) > maxNameLength || !namePattern.MatchString(name) {
		return fmt.Errorf("%w: name must be 1-%d ASCII letters, digits, dot, dash, or underscore and start with a letter or digit", ErrInvalidProfile, maxNameLength)
	}
	return nil
}

func (p Profile) Validate() error {
	if err := ValidateName(p.Name); err != nil {
		return err
	}
	if err := endpoint.ValidateServiceURL(p.ServiceURL); err != nil {
		return invalid("service_url: %v", err)
	}
	if err := endpoint.ValidateRESTBaseURL(p.ServiceURL, p.RESTBaseURL); err != nil {
		return invalid("rest_base_url: %v", err)
	}
	if err := endpoint.ValidateMCPURL(p.ServiceURL, p.MCPURL); err != nil {
		return invalid("mcp_url: %v", err)
	}
	if err := p.OAuth.Validate(); err != nil {
		return err
	}
	if err := validateExpectedIdentity(p.ExpectedAccountID, p.ExpectedLogin); err != nil {
		return err
	}
	if p.CredentialGeneration != "" || p.credentialGenerationPresent {
		if err := ValidateCredentialGeneration(p.CredentialGeneration); err != nil {
			return err
		}
	}
	if err := ValidateCapabilities(p.Capabilities); err != nil {
		return err
	}
	return ValidateExecutorAssurance(p.Executor, p.Assurance)
}

func (config OAuthConfig) Validate() error {
	if err := endpoint.ValidateOAuthTopology(config.IssuerURL, config.AuthorizationURL, config.TokenURL); err != nil {
		return invalid("oauth topology: %v", err)
	}
	if config.ClientID == "" || len(config.ClientID) > maxAccountValueLength || !clientIDPattern.MatchString(config.ClientID) {
		return invalid("oauth client_id must be a bounded public-client identifier")
	}
	if err := ValidateScopes(config.Scopes); err != nil {
		return err
	}
	if err := endpoint.ValidateLoopbackRedirect(config.RedirectURI); err != nil {
		return invalid("oauth redirect_uri: %v", err)
	}
	return nil
}

func validateExpectedIdentity(accountID, login string) error {
	if accountID == "" || len(accountID) > maxAccountValueLength || !accountIDPattern.MatchString(accountID) {
		return invalid("expected_account_id must be a bounded YouTrack entity ID")
	}
	if login == "" || len(login) > maxAccountValueLength || strings.TrimSpace(login) != login || !loginPattern.MatchString(login) {
		return invalid("expected_login must be a bounded single token without whitespace or controls")
	}
	return nil
}

func ValidateScopes(scopes []string) error {
	if len(scopes) == 0 || len(scopes) > 32 {
		return invalid("oauth scopes must contain 1-32 canonical values")
	}
	previous := ""
	for _, scope := range scopes {
		if scope == "" || len(scope) > 128 || !scopeTokenPattern.MatchString(scope) {
			return invalid("oauth scope %q is invalid", scope)
		}
		if previous != "" && scope <= previous {
			return invalid("oauth scopes must be unique and sorted")
		}
		previous = scope
	}
	return nil
}

func ValidateCapabilities(capabilities []Capability) error {
	if len(capabilities) == 0 || capabilities[0] != CapabilityRead {
		return invalid("capabilities must start with %q", CapabilityRead)
	}
	order := map[Capability]int{
		CapabilityRead: 0, CapabilityIssueCreate: 1,
		CapabilityIssueUpdate: 2, CapabilityCommentAdd: 3,
		CapabilityCommentDelete: 4, CapabilityIssueEdit: 5, CapabilityIssueLink: 7,
	}
	previous := -1
	for _, capability := range capabilities {
		position, ok := order[capability]
		if !ok || position <= previous {
			return invalid("capabilities must be a unique canonical subset ordered read, issue-create, issue-update, comment-add, comment-delete, issue-edit, issue-link (issue-link after issue-edit, and after issue-create-user-fields where that capability exists)")
		}
		previous = position
	}
	return nil
}

func ValidateExecutorAssurance(executor Executor, assurance Assurance) error {
	switch {
	case executor == ExecutorRESTBestEffort && assurance == AssuranceBestEffort:
		return nil
	case executor == ExecutorCustomMCPAtomic && assurance == AssuranceStrictAtomic:
		return nil
	default:
		return invalid("executor and assurance must be rest-best-effort + best-effort or custom-mcp-atomic + strict-atomic")
	}
}

func (p Profile) ValidateLoginIntent() error {
	if err := p.Validate(); err != nil {
		return err
	}
	if p.CredentialGeneration != "" || p.credentialGenerationPresent {
		return invalid("credential_generation is generated by login")
	}
	return nil
}

func (p Profile) WithNewCredentialGeneration() (Profile, error) {
	if err := p.ValidateLoginIntent(); err != nil {
		return Profile{}, err
	}
	generation, err := NewCredentialGeneration()
	if err != nil {
		return Profile{}, err
	}
	p.CredentialGeneration = generation
	p.credentialGenerationPresent = false
	if err := p.Validate(); err != nil {
		return Profile{}, err
	}
	return p, nil
}

// LoginIntent returns the same non-secret profile topology without an old
// credential generation. Authentication uses it when rotating an existing
// credential; Login will allocate and bind a fresh generation atomically.
func (p Profile) LoginIntent() (Profile, error) {
	p.CredentialGeneration = ""
	p.credentialGenerationPresent = false
	if err := p.ValidateLoginIntent(); err != nil {
		return Profile{}, err
	}
	return p, nil
}

func NewCredentialGeneration() (string, error) {
	raw := make([]byte, credentialGenerationBytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("generate credential generation: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func ValidateCredentialGeneration(generation string) error {
	if len(generation) != credentialGenerationLength {
		return invalid("credential_generation must be a %d-character base64url value", credentialGenerationLength)
	}
	raw, err := base64.RawURLEncoding.DecodeString(generation)
	if err != nil || len(raw) != credentialGenerationBytes || base64.RawURLEncoding.EncodeToString(raw) != generation {
		return invalid("credential_generation must encode %d bytes as unpadded base64url", credentialGenerationBytes)
	}
	return nil
}

func (p Profile) HasCapability(capability Capability) bool {
	index := sort.Search(len(p.Capabilities), func(index int) bool {
		return capabilityRank(p.Capabilities[index]) >= capabilityRank(capability)
	})
	return index < len(p.Capabilities) && p.Capabilities[index] == capability
}

func capabilityRank(value Capability) int {
	switch value {
	case CapabilityRead:
		return 0
	case CapabilityIssueCreate:
		return 1
	case CapabilityIssueUpdate:
		return 2
	case CapabilityCommentAdd:
		return 3
	case CapabilityCommentDelete:
		return 4
	case CapabilityIssueEdit:
		return 5
	case CapabilityIssueLink:
		// Rank 6 belongs to issue-create-user-fields on a parallel branch.
		return 7
	default:
		return 100
	}
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidProfile, fmt.Sprintf(format, args...))
}
