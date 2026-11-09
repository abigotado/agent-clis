// Package oauthrecovery is the fixed, secret-free OAuth token recovery contract.
// Its descriptors drive both machine errors and published recovery tables.
package oauthrecovery

import (
	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/oauth"
)

// Descriptor contains only fixed public recovery data. Category zero is the
// legacy exchange/refresh fallback, not an OAuth TokenFailure category.
type Descriptor struct {
	Category oauth.TokenFailureCategory
	Reason   string
	Exit     errx.Code
	Recovery string
	Hint     string
}

const refreshOperatorRecovery = "stop auth-dependent commands; ask an operator to start a fresh interactive auth login for the selected profile; if an existing credential would be replaced, obtain explicit operator approval; do not retry refresh"

// orderedCatalog owns the seven-row contract without package-level mutable
// state. A new value is constructed for every caller.
func orderedCatalog() [7]Descriptor {
	return [7]Descriptor{
		{
			Category: oauth.TokenEndpointUnavailable,
			Reason:   "OAUTH_TOKEN_ENDPOINT_UNAVAILABLE",
			Exit:     errx.CodeRetryable,
			Recovery: "Back off, then restart login for a fresh authorization code. Never replay the previous token POST.",
			Hint:     "back off, then restart auth login for a fresh authorization code",
		},
		{
			Category: oauth.TokenTransportRejected,
			Reason:   "OAUTH_TOKEN_TRANSPORT_REJECTED",
			Exit:     errx.CodeAuth,
			Recovery: "Check the endpoint, DNS name, and TLS trust; do not retry unchanged.",
			Hint:     "check the OAuth endpoint, DNS, and TLS trust; do not retry unchanged",
		},
		{
			Category: oauth.TokenRequestRejected,
			Reason:   "OAUTH_TOKEN_REQUEST_REJECTED",
			Exit:     errx.CodeAuth,
			Recovery: "Check the OAuth client and profile, then start a new login.",
			Hint:     "check OAuth client settings and profile, then start a new login",
		},
		{
			Category: oauth.TokenResponseInvalid,
			Reason:   "OAUTH_TOKEN_RESPONSE_INVALID",
			Exit:     errx.CodeAuth,
			Recovery: "Check token-response compatibility, then start a fresh interactive login for a new authorization code; never replay the previous token POST.",
			Hint:     "check YouTrack OAuth token response compatibility; start a fresh interactive auth login for a new authorization code; do not replay the previous token POST",
		},
		{
			Category: oauth.TokenRedirectRefused,
			Reason:   "OAUTH_TOKEN_REDIRECT_REFUSED",
			Exit:     errx.CodeAuth,
			Recovery: "Check the pinned token endpoint; never follow the redirect.",
			Hint:     "check the OAuth token endpoint in the profile; do not follow redirects",
		},
		{
			Category: oauth.TokenRequestInterrupted,
			Reason:   "OAUTH_TOKEN_REQUEST_INTERRUPTED",
			Exit:     errx.CodeAuth,
			Recovery: "An attempted authorization-code request or HTTP 200 response read was interrupted; start a fresh login and never replay the token POST.",
			Hint:     "start auth login again for a fresh authorization code; do not replay the request",
		},
		{
			Reason:   "OAUTH_TOKEN_EXCHANGE_FAILED",
			Exit:     errx.CodeAuth,
			Recovery: "Invalid local exchange input, refresh request failure, post-refresh binding rejection, or persistence uncertainty; use the applicable recovery.",
			Hint:     refreshOperatorRecovery,
		},
	}
}

// Catalog returns a defensive copy of the ordered recovery contract.
func Catalog() []Descriptor {
	rows := orderedCatalog()
	return rows[:]
}

// Lookup resolves only a typed authorization-code token failure. Unknown and
// zero-valued categories are deliberately left to the safe legacy fallback.
func Lookup(category oauth.TokenFailureCategory) (Descriptor, bool) {
	for _, descriptor := range Catalog() {
		if descriptor.Category == category && category != 0 {
			return descriptor, true
		}
	}
	return Descriptor{}, false
}

// Legacy returns the published non-retryable exchange and refresh fallback.
func Legacy() Descriptor {
	rows := orderedCatalog()
	return rows[len(rows)-1]
}
