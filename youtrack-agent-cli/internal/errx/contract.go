package errx

// docs/contract.md is generated from this table, so an exit status cannot be
// renumbered here and left stale in the agent-facing contract.
//go:generate go run github.com/abigotado/agent-clis/youtrack-agent-cli/tools/gencontract

// EnvelopeVersion is the `v` field of every response envelope.
//
// Bump it when a field is renamed, removed, or changes type. Additive fields
// do not require a bump.
const EnvelopeVersion = 1

// Code is a youtrack-agent-cli process exit status.
//
// Each status maps to a distinct caller recovery action. New API detail should
// normally be represented by Error.Reason rather than another status.
type Code int

const (
	// CodeOK signals success.
	CodeOK Code = 0
	// CodeInternal signals a youtrack-agent-cli defect.
	CodeInternal Code = 1
	// CodeUsage signals invalid flags or input.
	CodeUsage Code = 2
	// CodeNotFound signals an absent or invisible YouTrack entity.
	CodeNotFound Code = 3
	// CodeAmbiguous signals that several entities matched.
	CodeAmbiguous Code = 4
	// CodeAuth signals missing, expired, or rejected credentials.
	CodeAuth Code = 5
	// CodeRetryable signals a transient failure.
	CodeRetryable Code = 6
	// CodeConfirm signals that a write requires explicit approval.
	CodeConfirm Code = 7
	// CodePermission signals a denied YouTrack permission, API-token scope, or
	// local state access.
	CodePermission Code = 8
	// CodeConflict signals stale state or a write conflict.
	CodeConflict Code = 9
)

// CodeInfo documents one exit status.
type CodeInfo struct {
	Code     Code   `json:"code"`
	Name     string `json:"name"`
	Meaning  string `json:"meaning"`
	NextMove string `json:"next_move"`
}

var codes = []CodeInfo{
	{CodeOK, "OK", "ok", "proceed"},
	{CodeInternal, "INTERNAL", "internal failure", "report; do not retry unchanged"},
	{CodeUsage, "USAGE", "usage or validation error", "fix flags or input"},
	{CodeNotFound, "NOT_FOUND", "object not found or not visible", "check the key and profile"},
	{CodeAmbiguous, "AMBIGUOUS", "several objects matched", "pick from candidates"},
	{CodeAuth, "AUTH", "missing, expired, or rejected credentials", "log in or rotate the API token"},
	{CodeRetryable, "RETRYABLE", "rate limit or transient network failure", "back off and retry safely"},
	{CodeConfirm, "CONFIRMATION_REQUIRED", "write was not confirmed", "obtain human confirmation using the operation's approval mode"},
	{CodePermission, "PERMISSION_DENIED", "YouTrack permission, token scope, or local state access denied", "request the permission, scope, or local access; do not retry unchanged"},
	{CodeConflict, "CONFLICT", "stale state or write conflict", "re-read the YouTrack resource before deciding"},
}

// Codes returns a copy of the exit-code contract.
func Codes() []CodeInfo {
	out := make([]CodeInfo, len(codes))
	copy(out, codes)
	return out
}

// Contract is the machine-readable description emitted by `youtrack-agent-cli contract`.
type Contract struct {
	EnvelopeVersion int        `json:"envelope_version"`
	Codes           []CodeInfo `json:"codes"`
}

// Describe returns the full machine contract.
func Describe() Contract {
	return Contract{EnvelopeVersion: EnvelopeVersion, Codes: Codes()}
}
