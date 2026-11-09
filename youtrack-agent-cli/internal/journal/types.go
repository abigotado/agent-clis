// Package journal stores guarded-mutation plans in a crash-consistent,
// revision-CAS state machine. Each plan has its own advisory lock and file.
package journal

import (
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/intent"
)

const recordVersion = 1 // historical v1 only

// State is one durable point in the non-replayable mutation lifecycle.
type State string

const (
	StatePrepared                   State = "prepared"
	StateConfirmed                  State = "confirmed"
	StateCanceled                   State = "canceled"
	StateExpired                    State = "expired"
	StateInFlight                   State = "in_flight"
	StateFailedBeforeMutation       State = "failed_before_mutation"
	StateApplied                    State = "applied"
	StateAmbiguous                  State = "ambiguous"
	StateReconciled                 State = "reconciled"
	StateOperatorResolutionRequired State = "operator_resolution_required"
	StateResolvedApplied            State = "resolved_applied"
	StateResolvedNotApplied         State = "resolved_not_applied"
)

// ReceiptBinding is the minimum signed-receipt metadata needed for durable
// nonce consumption without importing the approval implementation.
type ReceiptBinding struct {
	ReceiptID     string    `json:"receipt_id"`
	Nonce         string    `json:"nonce"`
	PlanSHA256    string    `json:"plan_sha256"`
	ExpiresAt     time.Time `json:"expires_at"`
	KeyGeneration string    `json:"key_generation"`
	ReceiptSHA256 string    `json:"receipt_sha256"`
}

// Outcome records only bounded, non-secret mutation result metadata.
type Outcome struct {
	Code           string `json:"code"`
	RemoteID       string `json:"remote_id,omitempty"`
	EvidenceSHA256 string `json:"evidence_sha256,omitempty"`
}

// Evidence records bounded reconciliation or operator evidence.
type Evidence struct {
	SHA256      string    `json:"sha256"`
	Summary     string    `json:"summary"`
	CollectedAt time.Time `json:"collected_at"`
}

// Record is the authoritative durable audit record for one plan.
type Record struct {
	Version          int             `json:"version"`
	Revision         uint64          `json:"revision"`
	State            State           `json:"state"`
	Plan             intent.Plan     `json:"plan"`
	Receipt          *ReceiptBinding `json:"receipt,omitempty"`
	MutationAttempts uint8           `json:"mutation_attempts"`
	Outcome          *Outcome        `json:"outcome,omitempty"`
	Evidence         []Evidence      `json:"evidence,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

// Transition contains the bounded data required for one valid state change.
type Transition struct {
	To       State
	Receipt  *ReceiptBinding
	Outcome  *Outcome
	Evidence *Evidence
}

// NonReplayable reports states for which the same receipt can never dispatch
// another write, including in_flight recovered after a crash.
func (r Record) NonReplayable() bool {
	return r.State == StateInFlight || r.MutationAttempts > 0
}

// RequiresReconciliation reports states eligible for bounded read-only
// evidence collection.
func (r Record) RequiresReconciliation() bool {
	return r.State == StateInFlight || r.State == StateApplied || r.State == StateAmbiguous
}
