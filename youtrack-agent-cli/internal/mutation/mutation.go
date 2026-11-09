// Package mutation defines the small consumer-owned contracts around a
// one-shot YouTrack mutation. Application owns concrete orchestration.
package mutation

import (
	"context"
	"fmt"
	"strings"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/intent"
)

// Executor performs read-only preflight and exactly one typed mutation.
type Executor interface {
	Preflight(ctx context.Context, plan intent.Plan) (Preflight, error)
	Execute(ctx context.Context, plan intent.Plan) (Execution, error)
}

// Reconciler collects bounded read-only evidence after a non-replayable state.
type Reconciler interface {
	Reconcile(ctx context.Context, plan intent.Plan) (Reconciliation, error)
}

// Preflight binds remotely observed state to the approved plan.
type Preflight struct {
	ProfileIdentitySHA256 string `json:"profile_identity_sha256"`
	AccountID             string `json:"account_id"`
	ProjectID             string `json:"project_id"`
	ProjectKey            string `json:"project_key"`
	SchemaSHA256          string `json:"schema_sha256"`
	ExpectedSHA256        string `json:"expected_sha256"`
}

func (p Preflight) Validate(plan intent.Plan) error {
	if err := plan.Validate(); err != nil {
		return fmt.Errorf("validate mutation preflight plan: %w", err)
	}
	if p.ProfileIdentitySHA256 != plan.Profile.IdentitySHA256 ||
		p.AccountID != plan.Profile.Account.ID ||
		p.ProjectID != plan.Policy.Project.ID || p.ProjectKey != plan.Policy.Project.Key ||
		p.SchemaSHA256 != plan.Policy.SchemaSHA256 || p.ExpectedSHA256 != plan.ExpectedSHA256 {
		return errx.Conflict("MUTATION_PREFLIGHT_CHANGED", "the account, project, schema, or expected state changed after approval")
	}
	return nil
}

// Disposition classifies the single mutating request.
type Disposition string

const (
	DispositionApplied              Disposition = "applied"
	DispositionFailedBeforeMutation Disposition = "failed_before_mutation"
	DispositionAmbiguous            Disposition = "ambiguous"
)

// Execution is the bounded result of one Execute call.
type Execution struct {
	Disposition      Disposition `json:"disposition"`
	MutationAttempts uint8       `json:"mutation_attempts"`
	RemoteID         string      `json:"remote_id,omitempty"`
	EvidenceSHA256   string      `json:"evidence_sha256,omitempty"`
}

func (e Execution) Validate() error {
	if e.MutationAttempts != 1 {
		return errx.Internal("mutation executor must report exactly one mutating request attempt")
	}
	switch e.Disposition {
	case DispositionApplied:
		if strings.TrimSpace(e.RemoteID) == "" {
			return errx.Internal("applied mutation result is missing its exact remote ID")
		}
	case DispositionFailedBeforeMutation, DispositionAmbiguous:
	default:
		return errx.Internal("mutation executor returned an unsupported disposition")
	}
	return nil
}

// ReconciliationDisposition is the complete set of bounded-read conclusions.
type ReconciliationDisposition string

const (
	ReconciliationApplied          ReconciliationDisposition = "reconciled"
	ReconciliationNotApplied       ReconciliationDisposition = "resolved_not_applied"
	ReconciliationOperatorRequired ReconciliationDisposition = "operator_resolution_required"
)

// Reconciliation contains bounded safe evidence, never a full server response.
type Reconciliation struct {
	Disposition    ReconciliationDisposition `json:"disposition"`
	EvidenceSHA256 string                    `json:"evidence_sha256"`
	Summary        string                    `json:"summary"`
}

func (r Reconciliation) Validate() error {
	switch r.Disposition {
	case ReconciliationApplied, ReconciliationNotApplied, ReconciliationOperatorRequired:
	default:
		return errx.Internal("reconciler returned an unsupported disposition")
	}
	if len(r.EvidenceSHA256) != 64 || strings.TrimSpace(r.Summary) == "" || len(r.Summary) > 1024 {
		return errx.Internal("reconciler returned missing or oversized bounded evidence")
	}
	return nil
}
