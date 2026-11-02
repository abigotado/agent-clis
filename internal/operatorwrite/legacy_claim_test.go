//go:build linux || (darwin && cgo)

package operatorwrite

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
)

func TestLegacyPlansKeepExpiryAndClaimsAcrossReopen(t *testing.T) {
	for _, fixture := range []string{"plan-v1-comment-add.json", "plan-v1-issue-update.json", "plan-v1-issue-create.json"} {
		t.Run(fixture, func(t *testing.T) {
			raw, err := os.ReadFile("testdata/" + fixture)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := DecodePlan(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			store := New(root)
			if _, err := store.Create(t.Context(), plan); err != nil {
				t.Fatal(err)
			}
			_, err = store.Claim(t.Context(), plan.ID, plan.SHA256, plan.ExpiresAt)
			var typed *errx.Error
			if errx.ExitCode(err) != errx.CodeConflict || !errors.As(err, &typed) || typed.Reason != "OPERATOR_PLAN_EXPIRED" {
				t.Fatalf("legacy claim at expiry=%v", err)
			}
			prepared, err := New(root).Get(t.Context(), plan.ID)
			if err != nil || prepared.NonReplayable() {
				t.Fatalf("expired claim changed eligibility: %#v, %v", prepared, err)
			}
			attempt, err := store.Claim(t.Context(), plan.ID, plan.SHA256, plan.CreatedAt)
			if err != nil {
				t.Fatal(err)
			}
			claimed, err := New(root).Get(t.Context(), plan.ID)
			if err != nil || claimed.State != StateInFlight || !claimed.NonReplayable() ||
				claimed.Attempt == nil || *claimed.Attempt != attempt {
				t.Fatalf("reopened legacy claim=%#v, %v", claimed, err)
			}
		})
	}
}
