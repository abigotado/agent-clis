package application

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/operatorwrite"
)

// readOnlyGuard fronts the fixture transport during reconciliation: it records
// every non-GET request and can fail the exact attachment read.
type readOnlyGuard struct {
	next http.RoundTripper
	// exactStatus, when set, answers the exact attachment GET with that status.
	exactStatus int
	mu          sync.Mutex
	nonGet      []string
	lists       []string
}

func (g *readOnlyGuard) RoundTrip(request *http.Request) (*http.Response, error) {
	g.mu.Lock()
	if request.Method != http.MethodGet {
		g.nonGet = append(g.nonGet, request.Method+" "+request.URL.Path)
	}
	if strings.HasSuffix(request.URL.Path, "/attachments") {
		g.lists = append(g.lists, request.URL.RawQuery)
	}
	status := g.exactStatus
	g.mu.Unlock()
	if status != 0 && strings.HasPrefix(request.URL.Path, "/api/issues/2-12/attachments/") {
		return jsonResponse(request, status, `{"error":"x"}`), nil
	}
	return g.next.RoundTrip(request)
}

// unknownAttachmentPlan applies a plan whose upload outcome is unknown. With
// keepID the upload succeeds but the read-back disagrees, so the attachment ID
// is kept; without it the transport fails and no ID exists.
func unknownAttachmentPlan(t *testing.T, f *attachmentFixture, keepID bool) OperatorWriteInfo {
	t.Helper()
	plan := f.prepared(t, f.write(t, "shot.png", pngBytes("recon")), "")
	if keepID {
		f.transport.readBack = attachmentJSON("5-1", "shot.png", 1, "1-2")
	} else {
		f.transport.postErr = errors.New("connection reset by peer")
	}
	if _, err := f.apply(t, plan); operatorReason(t, err) != "WRITE_OUTCOME_UNKNOWN" {
		t.Fatalf("apply error=%v", err)
	}
	f.transport.readBack, f.transport.postErr = nil, nil
	return plan
}

func claimCutoff(t *testing.T, f *attachmentFixture, planID string) int64 {
	t.Helper()
	record, err := f.service.OperatorWrites.Get(t.Context(), planID)
	if err != nil || record.Attempt == nil {
		t.Fatalf("record=%#v err=%v", record, err)
	}
	cutoff := record.Attempt.ClaimedAt.UnixMilli()
	if record.Attempt.ClaimedAt.After(time.UnixMilli(cutoff)) {
		cutoff++
	}
	return cutoff
}

func reconcileAttachment(t *testing.T, f *attachmentFixture, planID string, limit int) (OperatorWriteInfo, error, *readOnlyGuard) {
	t.Helper()
	guard := &readOnlyGuard{next: f.service.HTTP}
	f.service.HTTP = guard
	info, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: planID, Limit: limit})
	f.service.HTTP = guard.next
	return info, err, guard
}

func storedCode(t *testing.T, f *attachmentFixture, planID string) string {
	t.Helper()
	record, err := f.service.OperatorWrites.Get(t.Context(), planID)
	if err != nil || record.Result == nil {
		t.Fatalf("record=%#v err=%v", record, err)
	}
	return record.Result.Code
}

func withCreated(item map[string]any, created int64) map[string]any {
	item["created"] = created
	return item
}

func TestAttachmentReconcileWithKeptIDReadsOnlyThatAttachment(t *testing.T) {
	size := int64(len(pngBytes("recon")))
	tests := []struct {
		name         string
		readBack     map[string]any
		exactStatus  int
		wantState    operatorwrite.State
		wantCode     string
		wantEvidence string
		wantErr      errx.Code
	}{
		{"matching attachment", attachmentJSON("5-1", "shot.png", size, "1-2"), 0, operatorwrite.StateReconciled, "ATTACHMENT_OBSERVED", "matching_attachment_observed", 0},
		{"different size", attachmentJSON("5-1", "shot.png", size+1, "1-2"), 0, operatorwrite.StateOperatorRequired, "OPERATOR_RESOLUTION_REQUIRED", "inconclusive", 0},
		{"different name", attachmentJSON("5-1", "other.png", size, "1-2"), 0, operatorwrite.StateOperatorRequired, "OPERATOR_RESOLUTION_REQUIRED", "inconclusive", 0},
		{"different author", attachmentJSON("5-1", "shot.png", size, "9-9"), 0, operatorwrite.StateOperatorRequired, "OPERATOR_RESOLUTION_REQUIRED", "inconclusive", 0},
		{"removed", func() map[string]any {
			m := attachmentJSON("5-1", "shot.png", size, "1-2")
			m["removed"] = true
			return m
		}(), 0,
			operatorwrite.StateOperatorRequired, "OPERATOR_RESOLUTION_REQUIRED", "inconclusive", 0},
		{"kept id not found", nil, http.StatusNotFound, operatorwrite.StateOperatorRequired, "OPERATOR_RESOLUTION_REQUIRED", "inconclusive", 0},
		{"kept id forbidden", nil, http.StatusForbidden, operatorwrite.StateOperatorRequired, "OPERATOR_RESOLUTION_REQUIRED", "inconclusive", 0},
		{"kept id unauthorized", nil, http.StatusUnauthorized, operatorwrite.StateOperatorRequired, "OPERATOR_RESOLUTION_REQUIRED", "inconclusive", 0},
		{"server error is returned", nil, http.StatusInternalServerError, "", "", "", errx.CodeRetryable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newAttachmentFixture(t)
			plan := unknownAttachmentPlan(t, f, true)
			f.transport.readBack = test.readBack
			f.transport.reset()
			guard := &readOnlyGuard{next: f.service.HTTP, exactStatus: test.exactStatus}
			f.service.HTTP = guard
			info, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: plan.PlanID, Limit: 2})
			requireNoSentinel(t, err, info)
			if len(guard.nonGet) != 0 {
				t.Fatalf("reconcile sent %v", guard.nonGet)
			}
			if _, posts := f.transport.counts(); posts != 0 {
				t.Fatalf("posts=%d", posts)
			}
			if test.wantErr != 0 {
				if err == nil || errx.ExitCode(err) != test.wantErr {
					t.Fatalf("error=%v want exit %d", err, test.wantErr)
				}
				if record, getErr := f.service.OperatorWrites.Get(t.Context(), plan.PlanID); getErr != nil || record.State != operatorwrite.StateUnknown {
					t.Fatalf("a failed read changed the record: %#v %v", record, getErr)
				}
				return
			}
			if err != nil || info.State != string(test.wantState) || storedCode(t, f, plan.PlanID) != test.wantCode || info.Evidence != test.wantEvidence {
				t.Fatalf("info=%#v err=%v", info, err)
			}
			if len(guard.lists) != 0 {
				t.Fatalf("kept-id reconcile listed attachments: %v", guard.lists)
			}
			if test.wantState == operatorwrite.StateReconciled && info.RemoteID != "5-1" {
				t.Fatalf("remote id=%q", info.RemoteID)
			}
		})
	}
}

func TestAttachmentReconcileWithoutIDNeedsOneCausallyUnprovenMatch(t *testing.T) {
	size := int64(len(pngBytes("recon")))
	const inconclusive = "inconclusive"
	const unproven = "matching_attachment_observed_without_causal_proof"
	later := func(cutoff int64, item map[string]any) map[string]any { return withCreated(item, cutoff+1000) }
	tests := []struct {
		name     string
		limit    int
		list     func(cutoff int64) []map[string]any
		evidence string
	}{
		{"unique match", 5, func(c int64) []map[string]any {
			return []map[string]any{later(c, attachmentJSON("5-3", "shot.png", size, "1-2"))}
		}, unproven},
		{"unique match among others", 5, func(c int64) []map[string]any {
			return []map[string]any{attachmentJSON("5-8", "other.png", size, "1-2"), later(c, attachmentJSON("5-3", "shot.png", size, "1-2"))}
		}, unproven},
		{"created exactly at the rounded claim", 5, func(c int64) []map[string]any {
			return []map[string]any{withCreated(attachmentJSON("5-3", "shot.png", size, "1-2"), c)}
		}, unproven},
		{"page exactly at the limit still counts", 2, func(c int64) []map[string]any {
			return []map[string]any{attachmentJSON("5-8", "other.png", size, "1-2"), later(c, attachmentJSON("5-3", "shot.png", size, "1-2"))}
		}, unproven},
		{"absent", 5, func(int64) []map[string]any { return []map[string]any{} }, inconclusive},
		{"duplicate", 5, func(c int64) []map[string]any {
			return []map[string]any{later(c, attachmentJSON("5-3", "shot.png", size, "1-2")), later(c, attachmentJSON("5-4", "shot.png", size, "1-2"))}
		}, inconclusive},
		{"truncated", 1, func(c int64) []map[string]any {
			return []map[string]any{later(c, attachmentJSON("5-3", "shot.png", size, "1-2")), attachmentJSON("5-8", "other.png", size, "1-2")}
		}, inconclusive},
		{"created before the claim", 5, func(c int64) []map[string]any {
			return []map[string]any{withCreated(attachmentJSON("5-3", "shot.png", size, "1-2"), c-1)}
		}, inconclusive},
		{"different size", 5, func(c int64) []map[string]any {
			return []map[string]any{later(c, attachmentJSON("5-3", "shot.png", size+1, "1-2"))}
		}, inconclusive},
		{"different author", 5, func(c int64) []map[string]any {
			return []map[string]any{later(c, attachmentJSON("5-3", "shot.png", size, "9-9"))}
		}, inconclusive},
		{"removed", 5, func(c int64) []map[string]any {
			item := later(c, attachmentJSON("5-3", "shot.png", size, "1-2"))
			item["removed"] = true
			return []map[string]any{item}
		}, inconclusive},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newAttachmentFixture(t)
			plan := unknownAttachmentPlan(t, f, false)
			cutoff := claimCutoff(t, f, plan.PlanID)
			f.transport.list = func(int) []map[string]any { return test.list(cutoff) }
			f.transport.reset()
			info, err, guard := reconcileAttachment(t, f, plan.PlanID, test.limit)
			requireNoSentinel(t, err, info)
			if err != nil || info.State != string(operatorwrite.StateOperatorRequired) || storedCode(t, f, plan.PlanID) != "OPERATOR_RESOLUTION_REQUIRED" ||
				info.Evidence != test.evidence || info.RemoteID != "" {
				t.Fatalf("info=%#v err=%v", info, err)
			}
			if len(guard.nonGet) != 0 {
				t.Fatalf("reconcile sent %v", guard.nonGet)
			}
			if _, posts := f.transport.counts(); posts != 0 {
				t.Fatalf("posts=%d", posts)
			}
			if len(guard.lists) != 1 || !strings.Contains(guard.lists[0], "%24top="+strconv.Itoa(test.limit+1)) && !strings.Contains(guard.lists[0], "$top="+strconv.Itoa(test.limit+1)) {
				t.Fatalf("list queries=%v", guard.lists)
			}
			repeated, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: plan.PlanID, Limit: test.limit})
			if err != nil || repeated.State != string(operatorwrite.StateOperatorRequired) {
				t.Fatalf("repeat=%#v err=%v", repeated, err)
			}
		})
	}
}

func TestAttachmentReconcileRefusesMovedProjectWithoutReadingAttachments(t *testing.T) {
	for _, keepID := range []bool{true, false} {
		t.Run(map[bool]string{true: "kept id", false: "no id"}[keepID], func(t *testing.T) {
			f := newAttachmentFixture(t)
			plan := unknownAttachmentPlan(t, f, keepID)
			f.setIssue(strings.Replace(editIssue("Example", strPtr("body"), 2), `"id":"0-3"`, `"id":"0-4"`, 1))
			f.transport.reset()
			_, err, guard := reconcileAttachment(t, f, plan.PlanID, 2)
			requireRefusal(t, err, "OPERATOR_PROJECT_CHANGED", errx.CodeConflict)
			if len(guard.nonGet) != 0 || len(guard.lists) != 0 {
				t.Fatalf("non-GET=%v lists=%v", guard.nonGet, guard.lists)
			}
			record, getErr := f.service.OperatorWrites.Get(t.Context(), plan.PlanID)
			if getErr != nil || record.State != operatorwrite.StateUnknown {
				t.Fatalf("record=%#v %v", record, getErr)
			}
		})
	}
}
