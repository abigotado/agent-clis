package application

import (
	"net/http"
	"sync"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/operatorwrite"
)

// driftOnMeReadTransport runs drift just before the nth GET of the current-user
// endpoint. Apply reads it once before the locks and once inside them, so
// n=2 lands the drift between the pre-lock part and the in-lock verify.
type driftOnMeReadTransport struct {
	next  http.RoundTripper
	nth   int
	drift func()
	mu    sync.Mutex
	reads int
}

func (d *driftOnMeReadTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method == http.MethodGet && request.URL.Path == "/api/users/me" {
		d.mu.Lock()
		d.reads++
		fire := d.reads == d.nth
		d.mu.Unlock()
		if fire {
			d.drift()
		}
	}
	return d.next.RoundTrip(request)
}

func (d *driftOnMeReadTransport) meReads() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.reads
}

// Drift that appears after the pre-lock checks must still be caught by the
// precondition verify inside the lock, before the claim and the single write.
func TestOperatorPreconditionIsVerifiedInsideTheLock(t *testing.T) {
	type world struct {
		service *Service
		prepare func(*testing.T) OperatorWriteInfo
		drift   func()
		apply   func(*testing.T, OperatorWriteInfo) (OperatorWriteInfo, error)
		writes  func() int
	}
	tests := []struct {
		name   string
		reason string
		setup  func(*testing.T) world
	}{
		{name: "issue.link", reason: "OPERATOR_LINK_STALE", setup: func(t *testing.T) world {
			f := newLinkFixture(t)
			return world{f.service, func(t *testing.T) OperatorWriteInfo { return f.prepare(t, nil) },
				func() { f.link("2-12", "105-1", "OUTWARD", "2-19") }, f.apply, func() int { return f.postCount() + f.deleteCount() }}
		}},
		{name: "issue.unlink", reason: "OPERATOR_LINK_STALE", setup: func(t *testing.T) world {
			f := newUnlinkFixture(t)
			return world{f.service, func(t *testing.T) OperatorWriteInfo { return f.prepareUnlink(t, nil) },
				func() { f.edit(func(f *linkFixture) { f.removeLocked("2-12", "105-1", "OUTWARD", "2-19") }) }, f.apply, func() int { return f.postCount() + f.deleteCount() }}
		}},
		{name: "issue.tag", reason: "OPERATOR_TAG_STALE", setup: func(t *testing.T) world {
			f := newTagFixture(t)
			return world{f.service, func(t *testing.T) OperatorWriteInfo { return f.prepare(t, "issue.tag", nil) },
				func() { f.edit(func(f *tagFixture) { f.onIssue["2-12"] = append(f.onIssue["2-12"], "t-1") }) }, f.apply, f.writeCount}
		}},
		{name: "issue.untag", reason: "OPERATOR_TAG_STALE", setup: func(t *testing.T) world {
			f := newTagFixture(t)
			return world{f.service, func(t *testing.T) OperatorWriteInfo { return f.prepare(t, "issue.untag", nil) },
				func() { f.edit(func(f *tagFixture) { f.onIssue["2-12"] = nil }) }, f.apply, f.writeCount}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			w := test.setup(t)
			plan := w.prepare(t)
			hook := &driftOnMeReadTransport{next: w.service.HTTP, nth: 2, drift: w.drift}
			w.service.HTTP = hook
			_, err := w.apply(t, plan)
			requireRefusal(t, err, test.reason, errx.CodeConflict)
			if hook.meReads() != 2 {
				t.Fatalf("current-user reads=%d, want 2 (pre-lock and in-lock)", hook.meReads())
			}
			status, statusErr := w.service.OperatorWriteStatus(t.Context(), plan.PlanID)
			if w.writes() != 0 || statusErr != nil || status.State != string(operatorwrite.StatePrepared) || status.NonReplayable {
				t.Fatalf("writes=%d status=%#v err=%v", w.writes(), status, statusErr)
			}
		})
	}
}
