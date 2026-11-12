package application

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/operatorwrite"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/profile"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/writepolicy"
)

func (f *linkFixture) addFillers(count int) []string {
	ids := make([]string, count)
	f.edit(func(f *linkFixture) {
		for index := range count {
			id := fmt.Sprintf("3-%d", index)
			f.issues[id] = &linkIssueState{id: id, readable: fmt.Sprintf("FIL-%d", index), projectID: "0-3", projectKey: "APP", updated: 1}
			ids[index] = id
		}
	})
	return ids
}

func TestOperatorIssueLinkPicksTheServerLinkEntryPerTypeAndAppliesOnce(t *testing.T) {
	tests := []struct {
		name, linkType, phrase, direction, wire, typeID string
	}{
		{"relates (undirected)", "Relates", "relates to", operatorwrite.LinkUndirected, "BOTH", "105-0"},
		{"depends on", "Depend", "depends on", operatorwrite.LinkOutward, "OUTWARD", "105-1"},
		{"is required for", "Depend", "is required for", operatorwrite.LinkInward, "INWARD", "105-1"},
		{"duplicates", "Duplicate", "duplicates", operatorwrite.LinkOutward, "OUTWARD", "105-2"},
		{"is duplicated by", "Duplicate", "is duplicated by", operatorwrite.LinkInward, "INWARD", "105-2"},
		{"subtask of", "Subtask", "subtask of", operatorwrite.LinkInward, "INWARD", "105-3"},
		{"parent for", "Subtask", "parent for", operatorwrite.LinkOutward, "OUTWARD", "105-3"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newLinkFixture(t)
			plan := f.prepare(t, func(in *OperatorSnapshotInput) { in.LinkType, in.Direction = test.linkType, test.phrase })
			wantID := linkEntryID("2-12", test.typeID, test.wire)
			link := plan.Plan.Snapshot.Link
			if plan.Kind != "issue.link" || plan.PlanVersion != operatorwrite.PlanVersion4 || link == nil || link.LinkID != wantID || link.Direction != test.direction ||
				link.Phrase != test.phrase || link.Type.ID != test.typeID || link.Target.ID != "2-19" || plan.TargetIssueID != "2-19" ||
				plan.TargetReadableID != "OPS-7" || plan.TargetProjectKey != "OPS" || plan.LinkID != wantID || plan.Direction != test.phrase || plan.ProjectKey != "APP" {
				t.Fatalf("plan=%#v link=%#v", plan, link)
			}
			if len(f.nonGET()) != 0 {
				t.Fatalf("snapshot and prepare wrote: %v", f.nonGET())
			}
			transport := &methodTransport{next: f.service.HTTP}
			f.service.HTTP = transport
			applied, err := f.apply(t, plan)
			if err != nil || applied.State != string(operatorwrite.StateApplied) || applied.RemoteID != "2-19" || applied.RemoteReadableID != "OPS-7" || f.postCount() != 1 {
				t.Fatalf("applied=%#v err=%v posts=%d", applied, err, f.postCount())
			}
			if len(transport.posts) != 1 || transport.posts[0] != "/api/issues/2-12/links/"+wantID+"/issues" || transport.bodies[0] != `{"id":"2-19"}` {
				t.Fatalf("posts=%q bodies=%q", transport.posts, transport.bodies)
			}
			_, err = f.apply(t, plan)
			requireRefusal(t, err, "OPERATOR_PLAN_CONSUMED", errx.CodeConflict)
			if f.postCount() != 1 {
				t.Fatalf("replay posted: %d", f.postCount())
			}
			f.requireNoSentinel(t, applied, err)
		})
	}
}

func TestOperatorIssueLinkSnapshotRefusals(t *testing.T) {
	manyTypes := func(f *linkFixture) {
		for index := range 100 {
			f.types = append(f.types, map[string]any{"id": fmt.Sprintf("106-%d", index), "name": fmt.Sprintf("Extra%d", index), "directed": false, "aggregation": false, "sourceToTarget": "x", "targetToSource": "x"})
		}
	}
	tests := []struct {
		name   string
		change func(*OperatorSnapshotInput)
		setup  func(*linkFixture)
		reason string
		code   errx.Code
		denied bool
	}{
		{name: "unknown link type", change: func(in *OperatorSnapshotInput) { in.LinkType = "Nope" }, reason: "NOT_FOUND_LINK_TYPE", code: errx.CodeNotFound},
		{name: "link type name is case sensitive", change: func(in *OperatorSnapshotInput) { in.LinkType = "depend" }, reason: "NOT_FOUND_LINK_TYPE", code: errx.CodeNotFound},
		{name: "duplicate link type name", setup: func(f *linkFixture) {
			f.types = append(f.types, map[string]any{"id": "105-9", "name": "Depend", "directed": false, "aggregation": false, "sourceToTarget": "x", "targetToSource": "x"})
		}, reason: "AMBIGUOUS_LINK_TYPE", code: errx.CodeAmbiguous},
		{name: "unknown link type id", change: func(in *OperatorSnapshotInput) { in.LinkType, in.LinkTypeID = "", "999-9" }, reason: "NOT_FOUND_LINK_TYPE", code: errx.CodeNotFound},
		{name: "phrase differs in case", change: func(in *OperatorSnapshotInput) { in.Direction = "Depends on" }, reason: "USAGE", code: errx.CodeUsage},
		{name: "phrase is a substring", change: func(in *OperatorSnapshotInput) { in.Direction = "depends" }, reason: "USAGE", code: errx.CodeUsage},
		{name: "phrase is the type name", change: func(in *OperatorSnapshotInput) { in.Direction = "Depend" }, reason: "USAGE", code: errx.CodeUsage},
		{name: "undirected phrase wrong", change: func(in *OperatorSnapshotInput) { in.LinkType, in.Direction = "Relates", "relate to" }, reason: "USAGE", code: errx.CodeUsage},
		{name: "missing direction", change: func(in *OperatorSnapshotInput) { in.Direction = "" }, reason: "USAGE", code: errx.CodeUsage},
		{name: "missing target", change: func(in *OperatorSnapshotInput) { in.TargetID = "" }, reason: "USAGE", code: errx.CodeUsage},
		{name: "missing link type", change: func(in *OperatorSnapshotInput) { in.LinkType = "" }, reason: "USAGE", code: errx.CodeUsage},
		{name: "both link type selectors", change: func(in *OperatorSnapshotInput) { in.LinkTypeID = "105-1" }, reason: "USAGE", code: errx.CodeUsage},
		{name: "field selectors", change: func(in *OperatorSnapshotInput) {
			in.Fields = []OperatorFieldSelection{{FieldID: "92-1", ValueID: "101-2"}}
		}, reason: "USAGE", code: errx.CodeUsage},
		{name: "project selector", change: func(in *OperatorSnapshotInput) { in.ProjectID = "APP" }, reason: "USAGE", code: errx.CodeUsage},
		{name: "comment selector", change: func(in *OperatorSnapshotInput) { in.CommentID = "4-1" }, reason: "USAGE", code: errx.CodeUsage},
		{name: "self link by id", change: func(in *OperatorSnapshotInput) { in.TargetID = "2-12" }, reason: "USAGE", code: errx.CodeUsage},
		{name: "self link by readable id", change: func(in *OperatorSnapshotInput) { in.TargetID = "APP-12" }, reason: "USAGE", code: errx.CodeUsage},
		{name: "unsafe target id", change: func(in *OperatorSnapshotInput) { in.TargetID = "../x" }, reason: "USAGE", code: errx.CodeUsage},
		{name: "unknown target issue", change: func(in *OperatorSnapshotInput) { in.TargetID = "OPS-99" }, reason: "NOT_FOUND_ISSUE", code: errx.CodeNotFound},
		{name: "target project not allowlisted", change: func(in *OperatorSnapshotInput) { in.TargetID = "ARC-1" }, denied: true},
		{name: "source project not allowlisted", change: func(in *OperatorSnapshotInput) { in.IssueID = "ARC-1" }, denied: true},
		{name: "target project archived", setup: func(f *linkFixture) { f.issues["2-19"].archived = true }, reason: "OPERATOR_PROJECT_ARCHIVED", code: errx.CodePermission},
		{name: "source project archived", setup: func(f *linkFixture) { f.issues["2-12"].archived = true }, reason: "OPERATOR_PROJECT_ARCHIVED", code: errx.CodePermission},
		{name: "directed type with identical phrases", setup: func(f *linkFixture) { f.types[1]["targetToSource"] = "depends on" }, reason: "OPERATOR_LINK_DIRECTION_AMBIGUOUS", code: errx.CodeUsage},
		{name: "undirected aggregation type", setup: func(f *linkFixture) { f.types[0]["aggregation"] = true }, change: func(in *OperatorSnapshotInput) { in.LinkType, in.Direction = "Relates", "relates to" }, reason: "OPERATOR_LINK_TYPE_UNSUPPORTED", code: errx.CodeUsage},
		{name: "link type page truncated", setup: manyTypes, reason: "OPERATOR_SCHEMA_TRUNCATED", code: errx.CodeConflict},
		{name: "link type without directed", setup: func(f *linkFixture) { delete(f.types[1], "directed") }, reason: "INTERNAL", code: errx.CodeInternal},
		{name: "link entries page truncated", setup: func(f *linkFixture) {
			for index := range 100 {
				f.entries["2-12"] = append(f.entries["2-12"], &linkEntryState{id: fmt.Sprintf("x-%d", index), typeID: "105-0", direction: "BOTH"})
			}
		}, reason: "OPERATOR_LINKS_TRUNCATED", code: errx.CodeConflict},
		{name: "no entry for the type and side", setup: func(f *linkFixture) {
			f.entries["2-12"] = f.entries["2-12"][:1]
		}, reason: "OPERATOR_LINK_ENTRY_UNAVAILABLE", code: errx.CodeUsage},
		{name: "two entries for the type and side", setup: func(f *linkFixture) {
			f.entries["2-12"] = append(f.entries["2-12"], &linkEntryState{id: "dup", typeID: "105-1", direction: "OUTWARD"})
		}, reason: "OPERATOR_LINK_ENTRY_UNAVAILABLE", code: errx.CodeUsage},
		{name: "already linked", setup: func(f *linkFixture) { f.addLocked("2-12", "105-1", "OUTWARD", "2-19") }, reason: "OPERATOR_LINK_ALREADY_PRESENT", code: errx.CodeUsage},
		{name: "already linked from the other side", setup: func(f *linkFixture) { f.addLocked("2-19", "105-1", "INWARD", "2-12") }, reason: "OPERATOR_LINK_ALREADY_PRESENT", code: errx.CodeUsage},
		{name: "already the parent", change: func(in *OperatorSnapshotInput) { in.LinkType, in.Direction = "Subtask", "subtask of" },
			setup:  func(f *linkFixture) { f.addLocked("2-19", "105-3", "OUTWARD", "2-12") },
			reason: "OPERATOR_LINK_ALREADY_PRESENT", code: errx.CodeUsage},
		{name: "child already has a parent (source is the child)", change: func(in *OperatorSnapshotInput) { in.LinkType, in.Direction = "Subtask", "subtask of" },
			setup:  func(f *linkFixture) { f.addLocked("2-13", "105-3", "OUTWARD", "2-12") },
			reason: "OPERATOR_LINK_PARENT_EXISTS", code: errx.CodeUsage},
		{name: "child already has a parent (target is the child)", change: func(in *OperatorSnapshotInput) { in.LinkType, in.Direction = "Subtask", "parent for" },
			setup:  func(f *linkFixture) { f.addLocked("2-13", "105-3", "OUTWARD", "2-19") },
			reason: "OPERATOR_LINK_PARENT_EXISTS", code: errx.CodeUsage},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newLinkFixture(t)
			f.edit(func(f *linkFixture) {
				if test.setup != nil {
					test.setup(f)
				}
			})
			_, err := f.snapshot(t, test.change)
			if test.denied {
				if !errors.Is(err, writepolicy.ErrProjectDenied) {
					t.Fatalf("err=%v, want a project policy denial", err)
				}
			} else {
				requireRefusal(t, err, test.reason, test.code)
			}
			if len(f.nonGET()) != 0 || f.postCount() != 0 {
				t.Fatalf("snapshot wrote: %v", f.nonGET())
			}
			f.requireNoSentinel(t, err)
		})
	}
}

func TestOperatorIssueLinkSnapshotErrorCarriesGuidance(t *testing.T) {
	f := newLinkFixture(t)
	_, err := f.snapshot(t, func(in *OperatorSnapshotInput) { in.LinkType = "Nope" })
	var typed *errx.Error
	if !errors.As(err, &typed) || len(typed.DidYouMean) != 4 {
		t.Fatalf("unknown type error=%#v", err)
	}
	f.link("2-12", "105-1", "OUTWARD", "2-19")
	_, err = f.snapshot(t, nil)
	if !errors.As(err, &typed) || !strings.Contains(typed.Hint, "nothing to change; do not retry unchanged") {
		t.Fatalf("already present error=%#v", err)
	}
}

func TestOperatorIssueLinkTruncatedLinkedIssuesAreRefused(t *testing.T) {
	f := newLinkFixture(t)
	fillers := f.addFillers(101)
	f.edit(func(f *linkFixture) { f.entry("2-12", "105-1", "OUTWARD").issues = fillers })
	_, err := f.snapshot(t, nil)
	requireRefusal(t, err, "OPERATOR_LINKS_TRUNCATED", errx.CodeConflict)
	var typed *errx.Error
	if !errors.As(err, &typed) || !strings.Contains(typed.Hint, "swap --id and --target-id") {
		t.Fatalf("hint=%#v", err)
	}
}

func TestOperatorIssueLinkByTypeIDNeedsNoTypeListing(t *testing.T) {
	f := newLinkFixture(t)
	f.edit(func(f *linkFixture) {
		for index := range 100 {
			f.types = append(f.types, map[string]any{"id": fmt.Sprintf("106-%d", index), "name": fmt.Sprintf("Extra%d", index), "directed": false, "aggregation": false, "sourceToTarget": "x", "targetToSource": "x"})
		}
	})
	info, err := f.snapshot(t, func(in *OperatorSnapshotInput) { in.LinkType, in.LinkTypeID = "", "105-1" })
	if err != nil || info.Snapshot.Link.Type.ID != "105-1" {
		t.Fatalf("info=%#v err=%v", info, err)
	}
	for _, request := range f.requests {
		if strings.Contains(request, "/issueLinkTypes?") {
			t.Fatalf("listed link types: %s", request)
		}
	}
}

func TestOperatorIssueLinkRequiresItsOwnCapability(t *testing.T) {
	f := newLinkFixture(t)
	selected, err := f.service.Profiles.Get(t.Context(), "work")
	if err != nil {
		t.Fatal(err)
	}
	selected.Capabilities = []profile.Capability{profile.CapabilityRead, profile.CapabilityIssueEdit}
	if err := f.service.Profiles.Put(t.Context(), selected); err != nil {
		t.Fatal(err)
	}
	_, err = f.snapshot(t, nil)
	requireRefusal(t, err, "OPERATOR_CAPABILITY_REQUIRED", errx.CodePermission)
	if f.requestCount() != 0 {
		t.Fatalf("refusal made %d requests", f.requestCount())
	}
}

func TestOperatorIssueLinkPrepareIsOfflineAndDigestMismatchPrecedesCredentials(t *testing.T) {
	f := newLinkFixture(t)
	snapshot, err := f.snapshot(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(snapshot.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	creds, network := &trapCredentials{}, &trapTransport{}
	f.service.Credentials, f.service.HTTP = creds, network
	plan, err := f.service.PrepareOperatorWrite(t.Context(), OperatorPrepareInput{Profile: "work", SnapshotJSON: raw, RequestJSON: []byte(`{"kind":"issue.link"}`)})
	if err != nil || plan.PlanID == "" || creds.calls != 0 || network.calls != 0 {
		t.Fatalf("prepare=%#v err=%v credentials=%d network=%d", plan, err, creds.calls, network.calls)
	}
	for _, mode := range []string{"missing yes", "wrong digest", "missing digest"} {
		input := OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: plan.IntentSHA256, Yes: true}
		switch mode {
		case "missing yes":
			input.Yes = false
		case "wrong digest":
			input.ConfirmIntent = strings.Repeat("a", 64)
		case "missing digest":
			input.ConfirmIntent = ""
		}
		_, err := f.service.ApplyOperatorWrite(t.Context(), input)
		requireRefusal(t, err, "OPERATOR_CONFIRMATION_REQUIRED", errx.CodeConfirm)
		if creds.calls != 0 || network.calls != 0 {
			t.Fatalf("%s reached credentials=%d network=%d", mode, creds.calls, network.calls)
		}
	}
	record, err := f.service.OperatorWrites.Get(t.Context(), plan.PlanID)
	if err != nil || record.NonReplayable() {
		t.Fatalf("refusals consumed the plan: %#v %v", record, err)
	}
}

func TestOperatorIssueLinkRemovedTargetProjectIsRefusedByApplyAndUnresolvedReconcile(t *testing.T) {
	removeOPS := func(t *testing.T, f *linkFixture) {
		t.Helper()
		selected, err := f.service.Profiles.Get(t.Context(), "work")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.service.Policies.Set(t.Context(), selected, []writepolicy.Project{{ID: "0-3", Key: "APP"}}); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("apply", func(t *testing.T) {
		f := newLinkFixture(t)
		plan := f.prepare(t, nil)
		removeOPS(t, f)
		before := f.requestCount()
		_, err := f.apply(t, plan)
		if !errors.Is(err, writepolicy.ErrProjectDenied) {
			t.Fatalf("err=%v, want a project policy denial", err)
		}
		status, statusErr := f.service.OperatorWriteStatus(t.Context(), plan.PlanID)
		if f.postCount() != 0 || f.requestCount() != before || statusErr != nil || status.NonReplayable {
			t.Fatalf("posts=%d requests=%d status=%#v %v", f.postCount(), f.requestCount()-before, status, statusErr)
		}
	})
	t.Run("unresolved reconcile", func(t *testing.T) {
		f := newLinkFixture(t)
		plan := f.prepare(t, nil)
		if _, err := f.service.OperatorWrites.Claim(t.Context(), plan.PlanID, plan.IntentSHA256, f.service.currentTime()); err != nil {
			t.Fatal(err)
		}
		removeOPS(t, f)
		before := f.requestCount()
		_, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: plan.PlanID, Limit: 20})
		if !errors.Is(err, writepolicy.ErrProjectDenied) {
			t.Fatalf("err=%v, want a project policy denial", err)
		}
		if f.requestCount() != before || len(f.nonGET()) != 0 {
			t.Fatalf("reconcile reached the server: %d new requests", f.requestCount()-before)
		}
	})
}

// A terminal record returns its preserved local outcome for every kind, with
// no policy check, credential access or network request, so removing a project
// from the allowlist does not change a verified result.
func TestOperatorIssueLinkAppliedRecordReconcilesOfflineAfterProjectLeavesPolicy(t *testing.T) {
	f := newLinkFixture(t)
	plan := f.prepare(t, nil)
	applied, err := f.apply(t, plan)
	if err != nil || applied.State != string(operatorwrite.StateApplied) || f.postCount() != 1 {
		t.Fatalf("apply=%#v err=%v posts=%d", applied, err, f.postCount())
	}
	selected, err := f.service.Profiles.Get(t.Context(), "work")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Policies.Set(t.Context(), selected, []writepolicy.Project{{ID: "0-3", Key: "APP"}}); err != nil {
		t.Fatal(err)
	}
	before := f.requestCount()
	result, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: plan.PlanID, Limit: 20})
	if err != nil || result.State != string(operatorwrite.StateApplied) || result.Evidence != "verified_terminal_record_preserved" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if f.requestCount() != before || f.postCount() != 1 {
		t.Fatalf("terminal reconcile reached the server: %d new requests, posts=%d", f.requestCount()-before, f.postCount())
	}
}

func TestOperatorIssueLinkApplyDriftIsConflictWithZeroPostAndPlanUnconsumed(t *testing.T) {
	subtask := func(in *OperatorSnapshotInput) { in.LinkType, in.Direction = "Subtask", "subtask of" }
	tests := []struct {
		name   string
		change func(*OperatorSnapshotInput)
		drift  func(*linkFixture)
		reason string
	}{
		{name: "source moved to another project", drift: func(f *linkFixture) { f.issues["2-12"].projectID, f.issues["2-12"].projectKey = "0-4", "OPS" }, reason: "OPERATOR_ISSUE_STALE"},
		{name: "target moved to another project", drift: func(f *linkFixture) { f.issues["2-19"].projectID, f.issues["2-19"].projectKey = "0-3", "APP" }, reason: "OPERATOR_ISSUE_STALE"},
		{name: "target project archived", drift: func(f *linkFixture) { f.issues["2-19"].archived = true }, reason: "OPERATOR_ISSUE_STALE"},
		{name: "source project archived", drift: func(f *linkFixture) { f.issues["2-12"].archived = true }, reason: "OPERATOR_ISSUE_STALE"},
		{name: "target readable id changed", drift: func(f *linkFixture) { f.issues["2-19"].readable = "OPS-70" }, reason: "OPERATOR_ISSUE_STALE"},
		{name: "link type renamed", drift: func(f *linkFixture) { f.types[1]["name"] = "Renamed" }, reason: "OPERATOR_LINK_STALE"},
		{name: "link type phrase changed", drift: func(f *linkFixture) { f.types[1]["sourceToTarget"] = "needs" }, reason: "OPERATOR_LINK_STALE"},
		{name: "link type became aggregation", drift: func(f *linkFixture) { f.types[1]["aggregation"] = true }, reason: "OPERATOR_LINK_STALE"},
		{name: "server link entry id changed", drift: func(f *linkFixture) { f.entry("2-12", "105-1", "OUTWARD").id = "renumbered" }, reason: "OPERATOR_LINK_STALE"},
		{name: "server link entry vanished", drift: func(f *linkFixture) { f.entries["2-12"] = f.entries["2-12"][:1] }, reason: "OPERATOR_LINK_STALE"},
		{name: "link appeared", drift: func(f *linkFixture) { f.addLocked("2-12", "105-1", "OUTWARD", "2-19") }, reason: "OPERATOR_LINK_STALE"},
		{name: "link appeared from the target side", drift: func(f *linkFixture) { f.addLocked("2-19", "105-1", "INWARD", "2-12") }, reason: "OPERATOR_LINK_STALE"},
		{name: "child gained a parent", change: subtask, drift: func(f *linkFixture) { f.addLocked("2-13", "105-3", "OUTWARD", "2-12") }, reason: "OPERATOR_LINK_STALE"},
		{name: "child inward entry vanished", change: subtask, drift: func(f *linkFixture) {
			var kept []*linkEntryState
			for _, entry := range f.entries["2-12"] {
				if entry.id != linkEntryID("2-12", "105-3", "INWARD") {
					kept = append(kept, entry)
				}
			}
			f.entries["2-12"] = kept
		}, reason: "OPERATOR_LINK_STALE"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newLinkFixture(t)
			plan := f.prepare(t, test.change)
			f.edit(test.drift)
			_, err := f.apply(t, plan)
			requireRefusal(t, err, test.reason, errx.CodeConflict)
			status, statusErr := f.service.OperatorWriteStatus(t.Context(), plan.PlanID)
			if f.postCount() != 0 || statusErr != nil || status.State != string(operatorwrite.StatePrepared) || status.NonReplayable {
				t.Fatalf("drift posted=%d or consumed the plan: %#v %v", f.postCount(), status, statusErr)
			}
			f.requireNoSentinel(t, err)
		})
	}
}

func TestOperatorIssueLinkUpdatedTimestampIsNotAPrecondition(t *testing.T) {
	f := newLinkFixture(t)
	plan := f.prepare(t, nil)
	f.edit(func(f *linkFixture) { f.issues["2-12"].updated++; f.issues["2-19"].updated += 5 })
	applied, err := f.apply(t, plan)
	if err != nil || applied.State != string(operatorwrite.StateApplied) || f.postCount() != 1 {
		t.Fatalf("applied=%#v err=%v posts=%d", applied, err, f.postCount())
	}
}

func TestOperatorIssueLinkConcurrentAddBeforePostIsRecordedApplied(t *testing.T) {
	f := newLinkFixture(t)
	plan := f.prepare(t, nil)
	f.beforePost = func(f *linkFixture) { f.addLocked("2-12", "105-1", "OUTWARD", "2-19") }
	applied, err := f.apply(t, plan)
	if err != nil || applied.State != string(operatorwrite.StateApplied) || f.postCount() != 1 {
		t.Fatalf("applied=%#v err=%v posts=%d", applied, err, f.postCount())
	}
}

func TestOperatorIssueLinkConcurrentApplyPostsOnce(t *testing.T) {
	f := newLinkFixture(t)
	plan := f.prepare(t, nil)
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for index := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[index] = f.service.ApplyOperatorWrite(t.Context(), OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: plan.IntentSHA256, Yes: true})
		}()
	}
	wg.Wait()
	succeeded := 0
	for _, err := range errs {
		if err == nil {
			succeeded++
		} else if reason := operatorReason(t, err); reason != "OPERATOR_PLAN_CONSUMED" && reason != "OPERATOR_LINK_STALE" {
			// A loser either sees the consumed plan or the link the winner added.
			t.Fatalf("loser err=%v", err)
		}
	}
	if succeeded != 1 || f.postCount() != 1 {
		t.Fatalf("succeeded=%d posts=%d errs=%v", succeeded, f.postCount(), errs)
	}
}

func TestOperatorIssueLinkTransportLossAfterClaimIsUnknownWithoutReplay(t *testing.T) {
	f := newLinkFixture(t)
	plan := f.prepare(t, nil)
	transport := &methodTransport{next: f.service.HTTP, failPOST: true}
	f.service.HTTP = transport
	_, err := f.apply(t, plan)
	if operatorReason(t, err) != "WRITE_OUTCOME_UNKNOWN" {
		t.Fatalf("err=%v", err)
	}
	status, statusErr := f.service.OperatorWriteStatus(t.Context(), plan.PlanID)
	if statusErr != nil || status.State != string(operatorwrite.StateUnknown) || !status.NonReplayable {
		t.Fatalf("status=%#v err=%v", status, statusErr)
	}
	transport.failPOST = false
	before := f.requestCount()
	_, err = f.apply(t, plan)
	requireRefusal(t, err, "OPERATOR_PLAN_CONSUMED", errx.CodeConflict)
	if len(transport.posts) != 1 || f.postCount() != 0 || f.requestCount() != before {
		t.Fatalf("replay attempted: posts=%d server posts=%d new requests=%d", len(transport.posts), f.postCount(), f.requestCount()-before)
	}
	f.requireNoSentinel(t, err, status)
}

func TestOperatorIssueLinkPostOutcomesAreSingleAndClassified(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		noEffect   bool
		wantState  operatorwrite.State
		wantReason string
		wantCode   errx.Code
	}{
		{name: "rate limited", status: 429, wantState: operatorwrite.StateUnknown, wantReason: "WRITE_OUTCOME_UNKNOWN", wantCode: errx.CodeConflict},
		{name: "server error", status: 500, wantState: operatorwrite.StateUnknown, wantReason: "WRITE_OUTCOME_UNKNOWN", wantCode: errx.CodeConflict},
		{name: "bad gateway", status: 502, wantState: operatorwrite.StateUnknown, wantReason: "WRITE_OUTCOME_UNKNOWN", wantCode: errx.CodeConflict},
		{name: "echo names another issue", body: `{"id":"2-20","idReadable":"OPS-8"}`, wantState: operatorwrite.StateUnknown, wantReason: "WRITE_OUTCOME_UNKNOWN", wantCode: errx.CodeConflict},
		{name: "echo without readable id", body: `{"id":"2-19"}`, wantState: operatorwrite.StateUnknown, wantReason: "WRITE_OUTCOME_UNKNOWN", wantCode: errx.CodeConflict},
		{name: "success that left no link", noEffect: true, wantState: operatorwrite.StateUnknown, wantReason: "WRITE_OUTCOME_UNKNOWN", wantCode: errx.CodeConflict},
		{name: "bad request", status: 400, wantState: operatorwrite.StateRejected, wantReason: "USAGE", wantCode: errx.CodeUsage},
		{name: "forbidden", status: 403, wantState: operatorwrite.StateRejected, wantReason: "PERMISSION_DENIED", wantCode: errx.CodePermission},
		{name: "not found", status: 404, wantState: operatorwrite.StateRejected, wantReason: "TARGET_CHANGED", wantCode: errx.CodeConflict},
		{name: "conflict", status: 409, wantState: operatorwrite.StateRejected, wantReason: "PRECONDITION_FAILED", wantCode: errx.CodeConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newLinkFixture(t)
			plan := f.prepare(t, nil)
			f.postStatus, f.postBody, f.postEffect = test.status, test.body, !test.noEffect
			_, err := f.apply(t, plan)
			requireRefusal(t, err, test.wantReason, test.wantCode)
			status, statusErr := f.service.OperatorWriteStatus(t.Context(), plan.PlanID)
			if statusErr != nil || status.State != string(test.wantState) || !status.NonReplayable || f.postCount() != 1 {
				t.Fatalf("status=%#v err=%v posts=%d", status, statusErr, f.postCount())
			}
			_, err = f.apply(t, plan)
			requireRefusal(t, err, "OPERATOR_PLAN_CONSUMED", errx.CodeConflict)
			if f.postCount() != 1 {
				t.Fatalf("replay posted: %d", f.postCount())
			}
		})
	}
}

func TestOperatorIssueLinkReconcileIsGETOnlyAndNeverProvesCausation(t *testing.T) {
	filler := func(f *linkFixture) []string { return f.addFillers(2) }
	tests := []struct {
		name         string
		setup        func(*linkFixture, []string)
		limit        int
		offset       int
		wantEvidence string
	}{
		{name: "link present", setup: func(f *linkFixture, _ []string) { f.addLocked("2-12", "105-1", "OUTWARD", "2-19") }, limit: 20, wantEvidence: "desired_link_observed_without_causal_proof"},
		{name: "link absent", limit: 20, wantEvidence: "inconclusive"},
		{name: "present beyond the bounded page", setup: func(f *linkFixture, fillers []string) {
			f.entry("2-12", "105-1", "OUTWARD").issues = append(append([]string{}, fillers...), "2-19")
		}, limit: 2, wantEvidence: "inconclusive"},
		{name: "present on the requested later page", setup: func(f *linkFixture, fillers []string) {
			f.entry("2-12", "105-1", "OUTWARD").issues = append(append([]string{}, fillers...), "2-19")
		}, limit: 2, offset: 2, wantEvidence: "desired_link_observed_without_causal_proof"},
		{name: "entry vanished", setup: func(f *linkFixture, _ []string) { f.entries["2-12"] = nil }, limit: 20, wantEvidence: "inconclusive"},
		{name: "target deleted after unknown POST", setup: func(f *linkFixture, _ []string) { delete(f.issues, "2-19") }, limit: 20, wantEvidence: "linked_issue_unavailable"},
		{name: "source deleted after unknown POST", setup: func(f *linkFixture, _ []string) { delete(f.issues, "2-12") }, limit: 20, wantEvidence: "linked_issue_unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newLinkFixture(t)
			fillers := filler(f)
			plan := f.prepare(t, nil)
			if _, err := f.service.OperatorWrites.Claim(t.Context(), plan.PlanID, plan.IntentSHA256, f.service.currentTime()); err != nil {
				t.Fatal(err)
			}
			if test.setup != nil {
				f.edit(func(f *linkFixture) { test.setup(f, fillers) })
			}
			result, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: plan.PlanID, Limit: test.limit, Offset: test.offset})
			if err != nil || result.State != string(operatorwrite.StateOperatorRequired) || result.Evidence != test.wantEvidence || !result.NonReplayable {
				t.Fatalf("result=%#v err=%v", result, err)
			}
			if len(f.nonGET()) != 0 || f.postCount() != 0 {
				t.Fatalf("reconcile wrote: %v", f.nonGET())
			}
			again, err := f.apply(t, plan)
			requireRefusal(t, err, "OPERATOR_PLAN_CONSUMED", errx.CodeConflict)
			f.requireNoSentinel(t, result, again)
		})
	}
}

func TestOperatorIssueLinkReconcileRefusesMovedProjects(t *testing.T) {
	for _, issue := range []string{"2-12", "2-19"} {
		t.Run(issue, func(t *testing.T) {
			f := newLinkFixture(t)
			plan := f.prepare(t, nil)
			if _, err := f.service.OperatorWrites.Claim(t.Context(), plan.PlanID, plan.IntentSHA256, f.service.currentTime()); err != nil {
				t.Fatal(err)
			}
			f.edit(func(f *linkFixture) { f.issues[issue].projectID, f.issues[issue].projectKey = "0-3", "ZZZ" })
			_, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: plan.PlanID, Limit: 20})
			requireRefusal(t, err, "OPERATOR_PROJECT_CHANGED", errx.CodeConflict)
			if len(f.nonGET()) != 0 {
				t.Fatalf("reconcile wrote: %v", f.nonGET())
			}
		})
	}
}

func TestOperatorIssueLinkCapabilitiesAdvertiseTheKind(t *testing.T) {
	f := newLinkFixture(t)
	info, err := f.service.Capabilities(t.Context(), "work")
	if err != nil {
		t.Fatal(err)
	}
	if info.PlanVersions["issue.link"] != operatorwrite.PlanVersion4 || len(info.Kinds) != 1 || info.Kinds[0] != "issue.link" || !info.LocallyReady {
		t.Fatalf("capabilities=%#v", info)
	}
}

func TestOperatorIssueLinkOldPlanVersionsRefuseTheKind(t *testing.T) {
	f := newLinkFixture(t)
	plan := f.prepare(t, nil)
	for _, version := range []int{operatorwrite.LegacyPlanVersion1, operatorwrite.PlanVersion2, operatorwrite.PlanVersion3} {
		old := *plan.Plan
		old.Version = version
		if operatorwrite.ValidatePlan(old) == nil {
			t.Fatalf("plan version %d accepted issue.link", version)
		}
	}
}
