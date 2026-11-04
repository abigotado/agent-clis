package operatorwrite

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testCommentDeleteSnapshot(t *testing.T) Snapshot {
	t.Helper()
	base := testSnapshot(t, KindCommentAdd)
	return Snapshot{Version: Version, Lane: Lane, Kind: KindCommentDelete, Binding: base.Binding, Issue: base.Issue,
		CapturedAt: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC),
		Comment: &Comment{ID: "4-1", Text: "A complete active comment", AuthorID: "1-2", AuthorLogin: "alice", Created: 101,
			Updated: nil, Deleted: false, Pinned: false,
			Visibility:  CommentVisibility{Type: "UnlimitedVisibility", PermittedGroupIDs: []string{}, PermittedUserIDs: []string{}},
			Attachments: []string{}, RequiredServerPermission: "Delete Not Own Comment"},
	}
}

func TestCommentDeleteSnapshotFreezesOnlyCompleteActiveTarget(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Snapshot)
		wantOK bool
	}{
		{"explicit null updated is accepted", func(snapshot *Snapshot) { snapshot.Comment.Updated = nil }, true},
		{"present updated timestamp is accepted", func(snapshot *Snapshot) { updated := int64(102); snapshot.Comment.Updated = &updated }, true},
		{"deleted target is rejected", func(snapshot *Snapshot) { snapshot.Comment.Deleted = true }, false},
		{"nil attachments are rejected", func(snapshot *Snapshot) { snapshot.Comment.Attachments = nil }, false},
		{"nonempty attachments are rejected", func(snapshot *Snapshot) { snapshot.Comment.Attachments = []string{"9-1"} }, false},
		{"missing target is rejected", func(snapshot *Snapshot) { snapshot.Comment = nil }, false},
		{"unknown required permission is rejected", func(snapshot *Snapshot) { snapshot.Comment.RequiredServerPermission = "Delete Everything" }, false},
		{"untrusted malformed visibility is rejected", func(snapshot *Snapshot) { snapshot.Comment.Visibility.Type = "" }, false},
		{"legacy comment add cannot contain delete target", func(snapshot *Snapshot) { snapshot.Kind = KindCommentAdd }, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := testCommentDeleteSnapshot(t)
			test.mutate(&snapshot)
			err := ValidateSnapshot(snapshot)
			if test.wantOK && err != nil {
				t.Fatalf("ValidateSnapshot() error = %v", err)
			}
			if !test.wantOK && err == nil {
				t.Fatal("ValidateSnapshot() accepted an incomplete or incompatible delete target")
			}
		})
	}
}

func TestCommentDeletePrepareIsVersion3AndDeleteOnly(t *testing.T) {
	tests := []struct {
		name    string
		request Request
		wantOK  bool
	}{
		{"kind only request produces a durable v3 plan", Request{Kind: KindCommentDelete}, true},
		{"comment body is rejected", Request{Kind: KindCommentDelete, CommentText: "never append a marker"}, false},
		{"summary is rejected", Request{Kind: KindCommentDelete, Summary: "delete"}, false},
		{"description is rejected", Request{Kind: KindCommentDelete, Description: "delete"}, false},
		{"different kind is rejected", Request{Kind: KindCommentAdd, CommentText: "text"}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := testCommentDeleteSnapshot(t)
			plan, err := Prepare(snapshot, test.request, snapshot.CapturedAt.Add(time.Minute))
			if !test.wantOK {
				if err == nil {
					t.Fatal("Prepare() accepted a non-delete-only request")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if plan.Version != PlanVersion3 || !plan.ExpiresAt.IsZero() || PlanLifetime(plan.Version) != CurrentPlanLifetime || plan.Request != (Request{Kind: KindCommentDelete}) {
				t.Fatalf("plan=%#v", plan)
			}
			raw, err := json.Marshal(plan)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(raw, []byte(Marker(plan.ID))) || bytes.Contains(raw, []byte(`"comment_text"`)) || bytes.Contains(raw, []byte(`"expires_at"`)) {
				t.Fatalf("delete plan retained add-only data: %s", raw)
			}
			decoded, err := DecodePlan(bytes.NewReader(raw))
			if err != nil || decoded.Version != PlanVersion3 || decoded.Snapshot.Comment == nil || decoded.Snapshot.Comment.ID != snapshot.Comment.ID {
				t.Fatalf("DecodePlan() plan=%#v err=%v", decoded, err)
			}
			plan.Snapshot.Comment.Text = "tampered"
			if ValidatePlan(plan) == nil {
				t.Fatal("ValidatePlan() accepted a frozen delete target changed without a new digest")
			}
		})
	}
}

func TestCommentDeleteSnapshotUsesDedicatedSixtyFourKiBCap(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		wantOK  bool
		minSize int
	}{
		{"plain complete comment above historical cap is accepted without truncation", strings.Repeat("x", MaxSnapshotBytes), true, MaxSnapshotBytes + 1},
		{"escaped complete comment above delete cap is rejected", strings.Repeat("<", 12*1024), false, MaxCommentDeleteSnapshotBytes + 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := testCommentDeleteSnapshot(t)
			snapshot.Comment.Text = test.text
			raw, err := json.Marshal(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if len(raw) < test.minSize || snapshot.Comment.Text != test.text {
				t.Fatalf("snapshot bytes=%d text bytes=%d", len(raw), len(snapshot.Comment.Text))
			}
			err = ValidateSnapshot(snapshot)
			if test.wantOK && err != nil {
				t.Fatalf("ValidateSnapshot() error = %v", err)
			}
			if !test.wantOK && err == nil {
				t.Fatal("ValidateSnapshot() accepted an oversized delete snapshot")
			}
		})
	}
}

func TestCommentDeleteCodecsPreserveRequiredFieldPresence(t *testing.T) {
	snapshot := testCommentDeleteSnapshot(t)
	snapshotBytes, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := Prepare(snapshot, Request{Kind: KindCommentDelete}, snapshot.CapturedAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	planBytes, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func([]byte) []byte
		wantOK bool
	}{
		{"explicit updated null is accepted", func(raw []byte) []byte { return raw }, true},
		{"missing updated is rejected", func(raw []byte) []byte { return bytes.Replace(raw, []byte(`,"updated":null`), nil, 1) }, false},
		{"missing deleted is rejected", func(raw []byte) []byte { return bytes.Replace(raw, []byte(`,"deleted":false`), nil, 1) }, false},
		{"null deleted is rejected", func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"deleted":false`), []byte(`"deleted":null`), 1)
		}, false},
		{"missing pinned is rejected", func(raw []byte) []byte { return bytes.Replace(raw, []byte(`,"pinned":false`), nil, 1) }, false},
		{"null pinned is rejected", func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"pinned":false`), []byte(`"pinned":null`), 1)
		}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidateSnapshot := test.mutate(snapshotBytes)
			candidatePlan := test.mutate(planBytes)
			if bytes.Equal(candidateSnapshot, snapshotBytes) != test.wantOK || bytes.Equal(candidatePlan, planBytes) != test.wantOK {
				t.Fatal("codec probe did not change exactly the intended field")
			}
			_, snapshotErr := DecodeSnapshot(bytes.NewReader(candidateSnapshot))
			_, planErr := DecodePlan(bytes.NewReader(candidatePlan))
			if test.wantOK && (snapshotErr != nil || planErr != nil) {
				t.Fatalf("DecodeSnapshot()=%v DecodePlan()=%v", snapshotErr, planErr)
			}
			if !test.wantOK && (snapshotErr == nil || planErr == nil) {
				t.Fatalf("required presence bypassed: DecodeSnapshot()=%v DecodePlan()=%v", snapshotErr, planErr)
			}
		})
	}
}

func TestCommentDeletePermissionMustMatchFrozenAuthor(t *testing.T) {
	tests := []struct {
		name       string
		permission string
		wantOK     bool
	}{
		{"other author requires delete not own comment", "Delete Not Own Comment", true},
		{"other author cannot claim own delete permission", "Delete Comment", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := testCommentDeleteSnapshot(t)
			snapshot.Comment.RequiredServerPermission = test.permission
			err := ValidateSnapshot(snapshot)
			if test.wantOK && err != nil {
				t.Fatalf("ValidateSnapshot() error = %v", err)
			}
			if !test.wantOK && err == nil {
				t.Fatal("ValidateSnapshot() accepted a permission inconsistent with the frozen author")
			}
		})
	}
}
