package operatorwrite

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func userSnapshot(t *testing.T) Snapshot {
	t.Helper()
	s := testSnapshot(t, KindIssueUpdate)
	s.Field = &Field{IssueFieldID: "92-2", ProjectFieldID: "94-2", GlobalFieldID: "58-3", Name: "Assignee", Type: "SingleUserIssueCustomField",
		ProjectFieldType: "UserProjectCustomField", ValueType: "user", FieldTypeID: "user[1]", FieldTypeType: "FieldType", IsPublic: true, CanBeEmpty: true,
		BundleID: "30-1", BundleType: "UserBundle",
		CurrentValue: &Value{ID: "1-5", Name: "alice", Type: "User"}, TargetValue: &Value{ID: "1-6", Name: "bob", Type: "User"}}
	return s
}

func clearSnapshot(t *testing.T) Snapshot {
	t.Helper()
	s := testSnapshot(t, KindIssueUpdate)
	s.Field.CanBeEmpty, s.Field.TargetValue = true, nil
	return s
}

func requestFor(s Snapshot) Request {
	if s.Kind == KindIssueCreate {
		return Request{Kind: s.Kind, Summary: "Summary", Description: "Description"}
	}
	return Request{Kind: s.Kind}
}

func prepareSnapshot(s Snapshot) (Plan, error) {
	return Prepare(s, requestFor(s), s.CapturedAt.Add(time.Minute))
}

func TestPlanVersionFor(t *testing.T) {
	for _, test := range []struct {
		kind Kind
		want int
	}{
		{KindIssueCreate, PlanVersion5},
		{KindIssueEdit, PlanVersion4},
		{KindIssueUpdate, PlanVersion4},
		{KindCommentAdd, PlanVersion5},
		{KindCommentDelete, PlanVersion3},
	} {
		t.Run(string(test.kind), func(t *testing.T) {
			if got := PlanVersionFor(test.kind); got != test.want {
				t.Fatalf("PlanVersionFor(%s) = %d, want %d", test.kind, got, test.want)
			}
		})
	}
	for _, version := range []int{PlanVersion2, PlanVersion3, PlanVersion4, PlanVersion5} {
		if PlanLifetime(version) != CurrentPlanLifetime || !durablePlanVersion(version) {
			t.Fatalf("version %d is not durable", version)
		}
	}
	if durablePlanVersion(LegacyPlanVersion1) || durablePlanVersion(6) || PlanLifetime(6) != "" {
		t.Fatal("legacy or unknown version treated as durable")
	}
}

func TestFieldDecodeRequiresTargetValueKey(t *testing.T) {
	field := testSnapshot(t, KindIssueUpdate).Field
	field.TargetValue = nil
	withNull, err := json.Marshal(field)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(withNull, []byte(`"target_value":null`)) {
		t.Fatalf("nil target must encode as an explicit null: %s", withNull)
	}
	missing := bytes.Replace(withNull, []byte(`,"target_value":null`), nil, 1)
	if bytes.Equal(missing, withNull) {
		t.Fatalf("test fixture did not drop the key: %s", withNull)
	}
	for _, test := range []struct {
		name    string
		raw     string
		wantErr bool
		wantNil bool
	}{
		{"explicit null", string(withNull), false, true},
		{"missing key", string(missing), true, false},
		{"unknown member", strings.Replace(string(withNull), `{`, `{"extra":1,`, 1), true, false},
		{"unknown target member", strings.Replace(string(withNull), `"target_value":null`, `"target_value":{"id":"1-1","name":"x","type":"User","archived":false,"extra":1}`, 1), true, false},
		{"trailing value", string(withNull) + `{}`, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var decoded Field
			err := json.Unmarshal([]byte(test.raw), &decoded)
			if (err != nil) != test.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, test.wantErr)
			}
			if err == nil && (decoded.TargetValue == nil) != test.wantNil {
				t.Fatalf("target=%#v", decoded.TargetValue)
			}
		})
	}
}

func TestSnapshotAndPlanDecodeRefuseMissingTargetKey(t *testing.T) {
	for _, test := range []struct {
		name     string
		snapshot func(*testing.T) Snapshot
		drop     string
	}{
		{"update", clearSnapshot, `"target_value":null`},
		{"update with value", func(t *testing.T) Snapshot { return testSnapshot(t, KindIssueUpdate) }, `"target_value":{"id":"20-2","name":"PR Review","type":"StateBundleElement","archived":false}`},
		{"create fields", testCreateSnapshot, `"target_value":{"id":"20-2","name":"In Progress","type":"StateBundleElement","archived":false}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := test.snapshot(t)
			raw, err := json.Marshal(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeSnapshot(bytes.NewReader(raw)); err != nil {
				t.Fatalf("complete snapshot refused: %v", err)
			}
			stripped := bytes.Replace(raw, []byte(","+test.drop), nil, 1)
			if bytes.Equal(stripped, raw) {
				t.Fatalf("fixture did not contain %s: %s", test.drop, raw)
			}
			if _, err := DecodeSnapshot(bytes.NewReader(stripped)); err == nil {
				t.Fatal("snapshot without target_value accepted")
			}
			plan, err := prepareSnapshot(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			planRaw, err := json.Marshal(plan)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodePlan(bytes.NewReader(planRaw)); err != nil {
				t.Fatalf("complete plan refused: %v", err)
			}
			if _, err := DecodePlan(bytes.NewReader(bytes.Replace(planRaw, []byte(","+test.drop), nil, 1))); err == nil {
				t.Fatal("plan without target_value accepted")
			}
		})
	}
}

func TestClearTargetValidation(t *testing.T) {
	for _, test := range []struct {
		name   string
		build  func(*testing.T) Snapshot
		change func(*Snapshot)
		ok     bool
	}{
		{"clearable update", clearSnapshot, func(*Snapshot) {}, true},
		{"not clearable", clearSnapshot, func(s *Snapshot) { s.Field.CanBeEmpty = false }, false},
		{"already empty", clearSnapshot, func(s *Snapshot) { s.Field.CurrentValue = nil }, false},
		{"clearable set to value", func(t *testing.T) Snapshot { return testSnapshot(t, KindIssueUpdate) }, func(s *Snapshot) { s.Field.CanBeEmpty = true }, true},
		{"create with null target on a required field", testCreateSnapshot, func(s *Snapshot) { s.Fields[0].TargetValue = nil }, false},
		{"create with null target on clearable field", testCreateSnapshot, func(s *Snapshot) { s.Fields[0].CanBeEmpty, s.Fields[0].TargetValue = true, nil }, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := test.build(t)
			test.change(&s)
			plan, err := prepareSnapshot(s)
			if (err == nil) != test.ok {
				t.Fatalf("err=%v, want ok=%v", err, test.ok)
			}
			if err == nil && ValidatePlan(plan) != nil {
				t.Fatal("prepared plan failed validation")
			}
		})
	}
}

func TestUserFieldValidation(t *testing.T) {
	if plan, err := prepareSnapshot(userSnapshot(t)); err != nil || plan.Version != PlanVersion4 {
		t.Fatalf("valid user plan: version=%d err=%v", plan.Version, err)
	}
	for _, test := range []struct {
		name   string
		change func(*Snapshot)
	}{
		{"target is a bundle element", func(s *Snapshot) { s.Field.TargetValue.Type = "EnumBundleElement" }},
		{"target without type", func(s *Snapshot) { s.Field.TargetValue.Type = "" }},
		{"current is a bundle element", func(s *Snapshot) { s.Field.CurrentValue.Type = "StateBundleElement" }},
		{"archived target", func(s *Snapshot) { s.Field.TargetValue.Archived = true }},
		{"archived current", func(s *Snapshot) { s.Field.CurrentValue.Archived = true }},
		{"blank login", func(s *Snapshot) { s.Field.TargetValue.Name = " " }},
		{"missing id", func(s *Snapshot) { s.Field.TargetValue.ID = "" }},
		{"wrong project field type", func(s *Snapshot) { s.Field.ProjectFieldType = "EnumProjectCustomField" }},
		{"wrong value type", func(s *Snapshot) { s.Field.ValueType = "enum" }},
		{"wrong bundle type", func(s *Snapshot) { s.Field.BundleType = "EnumBundle" }},
		{"wrong field type id", func(s *Snapshot) { s.Field.FieldTypeID = "enum[1]" }},
		{"multi value", func(s *Snapshot) { s.Field.IsMultiValue = true }},
		{"unknown issue field type", func(s *Snapshot) { s.Field.Type = "MultiUserIssueCustomField" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := userSnapshot(t)
			test.change(&s)
			if _, err := prepareSnapshot(s); err == nil {
				t.Fatal("invalid user snapshot accepted")
			}
		})
	}
	t.Run("clearing a user field", func(t *testing.T) {
		s := userSnapshot(t)
		s.Field.TargetValue = nil
		if plan, err := prepareSnapshot(s); err != nil || plan.Version != PlanVersion4 {
			t.Fatalf("user clear: version=%d err=%v", plan.Version, err)
		}
	})
}

func TestOlderPlanVersionsRefuseUserAndNullTarget(t *testing.T) {
	for _, test := range []struct {
		name     string
		snapshot func(*testing.T) Snapshot
		allowed  bool
	}{
		{"state field", func(t *testing.T) Snapshot { return testSnapshot(t, KindIssueUpdate) }, true},
		{"user field", userSnapshot, false},
		{"null target", clearSnapshot, false},
	} {
		for _, version := range []int{LegacyPlanVersion1, PlanVersion2, PlanVersion3, PlanVersion4} {
			t.Run(test.name+"/v"+string(rune('0'+version)), func(t *testing.T) {
				plan, err := prepareSnapshot(test.snapshot(t))
				if err != nil {
					t.Fatal(err)
				}
				plan.Version = version
				if version == LegacyPlanVersion1 {
					plan.ExpiresAt = plan.CreatedAt.Add(LegacyPlanTTL)
				}
				plan.SHA256, err = digest(plan)
				if err != nil {
					t.Fatal(err)
				}
				// v3 is the comment.delete version and never fits an update.
				want := test.allowed && version != PlanVersion3 || version == PlanVersion4
				if got := ValidatePlan(plan) == nil; got != want {
					t.Fatalf("ValidatePlan accepted=%v, want %v", got, want)
				}
			})
		}
	}
}

func TestClearPlanRoundTripsWithExplicitNull(t *testing.T) {
	plan, err := prepareSnapshot(clearSnapshot(t))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"target_value":null`)) {
		t.Fatalf("clear plan lost its explicit null: %s", raw)
	}
	decoded, err := DecodePlan(bytes.NewReader(raw))
	if err != nil || decoded.Snapshot.Field.TargetValue != nil || decoded.SHA256 != plan.SHA256 {
		t.Fatalf("decoded clear plan: %+v %v", decoded, err)
	}
}
