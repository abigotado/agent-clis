package operatorwrite

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// createUserField is a clearable single-user create field naming a target.
func createUserField() Field {
	return Field{ProjectFieldID: "189-9", GlobalFieldID: "58-9", Name: "Assignee", Type: "SingleUserIssueCustomField",
		ProjectFieldType: "UserProjectCustomField", ValueType: "user", FieldTypeID: "user[1]", FieldTypeType: "FieldType", IsPublic: true, CanBeEmpty: true,
		BundleID: "30-1", BundleType: "UserBundle", TargetValue: &Value{ID: "1-7", Name: "jdoe", Type: "User"}}
}

func createUserSnapshot(t *testing.T) Snapshot {
	t.Helper()
	s := testCreateSnapshot(t)
	s.Fields = append(s.Fields, createUserField())
	return s
}

func createClearSnapshot(t *testing.T) Snapshot {
	t.Helper()
	s := testCreateSnapshot(t)
	s.Fields[1].CanBeEmpty, s.Fields[1].TargetValue = true, nil
	return s
}

func createUserClearSnapshot(t *testing.T) Snapshot {
	t.Helper()
	s := testCreateSnapshot(t)
	user := createUserField()
	user.TargetValue = nil
	s.Fields = append(s.Fields, user)
	return s
}

func TestCreatePlanCarriesUserFieldsAndClearsAsVersion4(t *testing.T) {
	for _, test := range []struct {
		name     string
		snapshot func(*testing.T) Snapshot
		wantJSON string
	}{
		{"state and enum only", testCreateSnapshot, ""},
		{"user set", createUserSnapshot, `"target_value":{"id":"1-7","name":"jdoe","type":"User","archived":false}`},
		{"enum clear", createClearSnapshot, `"target_value":null`},
		{"user clear", createUserClearSnapshot, `"target_value":null`},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan, err := prepareSnapshot(test.snapshot(t))
			if err != nil || plan.Version != PlanVersion4 || !plan.ExpiresAt.IsZero() {
				t.Fatalf("version=%d err=%v", plan.Version, err)
			}
			raw, err := json.Marshal(plan)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(raw), test.wantJSON) || strings.Contains(string(raw), `"issue":`) {
				t.Fatalf("plan bytes lack %q or carry an issue: %s", test.wantJSON, raw)
			}
			decoded, err := DecodePlan(bytes.NewReader(raw))
			if err != nil || decoded.SHA256 != plan.SHA256 {
				t.Fatalf("round trip sha=%q err=%v", decoded.SHA256, err)
			}
			again, err := json.Marshal(decoded)
			if err != nil || !bytes.Equal(again, raw) {
				t.Fatalf("round trip bytes changed: %s %v", again, err)
			}
			if PlanLifetime(plan.Version) != CurrentPlanLifetime {
				t.Fatalf("lifetime=%q", PlanLifetime(plan.Version))
			}
		})
	}
}

func TestCreateFieldValidationForUserAndClear(t *testing.T) {
	for _, test := range []struct {
		name   string
		build  func(*testing.T) Snapshot
		change func(*Snapshot)
	}{
		{"clear on a field that cannot be empty", createClearSnapshot, func(s *Snapshot) { s.Fields[1].CanBeEmpty = false }},
		{"user clear on a field that cannot be empty", createUserClearSnapshot, func(s *Snapshot) { s.Fields[2].CanBeEmpty = false }},
		{"user target typed as a bundle element", createUserSnapshot, func(s *Snapshot) { s.Fields[2].TargetValue.Type = "EnumBundleElement" }},
		{"user target without a type", createUserSnapshot, func(s *Snapshot) { s.Fields[2].TargetValue.Type = "" }},
		{"user target archived", createUserSnapshot, func(s *Snapshot) { s.Fields[2].TargetValue.Archived = true }},
		{"user target blank login", createUserSnapshot, func(s *Snapshot) { s.Fields[2].TargetValue.Name = " " }},
		{"user target missing id", createUserSnapshot, func(s *Snapshot) { s.Fields[2].TargetValue.ID = "" }},
		{"user field with a current value", createUserSnapshot, func(s *Snapshot) {
			s.Fields[2].CurrentValue = &Value{ID: "1-5", Name: "alice", Type: "User"}
		}},
		{"user field with an issue field identity", createUserSnapshot, func(s *Snapshot) { s.Fields[2].IssueFieldID = "92-2" }},
		{"multi user field", createUserSnapshot, func(s *Snapshot) { s.Fields[2].IsMultiValue = true }},
		{"user field on a bundle of another type", createUserSnapshot, func(s *Snapshot) { s.Fields[2].BundleType = "EnumBundle" }},
		{"duplicate project field", createUserSnapshot, func(s *Snapshot) { s.Fields[2].ProjectFieldID = s.Fields[0].ProjectFieldID }},
		{"duplicate field name", createUserClearSnapshot, func(s *Snapshot) { s.Fields[2].Name = s.Fields[0].Name }},
		{"more fields than the cap counting clears", createUserClearSnapshot, func(s *Snapshot) {
			for len(s.Fields) <= MaxCreateFields {
				extra := createUserField()
				extra.TargetValue = nil
				index := string(rune('a' + len(s.Fields)))
				extra.ProjectFieldID, extra.GlobalFieldID, extra.Name = "x-"+index, "y-"+index, "Extra "+index
				s.Fields = append(s.Fields, extra)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := test.build(t)
			test.change(&s)
			if _, err := prepareSnapshot(s); err == nil {
				t.Fatal("invalid create snapshot accepted")
			}
		})
	}
}

func TestOlderPlanVersionsRefuseCreateUserAndClearFields(t *testing.T) {
	for _, test := range []struct {
		name     string
		snapshot func(*testing.T) Snapshot
		allowed  bool
	}{
		{"state and enum", testCreateSnapshot, true},
		{"user set", createUserSnapshot, false},
		{"enum clear", createClearSnapshot, false},
		{"user clear", createUserClearSnapshot, false},
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
				// v3 is the comment.delete version and never fits a create.
				want := test.allowed && version != PlanVersion3 || version == PlanVersion4
				if got := ValidatePlan(plan) == nil; got != want {
					t.Fatalf("ValidatePlan accepted=%v, want %v", got, want)
				}
			})
		}
	}
}

func TestCreateSnapshotDecodeRefusesMissingClearKey(t *testing.T) {
	snapshot := createUserClearSnapshot(t)
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeSnapshot(bytes.NewReader(raw)); err != nil {
		t.Fatalf("complete clear snapshot refused: %v", err)
	}
	stripped := bytes.Replace(raw, []byte(`,"target_value":null`), nil, 1)
	if bytes.Equal(stripped, raw) {
		t.Fatalf("fixture lacks an explicit null: %s", raw)
	}
	if _, err := DecodeSnapshot(bytes.NewReader(stripped)); err == nil {
		t.Fatal("create field without target_value read as a clear")
	}
}
