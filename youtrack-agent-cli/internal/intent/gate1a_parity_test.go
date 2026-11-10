package intent

import (
	"bytes"
	"math"
	"strconv"
	"testing"
)

func TestParseApprovalSnapshotPreservesFullUint64PolicyRevision(t *testing.T) {
	raw := approvalFixture(t, "plan-issue-create.json")
	maximum := bytes.Replace(raw, []byte(`"policy_revision":1`), []byte(`"policy_revision":`+strconv.FormatUint(math.MaxUint64, 10)), 1)
	plan, err := ParseApprovalSnapshot(maximum, MaxCanonicalPlanBytes)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Policy.PolicyRevision != math.MaxUint64 {
		t.Fatalf("policy revision = %d, want %d", plan.Policy.PolicyRevision, uint64(math.MaxUint64))
	}
	canonical, err := ApprovalDisplayBytes(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, maximum) {
		t.Fatal("maximum uint64 policy revision did not re-encode exactly")
	}

	overflow := bytes.Replace(maximum, []byte(strconv.FormatUint(math.MaxUint64, 10)), []byte("18446744073709551616"), 1)
	if _, err := ParseApprovalSnapshot(overflow, MaxCanonicalPlanBytes); err == nil {
		t.Fatal("ParseApprovalSnapshot() accepted uint64 overflow")
	}
}

func TestParseApprovalSnapshotRejectsUnionAndHashTamperingForEveryKind(t *testing.T) {
	for _, name := range []string{"plan-issue-create.json", "plan-issue-update.json", "plan-comment-add.json"} {
		t.Run(name, func(t *testing.T) {
			fixture := approvalFixture(t, name)

			tests := []struct {
				name   string
				mutate func(*Plan)
			}{
				{name: "second operation union member", mutate: func(plan *Plan) {
					if plan.Operation.IssueCreate == nil {
						plan.Operation.IssueCreate = &IssueCreateOperation{}
					} else {
						plan.Operation.CommentAdd = &CommentAddOperation{}
					}
				}},
				{name: "request hash", mutate: func(plan *Plan) { plan.RequestSHA256 = flipDigest(plan.RequestSHA256) }},
				{name: "expected hash", mutate: func(plan *Plan) { plan.ExpectedSHA256 = flipDigest(plan.ExpectedSHA256) }},
				{name: "request content without hash", mutate: func(plan *Plan) {
					switch {
					case plan.Operation.IssueCreate != nil:
						plan.Operation.IssueCreate.Request.Summary += "!"
					case plan.Operation.IssueUpdate != nil:
						plan.Operation.IssueUpdate.Request.IssueID = "APP-2"
					case plan.Operation.CommentAdd != nil:
						plan.Operation.CommentAdd.Request.Text += "!"
					}
				}},
			}
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					tampered, parseErr := ParseApprovalSnapshot(fixture, MaxCanonicalPlanBytes)
					if parseErr != nil {
						t.Fatal(parseErr)
					}
					tt.mutate(&tampered)
					raw, marshalErr := canonicalBytesUnchecked(tampered)
					if marshalErr != nil {
						t.Fatal(marshalErr)
					}
					if _, parseErr = ParseApprovalSnapshot(raw, MaxCanonicalPlanBytes); parseErr == nil {
						t.Fatal("ParseApprovalSnapshot() accepted union or hash tampering")
					}
				})
			}
		})
	}
}

func TestGoTrimSpaceContractForRequiredAndBoundStrings(t *testing.T) {
	spaces := []struct {
		name  string
		value string
	}{
		{name: "NEL", value: "\u0085"},
		{name: "no-break space", value: "\u00a0"},
		{name: "en quad", value: "\u2000"},
		{name: "figure space", value: "\u2007"},
		{name: "narrow no-break space", value: "\u202f"},
		{name: "ideographic space", value: "\u3000"},
	}
	for _, tt := range spaces {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateRequiredText("value", tt.value, 16); err == nil {
				t.Fatal("required text accepted a Go TrimSpace rune")
			}
			if err := validateBoundString("value", tt.value+"alice", 32); err == nil {
				t.Fatal("bound string accepted leading Go TrimSpace rune")
			}
		})
	}

	const zeroWidthSpace = "\u200b"
	if err := validateRequiredText("value", zeroWidthSpace, 16); err != nil {
		t.Fatalf("required text rejected non-whitespace U+200B: %v", err)
	}
	if err := validateBoundString("value", zeroWidthSpace+"alice", 32); err != nil {
		t.Fatalf("bound string rejected non-whitespace U+200B: %v", err)
	}
}

func flipDigest(value string) string {
	if value[0] == '0' {
		return "1" + value[1:]
	}
	return "0" + value[1:]
}
