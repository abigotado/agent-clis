package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/application"
	"github.com/abigotado/youtrack-agent-cli/internal/output"
)

func TestRemoteViewsAlwaysExposeUntrustedMarker(t *testing.T) {
	view := newIssueView(application.IssueInfo{
		ID: "2-1", ReadableID: "APP-1", Summary: "Remote text", Project: application.ProjectInfo{ID: "0-1", Key: "APP"},
	})
	if view.Trust != untrustedYouTrackContent {
		t.Fatalf("trust=%q", view.Trust)
	}
	fields := view.Fields()
	if len(fields) == 0 || fields[0].Name != "trust" || !fields[0].Always {
		t.Fatalf("trust field=%#v", fields)
	}
}

func stageAndAssigneeIssue() application.IssueInfo {
	return application.IssueInfo{
		ID: "2-1", ReadableID: "APP-1", Summary: "Issue fields", Project: application.ProjectInfo{ID: "0-1", Key: "APP"},
		CustomFields: []application.IssueCustomFieldInfo{
			{ID: "cf-priority", Name: "Priority", Type: "SingleEnumIssueCustomField", Value: []byte(`{"id":"e-1","name":"Critical","$type":"EnumBundleElement"}`)},
			{ID: "cf-stage", Name: "Stage", Type: "StateIssueCustomField", Value: []byte(`{"id":"s-1","name":"In Progress","isResolved":false,"$type":"StateBundleElement"}`)},
			{ID: "cf-assignee", Name: "Assignee", Type: "SingleUserIssueCustomField", Value: []byte(`{"id":"1-2","login":"alice","name":"Alice Doe","fullName":"Alice Doe","$type":"User"}`)},
			{ID: "cf-reviewers", Name: "Reviewers", Type: "MultiUserIssueCustomField", Value: []byte(`[{"id":"1-3","login":"bob","$type":"User"},{"id":"1-4","login":"carol","$type":"User"}]`)},
			{ID: "cf-owner", Name: "Owner", Type: "SingleUserIssueCustomField", Value: []byte(`null`)},
			{ID: "cf-approvers", Name: "Approvers", Type: "MultiUserIssueCustomField", Value: []byte(`[]`)},
		},
	}
}

func TestIssueDefaultOutputShowsStageAndAssignee(t *testing.T) {
	stdout := &bytes.Buffer{}
	writer := &output.Writer{Format: output.FormatJSON, Out: stdout, Err: &bytes.Buffer{}}
	if err := writer.Success(newIssueView(stageAndAssigneeIssue())); err != nil {
		t.Fatal(err)
	}
	data := decode(t, stdout)["data"].(map[string]any)

	want := map[string]string{
		"state_fields": `[{"name":"Stage","values":["In Progress"]}]`,
		"user_fields": `[{"name":"Assignee","values":["alice"]},{"name":"Reviewers","values":["bob","carol"]},` +
			`{"name":"Owner","values":[]},{"name":"Approvers","values":[]}]`,
	}
	for field, expected := range want {
		encoded, err := json.Marshal(data[field])
		if err != nil {
			t.Fatal(err)
		}
		if string(encoded) != expected {
			t.Errorf("%s=%s, want %s", field, encoded, expected)
		}
	}
	if _, present := data["custom_fields"]; present {
		t.Errorf("default output expanded custom_fields: %#v", data)
	}
}

func TestIssueFieldOutputSelection(t *testing.T) {
	tests := []struct {
		name    string
		format  output.Format
		fields  []string
		want    []string
		wantNot []string
	}{
		{
			name: "text keeps names beside values", format: output.FormatText,
			want:    []string{"Stage=In Progress", "Assignee=alice; Reviewers=bob,carol; Owner=; Approvers="},
			wantNot: []string{"Critical"},
		},
		{
			name: "explicit custom fields stay complete and exclude summaries", format: output.FormatJSON, fields: []string{"custom_fields"},
			want:    []string{"Critical", "StateIssueCustomField", `"isResolved":false`},
			wantNot: []string{"state_fields", "user_fields"},
		},
		{
			name: "summaries can be selected alone", format: output.FormatJSON, fields: []string{"state_fields"},
			want:    []string{`"state_fields":[{"name":"Stage","values":["In Progress"]}]`},
			wantNot: []string{"user_fields", "custom_fields", "summary"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stdout := &bytes.Buffer{}
			writer := &output.Writer{Format: test.format, Fields: test.fields, Out: stdout, Err: &bytes.Buffer{}}
			if err := writer.Success(newIssueView(stageAndAssigneeIssue())); err != nil {
				t.Fatal(err)
			}
			for _, want := range test.want {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("output omitted %q: %s", want, stdout)
				}
			}
			for _, unwanted := range test.wantNot {
				if strings.Contains(stdout.String(), unwanted) {
					t.Errorf("output contains %q: %s", unwanted, stdout)
				}
			}
		})
	}
}

func TestIssueFieldSummaryDistinguishesEmptyFromUnreadable(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		wantJSON string
		wantText string
	}{
		{name: "missing value is unknown", wantJSON: `null`, wantText: "Stage=?"},
		{name: "unexpected primitive is unknown", value: `"In Progress"`, wantJSON: `null`, wantText: "Stage=?"},
		{name: "null is empty", value: `null`, wantJSON: `[]`, wantText: "Stage="},
		{name: "object without a label is empty", value: `{"id":"s-1"}`, wantJSON: `[]`, wantText: "Stage="},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			view := newIssueView(application.IssueInfo{
				ID: "2-1", ReadableID: "APP-1", Summary: "S", Project: application.ProjectInfo{ID: "0-1", Key: "APP"},
				CustomFields: []application.IssueCustomFieldInfo{{Name: "Stage", Type: "StateIssueCustomField", Value: []byte(test.value)}},
			})
			encoded, err := json.Marshal(view.StateFields[0].Values)
			if err != nil {
				t.Fatal(err)
			}
			if string(encoded) != test.wantJSON {
				t.Errorf("values=%s, want %s", encoded, test.wantJSON)
			}
			stdout := &bytes.Buffer{}
			writer := &output.Writer{Format: output.FormatText, Out: stdout, Err: &bytes.Buffer{}}
			if err := writer.Success(view); err != nil {
				t.Fatal(err)
			}
			if !strings.HasSuffix(strings.TrimSpace(stdout.String()), "  "+test.wantText) {
				t.Errorf("text=%q, want suffix %q", stdout, test.wantText)
			}
		})
	}
}
