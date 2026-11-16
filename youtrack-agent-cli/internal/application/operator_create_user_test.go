package application

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/operatorwrite"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/profile"
)

const createTokenSentinel = "OPERATOR_CREATE_SENTINEL"

// absentValue omits the value member of a returned custom field.
const absentValue = "<absent>"

var (
	createUserCapabilities = []profile.Capability{profile.CapabilityRead, profile.CapabilityIssueCreate, profile.CapabilityIssueCreateUserFields}
	// mixedSelection clears the state field and sets the assignee, in that order.
	mixedSelection = []OperatorFieldSelection{{FieldName: "Stage", Clear: true}, {FieldName: "Assignee", ValueName: "carol"}}
)

// newCreateUserFixture adds a clearable Assignee user field next to the Stage
// state field. Both are clearable unless the test changes the fixture.
func newCreateUserFixture(t *testing.T, capabilities ...profile.Capability) *createFixture {
	t.Helper()
	if len(capabilities) == 0 {
		capabilities = createUserCapabilities
	}
	f := newCreateFixture(t, capabilities...)
	f.useAssignee(true, defaultUsers())
	return f
}

func (f *createFixture) useAssignee(canBeEmpty bool, users []string) {
	f.set(func() {
		schema := strings.NewReplacer(`"id":"92-1"`, `"id":"93-1"`, `"id":"42-1"`, `"id":"43-1"`).Replace(userSchemaJSON(canBeEmpty, users))
		f.extra = map[string]string{"93-1": schema}
	})
}

func (f *createFixture) useStageRequired() {
	f.set(func() { f.schema = strings.Replace(f.schema, `"canBeEmpty":true`, `"canBeEmpty":false`, 1) })
}

// respond answers a create POST with the issue the request asked for, except
// where values replaces a field's returned value (absentValue omits it).
func (f *createFixture) respond(values map[string]string) {
	f.set(func() {
		f.postResponse = func(body []byte) string {
			var request struct {
				Summary      string `json:"summary"`
				Description  string `json:"description"`
				CustomFields []struct {
					Name  string          `json:"name"`
					Type  string          `json:"$type"`
					Value json.RawMessage `json:"value"`
				} `json:"customFields"`
			}
			if err := json.Unmarshal(body, &request); err != nil {
				f.t.Errorf("create body is not JSON: %v", err)
			}
			projectFields := map[string]string{"Stage": `{"id":"92-1","field":{"id":"42-1"}}`, "Assignee": `{"id":"93-1","field":{"id":"43-1"}}`}
			fields := make([]string, 0, len(request.CustomFields))
			for _, field := range request.CustomFields {
				value := string(field.Value)
				if field.Type == "SingleUserIssueCustomField" && value != "null" {
					value = strings.Replace(value, `}`, `,"login":"carol","$type":"User"}`, 1)
				}
				if override, ok := values[field.Name]; ok {
					value = override
				}
				member := ""
				if value != absentValue {
					member = `,"value":` + value
				}
				fields = append(fields, `{"id":"issue-`+field.Name+`","name":"`+field.Name+`","$type":"`+field.Type+`"`+member+`,"projectCustomField":`+projectFields[field.Name]+`}`)
			}
			return `{"id":"2-99","idReadable":"APP-99","summary":` + mustJSON(f.t, request.Summary) + `,"description":` + mustJSON(f.t, request.Description) +
				`,"project":{"id":"0-3","shortName":"APP","name":"Application","archived":false},"reporter":{"id":"1-2","login":"alice"},"created":1,"updated":1,"commentsCount":0,"customFields":[` + strings.Join(fields, ",") + `]}`
		}
	})
}

func TestOperatorCreateSetsUserAndClearsFieldsWithOneExactPost(t *testing.T) {
	for _, test := range []struct {
		name     string
		fields   []OperatorFieldSelection
		wantBody string
	}{
		{"clear a state and set a user by name", mixedSelection,
			`"customFields":[{"name":"Stage","$type":"StateIssueCustomField","value":null},{"name":"Assignee","$type":"SingleUserIssueCustomField","value":{"id":"1-6"}}]`},
		{"set a user and a state by immutable ids", []OperatorFieldSelection{{FieldID: "92-1", ValueID: "101-2"}, {FieldID: "93-1", ValueID: "1-6"}},
			`"customFields":[{"name":"Stage","$type":"StateIssueCustomField","value":{"id":"101-2"}},{"name":"Assignee","$type":"SingleUserIssueCustomField","value":{"id":"1-6"}}]`},
		{"clear a user by id", []OperatorFieldSelection{{FieldID: "93-1", Clear: true}},
			`"customFields":[{"name":"Assignee","$type":"SingleUserIssueCustomField","value":null}]`},
		{"state set and user clear", []OperatorFieldSelection{{FieldName: "Stage", ValueName: "Done"}, {FieldName: "Assignee", Clear: true}},
			`"customFields":[{"name":"Stage","$type":"StateIssueCustomField","value":{"id":"101-2"}},{"name":"Assignee","$type":"SingleUserIssueCustomField","value":null}]`},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCreateUserFixture(t)
			snapshot, err := f.snapshot(test.fields)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.PlanVersion != operatorwrite.PlanVersion5 || len(snapshot.Snapshot.Fields) != len(test.fields) {
				t.Fatalf("snapshot version=%d fields=%#v", snapshot.PlanVersion, snapshot.Snapshot.Fields)
			}
			// Prepare is network- and secret-store-free.
			credentials, transport := f.service.Credentials, f.service.HTTP
			creds, network := f.trap()
			p, err := f.prepareFrom(snapshot, createRequestJSON)
			if err != nil || creds.calls != 0 || network.calls != 0 || p.PlanVersion != operatorwrite.PlanVersion5 || p.Plan.Version != operatorwrite.PlanVersion5 {
				t.Fatalf("prepare error=%v credentials=%d network=%d version=%d", err, creds.calls, network.calls, p.PlanVersion)
			}
			f.service.Credentials, f.service.HTTP = credentials, transport
			f.respond(nil)
			result, err := f.apply(p)
			if err != nil || result.State != "applied" || f.posts() != 1 {
				t.Fatalf("apply result=%#v error=%v posts=%d", result, err, f.posts())
			}
			post, _ := f.last(http.MethodPost, "/api/issues")
			if !strings.Contains(string(post.body), test.wantBody) || !strings.HasPrefix(string(post.body), `{"project":{"id":"0-3"},"summary":"New ticket","description":`) {
				t.Fatalf("body=%s\nwant fragment %s", post.body, test.wantBody)
			}
			if _, err := f.apply(p); operatorReason(t, err) != "OPERATOR_PLAN_CONSUMED" || f.posts() != 1 {
				t.Fatalf("replay error=%v posts=%d", err, f.posts())
			}
		})
	}
}

func TestOperatorCreateUserFieldRefusals(t *testing.T) {
	for _, test := range []struct {
		name    string
		prepare func(*createFixture)
		fields  []OperatorFieldSelection
		reason  string
		code    errx.Code
	}{
		{"banned user", nil, []OperatorFieldSelection{{FieldName: "Assignee", ValueName: "dave"}}, "USAGE", errx.CodeUsage},
		{"unknown user", nil, []OperatorFieldSelection{{FieldName: "Assignee", ValueName: "nobody"}}, "USAGE", errx.CodeUsage},
		{"unknown user id", nil, []OperatorFieldSelection{{FieldID: "93-1", ValueID: "9-9"}}, "USAGE", errx.CodeUsage},
		{"ambiguous login", nil, []OperatorFieldSelection{{FieldName: "Assignee", ValueName: "twin"}}, "USAGE", errx.CodeUsage},
		{"display name is not a login", nil, []OperatorFieldSelection{{FieldName: "Assignee", ValueName: "John"}}, "USAGE", errx.CodeUsage},
		{"clear a user field that cannot be empty", func(f *createFixture) { f.useAssignee(false, defaultUsers()) }, []OperatorFieldSelection{{FieldName: "Assignee", Clear: true}}, "OPERATOR_FIELD_REQUIRED", errx.CodeUsage},
		{"clear a state field that cannot be empty", func(f *createFixture) { f.useStageRequired() }, []OperatorFieldSelection{{FieldName: "Stage", Clear: true}}, "OPERATOR_FIELD_REQUIRED", errx.CodeUsage},
		{"same field set and cleared", nil, []OperatorFieldSelection{{FieldName: "Stage", ValueName: "Done"}, {FieldName: "Stage", Clear: true}}, "USAGE", errx.CodeUsage},
		{"same field cleared twice", nil, []OperatorFieldSelection{{FieldName: "Stage", Clear: true}, {FieldName: "Stage", Clear: true}}, "USAGE", errx.CodeUsage},
		{"clear mixed with field ids", nil, []OperatorFieldSelection{{FieldName: "Stage", Clear: true}, {FieldID: "93-1", ValueID: "1-6"}}, "USAGE", errx.CodeUsage},
		{"clear with a value", nil, []OperatorFieldSelection{{FieldName: "Stage", ValueName: "Done", Clear: true}}, "USAGE", errx.CodeUsage},
		{"clear with a name and an id", nil, []OperatorFieldSelection{{FieldName: "Stage", FieldID: "92-1", Clear: true}}, "USAGE", errx.CodeUsage},
		{"clear without a field", nil, []OperatorFieldSelection{{Clear: true}}, "USAGE", errx.CodeUsage},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCreateUserFixture(t)
			if test.prepare != nil {
				test.prepare(f)
			}
			_, err := f.snapshot(test.fields)
			requireFailure(t, err, test.reason, test.code)
			if f.posts() != 0 {
				t.Fatalf("posts=%d", f.posts())
			}
		})
	}
	t.Run("more selections than the cap, clears counted", func(t *testing.T) {
		f := newCreateUserFixture(t)
		var fields []OperatorFieldSelection
		for index := 0; index <= operatorwrite.MaxCreateFields; index++ {
			fields = append(fields, OperatorFieldSelection{FieldName: "Field " + string(rune('A'+index)), Clear: true})
		}
		_, err := f.snapshot(fields)
		requireFailure(t, err, "USAGE", errx.CodeUsage)
	})
}

func TestOperatorCreateUserFieldsNeedTheirOwnCapability(t *testing.T) {
	onlyCreate := []profile.Capability{profile.CapabilityRead, profile.CapabilityIssueCreate}
	t.Run("state and enum need only issue-create", func(t *testing.T) {
		f := newCreateUserFixture(t, onlyCreate...)
		p := f.prepare(mixedSelection[:1], createRequestJSON)
		f.respond(nil)
		if result, err := f.apply(p); err != nil || result.State != "applied" || f.posts() != 1 {
			t.Fatalf("result=%#v error=%v posts=%d", result, err, f.posts())
		}
	})
	for _, test := range []struct {
		name   string
		fields []OperatorFieldSelection
	}{
		{"set a user", []OperatorFieldSelection{{FieldName: "Assignee", ValueName: "carol"}}},
		{"clear a user", []OperatorFieldSelection{{FieldName: "Assignee", Clear: true}}},
	} {
		t.Run("snapshot refuses to "+test.name, func(t *testing.T) {
			f := newCreateUserFixture(t, onlyCreate...)
			_, err := f.snapshot(test.fields)
			requireFailure(t, err, "OPERATOR_CAPABILITY_REQUIRED", errx.CodePermission)
			if f.posts() != 0 {
				t.Fatalf("posts=%d", f.posts())
			}
		})
		t.Run("prepare and apply refuse to "+test.name+" after the capability is revoked", func(t *testing.T) {
			f := newCreateUserFixture(t)
			snapshot, err := f.snapshot(test.fields)
			if err != nil {
				t.Fatal(err)
			}
			p, err := f.prepareFrom(snapshot, createRequestJSON)
			if err != nil {
				t.Fatal(err)
			}
			selected, err := f.service.Profiles.Get(t.Context(), "work")
			if err != nil {
				t.Fatal(err)
			}
			selected.Capabilities = onlyCreate
			if err := f.service.Profiles.Put(t.Context(), selected); err != nil {
				t.Fatal(err)
			}
			creds, network := f.trap()
			_, err = f.prepareFrom(snapshot, createRequestJSON)
			requireFailure(t, err, "OPERATOR_CAPABILITY_REQUIRED", errx.CodePermission)
			_, err = f.apply(p)
			requireFailure(t, err, "OPERATOR_CAPABILITY_REQUIRED", errx.CodePermission)
			if creds.calls != 0 || network.calls != 0 || f.posts() != 0 {
				t.Fatalf("credentials=%d network=%d posts=%d", creds.calls, network.calls, f.posts())
			}
			f.requireNotConsumed(p.PlanID)
		})
	}
}

func TestOperatorCreateApplyDriftOfUserAndClearFieldsStopsBeforeDispatch(t *testing.T) {
	for _, test := range []struct {
		name   string
		fields []OperatorFieldSelection
		drift  func(*createFixture)
	}{
		{"target user banned", []OperatorFieldSelection{{FieldName: "Assignee", ValueName: "carol"}}, func(f *createFixture) {
			users := defaultUsers()
			users[1] = userEntry("1-6", "carol", "Carol C.", true)
			f.useAssignee(true, users)
		}},
		{"target user left the bundle", []OperatorFieldSelection{{FieldName: "Assignee", ValueName: "carol"}}, func(f *createFixture) {
			f.useAssignee(true, defaultUsers()[:1])
		}},
		{"user field stopped being clearable", []OperatorFieldSelection{{FieldName: "Assignee", Clear: true}}, func(f *createFixture) {
			f.useAssignee(false, defaultUsers())
		}},
		{"state field stopped being clearable", []OperatorFieldSelection{{FieldName: "Stage", Clear: true}}, func(f *createFixture) { f.useStageRequired() }},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCreateUserFixture(t)
			p := f.prepare(test.fields, createRequestJSON)
			test.drift(f)
			_, err := f.apply(p)
			requireFailure(t, err, "OPERATOR_FIELD_STALE", errx.CodeConflict)
			if f.posts() != 0 {
				t.Fatalf("posts=%d", f.posts())
			}
			f.requireNotConsumed(p.PlanID)
		})
	}
}

func TestOperatorCreateUserAndClearResponsesAreVerifiedOrUnknown(t *testing.T) {
	for _, test := range []struct {
		name   string
		fields []OperatorFieldSelection
		values map[string]string
		want   string
	}{
		{"set and cleared values echoed", mixedSelection, nil, "applied"},
		{"cleared field returned empty object", mixedSelection, map[string]string{"Stage": `{}`}, "unknown"},
		{"cleared field returned empty id", mixedSelection, map[string]string{"Stage": `{"id":""}`}, "unknown"},
		{"cleared field returned without a value", mixedSelection, map[string]string{"Stage": absentValue}, "unknown"},
		{"cleared field refilled", mixedSelection, map[string]string{"Stage": `{"id":"101-1","$type":"StateBundleElement"}`}, "unknown"},
		{"set user returned without a type", mixedSelection, map[string]string{"Assignee": `{"id":"1-6","login":"carol"}`}, "unknown"},
		{"set user returned as another type", mixedSelection, map[string]string{"Assignee": `{"id":"1-6","$type":"UserGroup"}`}, "unknown"},
		{"set user replaced by another user", mixedSelection, map[string]string{"Assignee": `{"id":"1-5","$type":"User"}`}, "unknown"},
		{"set user cleared by a workflow", mixedSelection, map[string]string{"Assignee": `null`}, "unknown"},
		{"cleared assignee refilled by the project", []OperatorFieldSelection{{FieldName: "Assignee", Clear: true}}, map[string]string{"Assignee": `{"id":"1-2","login":"alice","$type":"User"}`}, "unknown"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCreateUserFixture(t)
			p := f.prepare(test.fields, createRequestJSON)
			f.respond(test.values)
			result, err := f.apply(p)
			if f.posts() != 1 {
				t.Fatalf("posts=%d", f.posts())
			}
			if test.want == "applied" {
				if err != nil || result.State != "applied" {
					t.Fatalf("result=%#v error=%v", result, err)
				}
				return
			}
			requireFailure(t, err, "WRITE_OUTCOME_UNKNOWN", errx.CodeConflict)
			record := f.record(p.PlanID)
			if record.State != operatorwrite.StateUnknown || record.Result == nil || record.Result.RemoteID != "2-99" {
				t.Fatalf("record=%#v", record)
			}
			if _, err := f.apply(p); operatorReason(t, err) != "OPERATOR_PLAN_CONSUMED" || f.posts() != 1 {
				t.Fatalf("replay error=%v posts=%d", err, f.posts())
			}
		})
	}
}

func TestOperatorCreateWithUserFieldsIsOneShotOnTransientFailure(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			f := newCreateUserFixture(t)
			p := f.prepare(mixedSelection, createRequestJSON)
			f.set(func() { f.postStatus, f.postBody = status, `{"error":"`+createTokenSentinel+`"}` })
			_, err := f.apply(p)
			if err == nil || f.posts() != 1 || !f.record(p.PlanID).NonReplayable() {
				t.Fatalf("error=%v posts=%d record=%#v", err, f.posts(), f.record(p.PlanID))
			}
			if _, err := f.apply(p); operatorReason(t, err) != "OPERATOR_PLAN_CONSUMED" || f.posts() != 1 {
				t.Fatalf("replay error=%v posts=%d", err, f.posts())
			}
		})
	}
}

func TestOperatorCreateReconcileComparesUserAndClearFieldsExactly(t *testing.T) {
	for _, test := range []struct {
		name         string
		values       map[string]string
		wantEvidence string
	}{
		{"fields match", nil, "matching_issue_observed"},
		{"cleared assignee refilled", map[string]string{"Assignee": `{"id":"1-2","login":"alice","$type":"User"}`}, "matching_issue_observed_fields_differ"},
		{"cleared state returned as empty object", map[string]string{"Stage": `{}`}, "matching_issue_observed_fields_differ"},
		{"user returned without a type", map[string]string{"Assignee": `{"id":"1-6"}`}, "matching_issue_observed_fields_differ"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCreateUserFixture(t)
			p := f.prepare(mixedSelection, createRequestJSON)
			// The POST outcome is unknown (the response is cut off); reconcile
			// must read the issue by the identity the response carried.
			f.set(func() { f.postStatus, f.postBody = http.StatusOK, `{"id":"2-99","idReadable":"APP-99"}` })
			if _, err := f.apply(p); err == nil {
				t.Fatal("unverifiable create response accepted")
			}
			f.respond(test.values)
			f.set(func() { f.postStatus, f.postBody = 0, "" })
			// Reuse the response builder for the exact issue read.
			f.set(func() {
				post := f.postResponse
				f.issues["2-99"] = post([]byte(`{"summary":"New ticket","description":` + mustJSON(t, f.record(p.PlanID).Plan.Request.Description) + `,"customFields":[` +
					`{"name":"Stage","$type":"StateIssueCustomField","value":null},{"name":"Assignee","$type":"SingleUserIssueCustomField","value":{"id":"1-6"}}]}`))
			})
			posts := f.posts()
			result, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: p.PlanID, Limit: 20})
			if err != nil || result.State != "reconciled" || result.Evidence != test.wantEvidence || f.posts() != posts {
				t.Fatalf("result=%#v error=%v posts=%d->%d", result, err, posts, f.posts())
			}
		})
	}
}

func TestOperatorCreateUserFieldTokenSentinelStaysOutOfEverything(t *testing.T) {
	f := newCreateUserFixture(t)
	f.set(func() { f.postStatus, f.postBody = http.StatusForbidden, createTokenSentinel+" "+userSentinelEmail })
	snapshot, err := f.snapshot(mixedSelection)
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.prepareFrom(snapshot, createRequestJSON)
	if err != nil {
		t.Fatal(err)
	}
	_, applyErr := f.apply(p)
	if applyErr == nil {
		t.Fatal("rejected create reported success")
	}
	record, err := json.Marshal(f.record(p.PlanID))
	if err != nil {
		t.Fatal(err)
	}
	rawSnapshot, err := json.Marshal(snapshot.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	rawPlan, err := json.Marshal(p.Plan)
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{"error": applyErr.Error(), "translated error": TranslateError(applyErr, "work").Error(), "record": string(record), "snapshot": string(rawSnapshot), "plan": string(rawPlan)} {
		for _, secret := range []string{createTokenSentinel, userSentinelEmail, userSentinelFullName, userSentinelName} {
			if strings.Contains(text, secret) {
				t.Errorf("%s leaks %q: %s", name, secret, text)
			}
		}
	}
}

func TestOperatorCreateUnsupportedUserFieldIsRefusedBeforeTheCapabilityCheck(t *testing.T) {
	f := newCreateUserFixture(t, profile.CapabilityRead, profile.CapabilityIssueCreate)
	f.set(func() {
		multi := strings.NewReplacer(`"id":"92-1"`, `"id":"93-1"`, `"id":"42-1"`, `"id":"43-1"`, `"isMultiValue":false`, `"isMultiValue":true`).Replace(userSchemaJSON(true, defaultUsers()))
		f.extra = map[string]string{"93-1": multi}
	})
	_, err := f.snapshot([]OperatorFieldSelection{{FieldID: "93-1", Clear: true}})
	requireFailure(t, err, "OPERATOR_FIELD_UNSUPPORTED", errx.CodeUsage)
}

func TestOperatorCreateTruncatedSchemaHintNamesCreateFlags(t *testing.T) {
	for _, test := range []struct {
		name     string
		fields   []OperatorFieldSelection
		wantHint string
	}{
		{"clear by name", []OperatorFieldSelection{{FieldName: "Stage", Clear: true}}, "--clear-field-id"},
		{"set by name", []OperatorFieldSelection{{FieldName: "Stage", ValueName: "Open"}}, "--field-id and --value-id"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCreateFixture(t)
			f.set(func() {
				f.extra = map[string]string{}
				for index := 0; index < 100; index++ {
					f.extra[fmt.Sprintf("x-%d", index)] = f.schema
				}
			})
			_, err := f.snapshot(test.fields)
			requireFailure(t, err, "OPERATOR_SCHEMA_TRUNCATED", errx.CodeConflict)
			var coded *errx.Error
			if !errors.As(err, &coded) || !strings.Contains(coded.Hint, test.wantHint) || strings.Contains(coded.Hint, "--clear-value") {
				t.Fatalf("hint = %v", err)
			}
		})
	}
}
