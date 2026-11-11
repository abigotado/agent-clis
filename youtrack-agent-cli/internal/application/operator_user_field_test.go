package application

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/operatorwrite"
)

const (
	userSentinelFullName = "USER_FULLNAME_SENTINEL"
	userSentinelEmail    = "USER_EMAIL_SENTINEL@example.test"
	userSentinelName     = "USER_NAME_SENTINEL"
)

func userEntry(id, login, name string, banned bool) string {
	return fmt.Sprintf(`{"id":%q,"login":%q,"name":%q,"fullName":%q,"email":%q,"banned":%t}`, id, login, name, userSentinelFullName, userSentinelEmail, banned)
}

// defaultUsers has bob (the current assignee), carol, a banned user, a user whose
// display name differs from the login, and two users sharing one login.
func defaultUsers() []string {
	return []string{
		userEntry("1-5", "bob", userSentinelName, false),
		userEntry("1-6", "carol", "Carol C.", false),
		userEntry("1-7", "dave", "Dave D.", true),
		userEntry("1-8", "j.smith", "John", false),
		userEntry("1-9", "twin", "Twin One", false),
		userEntry("1-10", "twin", "Twin Two", false),
	}
}

func userSchemaJSON(canBeEmpty bool, users []string) string {
	return fmt.Sprintf(`{"id":"92-1","$type":"UserProjectCustomField","project":{"id":"0-3"},"field":{"id":"42-1","name":"Assignee","fieldType":{"id":"user[1]","valueType":"user","isMultiValue":false,"$type":"FieldType"}},"canBeEmpty":%t,"isPublic":true,"bundle":{"id":"100-9","$type":"UserBundle","aggregatedUsers":[%s]}}`, canBeEmpty, strings.Join(users, ","))
}

func userIssueJSON(value string) string {
	return strings.Replace(operatorIssueJSON, `"name":"Stage","$type":"StateIssueCustomField","value":null`, `"name":"Assignee","$type":"SingleUserIssueCustomField","value":`+value, 1)
}

const (
	currentBob  = `{"id":"1-5","login":"bob","$type":"User","fullName":"` + userSentinelFullName + `"}`
	currentGone = `{"id":"1-99","login":"departed","$type":"User","fullName":"` + userSentinelFullName + `"}`
)

// useUserField switches the fixture to an Assignee user field.
func (f *operatorFixture) useUserField(value string, canBeEmpty bool, users []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issue = userIssueJSON(value)
	f.schema = userSchemaJSON(canBeEmpty, users)
}

func userClear() []OperatorFieldSelection {
	return []OperatorFieldSelection{{FieldID: "92-1", Clear: true}}
}

func userSet(login string) []OperatorFieldSelection {
	return []OperatorFieldSelection{{FieldName: "Assignee", ValueName: login}}
}

func (f *operatorFixture) snapshotUpdate(t *testing.T, fields []OperatorFieldSelection) (OperatorWriteInfo, error) {
	t.Helper()
	return f.service.SnapshotOperatorWrite(t.Context(), OperatorSnapshotInput{Profile: "work", Kind: "issue.update", IssueID: "APP-12", Fields: fields})
}

func (f *operatorFixture) preparePlanFor(t *testing.T, fields []OperatorFieldSelection) OperatorWriteInfo {
	t.Helper()
	snapshot, err := f.snapshotUpdate(t, fields)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(snapshot.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := f.service.PrepareOperatorWrite(t.Context(), OperatorPrepareInput{Profile: "work", SnapshotJSON: raw, RequestJSON: []byte(`{"kind":"issue.update"}`)})
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func (f *operatorFixture) apply(t *testing.T, plan OperatorWriteInfo) (OperatorWriteInfo, error) {
	t.Helper()
	return f.service.ApplyOperatorWrite(t.Context(), OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: plan.IntentSHA256, Yes: true})
}

func requireRefusal(t *testing.T, err error, reason string, code errx.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got success", reason)
	}
	if got := operatorReason(t, err); got != reason || errx.ExitCode(err) != code {
		t.Fatalf("reason=%q code=%d, want %q %d: %v", got, errx.ExitCode(err), reason, code, err)
	}
}

func TestOperatorUserClearSnapshotFreezesLoginOnly(t *testing.T) {
	f := newOperatorFixture(t)
	f.useUserField(currentBob, true, defaultUsers())
	info, err := f.snapshotUpdate(t, userClear())
	if err != nil {
		t.Fatal(err)
	}
	field := info.Snapshot.Field
	if field.TargetValue != nil || field.CurrentValue == nil || *field.CurrentValue != (operatorwrite.Value{ID: "1-5", Name: "bob", Type: "User"}) ||
		field.Type != "SingleUserIssueCustomField" || field.ProjectFieldType != "UserProjectCustomField" || field.BundleType != "UserBundle" || info.PlanVersion != operatorwrite.PlanVersion4 {
		t.Fatalf("field=%#v info=%#v", field, info)
	}
}

func TestOperatorUserClearAllowsCurrentUserOutsideBundle(t *testing.T) {
	f := newOperatorFixture(t)
	f.useUserField(currentGone, true, []string{userEntry("1-6", "carol", "Carol C.", false)})
	info, err := f.snapshotUpdate(t, userClear())
	if err != nil || info.Snapshot.Field.CurrentValue == nil || info.Snapshot.Field.CurrentValue.Name != "departed" {
		t.Fatalf("info=%#v err=%v", info, err)
	}
}

func TestOperatorClearRefusals(t *testing.T) {
	for _, test := range []struct {
		name   string
		setup  func(*operatorFixture)
		fields []OperatorFieldSelection
		reason string
	}{
		{"user field cannot be empty", func(f *operatorFixture) { f.useUserField(currentBob, false, defaultUsers()) }, userClear(), "OPERATOR_FIELD_REQUIRED"},
		{"user field already empty", func(f *operatorFixture) { f.useUserField(`null`, true, defaultUsers()) }, userClear(), "OPERATOR_FIELD_ALREADY_EMPTY"},
		{"state field cannot be empty", func(f *operatorFixture) {
			f.issue = strings.Replace(operatorIssueJSON, `"value":null`, openStageIssueValue, 1)
			f.schema = strings.Replace(operatorSchemaJSON, `"canBeEmpty":true`, `"canBeEmpty":false`, 1)
		}, userClear(), "OPERATOR_FIELD_REQUIRED"},
		{"state field already empty", func(f *operatorFixture) {}, userClear(), "OPERATOR_FIELD_ALREADY_EMPTY"},
		{"user already set", func(f *operatorFixture) { f.useUserField(currentBob, true, defaultUsers()) }, userSet("bob"), "OPERATOR_FIELD_ALREADY_SET"},
		{"state already set", func(f *operatorFixture) {
			f.issue = strings.Replace(operatorIssueJSON, `"value":null`, openStageIssueValue, 1)
		}, []OperatorFieldSelection{{FieldID: "92-1", ValueID: "101-1"}}, "OPERATOR_FIELD_ALREADY_SET"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newOperatorFixture(t)
			test.setup(f)
			_, err := f.snapshotUpdate(t, test.fields)
			requireRefusal(t, err, test.reason, errx.CodeUsage)
			if f.posts.Load() != 0 {
				t.Fatalf("posts=%d", f.posts.Load())
			}
		})
	}
}

func TestOperatorClearStateFieldWhenCanBeEmpty(t *testing.T) {
	f := newOperatorFixture(t)
	f.issue = strings.Replace(operatorIssueJSON, `"value":null`, openStageIssueValue, 1)
	info, err := f.snapshotUpdate(t, []OperatorFieldSelection{{FieldName: "Stage", Clear: true}})
	if err != nil || info.Snapshot.Field.TargetValue != nil || info.Snapshot.Field.CurrentValue == nil || info.Snapshot.Field.CurrentValue.ID != "101-1" {
		t.Fatalf("info=%#v err=%v", info, err)
	}
}

func TestOperatorUserSetByLoginAndByID(t *testing.T) {
	for _, test := range []struct {
		name    string
		current string
		fields  []OperatorFieldSelection
		want    operatorwrite.Value
	}{
		{"by login", `null`, userSet("carol"), operatorwrite.Value{ID: "1-6", Name: "carol", Type: "User"}},
		{"by id", currentBob, []OperatorFieldSelection{{FieldID: "92-1", ValueID: "1-6"}}, operatorwrite.Value{ID: "1-6", Name: "carol", Type: "User"}},
		{"display name differs from login", currentBob, userSet("j.smith"), operatorwrite.Value{ID: "1-8", Name: "j.smith", Type: "User"}},
		{"current outside bundle", currentGone, userSet("carol"), operatorwrite.Value{ID: "1-6", Name: "carol", Type: "User"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newOperatorFixture(t)
			f.useUserField(test.current, true, defaultUsers())
			info, err := f.snapshotUpdate(t, test.fields)
			if err != nil {
				t.Fatal(err)
			}
			if info.Snapshot.Field.TargetValue == nil || *info.Snapshot.Field.TargetValue != test.want {
				t.Fatalf("target=%#v, want %#v", info.Snapshot.Field.TargetValue, test.want)
			}
		})
	}
}

func TestOperatorUserSetRefusesUnknownBannedAndAmbiguousTargets(t *testing.T) {
	for _, test := range []struct {
		name   string
		fields []OperatorFieldSelection
	}{
		{"absent login", userSet("nobody")},
		{"display name is not a login", userSet("John")},
		{"login is case sensitive", userSet("Carol")},
		{"absent id", []OperatorFieldSelection{{FieldID: "92-1", ValueID: "1-404"}}},
		{"banned user", userSet("dave")},
		{"duplicate login", userSet("twin")},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newOperatorFixture(t)
			f.useUserField(currentBob, true, defaultUsers())
			_, err := f.snapshotUpdate(t, test.fields)
			requireRefusal(t, err, "USAGE", errx.CodeUsage)
		})
	}
}

func TestOperatorUserBundleWithDuplicateIDsIsInvalid(t *testing.T) {
	f := newOperatorFixture(t)
	f.useUserField(currentBob, true, []string{userEntry("1-6", "carol", "Carol", false), userEntry("1-6", "carol2", "Carol 2", false)})
	_, err := f.snapshotUpdate(t, userSet("carol"))
	requireRefusal(t, err, "OPERATOR_BUNDLE_INVALID", errx.CodeConflict)
}

func TestOperatorUserCurrentValueMustBeAUser(t *testing.T) {
	for _, value := range []string{`{"id":"1-5","login":"bob","$type":"Group"}`, `{"id":"1-5","$type":"User"}`, `"bob"`} {
		f := newOperatorFixture(t)
		f.useUserField(value, true, defaultUsers())
		_, err := f.snapshotUpdate(t, userClear())
		requireRefusal(t, err, "OPERATOR_FIELD_VALUE_INVALID", errx.CodeConflict)
	}
	f := newOperatorFixture(t)
	f.useUserField(`null`, false, defaultUsers())
	_, err := f.snapshotUpdate(t, userSet("carol"))
	requireRefusal(t, err, "OPERATOR_FIELD_VALUE_INVALID", errx.CodeConflict)
}

func TestOperatorUserFieldSchemaVariantsStayUnsupported(t *testing.T) {
	f := newOperatorFixture(t)
	f.useUserField(currentBob, true, defaultUsers())
	f.schema = strings.Replace(f.schema, `"isMultiValue":false`, `"isMultiValue":true`, 1)
	_, err := f.snapshotUpdate(t, userClear())
	requireRefusal(t, err, "OPERATOR_FIELD_UNSUPPORTED", errx.CodeUsage)
}

func TestOperatorUserClearAppliesOneNullPost(t *testing.T) {
	f := newOperatorFixture(t)
	f.useUserField(currentBob, true, defaultUsers())
	plan := f.preparePlanFor(t, userClear())
	transport := &recordingTransport{next: f.service.HTTP}
	f.service.HTTP = transport
	f.postStatus, f.postBody = http.StatusOK, userIssueJSON(`null`)
	applied, err := f.apply(t, plan)
	if err != nil || applied.State != string(operatorwrite.StateApplied) || f.posts.Load() != 1 {
		t.Fatalf("apply=%#v err=%v posts=%d", applied, err, f.posts.Load())
	}
	if len(transport.bodies) != 1 || transport.bodies[0] != `{"customFields":[{"id":"issue-field-7","$type":"SingleUserIssueCustomField","value":null}]}` {
		t.Fatalf("bodies=%q", transport.bodies)
	}
	_, err = f.apply(t, plan)
	requireRefusal(t, err, "OPERATOR_PLAN_CONSUMED", errx.CodeConflict)
	if f.posts.Load() != 1 {
		t.Fatalf("second apply posted: %d", f.posts.Load())
	}
}

func TestOperatorUserClearResponseWithoutValueKeyIsUnknown(t *testing.T) {
	f := newOperatorFixture(t)
	f.useUserField(currentBob, true, defaultUsers())
	plan := f.preparePlanFor(t, userClear())
	f.postStatus, f.postBody = http.StatusOK, strings.Replace(userIssueJSON(`null`), `"value":null,`, ``, 1)
	if strings.Contains(f.postBody, `"value"`) {
		t.Fatal("fixture still has a value key")
	}
	_, err := f.apply(t, plan)
	requireRefusal(t, err, "WRITE_OUTCOME_UNKNOWN", errx.CodeConflict)
	status, err := f.service.OperatorWriteStatus(t.Context(), plan.PlanID)
	if err != nil || status.State != string(operatorwrite.StateUnknown) || !status.NonReplayable || f.posts.Load() != 1 {
		t.Fatalf("status=%#v err=%v posts=%d", status, err, f.posts.Load())
	}
}

func TestOperatorUserClearResponseStillSetIsUnknown(t *testing.T) {
	f := newOperatorFixture(t)
	f.useUserField(currentBob, true, defaultUsers())
	plan := f.preparePlanFor(t, userClear())
	f.postStatus, f.postBody = http.StatusOK, userIssueJSON(currentBob)
	_, err := f.apply(t, plan)
	requireRefusal(t, err, "WRITE_OUTCOME_UNKNOWN", errx.CodeConflict)
}

func TestOperatorUserSetSendsIDOnly(t *testing.T) {
	f := newOperatorFixture(t)
	f.useUserField(currentBob, true, defaultUsers())
	plan := f.preparePlanFor(t, userSet("carol"))
	transport := &recordingTransport{next: f.service.HTTP}
	f.service.HTTP = transport
	f.postStatus, f.postBody = http.StatusOK, userIssueJSON(`{"id":"1-6","login":"carol","$type":"User"}`)
	applied, err := f.apply(t, plan)
	if err != nil || applied.State != string(operatorwrite.StateApplied) || f.posts.Load() != 1 {
		t.Fatalf("apply=%#v err=%v posts=%d", applied, err, f.posts.Load())
	}
	if len(transport.bodies) != 1 || transport.bodies[0] != `{"customFields":[{"id":"issue-field-7","$type":"SingleUserIssueCustomField","value":{"id":"1-6"}}]}` {
		t.Fatalf("bodies=%q", transport.bodies)
	}
}

func TestOperatorUserApplyDriftIsStaleWithoutClaim(t *testing.T) {
	for _, test := range []struct {
		name   string
		fields []OperatorFieldSelection
		change func(*operatorFixture)
	}{
		{"assignee changed before clear", userClear(), func(f *operatorFixture) {
			f.useUserField(`{"id":"1-6","login":"carol","$type":"User"}`, true, defaultUsers())
		}},
		{"assignee already cleared", userClear(), func(f *operatorFixture) { f.useUserField(`null`, true, defaultUsers()) }},
		{"field became required", userClear(), func(f *operatorFixture) { f.useUserField(currentBob, false, defaultUsers()) }},
		{"target banned", userSet("carol"), func(f *operatorFixture) {
			f.useUserField(currentBob, true, []string{userEntry("1-5", "bob", "Bob", false), userEntry("1-6", "carol", "Carol", true)})
		}},
		{"target login renamed", userSet("carol"), func(f *operatorFixture) {
			f.useUserField(currentBob, true, []string{userEntry("1-5", "bob", "Bob", false), userEntry("1-6", "carol-new", "Carol", false)})
		}},
		{"target already assigned", userSet("carol"), func(f *operatorFixture) {
			f.useUserField(`{"id":"1-6","login":"carol","$type":"User"}`, true, defaultUsers())
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newOperatorFixture(t)
			f.useUserField(currentBob, true, defaultUsers())
			plan := f.preparePlanFor(t, test.fields)
			test.change(f)
			_, err := f.apply(t, plan)
			requireRefusal(t, err, "OPERATOR_FIELD_STALE", errx.CodeConflict)
			record, getErr := f.service.OperatorWrites.Get(t.Context(), plan.PlanID)
			if getErr != nil || record.NonReplayable() || f.posts.Load() != 0 {
				t.Fatalf("drift consumed or dispatched: %#v %v posts=%d", record, getErr, f.posts.Load())
			}
		})
	}
}

func TestOperatorUserReconcileIsGETOnly(t *testing.T) {
	for _, test := range []struct {
		name     string
		fields   []OperatorFieldSelection
		observed string
		evidence string
	}{
		{"clear observed", userClear(), `null`, "desired_value_observed_without_causal_proof"},
		{"clear not observed", userClear(), currentBob, "inconclusive"},
		{"set observed", userSet("carol"), `{"id":"1-6","login":"carol","$type":"User"}`, "desired_value_observed_without_causal_proof"},
		{"set not observed", userSet("carol"), currentBob, "inconclusive"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newOperatorFixture(t)
			f.useUserField(currentBob, true, defaultUsers())
			plan := f.preparePlanFor(t, test.fields)
			if _, err := f.service.OperatorWrites.Claim(t.Context(), plan.PlanID, plan.IntentSHA256, f.service.currentTime()); err != nil {
				t.Fatal(err)
			}
			f.useUserField(test.observed, true, defaultUsers())
			result, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: plan.PlanID, Limit: 2})
			if err != nil || result.State != string(operatorwrite.StateOperatorRequired) || result.Evidence != test.evidence || !result.NonReplayable || f.posts.Load() != 0 {
				t.Fatalf("result=%#v err=%v posts=%d", result, err, f.posts.Load())
			}
		})
	}
}

func TestOperatorUserFieldSentinelsStayOutOfSnapshotPlanAndErrors(t *testing.T) {
	f := newOperatorFixture(t)
	f.useUserField(currentBob, true, defaultUsers())
	var texts [][]byte
	for _, fields := range [][]OperatorFieldSelection{userClear(), userSet("carol"), userSet("j.smith")} {
		info, err := f.snapshotUpdate(t, fields)
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := json.Marshal(info)
		if err != nil {
			t.Fatal(err)
		}
		texts = append(texts, snapshot)
		plan := f.preparePlanFor(t, fields)
		raw, err := json.Marshal(plan)
		if err != nil {
			t.Fatal(err)
		}
		texts = append(texts, raw)
	}
	for _, fields := range [][]OperatorFieldSelection{userSet("nobody"), userSet("dave"), userSet("twin"), userSet("bob")} {
		_, err := f.snapshotUpdate(t, fields)
		if err == nil {
			t.Fatal("expected refusal")
		}
		texts = append(texts, []byte(err.Error()))
		for _, login := range []string{"nobody", "dave", "twin"} {
			if bytes.Contains([]byte(err.Error()), []byte(login)) {
				t.Fatalf("refused login %q leaked into error %q", login, err)
			}
			if typed, ok := err.(*errx.Error); ok && strings.Contains(typed.Message+typed.Hint, login) {
				t.Fatalf("refused login %q leaked into typed error %q %q", login, typed.Message, typed.Hint)
			}
		}
		if typed, ok := err.(*errx.Error); ok {
			texts = append(texts, []byte(typed.Message+typed.Hint))
		}
	}
	// Apply, status and reconcile surfaces and their stored records.
	addInfo := func(info OperatorWriteInfo) {
		raw, marshalErr := json.Marshal(info)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		texts = append(texts, raw)
	}
	applyPlan := f.preparePlanFor(t, userSet("carol"))
	f.postStatus, f.postBody = http.StatusOK, userIssueJSON(`{"id":"1-6","login":"carol","$type":"User","fullName":"`+userSentinelFullName+`"}`)
	applied, err := f.apply(t, applyPlan)
	if err != nil {
		t.Fatal(err)
	}
	addInfo(applied)
	status, err := f.service.OperatorWriteStatus(t.Context(), applyPlan.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	addInfo(status)
	reconcilePlan := f.preparePlanFor(t, userClear())
	if _, err := f.service.OperatorWrites.Claim(t.Context(), reconcilePlan.PlanID, reconcilePlan.IntentSHA256, f.service.currentTime()); err != nil {
		t.Fatal(err)
	}
	f.useUserField(`null`, true, defaultUsers())
	reconciled, err := f.service.ReconcileOperatorWrite(t.Context(), OperatorReconcileInput{Profile: "work", PlanID: reconcilePlan.PlanID, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	addInfo(reconciled)
	// Files on disk: the --out snapshot export, the --out plan export and the
	// stored plan itself.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	snapshotPath, planPath := filepath.Join(dir, "snapshot.json"), filepath.Join(dir, "plan.json")
	exported, err := f.service.SnapshotOperatorWrite(t.Context(), OperatorSnapshotInput{Profile: "work", Kind: "issue.update", IssueID: "APP-12", Fields: userSet("carol"), OutputPath: snapshotPath})
	if err != nil {
		t.Fatal(err)
	}
	rawSnapshot, err := json.Marshal(exported.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.PrepareOperatorWrite(t.Context(), OperatorPrepareInput{Profile: "work", SnapshotJSON: rawSnapshot, RequestJSON: []byte(`{"kind":"issue.update"}`), OutputPath: planPath}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{snapshotPath, planPath} {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		texts = append(texts, content)
	}
	err = filepath.WalkDir(f.service.OperatorWrites.Root(), func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		texts = append(texts, content)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, sentinel := range []string{userSentinelFullName, userSentinelEmail, userSentinelName, "OPERATOR_TEST_SENTINEL"} {
		for _, text := range texts {
			if bytes.Contains(text, []byte(sentinel)) {
				t.Fatalf("sentinel %q leaked into %s", sentinel, text)
			}
		}
	}
}

type failingTransport struct{ requests atomic.Int32 }

func (r *failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	r.requests.Add(1)
	return nil, errors.New("unexpected network request")
}

func TestSnapshotOperatorWriteClearSelectionValidation(t *testing.T) {
	for _, test := range []struct {
		name  string
		input OperatorSnapshotInput
	}{
		{"clear with value name", OperatorSnapshotInput{Kind: "issue.update", IssueID: "APP-12", Fields: []OperatorFieldSelection{{FieldName: "Stage", ValueName: "Done", Clear: true}}}},
		{"clear with value id", OperatorSnapshotInput{Kind: "issue.update", IssueID: "APP-12", Fields: []OperatorFieldSelection{{FieldName: "Stage", ValueID: "101-1", Clear: true}}}},
		{"clear on comment.add", OperatorSnapshotInput{Kind: "comment.add", IssueID: "APP-12", Fields: []OperatorFieldSelection{{FieldName: "Stage", Clear: true}}}},
		{"two clear selections", OperatorSnapshotInput{Kind: "issue.update", IssueID: "APP-12", Fields: []OperatorFieldSelection{{FieldName: "Stage", Clear: true}, {FieldName: "Assignee", Clear: true}}}},
		{"clear with field name and id", OperatorSnapshotInput{Kind: "issue.update", IssueID: "APP-12", Fields: []OperatorFieldSelection{{FieldName: "Stage", FieldID: "92-1", Clear: true}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newOperatorFixture(t)
			trap := &failingTransport{}
			f.service.HTTP = trap
			test.input.Profile = "work"
			_, err := f.service.SnapshotOperatorWrite(t.Context(), test.input)
			requireRefusal(t, err, "USAGE", errx.CodeUsage)
			if trap.requests.Load() != 0 || f.posts.Load() != 0 || f.pages.Load() != 0 {
				t.Fatalf("network touched: requests=%d posts=%d pages=%d", trap.requests.Load(), f.posts.Load(), f.pages.Load())
			}
		})
	}
}

func TestOperatorTruncatedFieldLookupHintMatchesTheSelection(t *testing.T) {
	tests := []struct {
		name   string
		fields []OperatorFieldSelection
		hint   string
	}{
		{"clear by name", []OperatorFieldSelection{{FieldName: "Assignee", Clear: true}}, "use exact --field-id with --clear-value"},
		{"set by name", userSet("bob"), "use exact --field-id and --value-id"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newOperatorFixture(t)
			f.useUserField(currentBob, true, defaultUsers())
			entries := make([]string, 101)
			for index := range entries {
				entries[index] = f.schema
			}
			f.mu.Lock()
			f.fieldList = "[" + strings.Join(entries, ",") + "]"
			f.mu.Unlock()
			_, err := f.snapshotUpdate(t, test.fields)
			requireRefusal(t, err, "OPERATOR_SCHEMA_TRUNCATED", errx.CodeConflict)
			var typed *errx.Error
			if !errors.As(err, &typed) || typed.Hint != test.hint {
				t.Fatalf("hint=%q, want %q", typed.Hint, test.hint)
			}
		})
	}
}
