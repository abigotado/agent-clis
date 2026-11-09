package journal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/intent"
)

type fixedID string

func (f fixedID) NewPlanID() (string, error) { return string(f), nil }

func journalPlan(t *testing.T) intent.Plan {
	t.Helper()
	plan, err := intent.PrepareWithSource(
		intent.ProfileSnapshot{Name: "work", Instance: "https://acme.youtrack.cloud", RESTBaseURL: "https://acme.youtrack.cloud/api", OAuthIssuerURL: "https://hub.example.test", IdentitySHA256: strings.Repeat("a", 64), CredentialGeneration: "gen-1", Account: intent.AccountBinding{ID: "1-2", Login: "alice"}},
		intent.ProjectPolicy{Project: intent.ProjectBinding{ID: "0-1", Key: "APP"}, PolicyRevision: 1, PolicySHA256: strings.Repeat("b", 64), SchemaSHA256: strings.Repeat("c", 64), ExecutorAssurance: "rest-best-effort", AuthorizedCapability: "issue-update", NotificationPolicy: "youtrack-default", ReconciliationStrategy: "bounded-exact-and-marker"},
		intent.KindIssueUpdate,
		[]byte(`{"issue_id":"APP-1","set":{"summary":"new"}}`),
		[]byte(`{"issue_id":"APP-1","issue_state_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","touched_fields_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}`),
		fixedID("YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func dispatchedRecord(t *testing.T) Record {
	t.Helper()
	now := time.Now().UTC()
	plan := journalPlan(t)
	return Record{
		Version: recordVersion, Revision: 3, State: StateInFlight, Plan: plan,
		Receipt: &ReceiptBinding{
			ReceiptID: "YTAR-AAAAAAAAAAAAAAAAAAAAAAAAAA", Nonce: "YTAN-BBBBBBBBBBBBBBBBBBBBBBBBBB",
			PlanSHA256: plan.IntentSHA256, ExpiresAt: now.Add(time.Minute),
			KeyGeneration: "key-1", ReceiptSHA256: strings.Repeat("f", 64),
		},
		MutationAttempts: 1, CreatedAt: now.Add(-time.Minute), UpdatedAt: now,
	}
}

func seedLegacyV1Journal(t *testing.T, store Store, planID string, raw []byte) string {
	t.Helper()
	if err := store.ensureDirectory(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.directory, planID+".json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestStoreCASRefusesV1WithoutChangingRecord(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "journal"))
	plan := journalPlan(t)

	path := seedLegacyV1Journal(t, store, plan.PlanID, []byte(historicalV1Prepared))
	record, err := store.Get(context.Background(), plan.PlanID)
	if err != nil || record.Version != 1 || record.State != StatePrepared || record.Revision != 1 {
		t.Fatalf("seeded v1 record = %#v, %v", record, err)
	}
	info, err := os.Stat(filepath.Join(store.directory, plan.PlanID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("record permissions = %o", info.Mode().Perm())
	}

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		revision uint64
		to       State
	}{{"current revision", 1, StateConfirmed}, {"stale revision", 0, StateCanceled}} {
		t.Run(test.name, func(t *testing.T) {
			_, err := store.CompareAndSwap(context.Background(), plan.PlanID, test.revision, Transition{To: test.to})
			var typed *errx.Error
			if !errors.As(err, &typed) || typed.Reason != "JOURNAL_AUTHORITY_UNAVAILABLE" || errx.ExitCode(err) != errx.CodeInternal {
				t.Fatalf("CAS authority refusal = %#v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, before) {
				t.Fatalf("CAS changed v1 bytes: %v", err)
			}
		})
	}
	recovered, err := store.Get(context.Background(), plan.PlanID)
	if err != nil || recovered.State != StatePrepared || recovered.Revision != 1 {
		t.Fatalf("read after denied CAS = %#v, %v", recovered, err)
	}
}

func TestStoreCreatePersistsCanonicalPreparedV2WithoutLegacyProvenance(t *testing.T) {
	stamp := time.Date(2026, 9, 29, 12, 34, 56, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "journal"))
	store.now = func() time.Time { return stamp }
	plan := journalPlan(t)
	created, err := store.Create(context.Background(), plan)
	if err != nil || created.Version != 2 || created.Revision != 1 || created.State != StatePrepared ||
		!created.CreatedAt.Equal(stamp) || !created.UpdatedAt.Equal(stamp) {
		t.Fatalf("fresh Create = %#v, %v", created, err)
	}
	path := filepath.Join(store.directory, plan.PlanID+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want, err := EncodePreparedV2(PreparedV2Record{Revision: 1, Plan: plan, CreatedAt: stamp, UpdatedAt: stamp})
	if err != nil || !bytes.Equal(raw, want) {
		t.Fatalf("fresh disk bytes differ from canonical prepared v2: %v", err)
	}
	decoded, err := DecodePreparedV2(raw)
	if err != nil || decoded.Revision != 1 || decoded.LegacyV1RecordSHA256 != nil || decoded.Plan.IntentSHA256 != plan.IntentSHA256 {
		t.Fatalf("fresh v2 decode = %#v, %v", decoded, err)
	}
	loaded, err := store.Get(context.Background(), plan.PlanID)
	if err != nil || loaded.Version != 2 || loaded.Revision != 1 || loaded.State != StatePrepared ||
		loaded.Plan.IntentSHA256 != plan.IntentSHA256 {
		t.Fatalf("fresh v2 Get = %#v, %v", loaded, err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("fresh v2 file mode = %v, %v", info, err)
	}
	for _, test := range []struct {
		name     string
		revision uint64
		to       State
	}{{"current revision", 1, StateConfirmed}, {"stale revision", 0, StateCanceled}} {
		t.Run(test.name, func(t *testing.T) {
			_, err := store.CompareAndSwap(context.Background(), plan.PlanID, test.revision, Transition{To: test.to})
			var typed *errx.Error
			if !errors.As(err, &typed) || typed.Reason != "JOURNAL_AUTHORITY_UNAVAILABLE" || errx.ExitCode(err) != errx.CodeInternal {
				t.Fatalf("fresh v2 CAS authority refusal = %v", err)
			}
			after, readErr := os.ReadFile(path)
			if readErr != nil || !bytes.Equal(after, raw) {
				t.Fatalf("denied CAS changed fresh v2: %v", readErr)
			}
		})
	}
}

func TestStoreRefusesCanonicalPreparedCanceledV2WithoutChangingBytes(t *testing.T) {
	plan := journalPlan(t)
	legacyDigest := historicalV1PreparedSHA256
	for _, tc := range []struct {
		name       string
		revision   uint64
		provenance *string
	}{
		{"fresh", 2, nil},
		{"migrated", 3, &legacyDigest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := New(filepath.Join(t.TempDir(), "journal"))
			if err := store.ensureDirectory(); err != nil {
				t.Fatal(err)
			}
			raw, err := EncodePreparedCanceledV2(PreparedCanceledV2Record{
				Revision: tc.revision, Plan: plan, LegacyV1RecordSHA256: tc.provenance,
				CreatedAt: codecTime, UpdatedAt: codecTime.Add(time.Second),
			})
			if err != nil || len(raw) == 0 || raw[len(raw)-1] != '\n' {
				t.Fatalf("canonical canceled bytes = %d, %v", len(raw), err)
			}
			decoded, err := DecodePreparedCanceledV2(raw)
			if err != nil || decoded.Revision != tc.revision || decoded.Plan.PlanID != plan.PlanID {
				t.Fatalf("codec rejected canceled fixture: %#v, %v", decoded, err)
			}
			path := filepath.Join(store.directory, plan.PlanID+".json")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
				t.Fatalf("seeded canceled file is not an owned private regular file: %v, %v", info, err)
			}
			checkUnchanged := func() {
				t.Helper()
				after, readErr := os.ReadFile(path)
				if readErr != nil || !bytes.Equal(after, raw) {
					t.Fatalf("denied Store operation changed canceled bytes: %v", readErr)
				}
			}
			if _, err := store.Get(context.Background(), plan.PlanID); err == nil {
				t.Fatal("Get admitted canceled v2 as an active journal record")
			} else {
				var typed *errx.Error
				if !errors.As(err, &typed) || typed.Code != errx.CodeInternal || typed.Reason != "INTERNAL" {
					t.Fatalf("Get canceled v2 refusal is not typed internal: %v", err)
				}
			}
			checkUnchanged()
			if _, err := store.CompareAndSwap(context.Background(), plan.PlanID, tc.revision, Transition{To: StateConfirmed}); err == nil {
				t.Fatal("CompareAndSwap admitted canceled v2")
			} else {
				var typed *errx.Error
				if !errors.As(err, &typed) || typed.Code != errx.CodeInternal || typed.Reason != "INTERNAL" {
					t.Fatalf("CompareAndSwap canceled v2 refusal is not typed internal: %v", err)
				}
			}
			checkUnchanged()
			if _, err := store.Create(context.Background(), plan); err == nil {
				t.Fatal("Create overwrote canceled v2")
			} else {
				var typed *errx.Error
				if !errors.As(err, &typed) || typed.Code != errx.CodeConflict || typed.Reason != "JOURNAL_RECORD_EXISTS" {
					t.Fatalf("Create canceled v2 refusal is not a record-exists conflict: %v", err)
				}
			}
			checkUnchanged()
			if _, err := store.MigratePreparedV1(context.Background(), plan.PlanID, 1); err == nil {
				t.Fatal("MigratePreparedV1 overwrote canceled v2")
			} else {
				var typed *errx.Error
				wantReason := "INTERNAL"
				if !migrationAvailable() {
					wantReason = "JOURNAL_MIGRATION_UNSUPPORTED"
				}
				if !errors.As(err, &typed) || typed.Code != errx.CodeInternal || typed.Reason != wantReason {
					t.Fatalf("MigratePreparedV1 canceled v2 refusal = %v, want typed %s", err, wantReason)
				}
			}
			checkUnchanged()
		})
	}
}

func TestStoreCreateReturnsCanonicalRecordReadBackFromDisk(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "journal"))
	stamp := time.Date(2026, 9, 29, 9, 34, 56, 123000000, time.FixedZone("west-three", -3*60*60))
	store.now = func() time.Time { return stamp }
	base := journalPlan(t)
	policy := base.Policy
	policy.AuthorizedCapability = "comment-add"
	plan, err := intent.PrepareWithSource(
		base.Profile, policy, intent.KindCommentAdd,
		[]byte(`{"issue_id":"APP-1","text":"reviewed","visibility":{"mode":"public"},"marker":"none"}`),
		[]byte(`{"issue_id":"APP-1","issue_state_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`),
		fixedID("YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA"),
	)
	if err != nil {
		t.Fatal(err)
	}
	// An omitted optional slice is canonical on disk, while a caller may have
	// supplied a non-nil empty slice with identical semantic content.
	plan.Operation.CommentAdd.Request.Visibility.GroupIDs = []string{}
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	created, err := store.Create(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Get(context.Background(), plan.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(created, loaded) {
		t.Fatalf("Create returned a record different from Get: created=%#v loaded=%#v", created, loaded)
	}
	if created.CreatedAt != stamp.UTC() || created.UpdatedAt != stamp.UTC() ||
		created.CreatedAt.Location() != time.UTC || created.UpdatedAt.Location() != time.UTC {
		t.Fatalf("Create timestamps were not canonically decoded: created=%v updated=%v", created.CreatedAt, created.UpdatedAt)
	}
	if created.Plan.Operation.CommentAdd.Request.Visibility.GroupIDs != nil {
		t.Fatalf("Create retained a non-canonical empty visibility slice: %#v", created.Plan.Operation.CommentAdd.Request.Visibility.GroupIDs)
	}
}

func TestStoreCreateRefusesDuplicateWithoutChangingV2(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "journal"))
	plan := journalPlan(t)
	if _, err := store.Create(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.directory, plan.PlanID+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Create(context.Background(), plan)
	var typed *errx.Error
	if !errors.As(err, &typed) || typed.Reason != "JOURNAL_RECORD_EXISTS" || errx.ExitCode(err) != errx.CodeConflict {
		t.Fatalf("duplicate Create refusal = %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatalf("duplicate Create changed v2 bytes: %v", err)
	}
}

func TestStorePersistsPlanAboveFormerRecordLimit(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "journal"))
	plan := largeJournalPlan(t)
	canonical, err := intent.CanonicalBytes(plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(canonical) <= 256<<10 {
		t.Fatalf("canonical plan is %d bytes; regression no longer exercises the former journal limit", len(canonical))
	}
	record, err := store.Create(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := store.Get(context.Background(), plan.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Revision != record.Revision || stored.Plan.IntentSHA256 != plan.IntentSHA256 {
		t.Fatalf("stored record does not match created plan: %#v", stored)
	}
	info, err := os.Stat(filepath.Join(store.directory, plan.PlanID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() <= 256<<10 || info.Size() > maxPreparedLineageV2Bytes {
		t.Fatalf("journal record size = %d, want former limit < size <= %d", info.Size(), maxPreparedLineageV2Bytes)
	}
}

func TestStoreFrozenV1BudgetAndRead(t *testing.T) {
	if maxLegacyV1Bytes != 1<<20 {
		t.Fatalf("frozen v1 read budget changed: %d", maxLegacyV1Bytes)
	}
	store := New(filepath.Join(t.TempDir(), "journal"))
	plan := journalPlan(t)
	seedLegacyV1Journal(t, store, plan.PlanID, []byte(historicalV1Prepared))
	loaded, err := store.Get(context.Background(), plan.PlanID)
	if err != nil || loaded.Version != 1 || loaded.State != StatePrepared || loaded.Revision != 1 ||
		loaded.Plan.IntentSHA256 != plan.IntentSHA256 {
		t.Fatalf("historical v1 cannot be read by frozen decoder: %#v, %v", loaded, err)
	}
}

func TestStoreCreateRejectsV2UnrepresentableTimeBeforeCommit(t *testing.T) {
	for _, test := range []struct {
		name string
		at   time.Time
	}{
		{"year zero", time.Date(0, time.January, 1, 0, 0, 0, 0, time.UTC)},
		{"year ten thousand", time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := New(filepath.Join(t.TempDir(), "journal"))
			store.now = func() time.Time { return test.at }
			plan := journalPlan(t)
			_, err := store.Create(context.Background(), plan)
			var typed *errx.Error
			if !errors.As(err, &typed) || typed.Reason != "INTERNAL" || errx.ExitCode(err) != errx.CodeInternal {
				t.Fatalf("Create invalid-time refusal = %v", err)
			}
			if _, err := os.Lstat(filepath.Join(store.directory, plan.PlanID+".json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unrepresentable Create committed journal bytes: %v", err)
			}
		})
	}
}

func TestStoreCreateRejectsInvalidPlanFieldsWithoutJournalFile(t *testing.T) {
	for _, test := range []struct {
		name                   string
		modify                 func(*intent.Plan)
		sourceContainsSentinel bool
	}{
		{"unsupported operation kind", func(plan *intent.Plan) {
			plan.Kind = intent.Kind("UNTRUSTED_SENTINEL")
			plan.Policy.AuthorizedCapability = ""
		}, true},
		{"overlong profile name", func(plan *intent.Plan) { plan.Profile.Name = strings.Repeat("UNTRUSTED_SENTINEL", 36<<10) }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := New(filepath.Join(t.TempDir(), "journal"))
			plan := journalPlan(t)
			test.modify(&plan)
			if sourceErr := plan.Validate(); sourceErr == nil ||
				(test.sourceContainsSentinel && !strings.Contains(sourceErr.Error(), "UNTRUSTED_SENTINEL")) {
				t.Fatalf("invalid source plan did not exercise the expected validation path: %v", sourceErr)
			}
			_, err := store.Create(context.Background(), plan)
			var typed *errx.Error
			if !errors.As(err, &typed) || typed.Reason != "USAGE" || errx.ExitCode(err) != errx.CodeUsage || !errors.Is(err, intent.ErrInvalidPlan) {
				t.Fatalf("Create %s refusal = %v", test.name, err)
			}
			if typed.Message != "input failed strict validation" || typed.Hint != "check the flags against --help" {
				t.Fatalf("Create %s changed the public usage contract: %#v", test.name, typed)
			}
			if strings.Contains(typed.Message, "UNTRUSTED_SENTINEL") || strings.Contains(typed.Hint, "UNTRUSTED_SENTINEL") ||
				strings.Contains(err.Error(), "UNTRUSTED_SENTINEL") {
				t.Fatalf("Create %s exposed plan-controlled text: %v", test.name, err)
			}
			if _, statErr := os.Lstat(filepath.Join(store.directory, plan.PlanID+".json")); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("Create %s wrote journal file: %v", test.name, statErr)
			}
		})
	}
}

func TestStoreReadsLegacyApprovalIncompatiblePlan(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "journal"))
	plan := journalPlan(t)
	path := seedLegacyV1Journal(t, store, plan.PlanID, []byte(historicalV1Prepared))
	canonical, err := intent.CanonicalBytes(plan)
	if err != nil {
		t.Fatal(err)
	}
	replacements := [][2][]byte{
		{[]byte(`"instance":"https://acme.youtrack.cloud"`), []byte(`"instance":"https://acme.youtrack.cloud:443"`)},
		{[]byte(`"rest_base_url":"https://acme.youtrack.cloud/api"`), []byte(`"rest_base_url":"https://acme.youtrack.cloud:443/api"`)},
		{[]byte(`"oauth_issuer_url":"https://hub.example.test"`), []byte(`"oauth_issuer_url":"https://hub.example.test:443"`)},
	}
	legacyCanonical := append([]byte(nil), canonical...)
	for _, replacement := range replacements {
		if !bytes.Contains(legacyCanonical, replacement[0]) {
			t.Fatalf("canonical plan is missing %q", replacement[0])
		}
		legacyCanonical = bytes.ReplaceAll(legacyCanonical, replacement[0], replacement[1])
	}
	digest := sha256.Sum256(legacyCanonical)
	legacyDigest := hex.EncodeToString(digest[:])
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, replacement := range [][2][]byte{
		{[]byte(`"https://acme.youtrack.cloud/api"`), []byte(`"https://acme.youtrack.cloud:443/api"`)},
		{[]byte(`"https://acme.youtrack.cloud"`), []byte(`"https://acme.youtrack.cloud:443"`)},
		{[]byte(`"https://hub.example.test"`), []byte(`"https://hub.example.test:443"`)},
	} {
		raw = bytes.ReplaceAll(raw, replacement[0], replacement[1])
	}
	raw = bytes.ReplaceAll(raw, []byte(plan.IntentSHA256), []byte(legacyDigest))
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Get(context.Background(), plan.PlanID)
	if err != nil {
		t.Fatalf("read legacy journal record: %v", err)
	}
	if loaded.Plan.Profile.Instance != "https://acme.youtrack.cloud:443" || loaded.Plan.IntentSHA256 != legacyDigest {
		t.Fatalf("loaded plan changed legacy bindings: %#v", loaded.Plan)
	}
}

func largeJournalPlan(t *testing.T) intent.Plan {
	t.Helper()
	fieldType := strings.Repeat("<", 128)
	literal := strings.Repeat("<", 8<<10)
	fields := `[{"field_id":"1","field_type":"` + fieldType + `","text_value":"` + literal +
		`"},{"field_id":"2","field_type":"` + fieldType + `","text_value":"` + literal +
		`"},{"field_id":"3","field_type":"` + fieldType + `","text_value":"` + literal + `"}]`
	request := []byte(`{"issue_id":"APP-1","set":{"summary":"` + strings.Repeat("<", 1024) +
		`","description":"` + strings.Repeat("<", 32<<10) + `","custom_fields":` + fields + `}}`)
	plan, err := intent.PrepareWithSource(
		intent.ProfileSnapshot{Name: "work", Instance: "https://acme.youtrack.cloud", RESTBaseURL: "https://acme.youtrack.cloud/api", OAuthIssuerURL: "https://hub.example.test", IdentitySHA256: strings.Repeat("a", 64), CredentialGeneration: "gen-1", Account: intent.AccountBinding{ID: "1-2", Login: "alice"}},
		intent.ProjectPolicy{Project: intent.ProjectBinding{ID: "0-1", Key: "APP"}, PolicyRevision: 1, PolicySHA256: strings.Repeat("b", 64), SchemaSHA256: strings.Repeat("c", 64), ExecutorAssurance: "rest-best-effort", AuthorizedCapability: "issue-update", NotificationPolicy: "youtrack-default", ReconciliationStrategy: "bounded-exact-and-marker"},
		intent.KindIssueUpdate,
		request,
		[]byte(`{"issue_id":"APP-1","issue_state_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","touched_fields_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}`),
		fixedID("YTAP-AAAQEAYEAUDAOCAJBIFQYDIOB4"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestStoreDistinguishesPreAndPostRenameFailures(t *testing.T) {
	plan := journalPlan(t)
	t.Run("rename failed before commit", func(t *testing.T) {
		store := New(filepath.Join(t.TempDir(), "journal"))
		store.rename = func(string, string) error { return errors.New("rename sentinel") }
		record, err := store.Create(context.Background(), plan)
		if err == nil || WasCommitted(err) || record.Plan.PlanID != plan.PlanID {
			t.Fatalf("record=%#v err=%v committed=%t", record, err, WasCommitted(err))
		}
	})
	t.Run("directory open failed after commit", func(t *testing.T) {
		store := New(filepath.Join(t.TempDir(), "journal"))
		store.openDir = func(string) (*os.File, error) { return nil, errors.New("open directory sentinel") }
		record, err := store.Create(context.Background(), plan)
		if !WasCommitted(err) || record.Plan.PlanID != plan.PlanID {
			t.Fatalf("record=%#v err=%v committed=%t", record, err, WasCommitted(err))
		}
		if _, statErr := os.Stat(filepath.Join(store.directory, plan.PlanID+".json")); statErr != nil {
			t.Fatalf("committed record missing: %v", statErr)
		}
		store.openDir = nil
		if recovered, getErr := store.Get(context.Background(), plan.PlanID); getErr != nil || recovered.Plan.PlanID != plan.PlanID {
			t.Fatalf("recovered=%#v err=%v", recovered, getErr)
		}
	})
	t.Run("directory sync failed after commit", func(t *testing.T) {
		store := New(filepath.Join(t.TempDir(), "journal"))
		store.openDir = func(path string) (*os.File, error) {
			file, err := os.Open(path)
			if err == nil {
				err = file.Close()
			}
			return file, err
		}
		record, err := store.Create(context.Background(), plan)
		if !WasCommitted(err) || record.Plan.PlanID != plan.PlanID {
			t.Fatalf("record=%#v err=%v committed=%t", record, err, WasCommitted(err))
		}
	})
}

func TestGetRejectsMisnamedValidRecord(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "journal"))
	plan := journalPlan(t)
	if _, err := store.Create(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	otherID := "YTAP-6DQNBQFQUCIIA4DAKBADAIAQAA"
	raw, err := os.ReadFile(filepath.Join(store.directory, plan.PlanID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.directory, otherID+".json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), otherID); err == nil {
		t.Fatal("misnamed journal record was accepted")
	}
}

func TestCompleteStateTable(t *testing.T) {
	allowed := map[State][]State{
		StatePrepared:                   {StateConfirmed, StateCanceled, StateExpired},
		StateConfirmed:                  {StateInFlight, StateCanceled, StateExpired},
		StateInFlight:                   {StateFailedBeforeMutation, StateApplied, StateAmbiguous},
		StateApplied:                    {StateReconciled, StateOperatorResolutionRequired},
		StateAmbiguous:                  {StateReconciled, StateResolvedNotApplied, StateOperatorResolutionRequired},
		StateOperatorResolutionRequired: {StateResolvedApplied, StateResolvedNotApplied},
	}
	all := []State{StatePrepared, StateConfirmed, StateCanceled, StateExpired, StateInFlight, StateFailedBeforeMutation, StateApplied, StateAmbiguous, StateReconciled, StateOperatorResolutionRequired, StateResolvedApplied, StateResolvedNotApplied}
	for _, from := range all {
		for _, to := range all {
			want := false
			for _, candidate := range allowed[from] {
				if candidate == to {
					want = true
				}
			}
			if got := allowedTransition(from, to); got != want {
				t.Fatalf("%s -> %s = %v, want %v", from, to, got, want)
			}
		}
	}
}

func TestResolvedFlowRequiresBoundedEvidence(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	plan := journalPlan(t)
	record := Record{Version: 1, Revision: 1, State: StatePrepared, Plan: plan, CreatedAt: now, UpdatedAt: now}
	receipt := &ReceiptBinding{ReceiptID: "YTAR-AAAAAAAAAAAAAAAAAAAAAAAAAA", Nonce: "YTAN-BBBBBBBBBBBBBBBBBBBBBBBBBB", PlanSHA256: plan.IntentSHA256, ExpiresAt: now.Add(time.Minute), KeyGeneration: "key-1", ReceiptSHA256: strings.Repeat("f", 64)}
	record, err := applyTransition(record, Transition{To: StateConfirmed, Receipt: receipt}, now)
	if err != nil {
		t.Fatal(err)
	}
	record, err = applyTransition(record, Transition{To: StateInFlight}, now)
	if err != nil {
		t.Fatal(err)
	}
	record, err = applyTransition(record, Transition{To: StateAmbiguous, Outcome: &Outcome{Code: string(StateAmbiguous)}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := applyTransition(record, Transition{To: StateOperatorResolutionRequired}, now); err == nil {
		t.Fatal("transition without evidence succeeded")
	}
	evidence := &Evidence{SHA256: strings.Repeat("1", 64), Summary: "bounded evidence was non-unique", CollectedAt: now}
	record, err = applyTransition(record, Transition{To: StateOperatorResolutionRequired, Evidence: evidence}, now)
	if err != nil {
		t.Fatal(err)
	}
	resolution := &Evidence{SHA256: strings.Repeat("2", 64), Summary: "operator reviewed exact issue", CollectedAt: now}
	record, err = applyTransition(record, Transition{To: StateResolvedApplied, Evidence: resolution}, now)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != StateResolvedApplied || len(record.Evidence) != 2 {
		t.Fatalf("resolved record = %#v", record)
	}
}

func TestDispatchOutcomeMustMatchStateAndShape(t *testing.T) {
	tests := []struct {
		name    string
		state   State
		outcome Outcome
	}{
		{"empty", StateAmbiguous, Outcome{}},
		{"wrong code", StateApplied, Outcome{Code: string(StateAmbiguous)}},
		{"applied missing remote id", StateApplied, Outcome{Code: string(StateApplied)}},
		{"ambiguous claims remote id", StateAmbiguous, Outcome{Code: string(StateAmbiguous), RemoteID: "APP-2"}},
		{"malformed evidence digest", StateFailedBeforeMutation, Outcome{Code: string(StateFailedBeforeMutation), EvidenceSHA256: "bad"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			current := dispatchedRecord(t)
			if _, err := applyTransition(current, Transition{To: test.state, Outcome: &test.outcome}, time.Now().UTC()); err == nil {
				t.Fatalf("accepted outcome=%#v for state=%s", test.outcome, test.state)
			}
		})
	}
}

func TestGetRejectsImpossibleDurableDispatchRecords(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "journal"))
	if err := store.ensureDirectory(); err != nil {
		t.Fatal(err)
	}
	evidence := Evidence{SHA256: strings.Repeat("a", 64), Summary: "bounded", CollectedAt: time.Now().UTC()}
	tests := []struct {
		name   string
		mutate func(*Record)
	}{
		{"applied without remote ID", func(record *Record) {
			record.State = StateApplied
			record.Outcome = &Outcome{Code: string(StateApplied)}
		}},
		{"in flight with evidence", func(record *Record) { record.Evidence = []Evidence{evidence} }},
		{"dispatch state with premature evidence", func(record *Record) {
			record.State = StateAmbiguous
			record.Outcome = &Outcome{Code: string(StateAmbiguous)}
			record.Evidence = []Evidence{evidence}
		}},
		{"resolved after failed-before-mutation", func(record *Record) {
			record.State = StateReconciled
			record.Outcome = &Outcome{Code: string(StateFailedBeforeMutation)}
			record.Evidence = []Evidence{evidence}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := dispatchedRecord(t)
			test.mutate(&record)
			raw, err := json.MarshalIndent(record, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			raw = append(raw, '\n')
			path := filepath.Join(store.directory, record.Plan.PlanID+".json")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Get(context.Background(), record.Plan.PlanID); err == nil {
				t.Fatalf("journal accepted impossible record: %#v", record)
			}
		})
	}
}
