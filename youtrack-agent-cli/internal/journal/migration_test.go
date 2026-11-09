//go:build darwin || linux

package journal

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
)

func migrationFixture(t *testing.T, raw []byte) (Store, string, string) {
	t.Helper()
	store := New(filepath.Join(t.TempDir(), "journal"))
	store.now = func() time.Time { return codecTime.Add(time.Second) }
	if err := store.ensureDirectory(); err != nil {
		t.Fatal(err)
	}
	planID := "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA"
	path := filepath.Join(store.directory, planID+".json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return store, path, filepath.Join(store.directory, planID+".v1-quarantine.json")
}

func assertLocalJournalNoRetryHint(t *testing.T, err error) {
	t.Helper()
	var typed *errx.Error
	if !errors.As(err, &typed) {
		t.Fatalf("journal refusal is not typed: %v", err)
	}
	hint := strings.ToLower(typed.Hint)
	if !strings.Contains(hint, "local journal") || !strings.Contains(hint, "do not retry a mutation") ||
		strings.Contains(hint, "retry youtrack") {
		t.Fatalf("journal refusal suggests unsafe remote retry: %q", typed.Hint)
	}
}

func TestStoreMigratePreparedV1WritesExactV2AndIsIdempotent(t *testing.T) {
	store, path, markerPath := migrationFixture(t, []byte(historicalV1Prepared))
	var renameCalls atomic.Int32
	store.migrateRename = func(dirFD int, oldName, newName string) error {
		renameCalls.Add(1)
		return defaultMigrationRename(dirFD, oldName, newName)
	}
	planID := "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA"
	before, err := store.Get(context.Background(), planID)
	if err != nil || before.Version != 1 || before.Revision != 1 {
		t.Fatalf("Get before explicit migration = %#v, %v", before, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, []byte(historicalV1Prepared)) {
		t.Fatalf("Get changed v1 bytes: %v", err)
	}
	if _, err := os.Lstat(markerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Get created marker: %v", err)
	}

	migrated, err := store.MigratePreparedV1(context.Background(), planID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if migrated.Revision != 2 || migrated.Plan.PlanID != planID || migrated.LegacyV1RecordSHA256 == nil ||
		*migrated.LegacyV1RecordSHA256 != historicalV1PreparedSHA256 ||
		!migrated.CreatedAt.Equal(codecTime) || !migrated.UpdatedAt.Equal(codecTime.Add(time.Second)) {
		t.Fatalf("migrated record lost frozen bindings: %#v", migrated)
	}
	want, err := EncodePreparedV2(PreparedV2Record{Revision: 2, Plan: migrated.Plan,
		LegacyV1RecordSHA256: migrated.LegacyV1RecordSHA256,
		CreatedAt:            codecTime, UpdatedAt: codecTime.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, want) {
		t.Fatalf("migrated bytes differ from canonical v2: %v", err)
	}
	const historicalMigratedV2SHA256 = "73db6b04881a1822b145d0b41f38fe4a0418bf912cae292e1478b55bfd959a16"
	if got := codecDigest(raw); got != historicalMigratedV2SHA256 {
		t.Fatalf("migrated exact v2 digest = %s, want %s", got, historicalMigratedV2SHA256)
	}
	if _, err := DecodePreparedV2(raw); err != nil {
		t.Fatalf("stored v2 cannot be decoded: %v", err)
	}
	loadedV2, err := store.Get(context.Background(), planID)
	if err != nil || loadedV2.Version != 2 || loadedV2.Revision != 2 || loadedV2.State != StatePrepared {
		t.Fatalf("read-only Get of migrated v2 = %#v, %v", loadedV2, err)
	}
	if _, err := store.CompareAndSwap(context.Background(), planID, 2, Transition{To: StateCanceled}); err == nil {
		t.Fatal("legacy CAS wrote authority-bearing state into prepared-only v2")
	} else {
		var typed *errx.Error
		if !errors.As(err, &typed) || typed.Reason != "JOURNAL_AUTHORITY_UNAVAILABLE" || errx.ExitCode(err) != errx.CodeInternal {
			t.Fatalf("v2 CAS authority refusal = %v", err)
		}
		assertLocalJournalNoRetryHint(t, err)
	}
	postCAS, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(postCAS, raw) {
		t.Fatalf("Get or denied CAS changed v2 bytes: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("migrated file mode = %v, %v", info, err)
	}
	if _, err := os.Lstat(markerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("successful migration created marker: %v", err)
	}

	again, err := store.MigratePreparedV1(context.Background(), planID, 1)
	if err != nil || again.Revision != migrated.Revision || again.LegacyV1RecordSHA256 == nil ||
		*again.LegacyV1RecordSHA256 != historicalV1PreparedSHA256 {
		t.Fatalf("idempotent retry = %#v, %v", again, err)
	}
	second, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(second, raw) {
		t.Fatalf("idempotent retry rewrote v2: %v", err)
	}
	if got := renameCalls.Load(); got != 1 {
		t.Fatalf("successful migration and retry used %d rename writes, want one", got)
	}
	if _, err := store.MigratePreparedV1(context.Background(), planID, 2); err == nil {
		t.Fatal("migration accepted expected revision 2 after consuming v1 revision 1")
	} else {
		assertLocalJournalNoRetryHint(t, err)
	}
	third, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(third, raw) {
		t.Fatalf("revision conflict rewrote v2: %v", err)
	}
	if got := renameCalls.Load(); got != 1 {
		t.Fatalf("revision conflict added a write; renames=%d", got)
	}
}

func TestStoreMigratePreparedV1QuarantinesOnlyValidUnsafeRecords(t *testing.T) {
	yearZero := legacyCodecRecord(t, StatePrepared)
	yearZero.CreatedAt = time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC)
	yearZero.UpdatedAt = yearZero.CreatedAt
	misnamed := "YTAP-6DQNBQFQUCIIA4DAKBADAIAQAA"
	tests := []struct {
		name           string
		raw            []byte
		planID         string
		wantQuarantine bool
		wantState      State
	}{
		{"confirmed", legacyCodecBytes(t, legacyCodecRecord(t, StateConfirmed)), "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA", true, StateConfirmed},
		{"prepared but v2 date unrepresentable", legacyCodecBytes(t, yearZero), "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA", true, StatePrepared},
		{"malformed", []byte(strings.Replace(historicalV1Prepared, `"version": 1`, `"version": 3`, 1)), "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA", false, ""},
		{"misnamed", []byte(historicalV1Prepared), misnamed, false, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, path, markerPath := migrationFixture(t, test.raw)
			if test.planID != "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA" {
				newPath := filepath.Join(store.directory, test.planID+".json")
				if err := os.Rename(path, newPath); err != nil {
					t.Fatal(err)
				}
				path = newPath
				markerPath = filepath.Join(store.directory, test.planID+".v1-quarantine.json")
			}
			_, err := store.MigratePreparedV1(context.Background(), test.planID, 1)
			if err == nil {
				t.Fatal("unsafe or invalid v1 record migrated")
			}
			original, readErr := os.ReadFile(path)
			if readErr != nil || !bytes.Equal(original, test.raw) {
				t.Fatalf("migration changed rejected source: %v", readErr)
			}
			markerRaw, markerErr := os.ReadFile(markerPath)
			if !test.wantQuarantine {
				if !errors.Is(markerErr, os.ErrNotExist) {
					t.Fatalf("invalid record gained quarantine marker: %v", markerErr)
				}
				return
			}
			var typed *errx.Error
			if !errors.As(err, &typed) || typed.Reason != "JOURNAL_V1_AUTHORITY_STATE_QUARANTINED" {
				t.Fatalf("quarantine error = %v", err)
			}
			if markerErr != nil {
				t.Fatalf("valid unsafe v1 has no marker: %v", markerErr)
			}
			marker, err := DecodeQuarantineMarker(markerRaw)
			if err != nil || marker.RecordSHA256 != codecDigest(test.raw) || marker.State != test.wantState {
				t.Fatalf("quarantine marker = %#v, %v", marker, err)
			}
		})
	}
}

func TestStoreCASCannotAdvanceQuarantinedV1(t *testing.T) {
	unsafe := legacyCodecBytes(t, legacyCodecRecord(t, StateConfirmed))
	store, path, _ := migrationFixture(t, unsafe)
	_, err := store.CompareAndSwap(context.Background(), "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA", 2, Transition{To: StateInFlight})
	var typed *errx.Error
	if !errors.As(err, &typed) || typed.Reason != "JOURNAL_AUTHORITY_UNAVAILABLE" || errx.ExitCode(err) != errx.CodeInternal {
		t.Fatalf("quarantined v1 CAS authority refusal = %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, unsafe) {
		t.Fatalf("CAS changed quarantined v1 bytes: %v", err)
	}
}

func TestStoreMigratePreparedV1ConcurrentCallersProduceOneRecord(t *testing.T) {
	store, path, markerPath := migrationFixture(t, []byte(historicalV1Prepared))
	var renameCalls atomic.Int32
	store.migrateRename = func(dirFD int, oldName, newName string) error {
		renameCalls.Add(1)
		return defaultMigrationRename(dirFD, oldName, newName)
	}
	const callers = 8
	results := make([]PreparedV2Record, callers)
	errorsByCaller := make([]error, callers)
	var group sync.WaitGroup
	for i := range results {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			results[index], errorsByCaller[index] = store.MigratePreparedV1(context.Background(), "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA", 1)
		}(i)
	}
	group.Wait()
	for i := range results {
		if errorsByCaller[i] != nil || results[i].Revision != 2 || results[i].LegacyV1RecordSHA256 == nil ||
			*results[i].LegacyV1RecordSHA256 != historicalV1PreparedSHA256 {
			t.Fatalf("caller %d = %#v, %v", i, results[i], errorsByCaller[i])
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePreparedV2(raw); err != nil {
		t.Fatalf("concurrent migration stored invalid v2: %v", err)
	}
	if _, err := os.Lstat(markerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("concurrent migration created marker: %v", err)
	}
	if got := renameCalls.Load(); got != 1 {
		t.Fatalf("concurrent callers performed %d migration writes, want one", got)
	}
}

func TestStoreMigratePreparedV1RefusesFreshV2WithoutWriting(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "journal"))
	plan := journalPlan(t)
	created, err := store.Create(context.Background(), plan)
	if err != nil || created.Version != 2 || created.Revision != 1 {
		t.Fatalf("fresh Create = %#v, %v", created, err)
	}
	path := filepath.Join(store.directory, plan.PlanID+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePreparedV2(before)
	if err != nil || decoded.LegacyV1RecordSHA256 != nil {
		t.Fatalf("fresh v2 fixture = %#v, %v", decoded, err)
	}
	var renameCalls atomic.Int32
	store.migrateRename = func(dirFD int, oldName, newName string) error {
		renameCalls.Add(1)
		return defaultMigrationRename(dirFD, oldName, newName)
	}
	_, err = store.MigratePreparedV1(context.Background(), plan.PlanID, 1)
	var typed *errx.Error
	if !errors.As(err, &typed) || typed.Reason != "JOURNAL_REVISION_CONFLICT" || errx.ExitCode(err) != errx.CodeConflict {
		t.Fatalf("fresh v2 migration refusal = %v", err)
	}
	if renameCalls.Load() != 0 {
		t.Fatal("fresh v2 migration attempted a rename")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatalf("fresh v2 migration changed source: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(store.directory, plan.PlanID+".v1-quarantine.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fresh v2 migration created marker: %v", err)
	}
}

func TestStoreMigratePreparedV1AcceptsLargeValidLegacyPlan(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "journal"))
	store.now = func() time.Time { return codecTime }
	plan := largeJournalPlan(t)
	legacyRecord := legacyCodecRecord(t, StatePrepared)
	legacyRecord.Plan = plan
	path := seedLegacyV1Journal(t, store, plan.PlanID, legacyCodecBytes(t, legacyRecord))
	legacy, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(legacy) <= 256<<10 {
		t.Fatalf("fixture only %d bytes; not a large legacy record", len(legacy))
	}
	store.now = func() time.Time { return codecTime.Add(time.Second) }
	result, err := store.MigratePreparedV1(context.Background(), plan.PlanID, 1)
	if err != nil || result.Revision != 2 || result.LegacyV1RecordSHA256 == nil ||
		*result.LegacyV1RecordSHA256 != codecDigest(legacy) {
		t.Fatalf("large v1 migration = %#v, %v", result, err)
	}
	v2, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(v2) > maxPreparedLineageV2Bytes {
		t.Fatalf("migrated v2 is %d bytes, above cap %d", len(v2), maxPreparedLineageV2Bytes)
	}
	if _, err := DecodePreparedV2(v2); err != nil {
		t.Fatalf("large migrated v2 is not canonical: %v", err)
	}
}

func TestStoreMigratePreparedV1RefusesClockRollbackWithoutWriting(t *testing.T) {
	store, path, markerPath := migrationFixture(t, []byte(historicalV1Prepared))
	store.now = func() time.Time { return codecTime.Add(-time.Second) }
	var renameCalls atomic.Int32
	store.migrateRename = func(dirFD int, oldName, newName string) error {
		renameCalls.Add(1)
		return defaultMigrationRename(dirFD, oldName, newName)
	}
	if _, err := store.MigratePreparedV1(context.Background(), "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA", 1); err == nil {
		t.Fatal("clock rollback produced v2 with updated_at before created_at")
	}
	if renameCalls.Load() != 0 {
		t.Fatal("clock rollback attempted a migration write")
	}
	raw, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, []byte(historicalV1Prepared)) {
		t.Fatalf("clock rollback changed v1 source: %v", err)
	}
	if _, err := os.Lstat(markerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("clock rollback created quarantine marker: %v", err)
	}
}

func TestStoreMigratePreparedV1RequiresExactExpectedRevisionBeforeWrite(t *testing.T) {
	for _, test := range []struct {
		name     string
		revision uint64
	}{{"zero", 0}, {"ahead", 2}} {
		t.Run(test.name, func(t *testing.T) {
			store, path, markerPath := migrationFixture(t, []byte(historicalV1Prepared))
			var renameCalls atomic.Int32
			store.migrateRename = func(dirFD int, oldName, newName string) error {
				renameCalls.Add(1)
				return defaultMigrationRename(dirFD, oldName, newName)
			}
			if _, err := store.MigratePreparedV1(context.Background(), "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA", test.revision); err == nil {
				t.Fatalf("migration accepted expected revision %d for v1 revision 1", test.revision)
			}
			if renameCalls.Load() != 0 {
				t.Fatal("revision conflict attempted a migration write")
			}
			raw, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(raw, []byte(historicalV1Prepared)) {
				t.Fatalf("revision conflict changed v1 source: %v", err)
			}
			if _, err := os.Lstat(markerPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("revision conflict created quarantine marker: %v", err)
			}
		})
	}
}
