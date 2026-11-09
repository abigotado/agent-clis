//go:build darwin || linux

package journal

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"golang.org/x/sys/unix"
)

func TestStoreMigratePreparedV1RejectsUnsafeSourceFiles(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(t *testing.T, path string)
	}{
		{"symlink", func(t *testing.T, path string) {
			t.Helper()
			target := filepath.Join(filepath.Dir(path), "target.json")
			if err := os.WriteFile(target, []byte(historicalV1Prepared), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}},
		{"mode 0644", func(t *testing.T, path string) {
			t.Helper()
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"multiple hard links", func(t *testing.T, path string) {
			t.Helper()
			if err := os.Link(path, filepath.Join(filepath.Dir(path), "second.json")); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversized", func(t *testing.T, path string) {
			t.Helper()
			if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, maxLegacyV1Bytes+1), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"FIFO", func(t *testing.T, path string) {
			t.Helper()
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, path, markerPath := migrationFixture(t, []byte(historicalV1Prepared))
			test.setup(t, path)
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.MigratePreparedV1(context.Background(), "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA", 1); err == nil {
				t.Fatal("unsafe source migrated")
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() {
				t.Fatalf("unsafe source changed: before=%v after=%v err=%v", before, after, err)
			}
			if _, err := os.Lstat(markerPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unsafe source gained marker: %v", err)
			}
		})
	}
}

func TestStoreGetAndCASRejectUnsafeSourceFiles(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(t *testing.T, path string)
	}{
		{"symlink", func(t *testing.T, path string) {
			t.Helper()
			target := filepath.Join(filepath.Dir(path), "target.json")
			if err := os.WriteFile(target, []byte(historicalV1Prepared), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}},
		{"mode 0644", func(t *testing.T, path string) {
			t.Helper()
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"multiple hard links", func(t *testing.T, path string) {
			t.Helper()
			if err := os.Link(path, filepath.Join(filepath.Dir(path), "second.json")); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversized", func(t *testing.T, path string) {
			t.Helper()
			if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, maxLegacyV1Bytes+1), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"FIFO", func(t *testing.T, path string) {
			t.Helper()
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, path, _ := migrationFixture(t, []byte(historicalV1Prepared))
			test.setup(t, path)
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, operation := range []struct {
				name string
				run  func() error
			}{
				{"Get", func() error { _, err := store.Get(context.Background(), "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA"); return err }},
				{"CompareAndSwap", func() error {
					_, err := store.CompareAndSwap(context.Background(), "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA", 1, Transition{To: StateCanceled})
					return err
				}},
			} {
				t.Run(operation.name, func(t *testing.T) {
					if err := operation.run(); err == nil {
						t.Fatal("unsafe journal source was accepted")
					}
					after, err := os.Lstat(path)
					if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() {
						t.Fatalf("unsafe journal source changed: before=%v after=%v err=%v", before, after, err)
					}
				})
			}
		})
	}
}

func TestStorePrivateSetgidDirectorySupportsCreateGetAndMigration(t *testing.T) {
	newSetgidStore := func(t *testing.T) Store {
		t.Helper()
		store := New(filepath.Join(t.TempDir(), "journal"))
		if err := os.Mkdir(store.directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(store.directory, 0o2700); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(store.directory)
		if err != nil || info.Mode()&os.ModeSetgid == 0 {
			t.Skipf("filesystem does not preserve setgid on private directory: %v, %v", info, err)
		}
		return store
	}
	t.Run("fresh v2 Create and Get", func(t *testing.T) {
		store := newSetgidStore(t)
		plan := journalPlan(t)
		created, err := store.Create(context.Background(), plan)
		if err != nil || created.Version != 2 || created.State != StatePrepared || created.Revision != 1 {
			t.Fatalf("Create under setgid directory = %#v, %v", created, err)
		}
		loaded, err := store.Get(context.Background(), plan.PlanID)
		if err != nil || loaded.Version != 2 || loaded.State != StatePrepared || loaded.Revision != 1 {
			t.Fatalf("Get under setgid directory = %#v, %v", loaded, err)
		}
	})
	t.Run("historical v1 migration", func(t *testing.T) {
		store := newSetgidStore(t)
		planID := "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA"
		seedLegacyV1Journal(t, store, planID, []byte(historicalV1Prepared))
		loaded, err := store.Get(context.Background(), planID)
		if err != nil || loaded.Version != 1 || loaded.Revision != 1 {
			t.Fatalf("Get historical v1 under setgid directory = %#v, %v", loaded, err)
		}
		store.now = func() time.Time { return codecTime.Add(time.Second) }
		migrated, err := store.MigratePreparedV1(context.Background(), planID, 1)
		if err != nil || migrated.Revision != 2 || migrated.LegacyV1RecordSHA256 == nil {
			t.Fatalf("Migrate historical v1 under setgid directory = %#v, %v", migrated, err)
		}
	})
}

func TestStoreRejectsOtherSpecialDirectoryBits(t *testing.T) {
	for _, test := range []struct {
		name string
		mode os.FileMode
	}{{"sticky", 0o1700}, {"setuid", 0o4700}} {
		t.Run(test.name, func(t *testing.T) {
			store := New(filepath.Join(t.TempDir(), "journal"))
			if err := os.Mkdir(store.directory, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(store.directory, test.mode); err != nil {
				t.Fatal(err)
			}
			info, err := os.Lstat(store.directory)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode()&(os.ModeSticky|os.ModeSetuid) == 0 {
				t.Skip("filesystem did not preserve requested special bit")
			}
			if _, err := store.Create(context.Background(), journalPlan(t)); err == nil {
				t.Fatal("Create accepted directory with unsafe special bit")
			}
			if _, err := store.Get(context.Background(), "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA"); err == nil {
				t.Fatal("Get accepted directory with unsafe special bit")
			}
		})
	}
}

func TestStoreMigratePreparedV1RenameAndSyncAmbiguity(t *testing.T) {
	sentinel := errors.New("injected migration failure")
	for _, test := range []struct {
		name          string
		inject        func(store *Store, path string, calls *int)
		wantV2        bool
		wantCommitted bool
		wantSuccess   bool
	}{
		{"rename fails before replacement", func(store *Store, _ string, calls *int) {
			store.migrateRename = func(int, string, string) error {
				*calls++
				return sentinel
			}
		}, false, false, false},
		{"rename replaces then reports error", func(store *Store, _ string, calls *int) {
			store.migrateRename = func(dirFD int, oldName, newName string) error {
				*calls++
				if err := unix.Renameat(dirFD, oldName, dirFD, newName); err != nil {
					return err
				}
				return sentinel
			}
		}, true, false, true},
		{"directory sync fails after replacement", func(store *Store, _ string, calls *int) {
			store.migrateDirSync = func(*os.File) error {
				*calls++
				return sentinel
			}
		}, true, true, false},
		{"source replaced before failed rename", func(store *Store, path string, calls *int) {
			store.migrateRename = func(int, string, string) error {
				*calls++
				if err := os.WriteFile(path, []byte("attacker replacement"), 0o600); err != nil {
					return err
				}
				return sentinel
			}
		}, false, true, false},
		{"rename replaces but reread differs", func(store *Store, path string, calls *int) {
			store.migrateRename = func(dirFD int, oldName, newName string) error {
				*calls++
				if err := unix.Renameat(dirFD, oldName, dirFD, newName); err != nil {
					return err
				}
				if err := os.WriteFile(path, []byte("attacker replacement"), 0o600); err != nil {
					return err
				}
				return sentinel
			}
		}, false, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, path, markerPath := migrationFixture(t, []byte(historicalV1Prepared))
			calls := 0
			test.inject(&store, path, &calls)
			migrated, err := store.MigratePreparedV1(context.Background(), "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA", 1)
			if (err == nil) != test.wantSuccess || WasCommitted(err) != test.wantCommitted {
				t.Fatalf("migration result = %#v, %v, committed=%t", migrated, err, WasCommitted(err))
			}
			if calls != 1 {
				t.Fatalf("injected operation called %d times; migration retried write", calls)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if test.wantV2 {
				if _, err := DecodePreparedV2(raw); err != nil {
					t.Fatalf("replaced record is not canonical v2: %v", err)
				}
			} else if test.name == "rename replaces but reread differs" || test.name == "source replaced before failed rename" {
				if string(raw) != "attacker replacement" {
					t.Fatalf("mismatched record changed: %q", raw)
				}
			} else if !bytes.Equal(raw, []byte(historicalV1Prepared)) {
				t.Fatal("failed pre-rename commit changed v1 source")
			}
			if _, err := os.Lstat(markerPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("migration error created marker: %v", err)
			}
		})
	}
}

func TestStoreMigratePreparedV1NeverClobbersExistingMarker(t *testing.T) {
	unsafe := legacyCodecBytes(t, legacyCodecRecord(t, StateConfirmed))
	matching, err := EncodeQuarantineMarker(QuarantineMarker{
		RecordSHA256: codecDigest(unsafe), State: StateConfirmed,
		DetectedAt: codecTime.Add(-time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	conflicting, err := EncodeQuarantineMarker(QuarantineMarker{
		RecordSHA256: historicalV1PreparedSHA256, State: StateConfirmed,
		DetectedAt: codecTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name       string
		marker     []byte
		asSymlink  bool
		wantReason string
	}{
		{"matching", matching, false, "JOURNAL_V1_AUTHORITY_STATE_QUARANTINED"},
		{"conflicting", conflicting, false, ""},
		{"symlink", matching, true, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, sourcePath, markerPath := migrationFixture(t, unsafe)
			actualMarkerPath := markerPath
			if test.asSymlink {
				actualMarkerPath = filepath.Join(store.directory, "marker-target.json")
			}
			if err := os.WriteFile(actualMarkerPath, test.marker, 0o600); err != nil {
				t.Fatal(err)
			}
			if test.asSymlink {
				if err := os.Symlink(actualMarkerPath, markerPath); err != nil {
					t.Fatal(err)
				}
			}
			beforeInfo, err := os.Lstat(markerPath)
			if err != nil {
				t.Fatal(err)
			}
			_, err = store.MigratePreparedV1(context.Background(), "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA", 1)
			if err == nil {
				t.Fatal("unsafe source migrated or marker silently accepted")
			}
			if test.wantReason != "" {
				var typed *errx.Error
				if !errors.As(err, &typed) || typed.Reason != test.wantReason {
					t.Fatalf("matching marker error = %v", err)
				}
			}
			afterInfo, err := os.Lstat(markerPath)
			if err != nil || !os.SameFile(beforeInfo, afterInfo) {
				t.Fatalf("marker inode changed: %v", err)
			}
			readMarker, err := os.ReadFile(actualMarkerPath)
			if err != nil || !bytes.Equal(readMarker, test.marker) {
				t.Fatalf("existing marker bytes changed: %v", err)
			}
			readSource, err := os.ReadFile(sourcePath)
			if err != nil || !bytes.Equal(readSource, unsafe) {
				t.Fatalf("unsafe source changed: %v", err)
			}
		})
	}
}

func TestStoreMigratePreparedV1MarkerPublishAmbiguityNeverReplacesSource(t *testing.T) {
	unsafe := legacyCodecBytes(t, legacyCodecRecord(t, StateConfirmed))
	sentinel := errors.New("injected marker link failure")
	for _, test := range []struct {
		name       string
		link       func(int, string, string) error
		wantMarker bool
	}{
		{"link fails before publish", func(int, string, string) error { return sentinel }, false},
		{"link publishes then reports error", func(dirFD int, oldName, newName string) error {
			if err := unix.Linkat(dirFD, oldName, dirFD, newName, 0); err != nil {
				return err
			}
			return sentinel
		}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, sourcePath, markerPath := migrationFixture(t, unsafe)
			calls := 0
			store.markerLink = func(dirFD int, oldName, newName string) error {
				calls++
				return test.link(dirFD, oldName, newName)
			}
			_, err := store.MigratePreparedV1(context.Background(), "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA", 1)
			if err == nil {
				t.Fatal("unsafe v1 migrated")
			}
			if calls != 1 {
				t.Fatalf("marker link called %d times; no-clobber publish retried", calls)
			}
			source, err := os.ReadFile(sourcePath)
			if err != nil || !bytes.Equal(source, unsafe) {
				t.Fatalf("unsafe source changed: %v", err)
			}
			markerRaw, err := os.ReadFile(markerPath)
			if !test.wantMarker {
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("failed marker link unexpectedly published marker: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ambiguous link did not publish marker: %v", err)
			}
			marker, err := DecodeQuarantineMarker(markerRaw)
			if err != nil || marker.RecordSHA256 != codecDigest(unsafe) || marker.State != StateConfirmed {
				t.Fatalf("published marker = %#v, %v", marker, err)
			}
		})
	}
}

func TestStoreQuarantineMarkerRecoversAfterUnlinkFailure(t *testing.T) {
	unsafe := legacyCodecBytes(t, legacyCodecRecord(t, StateConfirmed))
	for _, test := range []struct {
		name              string
		failures          int
		wantRestartRepair bool
	}{
		{"one-shot failure repaired in same call", 1, false},
		{"persistent failure repaired by fresh store", 2, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, sourcePath, markerPath := migrationFixture(t, unsafe)
			calls := 0
			store.markerUnlink = func(dirFD int, temporary string) error {
				calls++
				if calls <= test.failures {
					return syscall.EIO
				}
				return unix.Unlinkat(dirFD, temporary, 0)
			}
			_, err := store.MigratePreparedV1(context.Background(), "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA", 1)
			var typed *errx.Error
			if !errors.As(err, &typed) || typed.Reason != "JOURNAL_V1_AUTHORITY_STATE_QUARANTINED" {
				t.Fatalf("quarantine refusal = %v", err)
			}
			if calls < test.failures {
				t.Fatalf("unlink hook invoked only %d times", calls)
			}
			if test.wantRestartRepair {
				if errors.Unwrap(typed) == nil {
					t.Fatal("marker persistence failure was discarded")
				}
				restarted := New(store.directory)
				_, err = restarted.MigratePreparedV1(context.Background(), "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA", 1)
				if !errors.As(err, &typed) || typed.Reason != "JOURNAL_V1_AUTHORITY_STATE_QUARANTINED" || errors.Unwrap(typed) != nil {
					t.Fatalf("fresh Store did not securely recover matching marker: %v", err)
				}
			}
			markerRaw, err := os.ReadFile(markerPath)
			if err != nil {
				t.Fatal(err)
			}
			marker, err := DecodeQuarantineMarker(markerRaw)
			if err != nil || marker.RecordSHA256 != codecDigest(unsafe) || marker.State != StateConfirmed {
				t.Fatalf("recovered quarantine marker = %#v, %v", marker, err)
			}
			info, err := os.Lstat(markerPath)
			if err != nil || info.Mode().Perm() != 0o600 || info.Sys().(*syscall.Stat_t).Nlink != 1 {
				t.Fatalf("recovered marker is not a private single-link file: %v, %v", info, err)
			}
			source, err := os.ReadFile(sourcePath)
			if err != nil || !bytes.Equal(source, unsafe) {
				t.Fatalf("quarantine changed original v1 source: %v", err)
			}
		})
	}
}

func TestStoreQuarantineRecoveryRefusesAmbiguousExtraHardLink(t *testing.T) {
	unsafe := legacyCodecBytes(t, legacyCodecRecord(t, StateConfirmed))
	store, sourcePath, markerPath := migrationFixture(t, unsafe)
	store.markerUnlink = func(int, string) error { return syscall.EIO }
	_, err := store.MigratePreparedV1(context.Background(), "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA", 1)
	var typed *errx.Error
	if !errors.As(err, &typed) || typed.Reason != "JOURNAL_V1_AUTHORITY_STATE_QUARANTINED" || errors.Unwrap(typed) == nil {
		t.Fatalf("persistent unlink failure was not retained: %v", err)
	}
	before, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Link(markerPath, filepath.Join(store.directory, "extra-link.json")); err != nil {
		t.Fatal(err)
	}
	restarted := New(store.directory)
	_, err = restarted.MigratePreparedV1(context.Background(), "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA", 1)
	if !errors.As(err, &typed) || typed.Reason != "JOURNAL_V1_AUTHORITY_STATE_QUARANTINED" || errors.Unwrap(typed) == nil {
		t.Fatalf("ambiguous extra link was accepted or not diagnosed: %v", err)
	}
	after, err := os.ReadFile(markerPath)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatalf("ambiguous marker changed: %v", err)
	}
	source, err := os.ReadFile(sourcePath)
	if err != nil || !bytes.Equal(source, unsafe) {
		t.Fatalf("ambiguous recovery changed original v1 source: %v", err)
	}
}

func TestStoreMigrationRetainsPrivateOperationalCauses(t *testing.T) {
	sentinel := errors.New("journal-operational-sentinel-private")
	for _, test := range []struct {
		name   string
		source []byte
		inject func(*Store)
	}{
		{"marker link", legacyCodecBytes(t, legacyCodecRecord(t, StateConfirmed)), func(store *Store) {
			store.markerLink = func(int, string, string) error { return sentinel }
		}},
		{"marker directory sync", legacyCodecBytes(t, legacyCodecRecord(t, StateConfirmed)), func(store *Store) {
			store.migrateDirSync = func(*os.File) error { return sentinel }
		}},
		{"migration rename", []byte(historicalV1Prepared), func(store *Store) {
			store.migrateRename = func(int, string, string) error { return sentinel }
		}},
		{"pre-rename recheck", []byte(historicalV1Prepared), func(store *Store) {
			store.beforeMigrateRename = func(int, string) error { return sentinel }
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, sourcePath, _ := migrationFixture(t, test.source)
			test.inject(&store)
			_, err := store.MigratePreparedV1(context.Background(), "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA", 1)
			if !errors.Is(err, sentinel) {
				t.Fatalf("operational cause was discarded: %v", err)
			}
			var typed *errx.Error
			if !errors.As(err, &typed) || strings.Contains(typed.Message, sentinel.Error()) || strings.Contains(typed.Hint, sentinel.Error()) {
				t.Fatalf("private cause leaked to public contract: %#v", typed)
			}
			if test.name == "marker link" || test.name == "marker directory sync" {
				if typed.Reason != "JOURNAL_V1_AUTHORITY_STATE_QUARANTINED" {
					t.Fatalf("unsafe v1 lost quarantine reason: %#v", typed)
				}
			}
			after, readErr := os.ReadFile(sourcePath)
			if readErr != nil || !bytes.Equal(after, test.source) {
				t.Fatalf("operational failure changed source: %v", readErr)
			}
		})
	}
}

func TestStoreMigratePreparedV1MarkerDirSyncFailureStillQuarantines(t *testing.T) {
	unsafe := legacyCodecBytes(t, legacyCodecRecord(t, StateConfirmed))
	store, sourcePath, markerPath := migrationFixture(t, unsafe)
	store.migrateDirSync = func(*os.File) error { return errors.New("directory sync sentinel") }
	_, err := store.MigratePreparedV1(context.Background(), "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA", 1)
	if err == nil {
		t.Fatal("unsafe v1 migrated after marker directory sync failure")
	}
	source, err := os.ReadFile(sourcePath)
	if err != nil || !bytes.Equal(source, unsafe) {
		t.Fatalf("unsafe source changed: %v", err)
	}
	markerRaw, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatalf("marker was not published before sync failure: %v", err)
	}
	marker, err := DecodeQuarantineMarker(markerRaw)
	if err != nil || marker.RecordSHA256 != codecDigest(unsafe) {
		t.Fatalf("marker after sync failure = %#v, %v", marker, err)
	}
}

func TestStoreMigratePreparedV1RetryAfterDirSyncFailureRequiresConfirmedSync(t *testing.T) {
	store, path, markerPath := migrationFixture(t, []byte(historicalV1Prepared))
	planID := "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA"
	var renameCalls, syncCalls int
	store.migrateRename = func(dirFD int, oldName, newName string) error {
		renameCalls++
		return unix.Renameat(dirFD, oldName, dirFD, newName)
	}
	store.migrateDirSync = func(*os.File) error {
		syncCalls++
		return errors.New("directory sync sentinel")
	}
	first, err := store.MigratePreparedV1(context.Background(), planID, 1)
	if !WasCommitted(err) || first.Revision != 0 || renameCalls != 1 || syncCalls != 1 {
		t.Fatalf("first uncertain migration = %#v, %v; renames=%d syncs=%d", first, err, renameCalls, syncCalls)
	}
	firstBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePreparedV2(firstBytes); err != nil {
		t.Fatalf("uncertain commit did not leave canonical v2: %v", err)
	}
	second, err := store.MigratePreparedV1(context.Background(), planID, 1)
	if !WasCommitted(err) || second.Revision != 0 || renameCalls != 1 || syncCalls != 2 {
		t.Fatalf("retry incorrectly declared uncertain commit durable: %#v, %v; renames=%d syncs=%d", second, err, renameCalls, syncCalls)
	}
	secondBytes, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(secondBytes, firstBytes) {
		t.Fatalf("uncertain retry rewrote v2: %v", err)
	}
	store.migrateDirSync = nil
	confirmed, err := store.MigratePreparedV1(context.Background(), planID, 1)
	if err != nil || confirmed.Revision != 2 || confirmed.LegacyV1RecordSHA256 == nil ||
		*confirmed.LegacyV1RecordSHA256 != historicalV1PreparedSHA256 || renameCalls != 1 {
		t.Fatalf("confirmed retry = %#v, %v; renames=%d", confirmed, err, renameCalls)
	}
	confirmedBytes, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(confirmedBytes, firstBytes) {
		t.Fatalf("confirmed retry changed v2: %v", err)
	}
	if _, err := os.Lstat(markerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retry created quarantine marker: %v", err)
	}
}

func TestStoreMigratePreparedV1DetectsSourceReplacementBeforeRename(t *testing.T) {
	store, path, markerPath := migrationFixture(t, []byte(historicalV1Prepared))
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	var renameCalls int
	store.beforeMigrateRename = func(int, string) error {
		replacement := path + ".replacement"
		if err := os.WriteFile(replacement, []byte(historicalV1Prepared), 0o600); err != nil {
			return err
		}
		return os.Rename(replacement, path)
	}
	store.migrateRename = func(dirFD int, oldName, newName string) error {
		renameCalls++
		return unix.Renameat(dirFD, oldName, dirFD, newName)
	}
	if _, err := store.MigratePreparedV1(context.Background(), "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA", 1); err == nil || WasCommitted(err) {
		t.Fatalf("same-byte replacement was accepted or reported committed: %v", err)
	}
	if renameCalls != 0 {
		t.Fatalf("source replacement reached rename %d times", renameCalls)
	}
	after, err := os.Lstat(path)
	if err != nil || os.SameFile(before, after) {
		t.Fatalf("test did not replace the source inode: before=%v after=%v err=%v", before, after, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, []byte(historicalV1Prepared)) {
		t.Fatalf("replacement bytes were clobbered: %v", err)
	}
	if _, err := os.Lstat(markerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source replacement created marker: %v", err)
	}
}

func TestStoreRejectsSpecialBitJournalDirectoryForCreateAndGet(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "journal"))
	if err := os.MkdirAll(store.directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(store.directory, 0o1700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(store.directory)
	if err != nil || info.Mode()&os.ModeSticky == 0 {
		t.Skipf("filesystem did not retain sticky mode bit: %v, %v", info, err)
	}
	plan := journalPlan(t)
	if _, err := store.Create(context.Background(), plan); err == nil {
		t.Fatal("Create accepted special-bit journal directory")
	}
	if _, err := store.Get(context.Background(), plan.PlanID); err == nil {
		t.Fatal("Get accepted special-bit journal directory")
	}
	if _, err := os.Lstat(filepath.Join(store.directory, plan.PlanID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Create wrote into rejected directory: %v", err)
	}
}
