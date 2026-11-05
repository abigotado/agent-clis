package lockfile

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestWithCreatesAndReleasesLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "registry.json")
	if err := os.Mkdir(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	lock := path + ".lock"
	called := false
	if err := With(path, func() error {
		called = true
		if _, err := os.Stat(lock); err != nil {
			t.Errorf("lock is not held during callback: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("With: %v", err)
	}
	if !called {
		t.Error("callback was not called")
	}
	if info, err := os.Stat(lock); err != nil || !info.Mode().IsRegular() {
		t.Errorf("persistent lock file is unavailable: %v", err)
	}
}

func TestWithRejectsLockSymlink(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "registry.json")
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path+".lock"); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := With(path, func() error { called = true; return nil }); err == nil {
		t.Fatal("lock symlink was accepted")
	}
	if called {
		t.Fatal("callback ran through lock symlink")
	}
	raw, err := os.ReadFile(outside)
	if err != nil || string(raw) != "sentinel" {
		t.Fatalf("outside file changed: %q err=%v", raw, err)
	}
}

func TestWithReleasesLockAfterCallbackError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	want := errors.New("write failed")
	if err := With(path, func() error { return want }); !errors.Is(err, want) {
		t.Errorf("With error = %v, want callback error", err)
	}
	if info, err := os.Stat(path + ".lock"); err != nil || !info.Mode().IsRegular() {
		t.Errorf("persistent lock file is unavailable: %v", err)
	}
}

func TestWithSerializesConcurrentCallbacks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	entered := make(chan struct{})
	release := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := With(path, func() error {
			close(entered)
			<-release
			return nil
		}); err != nil {
			t.Errorf("first With: %v", err)
		}
	}()
	<-entered

	secondEntered := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := With(path, func() error {
			close(secondEntered)
			return nil
		}); err != nil {
			t.Errorf("second With: %v", err)
		}
	}()

	select {
	case <-secondEntered:
		t.Fatal("second callback ran while the first still held the lock")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	select {
	case <-secondEntered:
	case <-time.After(time.Second):
		t.Fatal("second callback did not run after lock release")
	}
	wg.Wait()
}

func TestOldMtimeCannotStealLiveAdvisoryLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- With(path, func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path+".lock", old, old); err != nil {
		t.Fatal(err)
	}
	secondEntered := false
	file, err := os.OpenFile(path+".lock", os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	err = acquire(file, path+".lock", 20*time.Millisecond)
	var timeout *TimeoutError
	if !errors.As(err, &timeout) {
		t.Fatalf("acquire error = %v, want TimeoutError", err)
	}
	if err == nil {
		secondEntered = true
	}
	_ = file.Close()
	if secondEntered {
		t.Fatal("old mtime allowed a live lock to be stolen")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("holder: %v", err)
	}
}

func TestWithRejectsNilCallback(t *testing.T) {
	if err := With(filepath.Join(t.TempDir(), "x"), nil); err == nil {
		t.Error("nil callback was accepted")
	}
}

func TestWithExistingRunsWithoutCreatingAndExcludesWith(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	lock := path + ".lock"
	err := WithExisting(path, func() error {
		t.Error("callback ran without a lock file")
		return nil
	})
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing lock: %v", err)
	}
	if _, err := os.Lstat(lock); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("WithExisting created the lock: %v", err)
	}
	if err := With(path, func() error { return nil }); err != nil {
		t.Fatal(err)
	}

	var timedOut *TimeoutError
	err = With(path, func() error {
		return WithExisting(path, func() error {
			t.Error("WithExisting entered while With held the lock")
			return nil
		})
	})
	if !errors.As(err, &timedOut) {
		t.Errorf("WithExisting inside With: %v", err)
	}
	err = WithExisting(path, func() error {
		return With(path, func() error {
			t.Error("With entered while WithExisting held the lock")
			return nil
		})
	})
	if !errors.As(err, &timedOut) {
		t.Errorf("With inside WithExisting: %v", err)
	}
}
