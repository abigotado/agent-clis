package secretstore

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestDisableCoreDumps(t *testing.T) {
	t.Run("zeroes the soft and hard limit in a fresh process", func(t *testing.T) {
		cur, limit, supported, err := readCoreLimit()
		if err != nil {
			t.Fatalf("read core limit: %v", err)
		}
		if supported && cur == 0 && limit == 0 {
			t.Skip("core limit is already 0/0, so the helper cannot show DisableCoreDumps changed anything")
		}
		runHelperProcess(t, "core-dumps")
	})
}

func TestDisableCoreDumpsFailureCarriesNoOSText(t *testing.T) {
	const osText = "operation not permitted at /home/someone/secret-path"
	for _, tt := range []struct {
		name       string
		err        error
		wantStatus int64
	}{
		{"errno", fmt.Errorf("setrlimit: %w", syscall.Errno(1)), 1},
		{"not an errno", errors.New(osText), 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := disableCoreDumpsWith(func() error { return fmt.Errorf("%s: %w", osText, tt.err) })
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("err = %v, want an *Error", err)
			}
			if e.Op != "disable-core-dumps" || e.Backend != "none" || e.Kind != KindOther || e.Status != tt.wantStatus {
				t.Fatalf("err = %#v", e)
			}
			if strings.Contains(err.Error(), "someone") || strings.Contains(err.Error(), "permitted") {
				t.Fatalf("error text %q carries OS text", err.Error())
			}
			want := "secretstore: disable-core-dumps (none): other"
			if tt.wantStatus != 0 {
				want += " status " + strconv.FormatInt(tt.wantStatus, 10)
			}
			if err.Error() != want {
				t.Fatalf("error text = %q, want %q", err.Error(), want)
			}
		})
	}

	t.Run("success is nil", func(t *testing.T) {
		if err := disableCoreDumpsWith(func() error { return nil }); err != nil {
			t.Fatalf("err = %v", err)
		}
	})
}
