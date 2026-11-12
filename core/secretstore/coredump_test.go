package secretstore

import "testing"

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
