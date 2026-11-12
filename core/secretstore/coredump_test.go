package secretstore

import "testing"

func TestDisableCoreDumps(t *testing.T) {
	t.Run("zeroes the soft and hard limit in a fresh process", func(t *testing.T) {
		runHelperProcess(t, "core-dumps")
	})
}
