//go:build windows && credmanintegration

package secretstore_test

import (
	"context"
	"os"
	"strconv"
	"testing"

	"github.com/abigotado/agent-clis/core/secretstore"
	"github.com/abigotado/agent-clis/core/secretstore/secretstoretest"
)

// requireCredman reports an unusable Credential Manager. CI sets
// SECRETSTORE_REQUIRE_CREDMAN=1, where it fails instead of skipping so a
// runner that lost the service cannot pass by testing nothing.
func requireCredman(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if os.Getenv("SECRETSTORE_REQUIRE_CREDMAN") == "1" {
		t.Fatalf("Credential Manager is required but unusable: %v", err)
	}
	t.Skipf("Credential Manager is unusable: %v", err)
}

func TestCredmanContract(t *testing.T) {
	for _, max := range []int{2560, 4096, secretstore.MaxSecretBytesLimit} {
		t.Run(strconv.Itoa(max), func(t *testing.T) {
			s := secretstore.NewCredmanStoreForTest(max)
			_, err := s.Exists(context.Background(), secretstore.Key{Service: "secretstore-test-probe", Account: "probe"})
			requireCredman(t, err)
			secretstoretest.Contract(t, s, max)
		})
	}
}
