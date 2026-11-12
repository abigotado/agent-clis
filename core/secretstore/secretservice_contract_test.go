package secretstore_test

import (
	"strconv"
	"testing"

	"github.com/abigotado/agent-clis/core/secretstore"
	"github.com/abigotado/agent-clis/core/secretstore/secretstoretest"
)

// TestSecretServiceContractOnFake runs the behaviour suite against the Secret
// Service logic over an in-memory provider, under both session algorithms. The
// real-provider run is the tagged integration test.
func TestSecretServiceContractOnFake(t *testing.T) {
	for _, plain := range []bool{false, true} {
		name := "dh"
		if plain {
			name = "plain"
		}
		for _, max := range []int{256, 4096, secretstore.MaxSecretBytesLimit} {
			t.Run(name+"/"+strconv.Itoa(max), func(t *testing.T) {
				secretstoretest.Contract(t, secretstore.NewFakeSecretServiceStoreForTest(max, plain), max)
			})
		}
	}
}
