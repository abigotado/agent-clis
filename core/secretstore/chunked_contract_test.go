package secretstore_test

import (
	"strconv"
	"testing"

	"github.com/abigotado/agent-clis/core/secretstore"
	"github.com/abigotado/agent-clis/core/secretstore/secretstoretest"
)

func TestChunkedStoreContract(t *testing.T) {
	for _, max := range []int{2560, 3000, secretstore.MaxSecretBytesLimit} {
		t.Run(strconv.Itoa(max), func(t *testing.T) {
			secretstoretest.Contract(t, secretstore.NewChunkedStoreForTest(max), max)
		})
	}
}
