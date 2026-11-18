//go:build darwin && !cgo

package secretstore

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func init() {
	platformHelpers["darwin-nocgo-open"] = func() error {
		_, err := Open(context.Background(), Options{MaxSecretBytes: 1024, Interaction: InteractionNever})
		var se *Error
		if !errors.Is(err, ErrUnavailable) || !errors.As(err, &se) || se.Op != "open" || se.Kind != KindUnavailable {
			return fmt.Errorf("Open without cgo = %v, want an open ErrUnavailable", err)
		}
		return nil
	}
}

func TestOpenWithoutCgoIsUnavailable(t *testing.T) {
	runHelperProcess(t, "darwin-nocgo-open")
}
