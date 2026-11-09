package intent

import (
	"fmt"

	"github.com/abigotado/youtrack-agent-cli/internal/protocolvalue"
)

const (
	planIDPrefix = "YTAP-"
)

// ValidatePlanID requires the single canonical encoding of a 128-bit plan ID:
// YTAP- followed by uppercase RFC 4648 Base32 without padding. Decode/re-encode
// equality rejects non-zero unused bits in the final symbol.
func ValidatePlanID(value string) error {
	if err := protocolvalue.ValidateCanonicalBase32ID(value, planIDPrefix); err != nil {
		return fmt.Errorf("%w: plan ID: %v", ErrInvalidPlan, err)
	}
	return nil
}
