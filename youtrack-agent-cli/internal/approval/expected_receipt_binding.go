package approval

// ExpectedReceiptBinding owns caller-supplied comparison claims. Construction
// validates grammar only: it does not verify registry authority or ledger state.
type ExpectedReceiptBinding struct {
	registryRevision           int
	authorizationContextSHA256 string
}

// NewExpectedReceiptBinding validates the exact revision and digest grammar.
func NewExpectedReceiptBinding(registryRevision int, authorizationContextSHA256 string) (*ExpectedReceiptBinding, error) {
	if !validRegistryRevision(registryRevision) || !isSHA256(authorizationContextSHA256) {
		return nil, receiptError("RECEIPT_INVALID", "the expected approval receipt binding is invalid")
	}
	return &ExpectedReceiptBinding{registryRevision: registryRevision, authorizationContextSHA256: authorizationContextSHA256}, nil
}

// RegistryRevision returns the claimed revision, or zero for a nil binding.
func (binding *ExpectedReceiptBinding) RegistryRevision() int {
	if binding == nil {
		return 0
	}
	return binding.registryRevision
}

// AuthorizationContextSHA256 returns the claimed digest, or empty for nil.
func (binding *ExpectedReceiptBinding) AuthorizationContextSHA256() string {
	if binding == nil {
		return ""
	}
	return binding.authorizationContextSHA256
}

func (binding *ExpectedReceiptBinding) valid() bool {
	return binding != nil && validRegistryRevision(binding.registryRevision) && isSHA256(binding.authorizationContextSHA256)
}

func validRegistryRevision(revision int) bool {
	return revision >= 1 && revision <= MaxRegistryRevision
}

// keyGenerationRevision accepts exactly YTAG- plus twenty decimal digits.
// Its bounded accumulator rejects overflow without platform-sized parsing.
func keyGenerationRevision(value string) int {
	if len(value) != MaxKeyGenerationBytes || value[:5] != "YTAG-" {
		return 0
	}
	revision := 0
	for i := 5; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return 0
		}
		revision = revision*10 + int(value[i]-'0')
		if revision > MaxRegistryRevision {
			return 0
		}
	}
	if !validRegistryRevision(revision) {
		return 0
	}
	return revision
}
