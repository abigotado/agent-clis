//go:build darwin && cgo && macos_identity_readonly

package readonlycli

import "github.com/abigotado/youtrack-agent-cli/internal/profile"

func editionPolicy() EditionPolicy {
	policy := EditionPolicy{
		id:                       "macos-identity-readonly",
		name:                     "macOS identity edition",
		versionShort:             "Print the macOS identity metadata edition version and provenance",
		capabilitiesMessage:      "macOS identity profiles must declare exactly capabilities [read]",
		failureMessage:           "macOS identity metadata operation failed safely",
		newRegistry:              profile.NewIdentityReadonlyRegistry,
		validateRegistryOnDryRun: true,
	}
	// A preexisting broad or authenticated record is therefore never displayed,
	// validated, replaced, or removed by identity.
	policy.validateLoadedProfile = strictLoadedProfileValidator(policy)
	return policy
}
