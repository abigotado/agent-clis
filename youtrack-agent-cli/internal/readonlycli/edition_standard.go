//go:build !portable_readonly && !macos_identity_readonly

package readonlycli

import "github.com/abigotado/youtrack-agent-cli/internal/profile"

func editionPolicy() EditionPolicy {
	return EditionPolicy{
		id:                  "portable-readonly",
		name:                "portable edition",
		versionShort:        "Print the portable edition version and provenance",
		capabilitiesMessage: "portable profiles must declare exactly capabilities [read]",
		failureMessage:      "portable read-only operation failed safely",
		newRegistry:         profile.NewDefaultRegistry,
		validateLoadedProfile: func(profile.Profile) error {
			return nil
		},
	}
}
