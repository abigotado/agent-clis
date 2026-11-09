package readonlycli

import (
	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/profile"
)

// EditionPolicy is the complete immutable policy selected for one readonly
// edition at compile time. App retains one value for its whole invocation so
// wording, registry selection, and loaded-profile handling cannot drift.
type EditionPolicy struct {
	id                       string
	name                     string
	versionShort             string
	capabilitiesMessage      string
	failureMessage           string
	newRegistry              func() (*profile.Registry, error)
	validateLoadedProfile    func(profile.Profile) error
	validateRegistryOnDryRun bool
}

func (policy EditionPolicy) validateAdmissionProfile(value profile.Profile) error {
	if err := value.ValidateLoginIntent(); err != nil {
		return errx.Usage("profile is invalid for the %s", policy.name)
	}
	if len(value.Capabilities) != 1 || value.Capabilities[0] != profile.CapabilityRead {
		return errx.Usage("%s", policy.capabilitiesMessage)
	}
	return nil
}

func strictLoadedProfileValidator(policy EditionPolicy) func(profile.Profile) error {
	return func(value profile.Profile) error {
		return policy.validateAdmissionProfile(value)
	}
}
