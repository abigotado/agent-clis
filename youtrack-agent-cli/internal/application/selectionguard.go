package application

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/profile"
)

type selectionGuardKey struct{}

type selectionGuard struct {
	name     string
	identity string
}

// ResolveSavedProfile resolves a local saved default for the requested role
// and returns a context that fences subsequent profile reads and client setup
// to that exact stable profile identity. Explicit profile selection must not
// call this method.
func (s *Service) ResolveSavedProfile(ctx context.Context, role string) (context.Context, string, error) {
	if s == nil || s.Profiles == nil {
		return ctx, "", errx.Internal("profile registry is unavailable")
	}
	defaults, err := s.Profiles.GetDefaults(ctx)
	if err != nil {
		return ctx, "", err
	}
	var slot *profile.DefaultSlot
	switch role {
	case "read":
		slot = defaults.Read
	case "write":
		slot = defaults.Write
	default:
		return ctx, "", errx.Usage("profile default role must be read or write")
	}
	if slot == nil {
		return ctx, "", errx.ProfileRequired()
	}
	value, err := s.Profiles.Get(ctx, slot.ProfileName)
	if errors.Is(err, profile.ErrNotFound) {
		return ctx, "", defaultStaleError()
	}
	if err != nil {
		return ctx, "", err
	}
	if profile.SelectionIdentity(value) != slot.ProfileIdentitySHA256 || !supportsDefaultRole(value, role) {
		return ctx, "", defaultStaleError()
	}
	return context.WithValue(ctx, selectionGuardKey{}, selectionGuard{name: slot.ProfileName, identity: slot.ProfileIdentitySHA256}), slot.ProfileName, nil
}

func (s *Service) checkSelectionGuard(ctx context.Context, value profile.Profile) error {
	guard, ok := ctx.Value(selectionGuardKey{}).(selectionGuard)
	if !ok {
		return nil
	}
	if guard.name != value.Name || guard.identity != profile.SelectionIdentity(value) {
		return defaultStaleError()
	}
	return nil
}

func checkSelectionLookupError(ctx context.Context, name string, err error) error {
	guard, ok := ctx.Value(selectionGuardKey{}).(selectionGuard)
	if ok && guard.name == name && errors.Is(err, profile.ErrNotFound) {
		return defaultStaleError()
	}
	return err
}

func defaultStaleError() *errx.Error {
	return errx.Conflict("PROFILE_DEFAULT_STALE", "the saved profile default no longer matches local profile metadata").
		WithHint("select a current local profile with profile defaults set before retrying")
}

func supportsDefaultRole(value profile.Profile, role string) bool {
	switch role {
	case "read":
		return value.HasCapability(profile.CapabilityRead)
	case "write":
		return value.Executor == profile.ExecutorRESTBestEffort && value.Assurance == profile.AssuranceBestEffort && hasWriteCapability(value)
	default:
		return false
	}
}

func defaultSlotFor(value profile.Profile, role string) (profile.DefaultSlot, error) {
	if !supportsDefaultRole(value, role) {
		return profile.DefaultSlot{}, errx.Usage("profile %q is not eligible for the %s default", value.Name, role)
	}
	return profile.DefaultSlot{ProfileName: value.Name, ProfileIdentitySHA256: profile.SelectionIdentity(value)}, nil
}

func withDefaultProfileLocks(ctx context.Context, registry *profile.Registry, names []string, fn func() error) error {
	if registry == nil {
		return errx.Internal("profile registry is unavailable")
	}
	unique := make(map[string]struct{}, len(names))
	for _, name := range names {
		if err := profile.ValidateName(name); err != nil {
			return err
		}
		unique[name] = struct{}{}
	}
	sorted := make([]string, 0, len(unique))
	for name := range unique {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)
	var lock func(int) error
	lock = func(index int) error {
		if index == len(sorted) {
			return fn()
		}
		return registry.WithProfileLock(ctx, sorted[index], func() error { return lock(index + 1) })
	}
	return lock(0)
}

func profileDefaultSlotInfo(ctx context.Context, registry *profile.Registry, slot *profile.DefaultSlot, role string) (ProfileDefaultSlotInfo, error) {
	if slot == nil {
		return ProfileDefaultSlotInfo{State: "unset"}, nil
	}
	result := ProfileDefaultSlotInfo{ProfileName: slot.ProfileName, ProfileIdentitySHA256: slot.ProfileIdentitySHA256}
	value, err := registry.Get(ctx, slot.ProfileName)
	if errors.Is(err, profile.ErrNotFound) {
		result.State = "missing_profile"
		return result, nil
	}
	if err != nil {
		return ProfileDefaultSlotInfo{}, fmt.Errorf("read saved %s default: %w", role, err)
	}
	if profile.SelectionIdentity(value) != slot.ProfileIdentitySHA256 || !supportsDefaultRole(value, role) {
		result.State = "stale"
		return result, nil
	}
	result.State = "valid"
	return result, nil
}
