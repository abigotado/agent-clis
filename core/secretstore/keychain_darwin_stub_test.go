//go:build darwin && cgo && !keychainintegration

package secretstore

// These tests run on a developer's Mac, in their login session. The system
// prompt setting that Open changes is process-wide and may be session-wide, so
// no test in this build may reach the real setter: this file replaces it for
// the whole test binary, including the helper processes it starts.

// uiSetterCalls records every call to the stubbed setter, in order.
var uiSetterCalls []bool

func init() {
	setUserInteractionAllowed = func(allowed bool) error {
		uiSetterCalls = append(uiSetterCalls, allowed)
		return nil
	}
}
