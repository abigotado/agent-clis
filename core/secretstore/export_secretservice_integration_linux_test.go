//go:build linux && secretserviceintegration

package secretstore

import "context"

// NewSecretServiceStoreForTest returns a Secret Service store on the session
// bus at address, without going through Open: Open reads the process
// environment and fixes the process-wide interaction mode, and the tests must
// reach a private bus and not the developer's. plainOnly skips the DH
// exchange; onSession, if set, is told each session algorithm opened. The
// external contract test uses it because secretstoretest imports this package.
func NewSecretServiceStoreForTest(address string, maxSecretBytes int, interaction Interaction, plainOnly bool, onSession func(string)) (Store, error) {
	endpoints, err := parseBusAddress(address)
	if err != nil {
		return nil, err
	}
	s := newSecretServiceStore(func(ctx context.Context) (ssBus, error) {
		return dialBus(ctx, endpoints)
	}, Options{MaxSecretBytes: maxSecretBytes, Interaction: interaction})
	s.plainOnly = plainOnly
	s.onSession = onSession
	return s, nil
}

// ProbeSecretServiceForTest reports whether a provider owns the default
// collection on the bus at address.
func ProbeSecretServiceForTest(ctx context.Context, address string) error {
	endpoints, err := parseBusAddress(address)
	if err != nil {
		return err
	}
	s := newSecretServiceStore(func(ctx context.Context) (ssBus, error) {
		return dialBus(ctx, endpoints)
	}, Options{MaxSecretBytes: 1})
	return s.probe(ctx)
}
