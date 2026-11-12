//go:build !darwin && !linux

package secretstore

func disableCoreDumps() error { return nil }
