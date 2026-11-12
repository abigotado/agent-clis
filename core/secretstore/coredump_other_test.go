//go:build !darwin && !linux

package secretstore

func readCoreLimit() (cur, limit uint64, supported bool, err error) {
	return 0, 0, false, nil
}
