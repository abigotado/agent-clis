//go:build darwin || linux

package secretstore

import "syscall"

func readCoreLimit() (cur, limit uint64, supported bool, err error) {
	var r syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &r); err != nil {
		return 0, 0, true, err
	}
	return uint64(r.Cur), uint64(r.Max), true, nil
}
