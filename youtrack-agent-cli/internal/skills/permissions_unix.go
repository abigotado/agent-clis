//go:build !windows && !darwin

package skills

import (
	"os"
	"syscall"
)

func isSharedWritable(_ string, info os.FileInfo) bool {
	return info.Mode().Perm()&0o022 != 0
}

func isStickyDirectory(info os.FileInfo) bool {
	mode := info.Mode()
	return mode.IsDir() && mode&os.ModeSticky != 0
}

func hasUnsafeOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return !ok || stat.Uid != 0 && int(stat.Uid) != os.Geteuid()
}
