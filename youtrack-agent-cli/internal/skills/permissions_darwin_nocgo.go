//go:build darwin && !cgo

package skills

import (
	"os"
	"syscall"
)

// A no-cgo Darwin build cannot inspect extended ACLs, so mutations fail closed.
func isSharedWritable(string, os.FileInfo) bool { return true }

func isStickyDirectory(info os.FileInfo) bool {
	mode := info.Mode()
	return mode.IsDir() && mode&os.ModeSticky != 0
}

func hasUnsafeOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return !ok || stat.Uid != 0 && int(stat.Uid) != os.Geteuid()
}
