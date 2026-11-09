//go:build linux

package operatorwrite

import (
	"errors"
	"golang.org/x/sys/unix"
)

func platformSupported() bool { return true }
func safeACL(fd int, directory bool) bool {
	names := []string{"system.posix_acl_access"}
	if directory {
		names = append(names, "system.posix_acl_default")
	}
	for _, name := range names {
		_, err := unix.Fgetxattr(fd, name, nil)
		if !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP) {
			return false
		}
	}
	return true
}
func localFilesystem(fd int) bool {
	var stat unix.Statfs_t
	if unix.Fstatfs(fd, &stat) != nil {
		return false
	}
	switch uint64(stat.Type) {
	case unix.EXT4_SUPER_MAGIC, unix.TMPFS_MAGIC, unix.OVERLAYFS_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC:
		return true
	default:
		return false
	}
}
