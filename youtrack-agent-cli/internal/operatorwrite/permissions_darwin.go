//go:build darwin && cgo

package operatorwrite

/*
#include <sys/acl.h>
#include <errno.h>
// Like the skills installer, refuse any allow ACL and fail closed on errors.
// Inspect the pinned descriptor, never reopen the caller's pathname.
static int operatorwrite_private_acl(int fd) {
	acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
	if (acl == NULL) return errno == ENOENT;
	int safe = 0;
	if (acl_valid(acl) == 0) {
		acl_entry_t entry;
		int id = ACL_FIRST_ENTRY;
		for (;;) {
			errno = 0;
			int found = acl_get_entry(acl, id, &entry);
			if (found == -1 && errno == EINVAL) { safe = 1; break; }
			if (found != 0) break;
			acl_tag_t tag;
			if (acl_get_tag_type(entry, &tag) != 0 || tag != ACL_EXTENDED_DENY) break;
			id = ACL_NEXT_ENTRY;
		}
	}
	if (acl_free(acl) != 0) safe = 0;
	return safe;
}
*/
import "C"

import "golang.org/x/sys/unix"

func platformSupported() bool     { return true }
func safeACL(fd int, _ bool) bool { return C.operatorwrite_private_acl(C.int(fd)) == 1 }
func localFilesystem(fd int) bool {
	var stat unix.Statfs_t
	return unix.Fstatfs(fd, &stat) == nil && stat.Flags&unix.MNT_LOCAL != 0
}
