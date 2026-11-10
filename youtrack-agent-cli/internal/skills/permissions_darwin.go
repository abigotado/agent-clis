//go:build darwin && cgo

package skills

/*
#include <sys/acl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

// Return zero only when the same filesystem object has no ACL or only deny entries.
static int youtrack_has_unsafe_acl(const char *path, uint64_t expected_dev, uint64_t expected_ino) {
	int fd = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) {
		return -1;
	}
	int unsafe = -1;
	acl_t value = NULL;
	struct stat actual;
	if (fstat(fd, &actual) != 0 || (uint64_t)actual.st_dev != expected_dev ||
		(uint64_t)actual.st_ino != expected_ino) {
		goto done;
	}

	value = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
	if (value == NULL) {
		if (errno == ENOENT) {
			unsafe = 0;
		}
		goto done;
	}
	if (acl_valid(value) != 0) {
		goto done;
	}

	acl_entry_t entry;
	int entry_id = ACL_FIRST_ENTRY;
	for (;;) {
		errno = 0;
		int found = acl_get_entry(value, entry_id, &entry);
		if (found == -1 && errno == EINVAL) {
			unsafe = 0;
			break;
		}
		if (found != 0) {
			break;
		}
		acl_tag_t tag;
		if (acl_get_tag_type(entry, &tag) != 0 || tag != ACL_EXTENDED_DENY) {
			break;
		}
		entry_id = ACL_NEXT_ENTRY;
	}

done:
	if (value != NULL && acl_free(value) != 0) {
		unsafe = -1;
	}
	if (close(fd) != 0) {
		unsafe = -1;
	}
	return unsafe;
}
*/
import "C"

import (
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

func isSharedWritable(path string, info os.FileInfo) bool {
	if info.Mode()&os.ModeSymlink != 0 {
		canonical, err := filepath.EvalSymlinks(path)
		if err != nil || canonical == filepath.Clean(path) {
			return true
		}
		return assertPrivateAncestors(canonical) != nil
	}
	if info.Mode().Perm()&0o022 != 0 {
		return true
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	// Fail closed when the ACL cannot be inspected.
	return C.youtrack_has_unsafe_acl(cPath, C.uint64_t(stat.Dev), C.uint64_t(stat.Ino)) != 0
}

func isStickyDirectory(info os.FileInfo) bool {
	mode := info.Mode()
	return mode.IsDir() && mode&os.ModeSticky != 0
}

func hasUnsafeOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return !ok || stat.Uid != 0 && int(stat.Uid) != os.Geteuid()
}
