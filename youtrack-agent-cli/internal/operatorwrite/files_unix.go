//go:build darwin || linux

package operatorwrite

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type secureDirectory struct {
	file *os.File
	fd   int
	path string
}

func openDirectory(path string, create bool) (*secureDirectory, error) {
	if !platformSupported() || path == "" {
		return nil, invalid()
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	// Resolve the existing ancestor once, then pin every subsequent component.
	// A final symlink is always refused; macOS's system /var alias is tolerated.
	if info, e := os.Lstat(abs); e == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, invalid()
	}
	ancestor := abs
	var missing []string
	for {
		_, e := os.Lstat(ancestor)
		if e == nil {
			break
		}
		if !errors.Is(e, os.ErrNotExist) || !create {
			return nil, e
		}
		missing = append([]string{filepath.Base(ancestor)}, missing...)
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			return nil, invalid()
		}
		ancestor = parent
	}
	canonical, err := filepath.EvalSymlinks(ancestor)
	if err != nil {
		return nil, err
	}
	for _, part := range missing {
		canonical = filepath.Join(canonical, part)
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "operator-write directory")
	if file == nil {
		_ = unix.Close(fd) /* No os.File owns the descriptor. */
		return nil, invalid()
	}
	fail := func(e error) (*secureDirectory, error) { return nil, errors.Join(e, file.Close()) }
	parts := strings.Split(strings.TrimPrefix(canonical, "/"), "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return fail(invalid())
		}
		var stat unix.Stat_t
		if unix.Fstat(fd, &stat) != nil || !safeAncestor(stat) || !safeACL(fd, true) {
			return fail(invalid())
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(e, unix.ENOENT) && create {
			if e = unix.Mkdirat(fd, part, 0o700); e != nil && !errors.Is(e, unix.EEXIST) {
				return fail(e)
			}
			next, e = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if e == nil {
				if syncErr := file.Sync(); syncErr != nil {
					_ = unix.Close(next) /* No os.File owns next yet. */
					return fail(syncErr)
				}
			}
		}
		if e != nil {
			return fail(e)
		}
		if e := file.Close(); e != nil {
			_ = unix.Close(next) /* Closing the previous descriptor failed. */
			return nil, e
		}
		fd = next
		file = os.NewFile(uintptr(fd), "operator-write directory")
		if file == nil {
			_ = unix.Close(fd) /* No os.File owns the descriptor. */
			return nil, invalid()
		}
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		stat.Mode&0o7777 != 0o700 ||
		stat.Uid != uint32(os.Geteuid()) || !safeACL(fd, true) || !localFilesystem(fd) {
		return fail(invalid())
	}
	return &secureDirectory{file: file, fd: fd, path: canonical}, nil
}

func safeAncestor(stat unix.Stat_t) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFDIR && (stat.Uid == 0 || stat.Uid == uint32(os.Geteuid())) &&
		(stat.Mode&0o022 == 0 || stat.Uid == 0 && stat.Mode&unix.S_ISVTX != 0)
}
func (d *secureDirectory) close() error { return d.file.Close() }
func (d *secureDirectory) exists(name string) (bool, error) {
	var stat unix.Stat_t
	err := unix.Fstatat(d.fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	return err == nil, err
}
func validFile(stat unix.Stat_t, limit int) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Mode&0o7777 == 0o600 && stat.Uid == uint32(os.Geteuid()) &&
		uint64(stat.Nlink) == 1 && stat.Size >= 0 && stat.Size <= int64(limit)
}
func (d *secureDirectory) read(name string, limit int) (raw []byte, err error) {
	var linked unix.Stat_t
	if e := unix.Fstatat(d.fd, name, &linked, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		if errors.Is(e, unix.ENOENT) {
			return nil, os.ErrNotExist
		}
		return nil, e
	}
	if !validFile(linked, limit) {
		return nil, invalid()
	}
	fd, err := unix.Openat(d.fd, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "operator-write record")
	if file == nil {
		_ = unix.Close(fd) /* No os.File owns the descriptor. */
		return nil, invalid()
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	var opened unix.Stat_t
	if unix.Fstat(fd, &opened) != nil || !validFile(opened, limit) || linked.Dev != opened.Dev || linked.Ino != opened.Ino || !safeACL(fd, false) {
		return nil, invalid()
	}
	raw, err = io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	var after, current unix.Stat_t
	if len(raw) > limit || int64(len(raw)) != opened.Size || unix.Fstat(fd, &after) != nil ||
		unix.Fstatat(d.fd, name, &current, unix.AT_SYMLINK_NOFOLLOW) != nil || !validFile(after, limit) || !validFile(current, limit) ||
		after.Ino != opened.Ino || current.Ino != opened.Ino || after.Dev != opened.Dev || current.Dev != opened.Dev ||
		after.Size != opened.Size || current.Size != opened.Size {
		return nil, invalid()
	}
	return raw, nil
}

// create intentionally retains partial files: in particular, a failed claim
// durability step must never make that plan dispatchable again.
func (d *secureDirectory) create(name string, raw []byte, s *Store) (err error) {
	fd, err := unix.Openat(d.fd, name, unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_CREAT|unix.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "operator-write record")
	if file == nil {
		_ = unix.Close(fd) /* No os.File owns the descriptor. */
		return invalid()
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || !validFile(stat, MaxRecordBytes) || !safeACL(fd, false) {
		return invalid()
	}
	write := func(f *os.File, b []byte) (int, error) { return f.Write(b) }
	syncFile := func(f *os.File) error { return f.Sync() }
	syncDir := syncFile
	if s != nil {
		if s.writeFile != nil {
			write = s.writeFile
		}
		if s.syncFile != nil {
			syncFile = s.syncFile
		}
		if s.syncDir != nil {
			syncDir = s.syncDir
		}
	}
	n, err := write(file, raw)
	if err != nil {
		return err
	}
	if n != len(raw) {
		return io.ErrShortWrite
	}
	if err := syncFile(file); err != nil {
		return err
	}
	return syncDir(d.file)
}
func (d *secureDirectory) replace(name string, raw []byte, s *Store) error {
	id, err := newID("tmp-")
	if err != nil {
		return err
	}
	if err := d.create(id, raw, s); err != nil {
		return err
	}
	if err := unix.Renameat(d.fd, id, d.fd, name); err != nil {
		return err
	}
	if s != nil && s.syncDir != nil {
		return s.syncDir(d.file)
	}
	return d.file.Sync()
}
