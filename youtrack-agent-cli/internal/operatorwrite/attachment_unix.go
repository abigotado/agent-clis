//go:build darwin || linux

package operatorwrite

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/protocolvalue"
)

// ReadAttachmentSource reads the attachment file once and returns its verified
// content. Snapshot and apply both use it, so the bytes hashed are the bytes
// uploaded. A symlink final component, non-regular file, empty or oversize
// file, or a file that changes while read is refused. Intermediate symlinked
// directories are followed on purpose (macOS /tmp and /var are symlinks); the
// content hash, not the path, is the guard. No returned error carries the path.
func ReadAttachmentSource(ctx context.Context, path string) (AttachmentSource, error) {
	if err := ctx.Err(); err != nil {
		return AttachmentSource{}, fmt.Errorf("read attachment source: %w", err)
	}
	if path == "" {
		return AttachmentSource{}, attachmentSourceInvalid("attachment source path is empty")
	}
	abs, err := filepath.Abs(path)
	if err != nil || !validAttachmentPath(abs) {
		return AttachmentSource{}, attachmentSourceInvalid("attachment source path is not an acceptable absolute path")
	}
	var linked unix.Stat_t
	if unix.Lstat(abs, &linked) != nil {
		return AttachmentSource{}, attachmentSourceInvalid("attachment source cannot be inspected")
	}
	if linked.Mode&unix.S_IFMT != unix.S_IFREG {
		return AttachmentSource{}, attachmentSourceInvalid("attachment source is not a regular file")
	}
	if err := checkAttachmentSize(linked.Size); err != nil {
		return AttachmentSource{}, err
	}
	// O_NONBLOCK keeps a FIFO swapped in after Lstat from hanging the open;
	// O_NOFOLLOW refuses a symlink swapped in at the final component.
	fd, err := unix.Open(abs, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return AttachmentSource{}, attachmentSourceInvalid("attachment source cannot be opened")
	}
	file := os.NewFile(uintptr(fd), "attachment source")
	if file == nil {
		_ = unix.Close(fd) // No os.File owns the descriptor.
		return AttachmentSource{}, attachmentSourceInvalid("attachment source cannot be opened")
	}
	// A close error on a read-only descriptor cannot change the verified bytes.
	defer func() { _ = file.Close() }()
	var opened unix.Stat_t
	if unix.Fstat(fd, &opened) != nil || opened.Mode&unix.S_IFMT != unix.S_IFREG ||
		opened.Dev != linked.Dev || opened.Ino != linked.Ino || opened.Size != linked.Size {
		return AttachmentSource{}, attachmentSourceInvalid("attachment source changed while opening")
	}
	if err := checkAttachmentSize(opened.Size); err != nil {
		return AttachmentSource{}, err
	}
	raw, err := io.ReadAll(io.LimitReader(file, opened.Size+1))
	if err != nil {
		return AttachmentSource{}, attachmentSourceInvalid("attachment source cannot be read")
	}
	var after unix.Stat_t
	if int64(len(raw)) != opened.Size || unix.Fstat(fd, &after) != nil || after.Size != opened.Size || after.Ino != opened.Ino || after.Dev != opened.Dev {
		return AttachmentSource{}, attachmentSourceInvalid("attachment source changed while reading")
	}
	if err := ctx.Err(); err != nil {
		return AttachmentSource{}, fmt.Errorf("read attachment source: %w", err)
	}
	contentType, ok := DetectAttachmentType(raw)
	if !ok {
		return AttachmentSource{}, attachmentTypeUnsupported("attachment file type is not supported", "attach a png, jpeg, gif, webp, or pdf file")
	}
	return AttachmentSource{Path: abs, Bytes: raw, Size: opened.Size, SHA256: protocolvalue.SHA256Hex(raw), ContentType: contentType}, nil
}

func checkAttachmentSize(size int64) error {
	switch {
	case size < 1:
		return attachmentSourceInvalid("attachment source is empty")
	case size > MaxAttachmentBytes:
		return attachmentTooLarge()
	default:
		return nil
	}
}
