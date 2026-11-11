//go:build !darwin && !linux

package operatorwrite

import "context"

// ReadAttachmentSource refuses on platforms without the descriptor-based
// reader; operator writes are not available there.
func ReadAttachmentSource(context.Context, string) (AttachmentSource, error) {
	return AttachmentSource{}, attachmentSourceInvalid("attachment files are not supported on this platform")
}
