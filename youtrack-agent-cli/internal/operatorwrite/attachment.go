package operatorwrite

import (
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/protocolvalue"
)

const (
	// MaxAttachmentBytes caps the file an attachment.add plan may upload.
	MaxAttachmentBytes = 10 << 20
	// MaxAttachmentNameBytes bounds the validated multipart file name.
	MaxAttachmentNameBytes = 255
	// MaxAttachmentPathBytes bounds the stored absolute source path.
	MaxAttachmentPathBytes = 1024
)

// Attachment is the exact local file an attachment.add plan uploads. The plan
// digest covers every member, so confirming the plan confirms the bytes.
type Attachment struct {
	SourcePath  string `json:"source_path"`
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	ContentType string `json:"content_type"`
}

// AttachmentSource is the verified content of a local attachment file. The same
// Bytes slice is hashed, compared with the plan, and uploaded.
type AttachmentSource struct {
	Path        string
	Bytes       []byte
	Size        int64
	SHA256      string
	ContentType string
}

// Attachment freezes the source under a validated name.
func (s AttachmentSource) Attachment(name string) (Attachment, error) {
	if err := ValidateAttachmentName(name, s.ContentType); err != nil {
		return Attachment{}, err
	}
	return Attachment{SourcePath: s.Path, Name: name, Size: s.Size, SHA256: s.SHA256, ContentType: s.ContentType}, nil
}

// attachmentExtensions lists the accepted file extensions per sniffed type; the
// first entry is the one a hint suggests.
var attachmentExtensions = map[string][]string{
	"image/png":       {".png"},
	"image/jpeg":      {".jpg", ".jpeg"},
	"image/gif":       {".gif"},
	"image/webp":      {".webp"},
	"application/pdf": {".pdf"},
}

// The error messages below never carry the path or file name: an os error
// would embed the path, so none is wrapped.

func attachmentSourceInvalid(message string) error {
	e := errx.Usage("%s", message)
	e.Reason = "OPERATOR_ATTACHMENT_SOURCE_INVALID"
	return e.WithHint("pass --file with a readable, non-empty regular file that is not a symlink")
}

func attachmentTooLarge() error {
	e := errx.Usage("attachment file exceeds the %d byte limit", MaxAttachmentBytes)
	e.Reason = "OPERATOR_ATTACHMENT_TOO_LARGE"
	return e.WithHint("attach a file of at most 10 MiB")
}

func attachmentTypeUnsupported(message, hint string) error {
	e := errx.Usage("%s", message)
	e.Reason = "OPERATOR_ATTACHMENT_TYPE_UNSUPPORTED"
	return e.WithHint("%s", hint)
}

func attachmentNameInvalid(contentType string) error {
	ext := ".png"
	if exts := attachmentExtensions[contentType]; len(exts) > 0 {
		ext = exts[0]
	}
	e := errx.Usage("attachment name is not an accepted ASCII file name")
	e.Reason = "OPERATOR_ATTACHMENT_NAME_INVALID"
	return e.WithHint("pass --name with an ASCII name ending in %s", ext)
}

// DetectAttachmentType derives the content type from the leading magic bytes.
// It is stricter than net/http sniffing: only PNG, JPEG, GIF, WebP and PDF are
// accepted, so SVG, HTML and text never qualify.
func DetectAttachmentType(b []byte) (string, bool) {
	switch {
	case hasPrefix(b, "\x89PNG\r\n\x1a\n"):
		return "image/png", true
	case hasPrefix(b, "\xff\xd8\xff"):
		return "image/jpeg", true
	case hasPrefix(b, "GIF87a"), hasPrefix(b, "GIF89a"):
		return "image/gif", true
	case len(b) >= 14 && hasPrefix(b, "RIFF") && string(b[8:14]) == "WEBPVP":
		return "image/webp", true
	case hasPrefix(b, "%PDF-"):
		return "application/pdf", true
	default:
		return "", false
	}
}

func hasPrefix(b []byte, prefix string) bool {
	return len(b) >= len(prefix) && string(b[:len(prefix)]) == prefix
}

// ValidateAttachmentName refuses, and never sanitizes, a multipart file name:
// 1..255 printable ASCII bytes without path or reserved characters, no leading
// dot or surrounding space, ending in an extension that matches the sniffed
// content type (case-insensitive).
func ValidateAttachmentName(name, contentType string) error {
	exts, ok := attachmentExtensions[contentType]
	if !ok {
		return attachmentTypeUnsupported("attachment content type is not supported", "attach a png, jpeg, gif, webp, or pdf file")
	}
	if name == "" || len(name) > MaxAttachmentNameBytes || name != strings.TrimSpace(name) || strings.HasPrefix(name, ".") ||
		strings.ContainsAny(name, `/\":*?<>|`) {
		return attachmentNameInvalid(contentType)
	}
	for i := 0; i < len(name); i++ {
		if name[i] < 0x20 || name[i] > 0x7e {
			return attachmentNameInvalid(contentType)
		}
	}
	lower := strings.ToLower(name)
	for _, ext := range exts {
		if strings.HasSuffix(lower, ext) && len(lower) > len(ext) {
			return nil
		}
	}
	return attachmentTypeUnsupported("attachment name extension does not match the detected file type",
		"pass --name with the extension of the detected type: "+strings.Join(exts, " or "))
}

func validAttachmentPath(p string) bool {
	if len(p) > MaxAttachmentPathBytes || !utf8.ValidString(p) || !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return false
	}
	for _, r := range p {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validAttachment(a Attachment) bool {
	_, typed := attachmentExtensions[a.ContentType]
	return typed && validAttachmentPath(a.SourcePath) && a.Size >= 1 && a.Size <= MaxAttachmentBytes &&
		protocolvalue.IsSHA256(a.SHA256) && ValidateAttachmentName(a.Name, a.ContentType) == nil
}
