package operatorwrite

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
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

	maxImageDimension = 16384
	maxImagePixels    = 64_000_000
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

// DetectAttachmentType derives the content type from the whole buffer. It is
// stricter than net/http sniffing: only PNG, JPEG, GIF, WebP and PDF are
// accepted, each only when the file is structurally well formed from its first
// byte to its last, so SVG, HTML, text and polyglots that merely start with a
// magic prefix never qualify. The checks are bounded by len(b) and allocate
// nothing.
func DetectAttachmentType(b []byte) (string, bool) {
	var contentType string
	var valid bool
	switch {
	case hasPrefix(b, "\x89PNG\r\n\x1a\n"):
		contentType, valid = "image/png", validPNG(b)
	case hasPrefix(b, "\xff\xd8\xff"):
		contentType, valid = "image/jpeg", validJPEG(b)
	case hasPrefix(b, "GIF87a"), hasPrefix(b, "GIF89a"):
		contentType, valid = "image/gif", validGIF(b)
	case hasPrefix(b, "RIFF"):
		contentType, valid = "image/webp", validWebP(b)
	case hasPrefix(b, "%PDF-1."):
		contentType, valid = "application/pdf", validPDF(b)
	}
	if !valid {
		return "", false
	}
	return contentType, true
}

func hasPrefix(b []byte, prefix string) bool {
	return len(b) >= len(prefix) && string(b[:len(prefix)]) == prefix
}

// validPNG walks every chunk: IHDR first, each CRC verified, IEND last with
// nothing after it.
func validPNG(b []byte) bool {
	pos := 8
	for first := true; ; first = false {
		if len(b)-pos < 12 {
			return false
		}
		length := uint64(binary.BigEndian.Uint32(b[pos:]))
		if length > uint64(len(b)-pos-12) {
			return false
		}
		kind := b[pos+4 : pos+8]
		for _, c := range kind {
			if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
				return false
			}
		}
		dataEnd := pos + 8 + int(length)
		if crc32.ChecksumIEEE(b[pos+4:dataEnd]) != binary.BigEndian.Uint32(b[dataEnd:]) {
			return false
		}
		switch {
		case first:
			if string(kind) != "IHDR" || length != 13 {
				return false
			}
		case string(kind) == "IEND":
			if length != 0 || dataEnd+4 != len(b) {
				return false
			}
			cfg, err := png.DecodeConfig(bytes.NewReader(b))
			return err == nil && dimensionsAllowed(cfg)
		case string(kind) == "IHDR":
			return false
		}
		pos = dataEnd + 4
	}
}

func validJPEG(b []byte) bool {
	if len(b) < 4 || b[len(b)-2] != 0xff || b[len(b)-1] != 0xd9 {
		return false
	}
	cfg, err := jpeg.DecodeConfig(bytes.NewReader(b))
	return err == nil && dimensionsAllowed(cfg)
}

// validGIF requires the trailer byte last and a header the stdlib accepts.
func validGIF(b []byte) bool {
	if len(b) < 14 || b[len(b)-1] != 0x3b {
		return false
	}
	cfg, err := gif.DecodeConfig(bytes.NewReader(b))
	return err == nil && dimensionsAllowed(cfg)
}

// dimensionsAllowed bounds the declared pixel area. Only DecodeConfig ever runs
// on attachment bytes, never a full decode, so a declared size cannot allocate.
func dimensionsAllowed(cfg image.Config) bool {
	return cfg.Width >= 1 && cfg.Height >= 1 && cfg.Width <= maxImageDimension && cfg.Height <= maxImageDimension &&
		cfg.Width*cfg.Height <= maxImagePixels
}

// validWebP requires the RIFF size to account for every byte (plus the pad
// byte of an odd size) and a first chunk that is a WebP image chunk.
func validWebP(b []byte) bool {
	if len(b) < 20 || string(b[8:12]) != "WEBP" {
		return false
	}
	size := uint64(binary.LittleEndian.Uint32(b[4:]))
	total := size + 8
	if size%2 == 1 {
		total++
	}
	if total != uint64(len(b)) {
		return false
	}
	switch string(b[12:16]) {
	case "VP8 ", "VP8L", "VP8X":
	default:
		return false
	}
	return uint64(binary.LittleEndian.Uint32(b[16:]))+8 <= size-4
}

const pdfTrailerWindow = 1024

func validPDF(b []byte) bool {
	trimmed := bytes.TrimRight(b, " \t\r\n\f\x00")
	return bytes.HasSuffix(trimmed, []byte("%%EOF")) && len(b)-len(trimmed)+len("%%EOF") <= pdfTrailerWindow
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
