package operatorwrite

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/protocolvalue"
)

func TestDetectAttachmentType(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
		ok   bool
	}{
		{"png", pngBytes, "image/png", true},
		{"jpeg", minimalJPEG, "image/jpeg", true},
		{"gif89a", minimalGIF, "image/gif", true},
		{"gif87a", append([]byte("GIF87a"), minimalGIF[6:]...), "image/gif", true},
		{"gif with global color table and image", gifWithImage(), "image/gif", true},
		{"webp", webpBytes, "image/webp", true},
		{"webp VP8L", withFourCC(minimalWebP, "VP8L"), "image/webp", true},
		{"webp VP8X", withFourCC(minimalWebP, "VP8X"), "image/webp", true},
		{"webp odd size with pad byte", oddWebP(), "image/webp", true},
		{"pdf", minimalPDF, "application/pdf", true},
		{"pdf with trailing whitespace", append(append([]byte{}, minimalPDF...), "\r\n \n"...), "application/pdf", true},
		{"svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`), "", false},
		{"html", []byte("<!DOCTYPE html><html></html>"), "", false},
		{"text", []byte("hello world"), "", false},
		{"zip", []byte("PK\x03\x04data"), "", false},
		{"elf", []byte("\x7fELF\x02\x01\x01"), "", false},
		{"riff wave", []byte("RIFF\x10\x00\x00\x00WAVEfmt "), "", false},

		{"gif magic with html body", []byte("GIF89a<!doctype html><html></html>"), "", false},
		{"gif magic with html body ending in trailer byte", []byte("GIF89a<!doctype html><script>x</script>;"), "", false},
		{"gif without trailer", minimalGIF[:len(minimalGIF)-1], "", false},
		{"gif trailer not last", append(append([]byte{}, minimalGIF...), "<svg/>"...), "", false},
		{"gif color table beyond file", []byte("GIF89a\x01\x00\x01\x00\xf7\x00\x00;"), "", false},
		{"png at the dimension cap", pngWithSize(8000, 8000), "image/png", true},
		{"png declaring 100000x100000", pngWithSize(100000, 100000), "", false},
		{"png width over the cap", pngWithSize(16385, 1), "", false},
		{"png area over the cap", pngWithSize(16384, 16384), "", false},
		{"png zero width", pngWithSize(0, 1), "", false},
		{"jpeg declaring 65535x65535", sizedJPEG(minimalJPEG, 0xff), "", false},
		{"png then svg", append(append([]byte{}, pngBytes...), `<svg xmlns="http://www.w3.org/2000/svg"/>`...), "", false},
		{"png signature then svg", append([]byte("\x89PNG\r\n\x1a\n"), `<svg xmlns="http://www.w3.org/2000/svg"/>`...), "", false},
		{"png bad crc in text chunk", flipByte(pngBytes, 8+25+8), "", false},
		{"png bad crc in ihdr", flipByte(pngBytes, 8+8+3), "", false},
		{"png data after iend", append(append([]byte{}, pngBytes...), 0), "", false},
		{"png without iend", pngBytes[:len(pngBytes)-12], "", false},
		{"png first chunk not ihdr", append([]byte("\x89PNG\r\n\x1a\n"), pngChunk("tEXt", []byte("x"))...), "", false},
		{"png ihdr wrong length", append(append([]byte("\x89PNG\r\n\x1a\n"), pngChunk("IHDR", make([]byte, 12))...), pngChunk("IEND", nil)...), "", false},
		{"png chunk length beyond buffer", append(append([]byte{}, pngBytes[:33]...), 0x7f, 0xff, 0xff, 0xff, 't', 'E', 'X', 't'), "", false},
		{"png iend with data", append(append([]byte{}, pngBytes[:len(pngBytes)-12]...), pngChunk("IEND", []byte{1})...), "", false},
		{"jpeg without eoi", []byte("\xff\xd8\xff\xe0\x00\x02<html>"), "", false},
		{"jpeg bytes after eoi", append(append([]byte{}, minimalJPEG...), 0), "", false},
		{"jpeg magic only", []byte("\xff\xd8\xff"), "", false},
		{"webp size too small", sizedWebP(minimalWebP, 0x14), "", false},
		{"webp size too large", sizedWebP(minimalWebP, 0x18), "", false},
		{"webp trailing bytes", append(append([]byte{}, minimalWebP...), "<svg/>"...), "", false},
		{"webp unknown first chunk", withFourCC(minimalWebP, "JUNK"), "", false},
		{"webp first chunk beyond riff", append(append([]byte{}, minimalWebP[:16]...), 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0), "", false},
		{"pdf without eof marker", []byte("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n"), "", false},
		{"pdf with data after eof", append(append([]byte{}, minimalPDF...), "<html>"...), "", false},
		{"pdf eof outside final 1024 bytes", append(append([]byte{}, minimalPDF...), bytes.Repeat([]byte("x"), 1100)...), "", false},
		{"pdf wrong version", []byte("%PDF-2.0\n%%EOF"), "", false},
		{"truncated png magic", []byte("\x89PNG\r\n\x1a"), "", false},
		{"truncated webp", []byte("RIFF\x10\x00\x00\x00WEBPV"), "", false},
		{"truncated pdf", []byte("%PDF"), "", false},
		{"empty", nil, "", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := DetectAttachmentType(test.data)
			if got != test.want || ok != test.ok {
				t.Fatalf("DetectAttachmentType = %q, %v; want %q, %v", got, ok, test.want, test.ok)
			}
		})
	}
}

func TestDetectAttachmentTypeRejectsEveryTruncation(t *testing.T) {
	for name, full := range map[string][]byte{"png": pngBytes, "jpeg": minimalJPEG, "gif": gifWithImage(), "webp": minimalWebP, "pdf": minimalPDF} {
		if _, ok := DetectAttachmentType(full); !ok {
			t.Fatalf("%s fixture is not accepted", name)
		}
		for n := 0; n < len(full); n++ {
			if got, ok := DetectAttachmentType(full[:n]); ok && name != "pdf" {
				t.Fatalf("%s truncated to %d bytes accepted as %q", name, n, got)
			}
		}
	}
	// A PDF is complete once its %%EOF marker is present; only a cut before it fails.
	for n := 0; n < bytes.Index(minimalPDF, []byte("%%EOF"))+5; n++ {
		if _, ok := DetectAttachmentType(minimalPDF[:n]); ok {
			t.Fatalf("pdf truncated to %d bytes accepted", n)
		}
	}
}

func gifWithImage() []byte {
	out := []byte("GIF89a\x01\x00\x01\x00\x80\x00\x00")
	out = append(out, 0, 0, 0, 255, 255, 255)          // 2-entry global color table
	out = append(out, 0x21, 0xf9, 0x04, 0, 0, 0, 0, 0) // graphic control extension
	out = append(out, 0x2c, 0, 0, 0, 0, 1, 0, 1, 0, 0) // image descriptor
	out = append(out, 2, 2, 0x44, 0x01, 0)             // LZW size, one data sub-block, terminator
	return append(out, ';')
}

// sizedJPEG rewrites the SOF0 height and width to the same 16-bit value.
func sizedJPEG(b []byte, v byte) []byte {
	out := append([]byte{}, b...)
	i := bytes.Index(out, []byte("\xff\xc0"))
	copy(out[i+5:i+9], []byte{v, v, v, v})
	return out
}

func withFourCC(b []byte, fourcc string) []byte {
	out := append([]byte{}, b...)
	copy(out[12:16], fourcc)
	return out
}

func sizedWebP(b []byte, size byte) []byte {
	out := append([]byte{}, b...)
	out[4] = size
	return out
}

// oddWebP is a WebP whose odd RIFF size is followed by one pad byte.
func oddWebP() []byte {
	out := []byte("RIFF\x15\x00\x00\x00WEBPVP8 \x09\x00\x00\x00012345678")
	return append(out, 0)
}

func flipByte(b []byte, i int) []byte {
	out := append([]byte{}, b...)
	out[i] ^= 0xff
	return out
}

func TestValidateAttachmentName(t *testing.T) {
	long := strings.Repeat("a", 251) + ".png"
	tests := []struct {
		name, file, contentType, reason string
	}{
		{"plain png", "shot.png", "image/png", ""},
		{"upper-case extension", "SHOT.PNG", "image/png", ""},
		{"jpg", "photo.jpg", "image/jpeg", ""},
		{"jpeg", "photo.JPEG", "image/jpeg", ""},
		{"gif", "a.gif", "image/gif", ""},
		{"webp", "a.webp", "image/webp", ""},
		{"pdf with spaces inside", "my report v2.pdf", "application/pdf", ""},
		{"max length", long, "image/png", ""},
		{"too long", "a" + long, "image/png", "OPERATOR_ATTACHMENT_NAME_INVALID"},
		{"empty", "", "image/png", "OPERATOR_ATTACHMENT_NAME_INVALID"},
		{"slash", "a/b.png", "image/png", "OPERATOR_ATTACHMENT_NAME_INVALID"},
		{"backslash", `a\b.png`, "image/png", "OPERATOR_ATTACHMENT_NAME_INVALID"},
		{"quote", `a".png`, "image/png", "OPERATOR_ATTACHMENT_NAME_INVALID"},
		{"colon", "a:b.png", "image/png", "OPERATOR_ATTACHMENT_NAME_INVALID"},
		{"star", "a*.png", "image/png", "OPERATOR_ATTACHMENT_NAME_INVALID"},
		{"question", "a?.png", "image/png", "OPERATOR_ATTACHMENT_NAME_INVALID"},
		{"angle", "a<b>.png", "image/png", "OPERATOR_ATTACHMENT_NAME_INVALID"},
		{"pipe", "a|b.png", "image/png", "OPERATOR_ATTACHMENT_NAME_INVALID"},
		{"newline", "a\nb.png", "image/png", "OPERATOR_ATTACHMENT_NAME_INVALID"},
		{"tab", "a\tb.png", "image/png", "OPERATOR_ATTACHMENT_NAME_INVALID"},
		{"nul", "a\x00b.png", "image/png", "OPERATOR_ATTACHMENT_NAME_INVALID"},
		{"del", "a\x7fb.png", "image/png", "OPERATOR_ATTACHMENT_NAME_INVALID"},
		{"leading dot", ".hidden.png", "image/png", "OPERATOR_ATTACHMENT_NAME_INVALID"},
		{"dot dot", "..", "image/png", "OPERATOR_ATTACHMENT_NAME_INVALID"},
		{"single dot", ".", "image/png", "OPERATOR_ATTACHMENT_NAME_INVALID"},
		{"leading space", " a.png", "image/png", "OPERATOR_ATTACHMENT_NAME_INVALID"},
		{"trailing space", "a.png ", "image/png", "OPERATOR_ATTACHMENT_NAME_INVALID"},
		{"macOS narrow no-break space", "Screenshot 2026-01-01 at 10.00.00 AM.png", "image/png", "OPERATOR_ATTACHMENT_NAME_INVALID"},
		{"non-ascii", "snímek.png", "image/png", "OPERATOR_ATTACHMENT_NAME_INVALID"},
		{"bidi override", "a‮gnp.exe.png", "image/png", "OPERATOR_ATTACHMENT_NAME_INVALID"},
		{"missing extension", "shot", "image/png", "OPERATOR_ATTACHMENT_TYPE_UNSUPPORTED"},
		{"mismatched extension", "shot.jpg", "image/png", "OPERATOR_ATTACHMENT_TYPE_UNSUPPORTED"},
		{"extension only", "x.png.exe", "image/png", "OPERATOR_ATTACHMENT_TYPE_UNSUPPORTED"},
		{"unknown content type", "a.png", "image/svg+xml", "OPERATOR_ATTACHMENT_TYPE_UNSUPPORTED"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateAttachmentName(test.file, test.contentType)
			if test.reason == "" {
				if err != nil {
					t.Fatalf("ValidateAttachmentName(%q) = %v", test.file, err)
				}
				return
			}
			var typed *errx.Error
			if !errors.As(err, &typed) || typed.Reason != test.reason || errx.ExitCode(err) != 2 {
				t.Fatalf("ValidateAttachmentName(%q) = %#v, want reason %s exit 2", test.file, err, test.reason)
			}
		})
	}
	t.Run("hints", func(t *testing.T) {
		var typed *errx.Error
		if err := ValidateAttachmentName("Screenshot .png", "image/png"); !errors.As(err, &typed) || !strings.Contains(typed.Hint, "ASCII name ending in .png") {
			t.Fatalf("name hint = %#v", err)
		}
		if err := ValidateAttachmentName("a.png", "image/jpeg"); !errors.As(err, &typed) || !strings.Contains(typed.Hint, ".jpg") {
			t.Fatalf("type hint = %#v", err)
		}
	})
}

func attachmentFixture(t *testing.T) Attachment {
	t.Helper()
	return Attachment{SourcePath: "/work/shot.png", Name: "shot.png", Size: int64(len(pngBytes)), SHA256: protocolvalue.SHA256Hex(pngBytes), ContentType: "image/png"}
}

func attachmentSnapshot(t *testing.T) Snapshot {
	t.Helper()
	s := testSnapshot(t, KindAttachmentAdd)
	a := attachmentFixture(t)
	s.Attachment = &a
	return s
}

func TestAttachmentPlanRoundTrip(t *testing.T) {
	s := attachmentSnapshot(t)
	q := Request{Kind: KindAttachmentAdd}
	p, err := Prepare(s, q, s.CapturedAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != PlanVersion4 || PlanVersionFor(KindAttachmentAdd) != PlanVersion4 || p.Request != q || p.Snapshot.Attachment == nil || *p.Snapshot.Attachment != *s.Attachment {
		t.Fatalf("plan = %#v", p)
	}
	if p.Snapshot.Attachment == s.Attachment {
		t.Fatal("plan aliases the caller's attachment")
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePlan(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if again, err := json.Marshal(decoded); err != nil || !bytes.Equal(again, raw) || decoded.SHA256 != p.SHA256 {
		t.Fatalf("round trip changed bytes: %v", err)
	}
	if sha, err := digest(decoded); err != nil || sha != p.SHA256 {
		t.Fatalf("digest = %q, %v", sha, err)
	}
	snapRaw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeSnapshot(bytes.NewReader(snapRaw)); err != nil {
		t.Fatalf("DecodeSnapshot: %v", err)
	}
	if _, err := DecodeRequest(strings.NewReader(`{"kind":"attachment.add"}`)); err != nil {
		t.Fatalf("DecodeRequest: %v", err)
	}
	for name, body := range map[string]string{
		"comment text": `{"kind":"attachment.add","comment_text":"x"}`,
		"summary":      `{"kind":"attachment.add","summary":"x"}`,
		"description":  `{"kind":"attachment.add","description":"x"}`,
	} {
		if _, err := DecodeRequest(strings.NewReader(body)); err == nil {
			t.Fatalf("%s accepted in an attachment request", name)
		}
	}
}

func TestAttachmentDigestCoversEveryMember(t *testing.T) {
	base := attachmentSnapshot(t)
	basePlan, err := Prepare(base, Request{Kind: KindAttachmentAdd}, base.CapturedAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*Attachment){
		"path": func(a *Attachment) { a.SourcePath = "/work/other.png" },
		"name": func(a *Attachment) { a.Name = "other.png" },
		"size": func(a *Attachment) { a.Size++ },
		"sha":  func(a *Attachment) { a.SHA256 = strings.Repeat("c", 64) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := basePlan
			a := *basePlan.Snapshot.Attachment
			mutate(&a)
			changed.Snapshot.Attachment = &a
			if err := ValidatePlan(changed); err == nil {
				t.Fatal("tampered attachment accepted under the old digest")
			}
			if sha, err := digest(changed); err != nil || sha == basePlan.SHA256 {
				t.Fatalf("digest unchanged: %v", err)
			}
		})
	}
}

func TestAttachmentSnapshotValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Snapshot)
	}{
		{"missing attachment", func(s *Snapshot) { s.Attachment = nil }},
		{"zero size", func(s *Snapshot) { s.Attachment.Size = 0 }},
		{"over cap", func(s *Snapshot) { s.Attachment.Size = MaxAttachmentBytes + 1 }},
		{"upper-case sha", func(s *Snapshot) { s.Attachment.SHA256 = strings.ToUpper(s.Attachment.SHA256) }},
		{"relative path", func(s *Snapshot) { s.Attachment.SourcePath = "shot.png" }},
		{"unclean path", func(s *Snapshot) { s.Attachment.SourcePath = "/work/../shot.png" }},
		{"control in path", func(s *Snapshot) { s.Attachment.SourcePath = "/work/a\nb.png" }},
		{"long path", func(s *Snapshot) { s.Attachment.SourcePath = "/" + strings.Repeat("a", MaxAttachmentPathBytes) }},
		{"invalid utf-8 path", func(s *Snapshot) { s.Attachment.SourcePath = "/work/\xff.png" }},
		{"bad name", func(s *Snapshot) { s.Attachment.Name = "../shot.png" }},
		{"unsupported type", func(s *Snapshot) { s.Attachment.ContentType = "image/svg+xml" }},
		{"mismatched extension", func(s *Snapshot) { s.Attachment.Name = "shot.pdf" }},
		{"with project", func(s *Snapshot) { s.Project = &Project{ID: "0-1", Key: "BGR"} }},
		{"with comment", func(s *Snapshot) { s.Comment = &Comment{} }},
		{"with text", func(s *Snapshot) { s.Text = &TextPrecondition{} }},
		{"without issue", func(s *Snapshot) { s.Issue = Issue{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := attachmentSnapshot(t)
			test.mutate(&s)
			if err := ValidateSnapshot(s); err == nil {
				t.Fatal("invalid attachment snapshot accepted")
			}
		})
	}
	if err := ValidateSnapshot(attachmentSnapshot(t)); err != nil {
		t.Fatal(err)
	}
}

func TestAttachmentMemberRefusedOnOtherKinds(t *testing.T) {
	for _, kind := range []Kind{KindIssueUpdate, KindCommentAdd, KindCommentDelete, KindIssueEdit, KindIssueCreate} {
		t.Run(string(kind), func(t *testing.T) {
			var s Snapshot
			switch kind {
			case KindIssueEdit:
				s = editSnapshot(t)
			case KindCommentDelete:
				s = testCommentDeleteSnapshot(t)
			case KindIssueCreate:
				s = testCreateSnapshot(t)
			default:
				s = testSnapshot(t, kind)
			}
			if err := ValidateSnapshot(s); err != nil {
				t.Fatalf("baseline snapshot invalid: %v", err)
			}
			a := attachmentFixture(t)
			s.Attachment = &a
			if err := ValidateSnapshot(s); err == nil {
				t.Fatal("attachment member accepted on another kind")
			}
		})
	}
}

func TestAttachmentPlanRefusedOutsideVersion4(t *testing.T) {
	base := attachmentSnapshot(t)
	p, err := Prepare(base, Request{Kind: KindAttachmentAdd}, base.CapturedAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []int{LegacyPlanVersion1, PlanVersion2, PlanVersion3} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			old := p
			old.Version = version
			if version == LegacyPlanVersion1 {
				old.ExpiresAt = old.CreatedAt.Add(LegacyPlanTTL)
			}
			var err error
			if old.SHA256, err = digest(old); err != nil {
				t.Fatal(err)
			}
			if err := ValidatePlan(old); err == nil {
				t.Fatalf("v%d plan with attachment.add accepted", version)
			}
		})
	}
	if err := ValidatePlan(p); err != nil {
		t.Fatalf("v4 plan refused: %v", err)
	}
}

func TestAttachmentPlanRefusesMismatchedRequest(t *testing.T) {
	s := attachmentSnapshot(t)
	if _, err := Prepare(s, Request{Kind: KindCommentAdd, CommentText: "x"}, s.CapturedAt.Add(time.Minute)); err == nil {
		t.Fatal("request kind differing from the snapshot accepted")
	}
}

func TestAttachmentSnapshotRefusesAliasedMembers(t *testing.T) {
	raw, err := json.Marshal(attachmentSnapshot(t))
	if err != nil {
		t.Fatal(err)
	}
	aliased := bytes.Replace(raw, []byte(`"attachment":`), []byte(`"Attachment":`), 1)
	duplicated := bytes.Replace(raw, []byte(`"attachment":`), []byte(`"attachment":{},"attachment":`), 1)
	for name, body := range map[string][]byte{"case variant": aliased, "duplicate": duplicated} {
		if _, err := DecodeSnapshot(bytes.NewReader(body)); err == nil {
			t.Fatalf("%s attachment member accepted", name)
		}
	}
}
