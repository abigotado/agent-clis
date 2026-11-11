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

var (
	pngBytes  = []byte("\x89PNG\r\n\x1a\n" + "body")
	webpBytes = []byte("RIFF\x10\x00\x00\x00WEBPVP8 body")
)

func TestDetectAttachmentType(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
		ok   bool
	}{
		{"png", pngBytes, "image/png", true},
		{"jpeg", []byte("\xff\xd8\xff\xe0data"), "image/jpeg", true},
		{"gif87a", []byte("GIF87adata"), "image/gif", true},
		{"gif89a", []byte("GIF89adata"), "image/gif", true},
		{"webp", webpBytes, "image/webp", true},
		{"pdf", []byte("%PDF-1.7\n"), "application/pdf", true},
		{"svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`), "", false},
		{"html", []byte("<!DOCTYPE html><html></html>"), "", false},
		{"text", []byte("hello world"), "", false},
		{"zip", []byte("PK\x03\x04data"), "", false},
		{"elf", []byte("\x7fELF\x02\x01\x01"), "", false},
		{"truncated png magic", []byte("\x89PNG\r\n\x1a"), "", false},
		{"truncated webp", []byte("RIFF\x10\x00\x00\x00WEBPV"), "", false},
		{"riff wave", []byte("RIFF\x10\x00\x00\x00WAVEfmt "), "", false},
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
