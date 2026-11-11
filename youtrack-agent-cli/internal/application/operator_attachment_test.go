package application

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"io/fs"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/auth"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/operatorwrite"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/profile"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/writepolicy"
)

const attachmentTokenSentinel = "perm:OPERATOR_ATTACHMENT_SENTINEL"

// pngBytes builds a structurally valid PNG (IHDR, a tEXt chunk carrying the distinguishing tail, IEND)
// so the strict attachment type check accepts it.
func pngBytes(tail string) []byte {
	chunk := func(kind string, data []byte) []byte {
		out := binary.BigEndian.AppendUint32(nil, uint32(len(data)))
		out = append(out, kind...)
		out = append(out, data...)
		return binary.BigEndian.AppendUint32(out, crc32.ChecksumIEEE(out[4:]))
	}
	out := []byte("\x89PNG\r\n\x1a\n")
	out = append(out, chunk("IHDR", []byte{0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0})...)
	out = append(out, chunk("tEXt", []byte(tail))...)
	return append(out, chunk("IEND", nil)...)
}

type uploadedPart struct {
	Name, ContentType, PartName string
	Content                     []byte
}

// attachmentTransport serves the attachment endpoints of the issue in front of
// the operator fixture's server and records what it saw.
type attachmentTransport struct {
	next http.RoundTripper
	mu   sync.Mutex
	// list returns the attachments listing for the nth list call (1-based).
	list func(call int) []map[string]any
	// issue, when set, replaces the issue read for the nth issue call (1-based).
	issue func(call int) string
	// postErr fails the upload at the transport; postWait blocks it until the
	// request context ends.
	postErr  error
	postWait bool
	// readBack, when set, replaces the exact read-back attachment.
	readBack map[string]any

	requests, lists, issues, posts int
	uploads                        []uploadedPart
	headers                        [][]byte
}

func (a *attachmentTransport) reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.requests, a.lists, a.issues, a.posts = 0, 0, 0, 0
	a.uploads, a.headers = nil, nil
}

func (a *attachmentTransport) counts() (requests, posts int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.requests, a.posts
}

func jsonResponse(request *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: request}
}

func attachmentJSON(id, name string, size int64, author string) map[string]any {
	return map[string]any{"id": id, "name": name, "size": size, "mimeType": "image/png", "created": 100, "removed": false,
		"author": map[string]string{"id": author, "login": "alice"}}
}

func (a *attachmentTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	a.mu.Lock()
	a.requests++
	a.mu.Unlock()
	switch {
	case request.URL.Path == "/api/issues/2-12/attachments" && request.Method == http.MethodGet:
		a.mu.Lock()
		a.lists++
		call, list := a.lists, a.list
		a.mu.Unlock()
		items := []map[string]any{}
		if list != nil {
			items = list(call)
		}
		raw, err := json.Marshal(items)
		if err != nil {
			return nil, err
		}
		return jsonResponse(request, http.StatusOK, string(raw)), nil
	case request.URL.Path == "/api/issues/2-12/attachments" && request.Method == http.MethodPost:
		return a.upload(request)
	case strings.HasPrefix(request.URL.Path, "/api/issues/2-12/attachments/"):
		a.mu.Lock()
		readBack := a.readBack
		var last *uploadedPart
		if len(a.uploads) > 0 {
			last = &a.uploads[len(a.uploads)-1]
		}
		a.mu.Unlock()
		item := readBack
		if item == nil && last != nil {
			item = attachmentJSON("5-1", last.Name, int64(len(last.Content)), "1-2")
		}
		raw, err := json.Marshal(item)
		if err != nil {
			return nil, err
		}
		return jsonResponse(request, http.StatusOK, string(raw)), nil
	case request.Method == http.MethodGet && (request.URL.Path == "/api/issues/2-12" || request.URL.Path == "/api/issues/APP-12"):
		a.mu.Lock()
		a.issues++
		call, issue := a.issues, a.issue
		a.mu.Unlock()
		if issue != nil {
			if body := issue(call); body != "" {
				return jsonResponse(request, http.StatusOK, body), nil
			}
		}
	}
	return a.next.RoundTrip(request)
}

func (a *attachmentTransport) upload(request *http.Request) (*http.Response, error) {
	a.mu.Lock()
	a.posts++
	postErr, wait := a.postErr, a.postWait
	a.mu.Unlock()
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	if err := request.Body.Close(); err != nil {
		return nil, err
	}
	if wait {
		<-request.Context().Done()
		return nil, request.Context().Err()
	}
	if postErr != nil {
		return nil, postErr
	}
	mediaType, params, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/form-data" {
		return nil, errors.New("upload is not multipart")
	}
	part, err := multipart.NewReader(bytes.NewReader(body), params["boundary"]).NextPart()
	if err != nil {
		return nil, err
	}
	content, err := io.ReadAll(part)
	if err != nil {
		return nil, err
	}
	uploaded := uploadedPart{Name: part.FileName(), ContentType: part.Header.Get("Content-Type"), PartName: part.FormName(), Content: content}
	head, _, _ := bytes.Cut(body, content)
	a.mu.Lock()
	a.uploads = append(a.uploads, uploaded)
	a.headers = append(a.headers, head)
	a.mu.Unlock()
	raw, err := json.Marshal([]map[string]any{attachmentJSON("5-1", uploaded.Name, int64(len(content)), "1-2")})
	if err != nil {
		return nil, err
	}
	return jsonResponse(request, http.StatusCreated, string(raw)), nil
}

type attachmentFixture struct {
	*operatorFixture
	transport *attachmentTransport
	files     string
}

// newAttachmentFixture has attachment-add enabled and a transport in front of
// the fake YouTrack server.
func newAttachmentFixture(t *testing.T) *attachmentFixture {
	t.Helper()
	f := newOperatorFixture(t)
	selected, err := f.service.Profiles.Get(t.Context(), "work")
	if err != nil {
		t.Fatal(err)
	}
	selected.Capabilities = append(selected.Capabilities, profile.CapabilityAttachmentAdd)
	if err := f.service.Profiles.Put(t.Context(), selected); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Policies.Set(t.Context(), selected, []writepolicy.Project{{ID: "0-3", Key: "APP"}}); err != nil {
		t.Fatal(err)
	}
	credential, err := auth.BindCredential(auth.Credential{Kind: auth.CredentialPermanentToken, PermanentToken: attachmentTokenSentinel}, selected)
	if err != nil {
		t.Fatal(err)
	}
	f.service.Credentials = &fixedCredentials{value: credential}
	transport := &attachmentTransport{next: f.service.HTTP}
	f.service.HTTP = transport
	return &attachmentFixture{operatorFixture: f, transport: transport, files: t.TempDir()}
}

func (f *attachmentFixture) write(t *testing.T, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(f.files, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func (f *attachmentFixture) snapshot(path, name string) (OperatorWriteInfo, error) {
	return f.service.SnapshotOperatorWrite(context.Background(), OperatorSnapshotInput{Profile: "work", Kind: "attachment.add", IssueID: "APP-12", FilePath: path, AttachmentName: name})
}

func (f *attachmentFixture) prepared(t *testing.T, path, name string) OperatorWriteInfo {
	t.Helper()
	snapshot, err := f.snapshot(path, name)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(snapshot.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := f.service.PrepareOperatorWrite(t.Context(), OperatorPrepareInput{Profile: "work", SnapshotJSON: raw, RequestJSON: []byte(`{"kind":"attachment.add"}`)})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

// trapped swaps in credential and network traps and returns a restore func.
func (f *attachmentFixture) trapped() (*trapCredentials, *trapTransport, func()) {
	credentials, network := &trapCredentials{}, &trapTransport{}
	savedCredentials, savedHTTP := f.service.Credentials, f.service.HTTP
	f.service.Credentials, f.service.HTTP = credentials, network
	return credentials, network, func() { f.service.Credentials, f.service.HTTP = savedCredentials, savedHTTP }
}

func requireNoSentinel(t *testing.T, values ...any) {
	t.Helper()
	for _, value := range values {
		var text string
		switch typed := value.(type) {
		case error:
			if typed != nil {
				text = typed.Error()
			}
		default:
			raw, err := json.Marshal(typed)
			if err != nil {
				t.Fatal(err)
			}
			text = string(raw)
		}
		if strings.Contains(text, "OPERATOR_ATTACHMENT_SENTINEL") {
			t.Fatalf("token sentinel leaked: %s", text)
		}
	}
}

func TestAttachmentSnapshotRefusalsPrecedeCredentialsAndNetwork(t *testing.T) {
	big := append(pngBytes(""), make([]byte, operatorwrite.MaxAttachmentBytes)...)
	tests := []struct {
		name   string
		setup  func(t *testing.T, f *attachmentFixture) (path, attachmentName string)
		reason string
	}{
		{"unsupported type", func(t *testing.T, f *attachmentFixture) (string, string) {
			return f.write(t, "note.png", []byte("just text")), ""
		}, "OPERATOR_ATTACHMENT_TYPE_UNSUPPORTED"},
		{"too large", func(t *testing.T, f *attachmentFixture) (string, string) { return f.write(t, "big.png", big), "" }, "OPERATOR_ATTACHMENT_TOO_LARGE"},
		{"empty", func(t *testing.T, f *attachmentFixture) (string, string) { return f.write(t, "empty.png", nil), "" }, ""},
		{"bad name", func(t *testing.T, f *attachmentFixture) (string, string) {
			return f.write(t, "a.png", pngBytes("x")), "dir/a.png"
		}, "OPERATOR_ATTACHMENT_NAME_INVALID"},
		{"extension mismatch", func(t *testing.T, f *attachmentFixture) (string, string) {
			return f.write(t, "a.png", pngBytes("x")), "a.pdf"
		}, "OPERATOR_ATTACHMENT_TYPE_UNSUPPORTED"},
		{"symlink", func(t *testing.T, f *attachmentFixture) (string, string) {
			target := f.write(t, "real.png", pngBytes("x"))
			link := filepath.Join(f.files, "link.png")
			if err := os.Symlink(target, link); err != nil {
				t.Skip("symlinks unavailable")
			}
			return link, ""
		}, "OPERATOR_ATTACHMENT_SOURCE_INVALID"},
		{"directory", func(t *testing.T, f *attachmentFixture) (string, string) { return f.files, "" }, "OPERATOR_ATTACHMENT_SOURCE_INVALID"},
		{"missing", func(t *testing.T, f *attachmentFixture) (string, string) {
			return filepath.Join(f.files, "missing.png"), ""
		}, "OPERATOR_ATTACHMENT_SOURCE_INVALID"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newAttachmentFixture(t)
			path, name := test.setup(t, f)
			credentials, network, _ := f.trapped()
			_, err := f.snapshot(path, name)
			if err == nil || errx.ExitCode(err) != errx.CodeUsage {
				t.Fatalf("error=%v", err)
			}
			if test.reason != "" && operatorReason(t, err) != test.reason {
				t.Fatalf("reason=%q want %q", operatorReason(t, err), test.reason)
			}
			if credentials.calls != 0 || network.calls != 0 {
				t.Fatalf("credentials=%d network=%d", credentials.calls, network.calls)
			}
			if strings.Contains(err.Error(), f.files) {
				t.Fatalf("source path leaked into the error: %v", err)
			}
		})
	}
}

func TestAttachmentSnapshotRequiresCapabilityAndExactSelectors(t *testing.T) {
	t.Run("capability", func(t *testing.T) {
		f := newOperatorFixture(t)
		path := filepath.Join(t.TempDir(), "a.png")
		if err := os.WriteFile(path, pngBytes("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := f.service.SnapshotOperatorWrite(t.Context(), OperatorSnapshotInput{Profile: "work", Kind: "attachment.add", IssueID: "APP-12", FilePath: path})
		requireRefusal(t, err, "OPERATOR_CAPABILITY_REQUIRED", errx.CodePermission)
	})
	selectors := []struct {
		name  string
		input OperatorSnapshotInput
	}{
		{"no file", OperatorSnapshotInput{Kind: "attachment.add", IssueID: "APP-12"}},
		{"no issue", OperatorSnapshotInput{Kind: "attachment.add", FilePath: "x.png"}},
		{"project", OperatorSnapshotInput{Kind: "attachment.add", IssueID: "APP-12", FilePath: "x.png", ProjectID: "APP"}},
		{"comment", OperatorSnapshotInput{Kind: "attachment.add", IssueID: "APP-12", FilePath: "x.png", CommentID: "4-1"}},
		{"fields", OperatorSnapshotInput{Kind: "attachment.add", IssueID: "APP-12", FilePath: "x.png", Fields: []OperatorFieldSelection{{FieldID: "92-1", ValueID: "101-2"}}}},
		{"file on comment.add", OperatorSnapshotInput{Kind: "comment.add", IssueID: "APP-12", FilePath: "x.png"}},
		{"name on issue.update", OperatorSnapshotInput{Kind: "issue.update", IssueID: "APP-12", AttachmentName: "x.png", Fields: []OperatorFieldSelection{{FieldID: "92-1", ValueID: "101-2"}}}},
	}
	for _, test := range selectors {
		t.Run(test.name, func(t *testing.T) {
			f := newAttachmentFixture(t)
			credentials, network, _ := f.trapped()
			input := test.input
			input.Profile = "work"
			_, err := f.service.SnapshotOperatorWrite(t.Context(), input)
			requireRefusal(t, err, "USAGE", errx.CodeUsage)
			if credentials.calls != 0 || network.calls != 0 {
				t.Fatalf("credentials=%d network=%d", credentials.calls, network.calls)
			}
		})
	}
}

func TestAttachmentSnapshotFreezesAbsoluteFileAndChecksNames(t *testing.T) {
	t.Run("freezes absolute path and default name", func(t *testing.T) {
		f := newAttachmentFixture(t)
		content := pngBytes("freeze")
		f.write(t, "shot.png", content)
		t.Chdir(f.files)
		info, err := f.snapshot("shot.png", "")
		if err != nil {
			t.Fatal(err)
		}
		frozen := info.Snapshot.Attachment
		resolved, err := filepath.EvalSymlinks(f.files)
		if err != nil {
			t.Fatal(err)
		}
		if frozen == nil || !filepath.IsAbs(frozen.SourcePath) || filepath.Base(frozen.SourcePath) != "shot.png" || frozen.Name != "shot.png" ||
			frozen.Size != int64(len(content)) || frozen.ContentType != "image/png" || info.Attachment == nil || info.PlanVersion != operatorwrite.PlanVersion4 {
			t.Fatalf("snapshot=%#v resolved=%s", frozen, resolved)
		}
	})
	t.Run("explicit name", func(t *testing.T) {
		f := newAttachmentFixture(t)
		path := f.write(t, "shot.png", pngBytes("n"))
		info, err := f.snapshot(path, "renamed.png")
		if err != nil || info.Snapshot.Attachment.Name != "renamed.png" {
			t.Fatalf("info=%#v err=%v", info.Snapshot, err)
		}
	})
	t.Run("same name exists", func(t *testing.T) {
		f := newAttachmentFixture(t)
		path := f.write(t, "shot.png", pngBytes("n"))
		f.transport.list = func(int) []map[string]any { return []map[string]any{attachmentJSON("5-9", "shot.png", 3, "1-2")} }
		_, err := f.snapshot(path, "")
		requireRefusal(t, err, "OPERATOR_ATTACHMENT_NAME_EXISTS", errx.CodeUsage)
		var typed *errx.Error
		if !errors.As(err, &typed) || !strings.Contains(typed.Hint, "--name") {
			t.Fatalf("hint=%v", err)
		}
		if _, err := f.snapshot(path, "other.png"); err != nil {
			t.Fatalf("different name refused: %v", err)
		}
	})
	t.Run("more than one page is truncated", func(t *testing.T) {
		f := newAttachmentFixture(t)
		path := f.write(t, "shot.png", pngBytes("n"))
		f.transport.list = func(int) []map[string]any {
			items := make([]map[string]any, 101)
			for i := range items {
				items[i] = attachmentJSON("5-"+string(rune('a'+i%26))+string(rune('a'+i/26)), "f"+string(rune('a'+i%26))+string(rune('a'+i/26))+".png", 1, "1-2")
			}
			return items
		}
		_, err := f.snapshot(path, "")
		requireRefusal(t, err, "OPERATOR_ATTACHMENTS_TRUNCATED", errx.CodeConflict)
	})
}

func TestAttachmentPrepareIsOfflineAndNeverOpensTheFile(t *testing.T) {
	f := newAttachmentFixture(t)
	path := f.write(t, "shot.png", pngBytes("offline"))
	snapshot, err := f.snapshot(path, "")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(snapshot.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	credentials, network, _ := f.trapped()
	for _, dryRun := range []bool{true, false} {
		plan, err := f.service.PrepareOperatorWrite(t.Context(), OperatorPrepareInput{Profile: "work", SnapshotJSON: raw, RequestJSON: []byte(`{"kind":"attachment.add"}`), DryRun: dryRun})
		if err != nil || plan.Attachment == nil || plan.PlanVersion != operatorwrite.PlanVersion4 || plan.Plan.Snapshot.Attachment == nil {
			t.Fatalf("dryRun=%v plan=%#v err=%v", dryRun, plan, err)
		}
	}
	if credentials.calls != 0 || network.calls != 0 {
		t.Fatalf("offline prepare touched credentials=%d network=%d", credentials.calls, network.calls)
	}
}

func TestAttachmentApplyUploadsExactBytesOnce(t *testing.T) {
	f := newAttachmentFixture(t)
	content := pngBytes("exact bytes \r\n with binary \x00\xff")
	path := f.write(t, "shot.png", content)
	plan := f.prepared(t, path, "")
	f.transport.reset()
	applied, err := f.apply(t, plan)
	if err != nil || applied.State != string(operatorwrite.StateApplied) || applied.RemoteID != "5-1" || !applied.NonReplayable {
		t.Fatalf("apply=%#v err=%v", applied, err)
	}
	if len(f.transport.uploads) != 1 || f.transport.posts != 1 {
		t.Fatalf("uploads=%d posts=%d", len(f.transport.uploads), f.transport.posts)
	}
	upload := f.transport.uploads[0]
	if !bytes.Equal(upload.Content, content) || upload.Name != "shot.png" || upload.ContentType != "image/png" || upload.PartName != "upload" {
		t.Fatalf("upload=%#v", upload)
	}
	if bytes.ContainsAny(bytes.ReplaceAll(f.transport.headers[0], []byte("\r\n"), nil), "\r\n") {
		t.Fatalf("stray CR or LF in multipart headers: %q", f.transport.headers[0])
	}
	before, _ := f.transport.counts()
	if _, err := f.apply(t, plan); operatorReason(t, err) != "OPERATOR_PLAN_CONSUMED" {
		t.Fatalf("replay=%v", err)
	}
	if after, posts := f.transport.counts(); after != before || posts != 1 {
		t.Fatalf("replay used the network: %d -> %d posts=%d", before, after, posts)
	}
	status, err := f.service.OperatorWriteStatus(t.Context(), plan.PlanID)
	if err != nil || status.State != "applied" || status.RemoteID != "5-1" {
		t.Fatalf("status=%#v err=%v", status, err)
	}
	requireNoSentinel(t, applied, status, plan)
	err = filepath.WalkDir(f.dir, func(p string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		raw, readErr := os.ReadFile(p)
		if readErr == nil && bytes.Contains(raw, []byte("OPERATOR_ATTACHMENT_SENTINEL")) {
			t.Errorf("token sentinel stored in %s", p)
		}
		return readErr
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAttachmentApplyWrongDigestRefusesBeforeReadingTheFile(t *testing.T) {
	f := newAttachmentFixture(t)
	path := f.write(t, "shot.png", pngBytes("x"))
	plan := f.prepared(t, path, "")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	_, _, _ = f.trapped()
	_, err := f.service.ApplyOperatorWrite(t.Context(), OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: strings.Repeat("a", 64), Yes: true})
	requireRefusal(t, err, "OPERATOR_CONFIRMATION_REQUIRED", errx.CodeConfirm)
}

func TestAttachmentApplySourceDriftRefusesBeforeAnyRequestAndKeepsPlan(t *testing.T) {
	original := pngBytes("original")
	tests := []struct {
		name   string
		mutate func(t *testing.T, path string)
	}{
		{"modified", func(t *testing.T, path string) {
			if err := os.WriteFile(path, pngBytes("tampered"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"same size different bytes", func(t *testing.T, path string) {
			if err := os.WriteFile(path, pngBytes("originaL"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"deleted", func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}},
		{"replaced by symlink", func(t *testing.T, path string) {
			other := filepath.Join(filepath.Dir(path), "other.png")
			if err := os.WriteFile(other, original, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(other, path); err != nil {
				t.Skip("symlinks unavailable")
			}
		}},
		{"no longer an accepted type", func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("<svg/>"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newAttachmentFixture(t)
			path := f.write(t, "shot.png", original)
			plan := f.prepared(t, path, "")
			test.mutate(t, path)
			credentials, network, restore := f.trapped()
			_, err := f.apply(t, plan)
			requireRefusal(t, err, "OPERATOR_ATTACHMENT_SOURCE_STALE", errx.CodeConflict)
			if credentials.calls != 0 || network.calls != 0 || strings.Contains(err.Error(), f.files) {
				t.Fatalf("credentials=%d network=%d err=%v", credentials.calls, network.calls, err)
			}
			record, getErr := f.service.OperatorWrites.Get(t.Context(), plan.PlanID)
			if getErr != nil || record.NonReplayable() || record.State != operatorwrite.StatePrepared {
				t.Fatalf("plan was consumed: %#v %v", record, getErr)
			}
			restore()
			if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}
			applied, err := f.apply(t, plan)
			if err != nil || applied.State != string(operatorwrite.StateApplied) || f.transport.posts != 1 {
				t.Fatalf("re-apply=%#v err=%v posts=%d", applied, err, f.transport.posts)
			}
			if !bytes.Equal(f.transport.uploads[0].Content, original) {
				t.Fatalf("uploaded %q", f.transport.uploads[0].Content)
			}
		})
	}
}

func TestAttachmentApplyRemoteDriftStopsBeforePost(t *testing.T) {
	updated := editIssue("Example", strPtr("body"), 3)
	existing := func(int) []map[string]any { return []map[string]any{attachmentJSON("5-9", "shot.png", 3, "1-2")} }
	tests := []struct {
		name   string
		setup  func(f *attachmentFixture)
		reason string
	}{
		{"issue updated before apply", func(f *attachmentFixture) { f.setIssue(updated) }, "OPERATOR_ISSUE_STALE"},
		{"issue updated inside the lock", func(f *attachmentFixture) {
			f.transport.issue = func(call int) string {
				if call >= 2 {
					return updated
				}
				return ""
			}
		}, "OPERATOR_ISSUE_STALE"},
		{"same name appeared before apply", func(f *attachmentFixture) { f.transport.list = existing }, "OPERATOR_ATTACHMENT_STALE"},
		{"same name appeared inside the lock", func(f *attachmentFixture) {
			f.transport.list = func(call int) []map[string]any {
				if call >= 2 {
					return existing(call)
				}
				return []map[string]any{}
			}
		}, "OPERATOR_ATTACHMENT_STALE"},
		{"attachments truncated inside the lock", func(f *attachmentFixture) {
			f.transport.list = func(call int) []map[string]any {
				if call < 2 {
					return []map[string]any{}
				}
				items := make([]map[string]any, 101)
				for i := range items {
					items[i] = attachmentJSON("5-x", "n"+string(rune('a'+i%26))+string(rune('a'+i/26))+".png", 1, "1-2")
				}
				return items
			}
		}, "OPERATOR_ATTACHMENTS_TRUNCATED"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newAttachmentFixture(t)
			path := f.write(t, "shot.png", pngBytes("drift"))
			plan := f.prepared(t, path, "")
			f.transport.reset()
			test.setup(f)
			_, err := f.apply(t, plan)
			requireRefusal(t, err, test.reason, errx.CodeConflict)
			if _, posts := f.transport.counts(); posts != 0 {
				t.Fatalf("posts=%d", posts)
			}
			record, getErr := f.service.OperatorWrites.Get(t.Context(), plan.PlanID)
			if getErr != nil || record.NonReplayable() {
				t.Fatalf("plan consumed: %#v %v", record, getErr)
			}
		})
	}
}

func TestAttachmentConcurrentApplyUsesOnePost(t *testing.T) {
	f := newAttachmentFixture(t)
	plan := f.prepared(t, f.write(t, "shot.png", pngBytes("race")), "")
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := f.apply(t, plan); errs <- err }()
	}
	wg.Wait()
	close(errs)
	successes := 0
	for err := range errs {
		if err == nil {
			successes++
		}
	}
	if _, posts := f.transport.counts(); successes != 1 || posts != 1 {
		t.Fatalf("successes=%d posts=%d", successes, posts)
	}
}

func TestAttachmentUnknownOutcomeIsConsumedAndNeverReplayed(t *testing.T) {
	tests := []struct {
		name         string
		setup        func(f *attachmentFixture)
		ctxTimeout   time.Duration
		wantRemoteID string
	}{
		{"transport loss after claim", func(f *attachmentFixture) { f.transport.postErr = errors.New("connection reset by peer") }, 0, ""},
		{"deadline during upload", func(f *attachmentFixture) { f.transport.postWait = true }, time.Second, ""},
		{"read-back size mismatch", func(f *attachmentFixture) {
			f.transport.readBack = attachmentJSON("5-1", "shot.png", 1, "1-2")
		}, 0, "5-1"},
		{"read-back by another author", func(f *attachmentFixture) {
			f.transport.readBack = attachmentJSON("5-1", "shot.png", int64(len(pngBytes("lost"))), "9-9")
		}, 0, "5-1"},
		{"read-back removed", func(f *attachmentFixture) {
			item := attachmentJSON("5-1", "shot.png", int64(len(pngBytes("lost"))), "1-2")
			item["removed"] = true
			f.transport.readBack = item
		}, 0, "5-1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newAttachmentFixture(t)
			plan := f.prepared(t, f.write(t, "shot.png", pngBytes("lost")), "")
			test.setup(f)
			ctx := t.Context()
			if test.ctxTimeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, test.ctxTimeout)
				defer cancel()
			}
			input := OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: plan.IntentSHA256, Yes: true}
			info, err := f.service.ApplyOperatorWrite(ctx, input)
			if operatorReason(t, err) != "WRITE_OUTCOME_UNKNOWN" {
				t.Fatalf("error=%v", err)
			}
			status, statusErr := f.service.OperatorWriteStatus(t.Context(), plan.PlanID)
			if statusErr != nil || status.State != string(operatorwrite.StateUnknown) || !status.NonReplayable || status.RemoteID != test.wantRemoteID || info.RemoteID != test.wantRemoteID {
				t.Fatalf("status=%#v info.remote=%q err=%v", status, info.RemoteID, statusErr)
			}
			before, posts := f.transport.counts()
			if _, err := f.service.ApplyOperatorWrite(t.Context(), input); operatorReason(t, err) != "OPERATOR_PLAN_CONSUMED" {
				t.Fatalf("second apply=%v", err)
			}
			if after, postsAfter := f.transport.counts(); after != before || postsAfter != posts || posts != 1 {
				t.Fatalf("second apply used the network: %d -> %d, posts %d -> %d", before, after, posts, postsAfter)
			}
			requireNoSentinel(t, err, info, status)
		})
	}
}

func TestCapabilitiesListAttachmentAddWithPlanVersion(t *testing.T) {
	f := newAttachmentFixture(t)
	info, err := f.service.Capabilities(t.Context(), "work")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, kind := range info.Kinds {
		found = found || kind == "attachment.add"
	}
	if !found || info.PlanVersions["attachment.add"] != 4 || info.PlanVersion != 4 {
		t.Fatalf("capabilities=%#v", info)
	}
	plain := newOperatorFixture(t)
	info, err = plain.service.Capabilities(t.Context(), "work")
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range info.Kinds {
		if kind == "attachment.add" {
			t.Fatalf("profile without attachment-add lists it: %v", info.Kinds)
		}
	}
	if info.PlanVersions["attachment.add"] != 4 {
		t.Fatalf("plan_versions=%v", info.PlanVersions)
	}
}
