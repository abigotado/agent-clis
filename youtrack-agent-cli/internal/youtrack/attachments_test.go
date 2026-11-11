package youtrack

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
)

var attachmentBytes = validPNG(bytes.Repeat([]byte{0x01, 0x00, '\r', '\n'}, 64))

// validPNG builds a structurally valid PNG (IHDR, a tEXt chunk carrying tail, IEND)
// so the strict attachment type check accepts it.
func validPNG(tail []byte) []byte {
	chunk := func(kind string, data []byte) []byte {
		out := binary.BigEndian.AppendUint32(nil, uint32(len(data)))
		out = append(out, kind...)
		out = append(out, data...)
		return binary.BigEndian.AppendUint32(out, crc32.ChecksumIEEE(out[4:]))
	}
	out := []byte("\x89PNG\r\n\x1a\n")
	out = append(out, chunk("IHDR", []byte{0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0})...)
	out = append(out, chunk("tEXt", tail)...)
	return append(out, chunk("IEND", nil)...)
}

const attachmentOKJSON = `[{"id":"8-5","name":"shot.png","size":%d,"mimeType":"image/png","created":1700000000000,"removed":false,"author":{"id":"1-2","login":"alice"}}]`

func attachmentResponseJSON(mutate func(string) string) string {
	body := strings.Replace(attachmentOKJSON, "%d", strconv.Itoa(len(attachmentBytes)), 1)
	if mutate != nil {
		mutated := mutate(body)
		if mutated == body {
			panic("mutation did not apply")
		}
		return mutated
	}
	return body
}

func validAddAttachmentInput() AddAttachmentInput {
	sum := sha256.Sum256(attachmentBytes)
	return AddAttachmentInput{
		IssueID: "2-12", ProjectID: "0-3", ProjectKey: "APP", Name: "shot.png", ContentType: "image/png",
		Content: attachmentBytes, ExpectedSHA256: hex.EncodeToString(sum[:]),
		ExpectedAuthorID: "1-2", ExpectedAuthorLogin: "alice",
	}
}

func TestAddAttachmentSendsOneExactMultipartRequest(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusCreated} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				calls.Add(1)
				if request.Method != http.MethodPost || request.URL.Path != "/youtrack/api/issues/2-12/attachments" ||
					request.URL.Query().Get("fields") != "id,name,size,mimeType,created,removed,author(id,login)" {
					t.Errorf("request=%s %s", request.Method, request.URL)
				}
				if request.Header.Get("Authorization") != "Bearer "+testToken {
					t.Error("authorization header missing")
				}
				mediaType, params, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
				if err != nil || mediaType != "multipart/form-data" || params["boundary"] == "" {
					t.Errorf("content type=%q err=%v", request.Header.Get("Content-Type"), err)
				}
				raw, err := io.ReadAll(request.Body)
				if err != nil {
					t.Error(err)
				}
				if request.ContentLength != int64(len(raw)) {
					t.Errorf("content length=%d body=%d", request.ContentLength, len(raw))
				}
				reader := multipart.NewReader(bytes.NewReader(raw), params["boundary"])
				part, err := reader.NextPart()
				if err != nil {
					t.Fatal(err)
				}
				if part.FormName() != "upload" || part.FileName() != "shot.png" || part.Header.Get("Content-Type") != "image/png" {
					t.Errorf("part=%q file=%q type=%q", part.FormName(), part.FileName(), part.Header.Get("Content-Type"))
				}
				if want := `form-data; name="upload"; filename="shot.png"`; part.Header.Get("Content-Disposition") != want {
					t.Errorf("disposition=%q", part.Header.Get("Content-Disposition"))
				}
				content, _ := io.ReadAll(part)
				if !bytes.Equal(content, attachmentBytes) {
					t.Error("part bytes differ")
				}
				if len(part.Header) != 2 {
					t.Errorf("unexpected part headers: %v", part.Header)
				}
				if _, err := reader.NextPart(); err != io.EOF {
					t.Errorf("second part err=%v", err)
				}
				writer.WriteHeader(status)
				_, _ = io.WriteString(writer, attachmentResponseJSON(nil))
			}))
			defer server.Close()
			attachment, err := newTestClient(t, server).AddAttachment(context.Background(), validAddAttachmentInput())
			if err != nil || attachment.ID != "8-5" || attachment.Name != "shot.png" || attachment.Size != int64(len(attachmentBytes)) || calls.Load() != 1 {
				t.Fatalf("attachment=%#v err=%v calls=%d", attachment, err, calls.Load())
			}
		})
	}
}

func TestAddAttachmentMultipartHeaderHasNoLineInjection(t *testing.T) {
	var captured []byte
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		captured, _ = io.ReadAll(request.Body)
		_, _ = io.WriteString(writer, attachmentResponseJSON(nil))
	}))
	defer server.Close()
	if _, err := newTestClient(t, server).AddAttachment(context.Background(), validAddAttachmentInput()); err != nil {
		t.Fatal(err)
	}
	headerEnd := bytes.Index(captured, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		t.Fatal("no header terminator")
	}
	lines := strings.Split(string(captured[:headerEnd]), "\r\n")
	// boundary line, Content-Disposition, Content-Type: nothing else.
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "--") || !strings.HasPrefix(lines[1], "Content-Disposition: ") ||
		!strings.HasPrefix(lines[2], "Content-Type: ") || strings.ContainsAny(strings.Join(lines, ""), "\n") {
		t.Fatalf("part header lines=%q", lines)
	}
}

func TestAddAttachmentUnverifiedResponseIsUnknown(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		gzip     bool
		wantID   string
		skipBody bool
	}{
		{name: "wrong name", body: attachmentResponseJSON(func(s string) string { return strings.Replace(s, `"shot.png"`, `"other.png"`, 1) }), wantID: "8-5"},
		{name: "wrong size", body: attachmentResponseJSON(func(s string) string { return strings.Replace(s, `"size":`, `"size":1`, 1) }), wantID: "8-5"},
		{name: "wrong author id", body: attachmentResponseJSON(func(s string) string { return strings.Replace(s, `"id":"1-2"`, `"id":"1-9"`, 1) }), wantID: "8-5"},
		{name: "wrong author login", body: attachmentResponseJSON(func(s string) string { return strings.Replace(s, `"alice"`, `"mallory"`, 1) }), wantID: "8-5"},
		{name: "missing author", body: attachmentResponseJSON(func(s string) string {
			return strings.Replace(s, `,"author":{"id":"1-2","login":"alice"}`, ``, 1)
		}), wantID: "8-5"},
		{name: "mime conflict", body: attachmentResponseJSON(func(s string) string {
			return strings.Replace(s, `"mimeType":"image/png"`, `"mimeType":"text/html"`, 1)
		}), wantID: "8-5"},
		{name: "malformed mime", body: attachmentResponseJSON(func(s string) string {
			return strings.Replace(s, `"mimeType":"image/png"`, `"mimeType":"; charset=binary"`, 1)
		}), wantID: "8-5"},
		{name: "removed", body: attachmentResponseJSON(func(s string) string { return strings.Replace(s, `"removed":false`, `"removed":true`, 1) }), wantID: "8-5"},
		{name: "missing removed", body: attachmentResponseJSON(func(s string) string { return strings.Replace(s, `"removed":false,`, ``, 1) }), wantID: "8-5"},
		{name: "null removed", body: attachmentResponseJSON(func(s string) string { return strings.Replace(s, `"removed":false`, `"removed":null`, 1) }), wantID: "8-5"},
		{name: "missing size", body: attachmentResponseJSON(func(s string) string {
			return strings.Replace(s, `"size":`+strconv.Itoa(len(attachmentBytes))+`,`, ``, 1)
		}), wantID: "8-5"},
		{name: "object instead of array", body: strings.Trim(attachmentResponseJSON(nil), "[]"), wantID: "8-5"},
		{name: "two elements", body: strings.Replace(attachmentResponseJSON(nil), "]", ","+strings.Trim(attachmentResponseJSON(nil), "[]")+"]", 1)},
		{name: "empty array", body: `[]`},
		{name: "malformed id", body: attachmentResponseJSON(func(s string) string { return strings.Replace(s, `"8-5"`, `"8 5"`, 1) })},
		{name: "non-JSON", body: "UPSTREAM_SENTINEL " + testToken},
		{name: "empty body", body: ""},
		{name: "oversize", body: strings.Repeat("x", maxResponseBodyBytes+1)},
		{name: "gzip oversize", body: strings.Repeat("x", maxResponseBodyBytes+1), gzip: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				if test.gzip {
					writer.Header().Set("Content-Encoding", "gzip")
					zipper := gzip.NewWriter(writer)
					_, _ = io.WriteString(zipper, test.body)
					_ = zipper.Close()
					return
				}
				_, _ = io.WriteString(writer, test.body)
			}))
			defer server.Close()
			attachment, err := newTestClient(t, server).AddAttachment(context.Background(), validAddAttachmentInput())
			assertError(t, err, errx.CodeConflict, "WRITE_OUTCOME_UNKNOWN")
			if calls.Load() != 1 || attachment.ID != test.wantID {
				t.Fatalf("calls=%d id=%q want %q", calls.Load(), attachment.ID, test.wantID)
			}
			if strings.Contains(err.Error(), "SENTINEL") || strings.Contains(err.Error(), testToken) {
				t.Fatalf("error leaks upstream text: %v", err)
			}
		})
	}
}

func TestAddAttachmentHTTPFailuresAreOneShot(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		wantCode   errx.Code
		wantReason string
	}{
		{"bad request", 400, errx.CodeUsage, "USAGE"},
		{"unauthorized", 401, errx.CodeAuth, "AUTHENTICATION_FAILED"},
		{"forbidden", 403, errx.CodePermission, "PERMISSION_DENIED"},
		{"not found", 404, errx.CodeConflict, "TARGET_CHANGED"},
		{"conflict", 409, errx.CodeConflict, "PRECONDITION_FAILED"},
		{"too large", 413, errx.CodeUsage, "PAYLOAD_TOO_LARGE"},
		{"rate limited", 429, errx.CodeConflict, "WRITE_OUTCOME_UNKNOWN"},
		{"server error", 500, errx.CodeConflict, "WRITE_OUTCOME_UNKNOWN"},
		{"bad gateway", 502, errx.CodeConflict, "WRITE_OUTCOME_UNKNOWN"},
		{"accepted", 202, errx.CodeConflict, "WRITE_OUTCOME_UNKNOWN"},
		{"no content", 204, errx.CodeConflict, "WRITE_OUTCOME_UNKNOWN"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				writer.WriteHeader(test.status)
				if test.status != 204 {
					_, _ = io.WriteString(writer, attachmentResponseJSON(nil)+" UPSTREAM_SENTINEL "+testToken)
				}
			}))
			defer server.Close()
			attachment, err := newTestClient(t, server).AddAttachment(context.Background(), validAddAttachmentInput())
			assertError(t, err, test.wantCode, test.wantReason)
			if calls.Load() != 1 || attachment.ID != "" || strings.Contains(err.Error(), "SENTINEL") ||
				strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), server.URL) {
				t.Fatalf("calls=%d attachment=%#v err=%v", calls.Load(), attachment, err)
			}
		})
	}
}

func TestAddAttachmentRefusesRedirectsWithoutFollowing(t *testing.T) {
	for _, status := range []int{301, 302, 307, 308} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			var posts, hits atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/elsewhere" {
					hits.Add(1)
					return
				}
				posts.Add(1)
				writer.Header().Set("Location", "/elsewhere")
				writer.WriteHeader(status)
			}))
			defer server.Close()
			_, err := newTestClient(t, server).AddAttachment(context.Background(), validAddAttachmentInput())
			assertError(t, err, errx.CodeConflict, "WRITE_OUTCOME_UNKNOWN")
			if posts.Load() != 1 || hits.Load() != 0 {
				t.Fatalf("posts=%d redirect hits=%d", posts.Load(), hits.Load())
			}
		})
	}
}

func TestAddAttachmentTransportDropIsUnknownAndNotReplayed(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, request.Body)
		connection, _, err := writer.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = connection.Close() // simulate a dropped connection after the body was sent
	}))
	defer server.Close()
	attachment, err := newTestClient(t, server).AddAttachment(context.Background(), validAddAttachmentInput())
	assertError(t, err, errx.CodeConflict, "WRITE_OUTCOME_UNKNOWN")
	if calls.Load() != 1 || attachment.ID != "" {
		t.Fatalf("calls=%d attachment=%#v", calls.Load(), attachment)
	}
}

func TestAddAttachmentTransportIsNonReplayableAndRedacted(t *testing.T) {
	transport := &commentFailureTransport{}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	client, err := New(Config{RESTBaseURL: "https://tracker.example.test/api"}, Credential{Token: testToken},
		WithHTTPClient(&http.Client{Transport: transport}), WithLogger(logger))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.AddAttachment(context.Background(), validAddAttachmentInput())
	assertError(t, err, errx.CodeConflict, "WRITE_OUTCOME_UNKNOWN")
	if transport.calls.Load() != 1 || transport.replayable.Load() {
		t.Fatalf("calls=%d replayable=%v", transport.calls.Load(), transport.replayable.Load())
	}
	for _, text := range []string{err.Error(), logs.String()} {
		if strings.Contains(text, "SENTINEL") || strings.Contains(text, testToken) || strings.Contains(text, "shot.png") {
			t.Fatalf("leak in %q", text)
		}
	}
	if !strings.Contains(logs.String(), "attachment.add") {
		t.Fatalf("expected operation log, got %q", logs.String())
	}
}

func TestAddAttachmentContextDeadlineIsUnknown(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		select {
		case <-release:
		case <-request.Context().Done():
		}
	}))
	defer server.Close()
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := newTestClient(t, server).AddAttachment(ctx, validAddAttachmentInput())
	assertError(t, err, errx.CodeConflict, "WRITE_OUTCOME_UNKNOWN")
}

func TestValidateAddAttachmentInputRefusesBeforeNetwork(t *testing.T) {
	big := bytes.Repeat([]byte{'a'}, maxAttachmentBytes+1)
	bigSum := sha256.Sum256(big)
	emptySum := sha256.Sum256(nil)
	tests := []struct {
		name   string
		change func(*AddAttachmentInput)
	}{
		{"sha mismatch", func(i *AddAttachmentInput) { i.ExpectedSHA256 = strings.Repeat("0", 64) }},
		{"sha uppercase", func(i *AddAttachmentInput) { i.ExpectedSHA256 = strings.ToUpper(i.ExpectedSHA256) }},
		{"sha short", func(i *AddAttachmentInput) { i.ExpectedSHA256 = "abc" }},
		{"empty content", func(i *AddAttachmentInput) { i.Content, i.ExpectedSHA256 = nil, hex.EncodeToString(emptySum[:]) }},
		{"over cap", func(i *AddAttachmentInput) { i.Content, i.ExpectedSHA256 = big, hex.EncodeToString(bigSum[:]) }},
		{"svg type", func(i *AddAttachmentInput) { i.ContentType = "image/svg+xml" }},
		{"html type", func(i *AddAttachmentInput) { i.ContentType = "text/html" }},
		{"type with parameter", func(i *AddAttachmentInput) { i.ContentType = "image/png; charset=x" }},
		{"type with newline", func(i *AddAttachmentInput) { i.ContentType = "image/png\r\nX: y" }},
		{"empty type", func(i *AddAttachmentInput) { i.ContentType = "" }},
		{"empty name", func(i *AddAttachmentInput) { i.Name = "" }},
		{"quote in name", func(i *AddAttachmentInput) { i.Name = `a"b.png` }},
		{"CRLF in name", func(i *AddAttachmentInput) { i.Name = "a\r\nX: y.png" }},
		{"LF in name", func(i *AddAttachmentInput) { i.Name = "a\n.png" }},
		{"NUL in name", func(i *AddAttachmentInput) { i.Name = "a\x00.png" }},
		{"DEL in name", func(i *AddAttachmentInput) { i.Name = "a\x7f.png" }},
		{"slash in name", func(i *AddAttachmentInput) { i.Name = "a/b.png" }},
		{"backslash in name", func(i *AddAttachmentInput) { i.Name = `a\b.png` }},
		{"colon in name", func(i *AddAttachmentInput) { i.Name = "a:b.png" }},
		{"non-ASCII name", func(i *AddAttachmentInput) { i.Name = "shöt.png" }},
		{"U+202F name", func(i *AddAttachmentInput) { i.Name = "shot .png" }},
		{"leading dot", func(i *AddAttachmentInput) { i.Name = ".png" }},
		{"dot dot", func(i *AddAttachmentInput) { i.Name = ".." }},
		{"leading space", func(i *AddAttachmentInput) { i.Name = " a.png" }},
		{"trailing space", func(i *AddAttachmentInput) { i.Name = "a.png " }},
		{"256-byte name", func(i *AddAttachmentInput) { i.Name = strings.Repeat("a", 252) + ".png" }},
		{"issue", func(i *AddAttachmentInput) { i.IssueID = "../2-12" }},
		{"project id", func(i *AddAttachmentInput) { i.ProjectID = "" }},
		{"project key", func(i *AddAttachmentInput) { i.ProjectKey = "" }},
		{"author id", func(i *AddAttachmentInput) { i.ExpectedAuthorID = "" }},
		{"author login", func(i *AddAttachmentInput) { i.ExpectedAuthorLogin = " " }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
			defer server.Close()
			input := validAddAttachmentInput()
			test.change(&input)
			if err := ValidateAddAttachmentInput(input); err == nil {
				t.Fatal("invalid input accepted")
			}
			_, err := newTestClient(t, server).AddAttachment(context.Background(), input)
			assertError(t, err, errx.CodeUsage, "USAGE")
			if calls.Load() != 0 {
				t.Fatalf("calls=%d", calls.Load())
			}
		})
	}
	t.Run("boundary sizes and 255-byte name accepted", func(t *testing.T) {
		input := validAddAttachmentInput()
		input.Name = strings.Repeat("a", 251) + ".png"
		input.Content = bytes.Repeat([]byte{'a'}, maxAttachmentBytes)
		sum := sha256.Sum256(input.Content)
		input.ExpectedSHA256 = hex.EncodeToString(sum[:])
		if err := ValidateAddAttachmentInput(input); err != nil {
			t.Fatal(err)
		}
		for _, contentType := range []string{"image/png", "image/jpeg", "image/gif", "image/webp", "application/pdf"} {
			input.ContentType = contentType
			if err := ValidateAddAttachmentInput(input); err != nil {
				t.Fatalf("%s: %v", contentType, err)
			}
		}
	})
}

const attachmentItemJSON = `{"id":"8-5","name":"shot.png","size":12,"mimeType":"image/png","created":1700000000000,"removed":false,"author":{"id":"1-2","login":"alice"}}`

func TestAttachmentReadsPinRequestAndShape(t *testing.T) {
	var paths []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		paths = append(paths, request.URL.RequestURI())
		if strings.HasSuffix(request.URL.Path, "/attachments") {
			_, _ = io.WriteString(writer, "["+attachmentItemJSON+"]")
			return
		}
		_, _ = io.WriteString(writer, attachmentItemJSON)
	}))
	defer server.Close()
	client := newTestClient(t, server)
	list, err := client.ListIssueAttachments(context.Background(), "2-12", PageOptions{Top: 101, Skip: 3})
	if err != nil || len(list) != 1 || list[0].ID != "8-5" || list[0].Size != 12 || list[0].Author == nil || list[0].Author.Login != "alice" {
		t.Fatalf("list=%#v err=%v", list, err)
	}
	item, err := client.GetIssueAttachment(context.Background(), "2-12", "8-5")
	if err != nil || item.Name != "shot.png" || item.MimeType != "image/png" || item.Removed {
		t.Fatalf("item=%#v err=%v", item, err)
	}
	fields := "fields=id%2Cname%2Csize%2CmimeType%2Ccreated%2Cremoved%2Cauthor%28id%2Clogin%29"
	for _, want := range []string{
		"/youtrack/api/issues/2-12/attachments?%24skip=3&%24top=101&" + fields,
		"/youtrack/api/issues/2-12/attachments/8-5?" + fields,
	} {
		found := false
		for _, got := range paths {
			found = found || got == want
		}
		if !found {
			t.Errorf("missing request %q in %q", want, paths)
		}
	}
}

func TestAttachmentReadsRefuseInvalidShapes(t *testing.T) {
	removeMember := func(member string) string {
		switch member {
		case "size":
			return strings.Replace(attachmentItemJSON, `"size":12,`, ``, 1)
		case "created":
			return strings.Replace(attachmentItemJSON, `"created":1700000000000,`, ``, 1)
		case "removed":
			return strings.Replace(attachmentItemJSON, `"removed":false,`, ``, 1)
		default:
			return strings.Replace(attachmentItemJSON, `"name":"shot.png",`, ``, 1)
		}
	}
	tests := []struct{ name, body string }{
		{"missing size", removeMember("size")},
		{"missing created", removeMember("created")},
		{"missing removed", removeMember("removed")},
		{"missing name", removeMember("name")},
		{"negative size", strings.Replace(attachmentItemJSON, `"size":12`, `"size":-1`, 1)},
		{"bad id", strings.Replace(attachmentItemJSON, `"id":"8-5"`, `"id":"8 5"`, 1)},
		{"other id", strings.Replace(attachmentItemJSON, `"id":"8-5"`, `"id":"8-6"`, 1)},
		{"bad author id", strings.Replace(attachmentItemJSON, `"id":"1-2"`, `"id":""`, 1)},
		{"not json", "not json"},
		{"array for get", "[" + attachmentItemJSON + "]"},
	}
	for _, test := range tests {
		t.Run(test.name+"/get", func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(writer, test.body) }))
			defer server.Close()
			_, err := newTestClient(t, server).GetIssueAttachment(context.Background(), "2-12", "8-5")
			assertError(t, err, errx.CodeInternal, "INTERNAL")
		})
		t.Run(test.name+"/list", func(t *testing.T) {
			if test.name == "other id" || test.name == "array for get" {
				t.Skip("get-only case")
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(writer, "["+test.body+"]")
			}))
			defer server.Close()
			_, err := newTestClient(t, server).ListIssueAttachments(context.Background(), "2-12", PageOptions{})
			assertError(t, err, errx.CodeInternal, "INTERNAL")
		})
	}
	t.Run("null list", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(writer, "null") }))
		defer server.Close()
		_, err := newTestClient(t, server).ListIssueAttachments(context.Background(), "2-12", PageOptions{})
		assertError(t, err, errx.CodeInternal, "INTERNAL")
	})
}

func TestAttachmentReadsAreBoundedAndRefuseRedirects(t *testing.T) {
	t.Run("oversize", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(writer, strings.Repeat(" ", maxResponseBodyBytes+1))
		}))
		defer server.Close()
		_, err := newTestClient(t, server).GetIssueAttachment(context.Background(), "2-12", "8-5")
		assertError(t, err, errx.CodeInternal, "RESPONSE_TOO_LARGE")
	})
	t.Run("redirect", func(t *testing.T) {
		var hits atomic.Int32
		server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/elsewhere" {
				hits.Add(1)
				return
			}
			writer.Header().Set("Location", "/elsewhere")
			writer.WriteHeader(http.StatusFound)
		}))
		defer server.Close()
		_, err := newTestClient(t, server).ListIssueAttachments(context.Background(), "2-12", PageOptions{})
		assertError(t, err, errx.CodeInternal, "INTERNAL")
		if hits.Load() != 0 {
			t.Fatal("redirect followed")
		}
	})
	t.Run("invalid arguments make no request", func(t *testing.T) {
		var calls atomic.Int32
		server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
		defer server.Close()
		client := newTestClient(t, server)
		if _, err := client.ListIssueAttachments(context.Background(), "../x", PageOptions{}); err == nil {
			t.Error("bad issue accepted")
		}
		if _, err := client.ListIssueAttachments(context.Background(), "2-12", PageOptions{Top: 102}); err == nil {
			t.Error("top 102 accepted")
		}
		if _, err := client.GetIssueAttachment(context.Background(), "2-12", "a/b"); err == nil {
			t.Error("bad attachment id accepted")
		}
		if calls.Load() != 0 {
			t.Fatalf("calls=%d", calls.Load())
		}
	})
}
