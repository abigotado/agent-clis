package youtrack

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
)

const (
	attachmentFields = "id,name,size,mimeType,created,removed,author(id,login)"
	// maxAttachmentBytes is the local upload cap; it mirrors the operator-write
	// limit but is defined here so this package imports neither.
	maxAttachmentBytes = 10 << 20
	// maxAttachmentRequestBytes leaves room for multipart framing.
	maxAttachmentRequestBytes = maxAttachmentBytes + 64<<10
	maxAttachmentNameBytes    = 255
	attachmentPartName        = "upload"
)

// IssueAttachment is the fixed attachment shape used for reads and for the
// verified result of an upload. Name is untrusted server data.
type IssueAttachment struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Size     int64     `json:"size"`
	MimeType string    `json:"mimeType"`
	Created  int64     `json:"created"`
	Removed  bool      `json:"removed"`
	Author   *Identity `json:"author"`
}

// AddAttachmentInput is the complete supported attachment.add payload. Project
// and expected author bind the verified response and are never sent.
type AddAttachmentInput struct {
	IssueID             string
	ProjectID           string
	ProjectKey          string
	Name                string
	ContentType         string
	Content             []byte
	ExpectedSHA256      string
	ExpectedAuthorID    string
	ExpectedAuthorLogin string
}

// attachmentResponse preserves member presence so an omitted size, created, or
// removed cannot masquerade as a verified value.
type attachmentResponse struct {
	ID       string    `json:"id"`
	Name     *string   `json:"name"`
	Size     *int64    `json:"size"`
	MimeType *string   `json:"mimeType"`
	Created  *int64    `json:"created"`
	Removed  *bool     `json:"removed"`
	Author   *Identity `json:"author"`
}

func (response attachmentResponse) attachment() (IssueAttachment, bool) {
	if !validEntityID(response.ID) || response.Name == nil || response.Size == nil || *response.Size < 0 ||
		response.Created == nil || response.Removed == nil {
		return IssueAttachment{}, false
	}
	if response.Author != nil && !validEntityID(response.Author.ID) {
		return IssueAttachment{}, false
	}
	attachment := IssueAttachment{
		ID: response.ID, Name: *response.Name, Size: *response.Size, Created: *response.Created,
		Removed: *response.Removed, Author: response.Author,
	}
	if response.MimeType != nil {
		attachment.MimeType = *response.MimeType
	}
	return attachment, true
}

// ListIssueAttachments reads exactly one bounded page of an issue's attachments.
func (client *Client) ListIssueAttachments(ctx context.Context, issueID string, options PageOptions) ([]IssueAttachment, error) {
	if err := validateIdentifier("issue", issueID); err != nil {
		return nil, err
	}
	query, err := pageQuery(options, attachmentFields)
	if err != nil {
		return nil, err
	}
	var responses []attachmentResponse
	if err := client.readJSON(ctx, request{
		path: "/issues/" + url.PathEscape(issueID) + "/attachments", query: query,
		operation: "attachments.list", pageReducible: options.CanReduce,
	}, &responses); err != nil {
		return nil, err
	}
	if responses == nil {
		return nil, invalidReadResponse()
	}
	attachments := make([]IssueAttachment, 0, len(responses))
	for _, response := range responses {
		attachment, ok := response.attachment()
		if !ok {
			return nil, invalidReadResponse()
		}
		attachments = append(attachments, attachment)
	}
	return attachments, nil
}

// GetIssueAttachment reads one exact attachment for read-back and reconciliation.
func (client *Client) GetIssueAttachment(ctx context.Context, issueID, attachmentID string) (IssueAttachment, error) {
	if err := validateIdentifier("issue", issueID); err != nil {
		return IssueAttachment{}, err
	}
	if err := validateIdentifier("attachment", attachmentID); err != nil {
		return IssueAttachment{}, err
	}
	var response attachmentResponse
	if err := client.readJSON(ctx, request{
		path:  "/issues/" + url.PathEscape(issueID) + "/attachments/" + url.PathEscape(attachmentID),
		query: fieldsQuery(attachmentFields), operation: "attachments.get",
	}, &response); err != nil {
		return IssueAttachment{}, err
	}
	attachment, ok := response.attachment()
	if !ok || attachment.ID != attachmentID {
		return IssueAttachment{}, invalidReadResponse()
	}
	return attachment, nil
}

// allowedAttachmentTypes is the closed set of uploadable media types.
var allowedAttachmentTypes = map[string]struct{}{
	"image/png": {}, "image/jpeg": {}, "image/gif": {}, "image/webp": {}, "application/pdf": {},
}

// ValidateAddAttachmentInput validates the complete upload offline, including
// that Content hashes to ExpectedSHA256.
func ValidateAddAttachmentInput(input AddAttachmentInput) error {
	if err := validateIdentifier("issue", input.IssueID); err != nil {
		return err
	}
	if err := validateIdentifier("project", input.ProjectID); err != nil {
		return err
	}
	if err := validateIdentifier("project", input.ProjectKey); err != nil {
		return err
	}
	if err := validateIdentifier("author", input.ExpectedAuthorID); err != nil {
		return err
	}
	if err := validateRequiredText("author login", input.ExpectedAuthorLogin, maxIdentifierBytes); err != nil {
		return err
	}
	if !validAttachmentName(input.Name) {
		return errx.Usage("attachment name must be 1-%d printable ASCII bytes without path or reserved characters", maxAttachmentNameBytes)
	}
	if _, allowed := allowedAttachmentTypes[input.ContentType]; !allowed {
		return errx.Usage("attachment content type is not supported")
	}
	if len(input.Content) < 1 || len(input.Content) > maxAttachmentBytes {
		return errx.Usage("attachment must be between 1 and %d bytes", maxAttachmentBytes)
	}
	sum := sha256.Sum256(input.Content)
	if !validLowerHexSHA256(input.ExpectedSHA256) || hex.EncodeToString(sum[:]) != input.ExpectedSHA256 {
		return errx.Usage("attachment content does not match the expected SHA-256")
	}
	return nil
}

func validLowerHexSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range []byte(value) {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

// validAttachmentName refuses rather than sanitizes, so the name sent equals
// the name compared in the response and cannot inject multipart header bytes.
func validAttachmentName(name string) bool {
	if name == "" || len(name) > maxAttachmentNameBytes || name == "." || name == ".." ||
		name[0] == '.' || name[0] == ' ' || name[len(name)-1] == ' ' {
		return false
	}
	for _, character := range []byte(name) {
		if character < 0x20 || character > 0x7e || strings.IndexByte(`/\":*?<>|`, character) >= 0 {
			return false
		}
	}
	return true
}

// AddAttachment dispatches exactly one non-replayable multipart POST. The
// documented success answer is a JSON array holding the one created
// attachment; status 200 and 201 are both accepted. Any response that cannot be
// verified is WRITE_OUTCOME_UNKNOWN, returning the well-formed attachment ID
// (when exactly one is named) so reconciliation can read it exactly.
func (client *Client) AddAttachment(ctx context.Context, input AddAttachmentInput) (IssueAttachment, error) {
	if err := ValidateAddAttachmentInput(input); err != nil {
		return IssueAttachment{}, err
	}
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)
	header := textproto.MIMEHeader{}
	header.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, attachmentPartName, input.Name))
	header.Set("Content-Type", input.ContentType)
	part, err := writer.CreatePart(header)
	if err != nil {
		return IssueAttachment{}, errx.Internal("could not encode the typed YouTrack attachment")
	}
	if _, err := part.Write(input.Content); err != nil {
		return IssueAttachment{}, errx.Internal("could not encode the typed YouTrack attachment")
	}
	if err := writer.Close(); err != nil {
		return IssueAttachment{}, errx.Internal("could not encode the typed YouTrack attachment")
	}
	if buffer.Len() > maxAttachmentRequestBytes {
		return IssueAttachment{}, errx.Usage("attachment request exceeds the %d-byte safety limit", maxAttachmentRequestBytes)
	}

	var raw json.RawMessage
	if err := client.writeJSON(ctx, request{
		method: http.MethodPost, path: "/issues/" + url.PathEscape(input.IssueID) + "/attachments",
		query: fieldsQuery(attachmentFields), body: buffer.Bytes(), operation: "attachment.add", write: true,
		contentType: writer.FormDataContentType(), acceptStatus: []int{http.StatusOK, http.StatusCreated},
	}, &raw); err != nil {
		return IssueAttachment{}, err
	}

	unknown := errx.WriteOutcomeUnknown("attachment.add")
	var responses []attachmentResponse
	if err := decodeOneJSON(raw, &responses); err != nil {
		// A single object is the wrong shape, but a well-formed ID still lets
		// reconciliation read the exact attachment.
		var single attachmentResponse
		if decodeOneJSON(raw, &single) == nil && validEntityID(single.ID) {
			return IssueAttachment{ID: single.ID}, unknown
		}
		return IssueAttachment{}, unknown
	}
	if len(responses) != 1 {
		return IssueAttachment{}, unknown
	}
	response := responses[0]
	identity := IssueAttachment{}
	if validEntityID(response.ID) {
		identity.ID = response.ID
	}
	attachment, ok := response.attachment()
	if !ok || attachment.Name != input.Name || attachment.Size != int64(len(input.Content)) || attachment.Removed || AttachmentMimeConflicts(attachment.MimeType, input.ContentType) ||
		attachment.Author == nil || attachment.Author.ID != input.ExpectedAuthorID || attachment.Author.Login != input.ExpectedAuthorLogin {
		return identity, unknown
	}
	return attachment, nil
}

// AttachmentMimeConflicts reports a server-reported media type that differs from
// the confirmed one. An absent value cannot be checked and is not a conflict.
func AttachmentMimeConflicts(observed, confirmed string) bool {
	observed, _, _ = strings.Cut(strings.ToLower(strings.TrimSpace(observed)), ";")
	return strings.TrimSpace(observed) != "" && strings.TrimSpace(observed) != confirmed
}
