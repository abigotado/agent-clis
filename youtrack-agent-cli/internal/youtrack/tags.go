package youtrack

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
)

const (
	tagFields       = "id,name,$type,owner(id,login),untagOnResolve,visibleFor(id),updateableBy(id)"
	maxTagNameBytes = 255
	maxTagQueryLen  = 512
)

// Tag is the strict projection of a YouTrack tag. OwnerID and OwnerLogin are
// empty for an ownerless tag; the caller decides whether that is acceptable.
// Shared is true when the tag is visible to or updatable by any group, that is,
// by anyone besides its owner.
type Tag struct {
	ID             string
	Name           string
	Type           string
	OwnerID        string
	OwnerLogin     string
	UntagOnResolve bool
	Shared         bool
}

type tagResponse struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Type           string `json:"$type"`
	UntagOnResolve *bool  `json:"untagOnResolve"`
	Owner          *struct {
		ID    string `json:"id"`
		Login string `json:"login"`
	} `json:"owner"`
	VisibleFor   json.RawMessage `json:"visibleFor"`
	UpdateableBy json.RawMessage `json:"updateableBy"`
}

type addIssueTagPayload struct {
	ID string `json:"id"`
}

func (response tagResponse) strict() (Tag, error) {
	if !validEntityID(response.ID) || !validTagName(response.Name) || strings.TrimSpace(response.Type) == "" || response.UntagOnResolve == nil {
		return Tag{}, invalidReadResponse()
	}
	tag := Tag{
		ID: response.ID, Name: response.Name, Type: response.Type, UntagOnResolve: *response.UntagOnResolve,
		Shared: rawPresent(response.VisibleFor) || rawPresent(response.UpdateableBy),
	}
	if response.Owner != nil {
		if !validEntityID(response.Owner.ID) || strings.TrimSpace(response.Owner.Login) == "" {
			return Tag{}, invalidReadResponse()
		}
		tag.OwnerID, tag.OwnerLogin = response.Owner.ID, response.Owner.Login
	}
	return tag, nil
}

// rawPresent reports whether a nullable JSON member carries a non-null value.
func rawPresent(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) != 0 && !bytes.Equal(trimmed, []byte("null"))
}

func validTagName(name string) bool {
	if strings.TrimSpace(name) == "" || len(name) > maxTagNameBytes || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func tagsFromResponses(responses []tagResponse) ([]Tag, error) {
	if responses == nil {
		return nil, invalidReadResponse()
	}
	tags := make([]Tag, len(responses))
	for index, response := range responses {
		tag, err := response.strict()
		if err != nil {
			return nil, err
		}
		tags[index] = tag
	}
	return tags, nil
}

// ListTags reads exactly one page of at most top tags visible to the account,
// optionally filtered by the caller's tag query. The caller asks for one more
// than it shows to detect truncation.
func (client *Client) ListTags(ctx context.Context, query string, top int) ([]Tag, error) {
	if len(query) > maxTagQueryLen || !utf8.ValidString(query) || strings.ContainsFunc(query, unicode.IsControl) {
		return nil, errx.Usage("tag query must be at most %d bytes of printable text", maxTagQueryLen)
	}
	values, err := pageQuery(PageOptions{Top: top}, tagFields)
	if err != nil {
		return nil, err
	}
	values.Del("$skip")
	if query != "" {
		values.Set("query", query)
	}
	var responses []tagResponse
	if err := client.readJSON(ctx, request{path: "/tags", query: values, operation: "tags.list", callerQuery: query != ""}, &responses); err != nil {
		return nil, err
	}
	return tagsFromResponses(responses)
}

// GetTag reads one tag by exact entity ID.
func (client *Client) GetTag(ctx context.Context, id string) (Tag, error) {
	if err := validateIdentifier("tag", id); err != nil {
		return Tag{}, err
	}
	return client.getTag(ctx, "/tags/"+url.PathEscape(id), "tags.get", id)
}

func (client *Client) getTag(ctx context.Context, path, operation, id string) (Tag, error) {
	var response tagResponse
	if err := client.readJSON(ctx, request{path: path, query: fieldsQuery(tagFields), operation: operation}, &response); err != nil {
		return Tag{}, err
	}
	tag, err := response.strict()
	if err != nil {
		return Tag{}, err
	}
	if tag.ID != id {
		return Tag{}, invalidReadResponse()
	}
	return tag, nil
}

// ListIssueTags reads exactly one bounded page of the tags on one issue.
func (client *Client) ListIssueTags(ctx context.Context, issueID string, options PageOptions) ([]Tag, error) {
	if err := validateIdentifier("issue", issueID); err != nil {
		return nil, err
	}
	query, err := pageQuery(options, tagFields)
	if err != nil {
		return nil, err
	}
	var responses []tagResponse
	if err := client.readJSON(ctx, request{
		path: "/issues/" + url.PathEscape(issueID) + "/tags", query: query, operation: "issue_tags.list", pageReducible: options.CanReduce,
	}, &responses); err != nil {
		return nil, err
	}
	return tagsFromResponses(responses)
}

// GetIssueTag reads one tag as attached to one issue. A 404 means the tag is
// not on the issue and is reported as absent, not as an error.
func (client *Client) GetIssueTag(ctx context.Context, issueID, tagID string) (Tag, bool, error) {
	if err := validateIdentifier("issue", issueID); err != nil {
		return Tag{}, false, err
	}
	if err := validateIdentifier("tag", tagID); err != nil {
		return Tag{}, false, err
	}
	tag, err := client.getTag(ctx, "/issues/"+url.PathEscape(issueID)+"/tags/"+url.PathEscape(tagID), "issue_tags.get", tagID)
	if err != nil {
		var typed *errx.Error
		if errors.As(err, &typed) && typed.Code == errx.CodeNotFound {
			return Tag{}, false, nil
		}
		return Tag{}, false, err
	}
	return tag, true, nil
}

// AddIssueTag dispatches exactly one non-replayable POST that attaches the tag
// to the issue. Success is only HTTP 200, 201 or 204 with an empty body or one
// JSON object; the body is never trusted. Anything else that is not a typed
// rejection is WRITE_OUTCOME_UNKNOWN.
func (client *Client) AddIssueTag(ctx context.Context, issueID, tagID string) error {
	if err := validateIdentifier("issue", issueID); err != nil {
		return err
	}
	if err := validateIdentifier("tag", tagID); err != nil {
		return err
	}
	body, err := json.Marshal(addIssueTagPayload{ID: tagID})
	if err != nil {
		return errx.Internal("could not encode the typed YouTrack tag")
	}
	const operation = "issue.tag"
	response, err := client.send(ctx, request{
		method: http.MethodPost, path: "/issues/" + url.PathEscape(issueID) + "/tags",
		body: body, operation: operation, write: true,
	})
	if err != nil || response == nil || response.Body == nil {
		return errx.WriteOutcomeUnknown(operation)
	}
	defer closeAndDrain(response.Body)
	if !statusAccepted(response.StatusCode, []int{http.StatusOK, http.StatusCreated, http.StatusNoContent}) {
		return client.translateWriteStatus(response, operation)
	}
	payload, tooLarge, readErr := readResponseBody(response)
	if readErr != nil || tooLarge {
		return errx.WriteOutcomeUnknown(operation)
	}
	if len(bytes.TrimSpace(payload)) == 0 || singleJSONObject(payload) {
		return nil
	}
	return errx.WriteOutcomeUnknown(operation)
}

// RemoveIssueTag dispatches exactly one non-replayable DELETE that detaches
// the tag from the issue. Success is only HTTP 200 or 204 with an empty body or
// one JSON object; anything else that is not a typed rejection is
// WRITE_OUTCOME_UNKNOWN.
func (client *Client) RemoveIssueTag(ctx context.Context, issueID, tagID string) error {
	if err := validateIdentifier("issue", issueID); err != nil {
		return err
	}
	if err := validateIdentifier("tag", tagID); err != nil {
		return err
	}
	return client.deleteExact(ctx, "/issues/"+url.PathEscape(issueID)+"/tags/"+url.PathEscape(tagID), "issue.untag", deleteBodyEmptyOrObject)
}
