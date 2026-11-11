package youtrack

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
)

const (
	issueLinkTypeFields = "id,name,directed,aggregation,sourceToTarget,targetToSource"
	issueLinksFields    = "id,direction,linkType(id)"
	linkedIssueFields   = "id,idReadable"
)

// Link entry directions as YouTrack reports them for one issue's side.
const (
	LinkDirectionOutward = "OUTWARD"
	LinkDirectionInward  = "INWARD"
	LinkDirectionBoth    = "BOTH"
)

// IssueLinkType is the strict projection of an issue link type. For an
// undirected type YouTrack may omit the inward phrase; it is then the outward
// phrase, because an undirected link reads the same from both sides.
type IssueLinkType struct {
	ID             string
	Name           string
	Directed       bool
	Aggregation    bool
	SourceToTarget string
	TargetToSource string
}

// IssueLink is one link entry of an issue: a link type seen from one side. Its
// ID is the server's own identity of that entry and addresses the entry's
// issues; it is never derived from the link type ID.
type IssueLink struct {
	ID         string
	Direction  string
	LinkTypeID string
}

// LinkedIssue is the minimal identity of an issue inside a link entry.
type LinkedIssue struct {
	ID         string
	IDReadable string
}

// AddIssueLinkInput is the complete issue.link payload. SourceID owns the link
// entry LinkID; TargetID is the database ID sent in the body.
type AddIssueLinkInput struct {
	SourceID         string
	LinkID           string
	TargetID         string
	TargetReadableID string
}

type issueLinkTypeResponse struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	Directed       *bool   `json:"directed"`
	Aggregation    *bool   `json:"aggregation"`
	SourceToTarget *string `json:"sourceToTarget"`
	TargetToSource *string `json:"targetToSource"`
}

type issueLinkResponse struct {
	ID        string  `json:"id"`
	Direction *string `json:"direction"`
	LinkType  *struct {
		ID string `json:"id"`
	} `json:"linkType"`
}

type linkedIssueResponse struct {
	ID         string `json:"id"`
	IDReadable string `json:"idReadable"`
}

type addIssueLinkPayload struct {
	ID string `json:"id"`
}

func (response issueLinkTypeResponse) strict() (IssueLinkType, error) {
	if !validEntityID(response.ID) || strings.TrimSpace(response.Name) == "" || response.Directed == nil || response.Aggregation == nil ||
		response.SourceToTarget == nil || strings.TrimSpace(*response.SourceToTarget) == "" {
		return IssueLinkType{}, invalidReadResponse()
	}
	linkType := IssueLinkType{ID: response.ID, Name: response.Name, Directed: *response.Directed, Aggregation: *response.Aggregation, SourceToTarget: *response.SourceToTarget}
	switch {
	case response.TargetToSource != nil && strings.TrimSpace(*response.TargetToSource) != "":
		linkType.TargetToSource = *response.TargetToSource
	case !linkType.Directed:
		linkType.TargetToSource = linkType.SourceToTarget
	default:
		return IssueLinkType{}, invalidReadResponse()
	}
	return linkType, nil
}

// ListIssueLinkTypes reads exactly one bounded page of link types.
func (client *Client) ListIssueLinkTypes(ctx context.Context, options PageOptions) ([]IssueLinkType, error) {
	query, err := pageQuery(options, issueLinkTypeFields)
	if err != nil {
		return nil, err
	}
	var responses []issueLinkTypeResponse
	if err := client.readJSON(ctx, request{path: "/issueLinkTypes", query: query, operation: "issue_link_types.list", pageReducible: options.CanReduce}, &responses); err != nil {
		return nil, err
	}
	if responses == nil {
		return nil, invalidReadResponse()
	}
	types := make([]IssueLinkType, len(responses))
	for index, response := range responses {
		if types[index], err = response.strict(); err != nil {
			return nil, err
		}
	}
	return types, nil
}

// GetIssueLinkType reads one link type by exact entity ID.
func (client *Client) GetIssueLinkType(ctx context.Context, linkTypeID string) (IssueLinkType, error) {
	if err := validateIdentifier("link type", linkTypeID); err != nil {
		return IssueLinkType{}, err
	}
	var response issueLinkTypeResponse
	if err := client.readJSON(ctx, request{
		path: "/issueLinkTypes/" + url.PathEscape(linkTypeID), query: fieldsQuery(issueLinkTypeFields), operation: "issue_link_types.get",
	}, &response); err != nil {
		return IssueLinkType{}, err
	}
	linkType, err := response.strict()
	if err != nil {
		return IssueLinkType{}, err
	}
	if linkType.ID != linkTypeID {
		return IssueLinkType{}, invalidReadResponse()
	}
	return linkType, nil
}

// ListIssueLinks reads exactly one bounded page of the issue's link entries.
func (client *Client) ListIssueLinks(ctx context.Context, issueID string, options PageOptions) ([]IssueLink, error) {
	if err := validateIdentifier("issue", issueID); err != nil {
		return nil, err
	}
	query, err := pageQuery(options, issueLinksFields)
	if err != nil {
		return nil, err
	}
	var responses []issueLinkResponse
	if err := client.readJSON(ctx, request{
		path: "/issues/" + url.PathEscape(issueID) + "/links", query: query, operation: "issue_links.list", pageReducible: options.CanReduce,
	}, &responses); err != nil {
		return nil, err
	}
	if responses == nil {
		return nil, invalidReadResponse()
	}
	links := make([]IssueLink, len(responses))
	for index, response := range responses {
		if !validEntityID(response.ID) || response.LinkType == nil || !validEntityID(response.LinkType.ID) || response.Direction == nil {
			return nil, invalidReadResponse()
		}
		switch *response.Direction {
		case LinkDirectionOutward, LinkDirectionInward, LinkDirectionBoth:
		default:
			return nil, invalidReadResponse()
		}
		links[index] = IssueLink{ID: response.ID, Direction: *response.Direction, LinkTypeID: response.LinkType.ID}
	}
	return links, nil
}

// ListLinkedIssues reads exactly one bounded page of the issues in one link
// entry of the source issue.
func (client *Client) ListLinkedIssues(ctx context.Context, issueID, linkID string, options PageOptions) ([]LinkedIssue, error) {
	if err := validateIdentifier("issue", issueID); err != nil {
		return nil, err
	}
	if err := validateIdentifier("link", linkID); err != nil {
		return nil, err
	}
	query, err := pageQuery(options, linkedIssueFields)
	if err != nil {
		return nil, err
	}
	var responses []linkedIssueResponse
	if err := client.readJSON(ctx, request{
		path:  "/issues/" + url.PathEscape(issueID) + "/links/" + url.PathEscape(linkID) + "/issues",
		query: query, operation: "issue_links.issues", pageReducible: options.CanReduce,
	}, &responses); err != nil {
		return nil, err
	}
	if responses == nil {
		return nil, invalidReadResponse()
	}
	issues := make([]LinkedIssue, len(responses))
	for index, response := range responses {
		if !validEntityID(response.ID) || !validEntityID(response.IDReadable) {
			return nil, invalidReadResponse()
		}
		issues[index] = LinkedIssue{ID: response.ID, IDReadable: response.IDReadable}
	}
	return issues, nil
}

// ValidateAddIssueLinkInput validates link intent without credentials or
// network access.
func ValidateAddIssueLinkInput(input AddIssueLinkInput) error {
	if err := validateIdentifier("source issue", input.SourceID); err != nil {
		return err
	}
	if err := validateIdentifier("link", input.LinkID); err != nil {
		return err
	}
	if err := validateIdentifier("target issue", input.TargetID); err != nil {
		return err
	}
	if err := validateIdentifier("target issue", input.TargetReadableID); err != nil {
		return err
	}
	if input.SourceID == input.TargetID {
		return errx.Usage("an issue cannot be linked to itself")
	}
	return nil
}

// AddIssueLink dispatches exactly one non-replayable POST that adds the target
// to the source's link entry. It is verified only when HTTP 200 returns exactly
// the target's database and readable IDs; anything else that is not a typed
// rejection is WRITE_OUTCOME_UNKNOWN.
func (client *Client) AddIssueLink(ctx context.Context, input AddIssueLinkInput) error {
	if err := ValidateAddIssueLinkInput(input); err != nil {
		return err
	}
	body, err := json.Marshal(addIssueLinkPayload{ID: input.TargetID})
	if err != nil {
		return errx.Internal("could not encode the typed YouTrack link")
	}
	var response linkedIssueResponse
	if err := client.writeJSON(ctx, request{
		method: http.MethodPost, path: "/issues/" + url.PathEscape(input.SourceID) + "/links/" + url.PathEscape(input.LinkID) + "/issues",
		query: fieldsQuery(linkedIssueFields), body: body, operation: "issue.link", write: true,
	}, &response); err != nil {
		return err
	}
	if response.ID != input.TargetID || response.IDReadable != input.TargetReadableID {
		return errx.WriteOutcomeUnknown("issue.link")
	}
	return nil
}
