package application

import (
	"context"
	"errors"
	"sort"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/operatorwrite"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/profile"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/youtrack"
)

// linkPageTop is one bounded page plus the sentinel that proves truncation.
const (
	linkPageLimit = 100
	linkPageTop   = linkPageLimit + 1
)

// linkBlock is why a planned link cannot be added right now.
type linkBlock int

const (
	linkClear linkBlock = iota
	linkPresent
	linkParentExists
)

func errLinkAlreadyPresent() *errx.Error {
	return errx.Unsupported("OPERATOR_LINK_ALREADY_PRESENT", "the issues are already linked this way").WithHint("nothing to change; do not retry unchanged")
}

func errLinkParentExists() *errx.Error {
	return errx.Unsupported("OPERATOR_LINK_PARENT_EXISTS", "the child issue already has a parent, and YouTrack would silently replace it").
		WithHint("remove the existing parent link in YouTrack first; do not retry unchanged")
}

func errLinksTruncated() *errx.Error {
	return errx.Conflict("OPERATOR_LINKS_TRUNCATED", "the bounded link read is truncated, so absence cannot be shown").
		WithHint("swap --id and --target-id and use the reverse --direction phrase, or reduce the links of the issue in YouTrack")
}

func errLinkStale(message string) *errx.Error {
	return errx.Conflict("OPERATOR_LINK_STALE", "%s", message).WithHint("inspect a new snapshot and prepare a fresh intent")
}

func errLinkEntryUnavailable() *errx.Error {
	return errx.Unsupported("OPERATOR_LINK_ENTRY_UNAVAILABLE", "the server lists no single link entry for this link type and direction on the source issue").
		WithHint("check the link type in the source project; do not retry unchanged")
}

func linkWireDirection(direction string) string {
	switch direction {
	case operatorwrite.LinkOutward:
		return youtrack.LinkDirectionOutward
	case operatorwrite.LinkInward:
		return youtrack.LinkDirectionInward
	default:
		return youtrack.LinkDirectionBoth
	}
}

func operatorLinkType(value youtrack.IssueLinkType) operatorwrite.LinkType {
	return operatorwrite.LinkType{ID: value.ID, Name: value.Name, Directed: value.Directed, Aggregation: value.Aggregation,
		SourceToTarget: value.SourceToTarget, TargetToSource: value.TargetToSource}
}

// resolveLinkType finds the exact link type by immutable ID or by exact name.
// A name read is one bounded page; a truncated page, an unknown name and a
// duplicate name are all refused, never guessed.
func resolveLinkType(ctx context.Context, client *youtrack.Client, name, id string) (youtrack.IssueLinkType, error) {
	if id != "" {
		linkType, err := client.GetIssueLinkType(ctx, id)
		if errx.ExitCode(err) == errx.CodeNotFound {
			return youtrack.IssueLinkType{}, errx.NotFound("link_type", id, nil)
		}
		return linkType, err
	}
	types, err := client.ListIssueLinkTypes(ctx, youtrack.PageOptions{Top: linkPageTop})
	if err != nil {
		return youtrack.IssueLinkType{}, err
	}
	if len(types) > linkPageLimit {
		return youtrack.IssueLinkType{}, errx.Conflict("OPERATOR_SCHEMA_TRUNCATED", "bounded link type lookup is truncated").WithHint("use exact --link-type-id")
	}
	var matches, all []errx.Candidate
	var found youtrack.IssueLinkType
	for _, candidate := range types {
		entry := errx.Candidate{ID: candidate.ID, Name: candidate.Name, Kind: "link_type"}
		all = append(all, entry)
		if candidate.Name == name {
			matches = append(matches, entry)
			found = candidate
		}
	}
	switch len(matches) {
	case 1:
		return found, nil
	case 0:
		sort.Slice(all, func(i, j int) bool { return all[i].Name < all[j].Name })
		return youtrack.IssueLinkType{}, errx.NotFound("link_type", name, all)
	default:
		return youtrack.IssueLinkType{}, errx.Ambiguous("link_type", name, matches)
	}
}

// resolveLinkDirection maps the exact phrase to a direction. Matching is
// case-sensitive and never fuzzy.
func resolveLinkDirection(linkType youtrack.IssueLinkType, phrase string) (string, error) {
	if linkType.Aggregation && !linkType.Directed {
		return "", errx.Unsupported("OPERATOR_LINK_TYPE_UNSUPPORTED", "an aggregation link type must be directed")
	}
	if !linkType.Directed {
		if phrase != linkType.SourceToTarget {
			return "", errx.Usage("--direction must equal %q exactly for this undirected link type", linkType.SourceToTarget)
		}
		return operatorwrite.LinkUndirected, nil
	}
	if linkType.SourceToTarget == linkType.TargetToSource {
		return "", errx.Unsupported("OPERATOR_LINK_DIRECTION_AMBIGUOUS", "both phrases of this directed link type are identical, so the direction cannot be told").
			WithHint("choose another link type")
	}
	switch phrase {
	case linkType.SourceToTarget:
		return operatorwrite.LinkOutward, nil
	case linkType.TargetToSource:
		return operatorwrite.LinkInward, nil
	default:
		return "", errx.Usage("--direction must equal %q or %q exactly", linkType.SourceToTarget, linkType.TargetToSource)
	}
}

// linkEntries lists one issue's link entries in one bounded page and returns
// those for the type and side. A truncated page cannot prove a missing or
// unique entry.
func linkEntries(ctx context.Context, client *youtrack.Client, issueID, typeID, wireDirection string) ([]youtrack.IssueLink, error) {
	entries, err := client.ListIssueLinks(ctx, issueID, youtrack.PageOptions{Top: linkPageTop})
	if err != nil {
		return nil, err
	}
	if len(entries) > linkPageLimit {
		return nil, errLinksTruncated()
	}
	var matches []youtrack.IssueLink
	for _, entry := range entries {
		if entry.LinkTypeID == typeID && entry.Direction == wireDirection {
			matches = append(matches, entry)
		}
	}
	return matches, nil
}

// linkEntry returns the one server-provided entry, or false when it is
// missing or duplicated.
func linkEntry(ctx context.Context, client *youtrack.Client, issueID, typeID, direction string) (youtrack.IssueLink, bool, error) {
	matches, err := linkEntries(ctx, client, issueID, typeID, linkWireDirection(direction))
	if err != nil || len(matches) != 1 {
		return youtrack.IssueLink{}, false, err
	}
	return matches[0], true, nil
}

// linkContains reports whether the target is in the entry's single bounded
// page. A truncated page without the target proves nothing.
func linkContains(ctx context.Context, client *youtrack.Client, sourceID, linkID, targetID string) (bool, error) {
	issues, err := client.ListLinkedIssues(ctx, sourceID, linkID, youtrack.PageOptions{Top: linkPageTop})
	if err != nil {
		return false, err
	}
	for _, issue := range issues {
		if issue.ID == targetID {
			return true, nil
		}
	}
	if len(issues) > linkPageLimit {
		return false, errLinksTruncated()
	}
	return false, nil
}

// probeLink reports what blocks the planned link. YouTrack silently replaces
// the parent of an aggregation (subtask) child, so a child that already has
// one blocks the link instead of losing it. The child is the issue on the
// inward side of the type.
func probeLink(ctx context.Context, client *youtrack.Client, link operatorwrite.Link, source, target string) (linkBlock, error) {
	present, err := linkContains(ctx, client, source, link.LinkID, target)
	if err != nil {
		return linkClear, err
	}
	if present {
		return linkPresent, nil
	}
	if !link.Type.Aggregation {
		return linkClear, nil
	}
	child := source
	if link.Direction == operatorwrite.LinkOutward {
		child = target
	}
	entry, ok, err := linkEntry(ctx, client, child, link.Type.ID, operatorwrite.LinkInward)
	if err != nil {
		return linkClear, err
	}
	if !ok {
		return linkClear, errLinkEntryUnavailable()
	}
	parents, err := client.ListLinkedIssues(ctx, child, entry.ID, youtrack.PageOptions{Top: 1})
	if err != nil {
		return linkClear, err
	}
	if len(parents) > 0 {
		return linkParentExists, nil
	}
	return linkClear, nil
}

// freezeIssueLink reads both issues, the link type and the source's link
// entry, and refuses every state in which the link would change nothing or
// something other than a pure addition.
func (s *Service) freezeIssueLink(ctx context.Context, client *youtrack.Client, selected profile.Profile, input OperatorSnapshotInput, snapshot operatorwrite.Snapshot) (operatorwrite.Snapshot, error) {
	source, err := client.GetIssue(ctx, input.IssueID)
	if err != nil {
		return snapshot, err
	}
	target, err := client.GetIssue(ctx, input.TargetID)
	if err != nil {
		return snapshot, err
	}
	if source.ID == target.ID {
		return snapshot, errx.Usage("an issue cannot be linked to itself")
	}
	var binding operatorwrite.Binding
	for index, issue := range []youtrack.Issue{source, target} {
		if issue.Project.Archived {
			return snapshot, errx.Permission("OPERATOR_PROJECT_ARCHIVED", "a linked issue belongs to an archived project")
		}
		policy, err := s.Policies.RequireProject(ctx, selected, issue.Project.ID, issue.Project.ShortName)
		if err != nil {
			return snapshot, err
		}
		if index == 0 {
			binding = operatorBinding(selected, policy)
		} else if operatorBinding(selected, policy) != binding {
			return snapshot, errx.Conflict("OPERATOR_BINDING_STALE", "operator project policy changed during snapshot")
		}
	}
	linkType, err := resolveLinkType(ctx, client, input.LinkType, input.LinkTypeID)
	if err != nil {
		return snapshot, err
	}
	direction, err := resolveLinkDirection(linkType, input.Direction)
	if err != nil {
		return snapshot, err
	}
	entry, ok, err := linkEntry(ctx, client, source.ID, linkType.ID, direction)
	if err != nil {
		return snapshot, err
	}
	if !ok {
		return snapshot, errLinkEntryUnavailable()
	}
	link := operatorwrite.Link{
		Target: operatorwrite.Issue{ID: target.ID, ReadableID: target.IDReadable, ProjectID: target.Project.ID, ProjectKey: target.Project.ShortName, Updated: target.Updated},
		Type:   operatorLinkType(linkType), Direction: direction, Phrase: input.Direction, LinkID: entry.ID,
	}
	block, err := probeLink(ctx, client, link, source.ID, target.ID)
	if err != nil {
		return snapshot, err
	}
	switch block {
	case linkPresent:
		return snapshot, errLinkAlreadyPresent()
	case linkParentExists:
		return snapshot, errLinkParentExists()
	}
	snapshot.Binding = binding
	snapshot.Issue = operatorwrite.Issue{ID: source.ID, ReadableID: source.IDReadable, ProjectID: source.Project.ID, ProjectKey: source.Project.ShortName, Updated: source.Updated}
	snapshot.Link = &link
	return snapshot, nil
}

// requireLinkIssue compares an issue with its frozen identity. The updated
// timestamp is deliberately not compared: a link is not a function of an
// issue's other attributes, and busy issues would otherwise always be stale.
func requireLinkIssue(issue youtrack.Issue, frozen operatorwrite.Issue) error {
	if issue.ID != frozen.ID || issue.IDReadable != frozen.ReadableID || issue.Project.Archived ||
		issue.Project.ID != frozen.ProjectID || issue.Project.ShortName != frozen.ProjectKey {
		return errx.Conflict("OPERATOR_ISSUE_STALE", "a linked issue identity, project, or archive state changed").WithHint("inspect a new snapshot and prepare a fresh intent")
	}
	return nil
}

// verifyIssueLink re-checks every precondition inside the final lock. Any
// drift is a conflict and nothing is sent.
func verifyIssueLink(ctx context.Context, client *youtrack.Client, snapshot operatorwrite.Snapshot) error {
	link := *snapshot.Link
	source, err := client.GetIssue(ctx, snapshot.Issue.ID)
	if err != nil {
		return err
	}
	if err := requireLinkIssue(source, snapshot.Issue); err != nil {
		return err
	}
	target, err := client.GetIssue(ctx, link.Target.ID)
	if err != nil {
		return err
	}
	if err := requireLinkIssue(target, link.Target); err != nil {
		return err
	}
	linkType, err := client.GetIssueLinkType(ctx, link.Type.ID)
	if err != nil {
		return err
	}
	if operatorLinkType(linkType) != link.Type {
		return errLinkStale("the link type changed after snapshot")
	}
	entry, ok, err := linkEntry(ctx, client, source.ID, link.Type.ID, link.Direction)
	if err != nil {
		return err
	}
	if !ok || entry.ID != link.LinkID {
		return errLinkStale("the source issue link entry changed after snapshot")
	}
	block, err := probeLink(ctx, client, link, source.ID, target.ID)
	if err != nil {
		var typed *errx.Error
		if errors.As(err, &typed) && typed.Reason == "OPERATOR_LINK_ENTRY_UNAVAILABLE" {
			return errLinkStale("the child issue link entry changed after snapshot")
		}
		return err
	}
	switch block {
	case linkPresent:
		return errLinkStale("the link already exists")
	case linkParentExists:
		return errLinkStale("the child issue gained a parent after snapshot")
	}
	return nil
}

// dispatchIssueLink sends the one POST and then confirms the result with
// reads. Anything that cannot be confirmed is an unknown outcome.
func dispatchIssueLink(ctx context.Context, client *youtrack.Client, plan operatorwrite.Plan) (string, string, error) {
	snapshot := plan.Snapshot
	link := *snapshot.Link
	if err := client.AddIssueLink(ctx, youtrack.AddIssueLinkInput{SourceID: snapshot.Issue.ID, LinkID: link.LinkID,
		TargetID: link.Target.ID, TargetReadableID: link.Target.ReadableID}); err != nil {
		return "", "", err
	}
	for _, frozen := range []operatorwrite.Issue{snapshot.Issue, link.Target} {
		issue, err := client.GetIssue(ctx, frozen.ID)
		if err != nil || issue.Project.ID != frozen.ProjectID || issue.Project.ShortName != frozen.ProjectKey {
			return link.Target.ID, link.Target.ReadableID, operatorUnknownError()
		}
	}
	entry, ok, err := linkEntry(ctx, client, snapshot.Issue.ID, link.Type.ID, link.Direction)
	if err != nil || !ok || entry.ID != link.LinkID {
		return link.Target.ID, link.Target.ReadableID, operatorUnknownError()
	}
	present, err := linkContains(ctx, client, snapshot.Issue.ID, link.LinkID, link.Target.ID)
	if err != nil || !present {
		return link.Target.ID, link.Target.ReadableID, operatorUnknownError()
	}
	return link.Target.ID, link.Target.ReadableID, nil
}

// observeIssueLink is the GET-only reconcile observation. Presence of the
// desired link is evidence without causal proof: the link may have been added
// by someone else, and an absent link proves nothing after an ambiguous POST.
func observeIssueLink(ctx context.Context, client *youtrack.Client, snapshot operatorwrite.Snapshot, limit, offset int) (string, error) {
	link := *snapshot.Link
	for _, frozen := range []operatorwrite.Issue{snapshot.Issue, link.Target} {
		issue, err := client.GetIssue(ctx, frozen.ID)
		if err != nil {
			return "", err
		}
		if issue.Project.ID != frozen.ProjectID || issue.Project.ShortName != frozen.ProjectKey {
			return "", errx.Conflict("OPERATOR_PROJECT_CHANGED", "a linked issue moved from its frozen project")
		}
	}
	issues, err := client.ListLinkedIssues(ctx, snapshot.Issue.ID, link.LinkID, youtrack.PageOptions{Top: limit + 1, Skip: offset})
	if err != nil {
		if errx.ExitCode(err) == errx.CodeNotFound {
			// A vanished entry cannot show the link.
			return "inconclusive", nil
		}
		return "", err
	}
	if len(issues) > limit {
		issues = issues[:limit]
	}
	for _, issue := range issues {
		if issue.ID == link.Target.ID {
			return "desired_link_observed_without_causal_proof", nil
		}
	}
	return "inconclusive", nil
}
