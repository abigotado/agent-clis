package application

import (
	"context"
	"errors"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/operatorwrite"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/profile"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/youtrack"
)

func errLinkAbsent() *errx.Error {
	return errx.Unsupported("OPERATOR_LINK_ABSENT", "the issues are not linked this way").WithHint("nothing to change; do not retry unchanged")
}

// freezeIssueUnlink reads what issue.link reads and additionally requires the
// link to be present now, so the plan removes something that exists.
func (s *Service) freezeIssueUnlink(ctx context.Context, client *youtrack.Client, selected profile.Profile, input OperatorSnapshotInput, snapshot operatorwrite.Snapshot) (operatorwrite.Snapshot, error) {
	snapshot, link, err := s.freezeLinkEntry(ctx, client, selected, input, snapshot, "unlinked")
	if err != nil {
		return snapshot, err
	}
	present, err := linkContains(ctx, client, snapshot.Issue.ID, link.LinkID, link.Target.ID)
	if err != nil {
		return snapshot, err
	}
	if !present {
		return snapshot, errLinkAbsent()
	}
	snapshot.Link = &link
	return snapshot, nil
}

// staleWhenMissing maps a 404 inside the final lock to stale state: a deleted
// issue, link type or link entry is drift for a removal. Other failures keep
// their class.
func staleWhenMissing(err error) error {
	if err != nil && errx.ExitCode(err) == errx.CodeNotFound {
		return errLinkStale("a linked resource disappeared after snapshot")
	}
	return err
}

// verifyIssueUnlink re-checks every precondition inside the final lock. Any
// drift is a conflict and nothing is sent.
func verifyIssueUnlink(ctx context.Context, client *youtrack.Client, snapshot operatorwrite.Snapshot) error {
	link := *snapshot.Link
	source, err := client.GetIssue(ctx, snapshot.Issue.ID)
	if err != nil {
		return staleWhenMissing(err)
	}
	if err := requireLinkIssue(source, snapshot.Issue); err != nil {
		return err
	}
	target, err := client.GetIssue(ctx, link.Target.ID)
	if err != nil {
		return staleWhenMissing(err)
	}
	if err := requireLinkIssue(target, link.Target); err != nil {
		return err
	}
	linkType, err := client.GetIssueLinkType(ctx, link.Type.ID)
	if err != nil {
		return staleWhenMissing(err)
	}
	if operatorLinkType(linkType) != link.Type {
		return errLinkStale("the link type changed after snapshot")
	}
	entry, ok, err := linkEntry(ctx, client, source.ID, link.Type.ID, link.Direction)
	if err != nil {
		return staleWhenMissing(err)
	}
	if !ok || entry.ID != link.LinkID {
		return errLinkStale("the source issue link entry changed after snapshot")
	}
	present, err := linkContains(ctx, client, source.ID, link.LinkID, target.ID)
	if err != nil {
		return staleWhenMissing(err)
	}
	if !present {
		return errLinkStale("the link no longer exists")
	}
	return nil
}

// dispatchIssueUnlink sends the one DELETE and then confirms the result with
// reads. Anything that cannot be confirmed is an unknown outcome.
func dispatchIssueUnlink(ctx context.Context, client *youtrack.Client, plan operatorwrite.Plan) (string, string, error) {
	snapshot := plan.Snapshot
	link := *snapshot.Link
	if err := client.RemoveIssueLink(ctx, youtrack.RemoveIssueLinkInput{SourceID: snapshot.Issue.ID, LinkID: link.LinkID, TargetID: link.Target.ID}); err != nil {
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
	if err != nil || present {
		return link.Target.ID, link.Target.ReadableID, operatorUnknownError()
	}
	return link.Target.ID, link.Target.ReadableID, nil
}

// observeIssueUnlink is the GET-only reconcile observation. An absent link is
// evidence without causal proof: someone else may have removed it, and a
// present link proves nothing about whether the DELETE reached the server.
func observeIssueUnlink(ctx context.Context, client *youtrack.Client, snapshot operatorwrite.Snapshot) (string, error) {
	link := *snapshot.Link
	for _, frozen := range []operatorwrite.Issue{snapshot.Issue, link.Target} {
		issue, err := client.GetIssue(ctx, frozen.ID)
		if err != nil {
			switch errx.ExitCode(err) {
			case errx.CodeAuth, errx.CodePermission, errx.CodeNotFound:
				return "linked_issue_unavailable", nil
			default:
				return "", err
			}
		}
		if issue.Project.ID != frozen.ProjectID || issue.Project.ShortName != frozen.ProjectKey {
			return "", errx.Conflict("OPERATOR_PROJECT_CHANGED", "a linked issue moved from its frozen project")
		}
	}
	present, err := linkContains(ctx, client, snapshot.Issue.ID, link.LinkID, link.Target.ID)
	if err != nil {
		var typed *errx.Error
		if errors.As(err, &typed) && typed.Reason == "OPERATOR_LINKS_TRUNCATED" {
			return "inconclusive", nil
		}
		switch errx.ExitCode(err) {
		case errx.CodeAuth, errx.CodePermission, errx.CodeNotFound:
			// A vanished or inaccessible entry cannot show the link.
			return "inconclusive", nil
		default:
			return "", err
		}
	}
	if present {
		return "link_still_present", nil
	}
	return "desired_link_absence_observed_without_causal_proof", nil
}
