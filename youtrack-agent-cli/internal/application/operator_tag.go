package application

import (
	"context"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/operatorwrite"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/profile"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/youtrack"
)

const (
	// operatorTagPage is the most tags a name resolution may consider; one more
	// is requested so a longer list is detected instead of silently truncated.
	operatorTagPage = 100
	// operatorTagCandidates bounds the candidates an error carries.
	operatorTagCandidates = 10
	// operatorTagCandidateRunes bounds a candidate name.
	operatorTagCandidateRunes = 64
	maxOperatorTagNameBytes   = 255
	maxOperatorTagIDBytes     = 128
	starFolderType            = "StarWatchFolder"
)

const noChangeHint = "nothing to change; do not retry unchanged"

func errTagStale(message string) *errx.Error {
	return errx.Conflict("OPERATOR_TAG_STALE", "%s", message).WithHint("inspect a new snapshot and prepare a fresh intent")
}

// staleTagWhenMissing maps a 404 inside the final lock to stale state.
func staleTagWhenMissing(err error) error {
	if err != nil && errx.ExitCode(err) == errx.CodeNotFound {
		return errTagStale("the issue or tag disappeared after snapshot")
	}
	return err
}

// validateTagSelectors checks the tag selectors offline.
func validateTagSelectors(input OperatorSnapshotInput) error {
	if (input.Tag == "") == (input.TagID == "") {
		return errx.Usage("exactly one of --tag or --tag-id is required")
	}
	if input.TagID != "" && !validOperatorEntityID(input.TagID, maxOperatorTagIDBytes) {
		return errx.Usage("--tag-id must be 1-%d ASCII letters, digits, dot, dash, or underscore", maxOperatorTagIDBytes)
	}
	if input.Tag != "" && (len(input.Tag) > maxOperatorTagNameBytes || !utf8.ValidString(input.Tag) || strings.ContainsFunc(input.Tag, unicode.IsControl)) {
		return errx.Usage("--tag must be at most %d bytes of printable text", maxOperatorTagNameBytes)
	}
	return nil
}

func validOperatorEntityID(value string, limit int) bool {
	if value == "" || len(value) > limit {
		return false
	}
	for index := 0; index < len(value); index++ {
		c := value[index]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !alnum && (index == 0 || c != '-' && c != '_' && c != '.') {
			return false
		}
	}
	return true
}

func operatorTag(tag youtrack.Tag) operatorwrite.Tag {
	return operatorwrite.Tag{ID: tag.ID, Name: tag.Name, Type: tag.Type, OwnerID: tag.OwnerID, OwnerLogin: tag.OwnerLogin, UntagOnResolve: tag.UntagOnResolve, Shared: tag.Shared}
}

func tagCandidates(tags []youtrack.Tag) []errx.Candidate {
	out := make([]errx.Candidate, 0, len(tags))
	for _, tag := range tags {
		name := strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return -1
			}
			return r
		}, tag.Name)
		if runes := []rune(name); len(runes) > operatorTagCandidateRunes {
			name = string(runes[:operatorTagCandidateRunes])
		}
		out = append(out, errx.Candidate{ID: tag.ID, Name: name, Kind: "tag"})
	}
	return out
}

func boundCandidates(candidates []errx.Candidate) []errx.Candidate {
	return candidates[:min(len(candidates), operatorTagCandidates)]
}

// matchTagName resolves an exact, case-sensitive tag name from a bounded list.
// The error is built from the full match set so counts stay true, then its
// candidate list is bounded.
func matchTagName(tags []youtrack.Tag, name string, absent *errx.Error) (youtrack.Tag, error) {
	var exact, folded []youtrack.Tag
	for _, tag := range tags {
		switch {
		case tag.Name == name:
			exact = append(exact, tag)
		case strings.EqualFold(tag.Name, name):
			folded = append(folded, tag)
		}
	}
	switch {
	case len(exact) == 1:
		return exact[0], nil
	case len(exact) > 1:
		err := errx.Ambiguous("tag", name, tagCandidates(exact))
		err.Candidates = boundCandidates(err.Candidates)
		return youtrack.Tag{}, err
	case len(folded) > 0:
		err := errx.Inexact("tag", name, tagCandidates(folded))
		err.Candidates = boundCandidates(err.Candidates)
		return youtrack.Tag{}, err
	}
	if absent == nil {
		err := errx.NotFound("tag", name, boundCandidates(tagCandidates(tags)))
		if len(err.DidYouMean) == 0 {
			err = err.WithHint("verify the tag name or use --tag-id")
		}
		return youtrack.Tag{}, err
	}
	return youtrack.Tag{}, absent
}

// freezeIssueTag reads the issue, resolves the tag, and freezes both, for
// issue.tag and issue.untag.
func (s *Service) freezeIssueTag(ctx context.Context, client *youtrack.Client, selected profile.Profile, input OperatorSnapshotInput, snapshot operatorwrite.Snapshot, untag bool) (operatorwrite.Snapshot, error) {
	issue, err := client.GetIssue(ctx, input.IssueID)
	if err != nil {
		return snapshot, err
	}
	if issue.Project.Archived {
		return snapshot, errx.Permission("OPERATOR_PROJECT_ARCHIVED", "the issue belongs to an archived project")
	}
	policy, err := s.Policies.RequireProject(ctx, selected, issue.Project.ID, issue.Project.ShortName)
	if err != nil {
		return snapshot, err
	}
	tagID := input.TagID
	if tagID == "" {
		var resolved youtrack.Tag
		if untag {
			tags, err := client.ListIssueTags(ctx, issue.ID, youtrack.PageOptions{Top: operatorTagPage + 1})
			if err != nil {
				return snapshot, err
			}
			if len(tags) > operatorTagPage {
				return snapshot, errx.Conflict("OPERATOR_TAGS_TRUNCATED", "the issue has more than %d tags", operatorTagPage).WithHint("use exact --tag-id")
			}
			absent := errx.Unsupported("OPERATOR_TAG_ABSENT", "the issue does not carry a tag with this name").WithHint(noChangeHint)
			resolved, err = matchTagName(tags, input.Tag, absent)
			if err != nil {
				return snapshot, err
			}
		} else {
			tags, err := client.ListTags(ctx, input.Tag, operatorTagPage+1)
			if err != nil {
				return snapshot, err
			}
			if len(tags) > operatorTagPage {
				return snapshot, errx.Conflict("OPERATOR_SCHEMA_TRUNCATED", "more than %d tags match the name", operatorTagPage).WithHint("use exact --tag-id")
			}
			resolved, err = matchTagName(tags, input.Tag, nil)
			if err != nil {
				return snapshot, err
			}
		}
		tagID = resolved.ID
	}
	tag, err := client.GetTag(ctx, tagID)
	if err != nil {
		if untag && input.TagID == "" && errx.ExitCode(err) == errx.CodeNotFound {
			return snapshot, errx.Conflict("OPERATOR_TAG_UNREADABLE", "a tag listed on the issue cannot be read").WithHint("use exact --tag-id or inspect the tag's visibility")
		}
		return snapshot, err
	}
	if input.TagID == "" && tag.Name != input.Tag {
		return snapshot, errTagStale("the tag changed while it was being resolved")
	}
	if tag.Type == starFolderType || (tag.Name == "Star" && tag.OwnerID == selected.ExpectedAccountID) {
		return snapshot, errx.Unsupported("OPERATOR_TAG_STAR_UNSUPPORTED", "the personal Star tag is not managed by this command")
	}
	if tag.Type != "Tag" && tag.Type != "IssueTag" {
		return snapshot, errx.Unsupported("OPERATOR_TAG_TYPE_UNSUPPORTED", "the tag type is not supported")
	}
	if tag.OwnerID == "" || tag.OwnerLogin == "" {
		return snapshot, errx.Unsupported("OPERATOR_TAG_TYPE_UNSUPPORTED", "the tag has no owner")
	}
	_, present, err := client.GetIssueTag(ctx, issue.ID, tag.ID)
	if err != nil {
		return snapshot, err
	}
	if present && !untag {
		return snapshot, errx.Unsupported("OPERATOR_TAG_ALREADY_PRESENT", "the issue already carries this tag").WithHint(noChangeHint)
	}
	if !present && untag {
		return snapshot, errx.Unsupported("OPERATOR_TAG_ABSENT", "the issue does not carry this tag").WithHint(noChangeHint)
	}
	frozen := operatorTag(tag)
	snapshot.Binding = operatorBinding(selected, policy)
	snapshot.Issue = operatorwrite.Issue{ID: issue.ID, ReadableID: issue.IDReadable, ProjectID: issue.Project.ID, ProjectKey: issue.Project.ShortName, Updated: issue.Updated}
	snapshot.Tag = &frozen
	return snapshot, nil
}

// verifyIssueTag re-checks every precondition inside the final lock. Any drift
// is a conflict and nothing is sent.
func verifyIssueTag(ctx context.Context, client *youtrack.Client, snapshot operatorwrite.Snapshot) error {
	issue, err := client.GetIssue(ctx, snapshot.Issue.ID)
	if err != nil {
		return staleTagWhenMissing(err)
	}
	if issue.ID != snapshot.Issue.ID || issue.IDReadable != snapshot.Issue.ReadableID || issue.Project.Archived ||
		issue.Project.ID != snapshot.Issue.ProjectID || issue.Project.ShortName != snapshot.Issue.ProjectKey {
		return errx.Conflict("OPERATOR_ISSUE_STALE", "the issue identity, project, or archive state changed").WithHint("inspect a new snapshot and prepare a fresh intent")
	}
	tag, err := client.GetTag(ctx, snapshot.Tag.ID)
	if err != nil {
		return staleTagWhenMissing(err)
	}
	if operatorTag(tag) != *snapshot.Tag {
		return errTagStale("the tag changed after snapshot")
	}
	_, present, err := client.GetIssueTag(ctx, issue.ID, tag.ID)
	if err != nil {
		return staleTagWhenMissing(err)
	}
	if present != (snapshot.Kind == operatorwrite.KindIssueUntag) {
		return errTagStale("the tag presence on the issue changed after snapshot")
	}
	return nil
}

// dispatchIssueTag sends the one POST or DELETE and then confirms the result
// with reads. Anything that cannot be confirmed is an unknown outcome.
func dispatchIssueTag(ctx context.Context, client *youtrack.Client, plan operatorwrite.Plan) (string, string, error) {
	snapshot := plan.Snapshot
	untag := snapshot.Kind == operatorwrite.KindIssueUntag
	var err error
	if untag {
		err = client.RemoveIssueTag(ctx, snapshot.Issue.ID, snapshot.Tag.ID)
	} else {
		err = client.AddIssueTag(ctx, snapshot.Issue.ID, snapshot.Tag.ID)
	}
	if err != nil {
		return "", "", err
	}
	issue, err := client.GetIssue(ctx, snapshot.Issue.ID)
	if err != nil || issue.Project.ID != snapshot.Issue.ProjectID || issue.Project.ShortName != snapshot.Issue.ProjectKey {
		return snapshot.Tag.ID, "", operatorUnknownError()
	}
	_, present, err := client.GetIssueTag(ctx, snapshot.Issue.ID, snapshot.Tag.ID)
	if err != nil || present == untag {
		return snapshot.Tag.ID, "", operatorUnknownError()
	}
	return snapshot.Tag.ID, "", nil
}

// observeIssueTag is the GET-only reconcile observation. The observed state is
// evidence without causal proof: someone else may have changed the tag.
func observeIssueTag(ctx context.Context, client *youtrack.Client, snapshot operatorwrite.Snapshot) (string, error) {
	untag := snapshot.Kind == operatorwrite.KindIssueUntag
	issue, err := client.GetIssue(ctx, snapshot.Issue.ID)
	if err != nil {
		switch errx.ExitCode(err) {
		case errx.CodeAuth, errx.CodePermission, errx.CodeNotFound:
			return "tagged_issue_unavailable", nil
		default:
			return "", err
		}
	}
	if issue.Project.ID != snapshot.Issue.ProjectID || issue.Project.ShortName != snapshot.Issue.ProjectKey {
		return "", errx.Conflict("OPERATOR_PROJECT_CHANGED", "the tagged issue moved from its frozen project")
	}
	_, present, err := client.GetIssueTag(ctx, snapshot.Issue.ID, snapshot.Tag.ID)
	if err != nil {
		switch errx.ExitCode(err) {
		case errx.CodeAuth, errx.CodePermission:
			return "inconclusive", nil
		default:
			return "", err
		}
	}
	switch {
	case untag && present:
		return "tag_still_present", nil
	case untag:
		return "desired_tag_absence_observed_without_causal_proof", nil
	case present:
		return "desired_tag_observed_without_causal_proof", nil
	default:
		return "tag_still_absent", nil
	}
}
