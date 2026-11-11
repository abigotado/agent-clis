package application

import (
	"time"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/operatorwrite"
)

const (
	MaxOperatorSnapshotBytes = operatorwrite.MaxCommentDeleteSnapshotBytes
	MaxOperatorRequestBytes  = operatorwrite.MaxRequestBytes
)

// OperatorFieldSelection names one target field value either by exact names
// or by immutable project-field and bundle-value IDs, never a mix.
type OperatorFieldSelection struct {
	FieldName, ValueName, FieldID, ValueID string
	// Clear empties the field instead of selecting a value; it carries a field
	// selector only.
	Clear bool
}

// OperatorSnapshotInput selects an exact issue for issue.update/comment.add,
// or an exact project entity ID or key for issue.create.
type OperatorSnapshotInput struct {
	Profile, Kind, IssueID, CommentID, ProjectID, OutputPath string
	// TargetID, LinkType, LinkTypeID and Direction select an issue.link: the
	// target issue, the link type by exact name or immutable ID, and the exact
	// phrase read from the source issue's side.
	TargetID, LinkType, LinkTypeID, Direction string
	Fields                                    []OperatorFieldSelection
}

type OperatorPrepareInput struct {
	Profile                   string
	SnapshotJSON, RequestJSON []byte
	OutputPath                string
	DryRun                    bool
}

type OperatorApplyInput struct {
	Profile, PlanID, ConfirmIntent string
	Yes                            bool
}
type OperatorReconcileInput struct {
	Profile, PlanID string
	Limit, Offset   int
}

// OperatorWriteInfo keeps the application boundary compact while making the
// frozen intent available for explicit review with --fields or raw output.
type OperatorWriteInfo struct {
	PlanVersion      int                     `json:"plan_version,omitempty"`
	PlanLifetime     string                  `json:"plan_lifetime,omitempty"`
	PlanID           string                  `json:"plan_id,omitempty"`
	State            string                  `json:"state"`
	Kind             string                  `json:"kind"`
	ConfirmationMode string                  `json:"confirmation_mode"`
	Notifications    string                  `json:"notifications"`
	ExpiresAt        string                  `json:"expires_at,omitempty"`
	IntentSHA256     string                  `json:"intent_sha256,omitempty"`
	Profile          string                  `json:"profile"`
	Instance         string                  `json:"instance"`
	AccountID        string                  `json:"account_id"`
	AccountLogin     string                  `json:"account_login"`
	IssueID          string                  `json:"issue_id"`
	CommentID        string                  `json:"comment_id,omitempty"`
	ProjectID        string                  `json:"project_id"`
	ProjectKey       string                  `json:"project_key"`
	TargetIssueID    string                  `json:"target_issue_id,omitempty"`
	TargetReadableID string                  `json:"target_readable_id,omitempty"`
	TargetProjectKey string                  `json:"target_project_key,omitempty"`
	LinkType         string                  `json:"link_type,omitempty"`
	Direction        string                  `json:"direction,omitempty"`
	LinkID           string                  `json:"link_id,omitempty"`
	NonReplayable    bool                    `json:"non_replayable"`
	RemoteID         string                  `json:"remote_id,omitempty"`
	RemoteReadableID string                  `json:"remote_readable_id,omitempty"`
	OutputPath       string                  `json:"output_path,omitempty"`
	Snapshot         *operatorwrite.Snapshot `json:"snapshot,omitempty"`
	Plan             *operatorwrite.Plan     `json:"plan,omitempty"`
	Evidence         string                  `json:"evidence,omitempty"`
}

func operatorSnapshotInfo(snapshot operatorwrite.Snapshot) OperatorWriteInfo {
	projectID, projectKey := snapshot.ProjectRef()
	version := operatorwrite.PlanVersionFor(snapshot.Kind)
	result := OperatorWriteInfo{PlanVersion: version, PlanLifetime: operatorwrite.PlanLifetime(version),
		State: "snapshot", Kind: string(snapshot.Kind), ConfirmationMode: operatorwrite.ConfirmationMode, Notifications: operatorwrite.Notifications,
		Profile: snapshot.Binding.ProfileName, Instance: snapshot.Binding.InstanceURL, AccountID: snapshot.Binding.AccountID,
		AccountLogin: snapshot.Binding.AccountLogin, IssueID: snapshot.Issue.ID, ProjectID: projectID,
		ProjectKey: projectKey, Snapshot: &snapshot}
	if snapshot.Comment != nil {
		result.CommentID = snapshot.Comment.ID
	}
	if link := snapshot.Link; link != nil {
		result.TargetIssueID, result.TargetReadableID, result.TargetProjectKey = link.Target.ID, link.Target.ReadableID, link.Target.ProjectKey
		result.LinkType, result.Direction, result.LinkID = link.Type.Name, link.Phrase, link.LinkID
	}
	return result
}

func operatorRecordInfo(record operatorwrite.Record) OperatorWriteInfo {
	result := operatorSnapshotInfo(record.Plan.Snapshot)
	result.Snapshot = nil
	result.PlanVersion, result.PlanLifetime = record.Plan.Version, operatorwrite.PlanLifetime(record.Plan.Version)
	result.PlanID, result.State, result.IntentSHA256 = record.Plan.ID, string(record.State), record.Plan.SHA256
	if !record.Plan.ExpiresAt.IsZero() {
		result.ExpiresAt = record.Plan.ExpiresAt.Format(time.RFC3339)
	}
	result.NonReplayable, result.Plan = record.NonReplayable(), &record.Plan
	if record.Result != nil {
		result.RemoteID, result.RemoteReadableID = record.Result.RemoteID, record.Result.RemoteReadableID
	}
	return result
}

// OperatorWriteSupported reports the standard build's native credential-store
// support without opening it.
func OperatorWriteSupported() bool { return operatorWriteSupported }

// OperatorBackendSupported applies an explicitly injected service backend in
// tests; production services retain the immutable platform default.
func (s *Service) OperatorBackendSupported() bool {
	if s != nil && s.OperatorWriteSupport != nil {
		return s.OperatorWriteSupport()
	}
	return operatorWriteSupported
}
