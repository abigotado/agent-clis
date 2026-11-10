package youtrack

import "encoding/json"

// User is the field-minimal identity returned by /api/users/me and nested
// issue/comment identity fields.
type User struct {
	ID       string `json:"id"`
	Login    string `json:"login"`
	Name     string `json:"name,omitempty"`
	FullName string `json:"fullName,omitempty"`
	Email    string `json:"email,omitempty"`
	// Banned is read for bundle users only; it is not requested elsewhere.
	Banned bool `json:"banned,omitempty"`
}

// Project is the exact project identity used by policy checks.
type Project struct {
	ID        string `json:"id"`
	ShortName string `json:"shortName"`
	Name      string `json:"name"`
	Archived  bool   `json:"archived"`
}

// IssueCustomField retains only the stable field identity/type and a bounded
// raw value. The value is untrusted YouTrack content, not executable input.
type IssueCustomField struct {
	ID                 string                       `json:"id"`
	Name               string                       `json:"name"`
	Type               string                       `json:"$type"`
	Value              json.RawMessage              `json:"value"`
	ProjectCustomField *ProjectCustomFieldReference `json:"projectCustomField,omitempty"`
}

// ProjectCustomFieldReference links an issue field to its project schema and
// global definition. It contains identities only, never a returned URL.
type ProjectCustomFieldReference struct {
	ID    string         `json:"id"`
	Field FieldReference `json:"field"`
}

// FieldReference identifies the global custom-field definition.
type FieldReference struct {
	ID string `json:"id"`
}

// Issue is the fixed detailed shape used for exact reads and reconciliation.
type Issue struct {
	ID            string             `json:"id"`
	IDReadable    string             `json:"idReadable"`
	Summary       string             `json:"summary"`
	Description   *string            `json:"description"`
	Project       Project            `json:"project"`
	Reporter      *User              `json:"reporter"`
	Created       int64              `json:"created"`
	Updated       int64              `json:"updated"`
	CommentsCount int                `json:"commentsCount"`
	CustomFields  []IssueCustomField `json:"customFields"`
}

// IssueSummary is the deliberately small issue shape used for bounded
// discovery. It must not grow into the detailed issue or reconciliation shape.
// CustomFields holds each field's name, type and value, never its identity.
// Plain-value fields come back whole whatever properties the query names.
type IssueSummary struct {
	ID           string             `json:"id"`
	IDReadable   string             `json:"idReadable"`
	Summary      string             `json:"summary"`
	Project      Project            `json:"project"`
	Updated      int64              `json:"updated"`
	CustomFields []IssueCustomField `json:"customFields"`
}

// FieldType identifies the value type and cardinality of a project field.
type FieldType struct {
	ID           string `json:"id"`
	ValueType    string `json:"valueType"`
	IsMultiValue bool   `json:"isMultiValue"`
	Type         string `json:"$type"`
}

// FieldDefinition is the global prototype referenced by a project field.
type FieldDefinition struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	FieldType FieldType `json:"fieldType"`
}

// BundleValue is one immutable value identifier in a custom-field bundle.
type BundleValue struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Localized string `json:"localizedName,omitempty"`
	Archived  bool   `json:"archived,omitempty"`
	Type      string `json:"$type"`
}

// Bundle is the bounded-by-response-size value set attached to a field.
type Bundle struct {
	ID              string        `json:"id"`
	Values          []BundleValue `json:"values,omitempty"`
	AggregatedUsers []User        `json:"aggregatedUsers,omitempty"`
	Type            string        `json:"$type"`
}

// ProjectField is one project-specific custom-field schema entry.
type ProjectField struct {
	ID         string                        `json:"id"`
	Type       string                        `json:"$type"`
	Field      FieldDefinition               `json:"field"`
	CanBeEmpty bool                          `json:"canBeEmpty"`
	IsPublic   bool                          `json:"isPublic"`
	Bundle     *Bundle                       `json:"bundle,omitempty"`
	Project    *ProjectFieldProjectReference `json:"project,omitempty"`
}

// ProjectFieldProjectReference binds an exact schema read to its project.
type ProjectFieldProjectReference struct {
	ID string `json:"id"`
}

// Visibility contains explicit comment visibility identities.
type Visibility struct {
	Type            string     `json:"$type"`
	PermittedGroups []Identity `json:"permittedGroups,omitempty"`
	PermittedUsers  []Identity `json:"permittedUsers,omitempty"`
}

// Identity is a minimal user or group identity.
type Identity struct {
	ID    string `json:"id"`
	Name  string `json:"name,omitempty"`
	Login string `json:"login,omitempty"`
}

// Comment is the fixed, bounded-list comment shape used by inspection and
// reconciliation. Text remains untrusted data.
type Comment struct {
	ID         string      `json:"id"`
	Author     *User       `json:"author"`
	Created    int64       `json:"created"`
	Updated    *int64      `json:"updated"`
	Deleted    bool        `json:"deleted"`
	Text       *string     `json:"text"`
	Visibility *Visibility `json:"visibility"`
}

// CommentDeleteTarget is the strict, immutable projection required before an
// operator-confirmed comment deletion. Its fields are untrusted server data;
// callers bind them into the durable deletion plan before dispatch.
type CommentDeleteTarget struct {
	ID          string     `json:"id"`
	IssueID     string     `json:"issue_id"`
	Text        string     `json:"text"`
	AuthorID    string     `json:"author_id"`
	AuthorLogin string     `json:"author_login"`
	Created     int64      `json:"created"`
	Updated     *int64     `json:"updated"`
	Deleted     bool       `json:"deleted"`
	Pinned      bool       `json:"pinned"`
	Visibility  Visibility `json:"visibility"`
	Attachments []string   `json:"attachments"`
}

// PageOptions bounds one collection request. The client never follows or
// automatically requests another page.
type PageOptions struct {
	Top       int
	Skip      int
	CanReduce bool
}
