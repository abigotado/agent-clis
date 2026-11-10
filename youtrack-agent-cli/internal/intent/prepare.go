package intent

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

const visibleMarkerPrefix = "Agent plan: "

// IDSource allocates a non-secret, unpredictable plan identifier.
type IDSource interface {
	NewPlanID() (string, error)
}

// CryptoIDSource allocates 128-bit plan identifiers from crypto/rand.
type CryptoIDSource struct{}

func (CryptoIDSource) NewPlanID() (string, error) {
	raw := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("allocate plan ID: %w", err)
	}
	return "YTAP-" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

// Prepare validates bounded operation JSON, allocates a plan ID, inserts any
// approved visible marker, then hashes the final typed operation and all
// identity bindings. It performs no network, credential, browser, or file I/O.
func Prepare(profile ProfileSnapshot, policy ProjectPolicy, kind Kind, requestJSON, expectedJSON []byte) (Plan, error) {
	return PrepareWithSource(profile, policy, kind, requestJSON, expectedJSON, CryptoIDSource{})
}

// PrepareWithSource is Prepare with an injected ID source for deterministic
// tests and callers that preallocate IDs in an offline transaction.
func PrepareWithSource(profile ProfileSnapshot, policy ProjectPolicy, kind Kind, requestJSON, expectedJSON []byte, source IDSource) (Plan, error) {
	if source == nil {
		return Plan{}, fmt.Errorf("%w: nil plan ID source", ErrInvalidPlan)
	}
	if err := validateProfileLegacy(profile); err != nil {
		return Plan{}, err
	}
	if err := ValidateApprovalProfile(profile); err != nil {
		return Plan{}, err
	}
	if err := validatePolicy(policy); err != nil {
		return Plan{}, err
	}
	if policy.AuthorizedCapability != authorizedCapability(kind) {
		return Plan{}, fmt.Errorf("%w: authorized capability does not match operation kind", ErrInvalidPlan)
	}
	if err := boundJSON("request", requestJSON, MaxRequestBytes); err != nil {
		return Plan{}, err
	}
	if err := boundJSON("expected state", expectedJSON, MaxExpectedBytes); err != nil {
		return Plan{}, err
	}

	operation, err := decodeOperation(kind, requestJSON, expectedJSON)
	if err != nil {
		return Plan{}, err
	}
	if err := validateRequiredOperationText(operation); err != nil {
		return Plan{}, err
	}
	planID, err := source.NewPlanID()
	if err != nil {
		return Plan{}, err
	}
	if err := ValidatePlanID(planID); err != nil {
		return Plan{}, fmt.Errorf("generated plan ID: %w", err)
	}
	insertMarker(operation, planID)
	normalizeOperation(operation)
	if err := validateOperation(kind, operation, planID); err != nil {
		return Plan{}, err
	}

	requestBytes, expectedBytes, err := operationBytes(kind, operation)
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{
		SchemaVersion:  SchemaVersion,
		PlanID:         planID,
		Kind:           kind,
		Profile:        profile,
		Policy:         policy,
		Operation:      operation,
		RequestSHA256:  digest(requestBytes),
		ExpectedSHA256: digest(expectedBytes),
	}
	canonical, err := canonicalBytesUnchecked(plan)
	if err != nil {
		return Plan{}, err
	}
	plan.IntentSHA256 = digest(canonical)
	return plan, nil
}

func decodeOperation(kind Kind, requestJSON, expectedJSON []byte) (Operation, error) {
	switch kind {
	case KindIssueCreate:
		var request IssueCreateRequest
		var expected IssueCreateExpected
		if err := decodeStrict(requestJSON, &request); err != nil {
			return Operation{}, fmt.Errorf("%w: decode issue.create request: %v", ErrInvalidPlan, err)
		}
		if err := decodeStrict(expectedJSON, &expected); err != nil {
			return Operation{}, fmt.Errorf("%w: decode issue.create expected state: %v", ErrInvalidPlan, err)
		}
		return Operation{IssueCreate: &IssueCreateOperation{Request: request, Expected: expected}}, nil
	case KindIssueUpdate:
		var request IssueUpdateRequest
		var expected IssueUpdateExpected
		if err := decodeStrict(requestJSON, &request); err != nil {
			return Operation{}, fmt.Errorf("%w: decode issue.update request: %v", ErrInvalidPlan, err)
		}
		if err := decodeStrict(expectedJSON, &expected); err != nil {
			return Operation{}, fmt.Errorf("%w: decode issue.update expected state: %v", ErrInvalidPlan, err)
		}
		return Operation{IssueUpdate: &IssueUpdateOperation{Request: request, Expected: expected}}, nil
	case KindCommentAdd:
		var request CommentAddRequest
		var expected CommentAddExpected
		if err := decodeStrict(requestJSON, &request); err != nil {
			return Operation{}, fmt.Errorf("%w: decode comment.add request: %v", ErrInvalidPlan, err)
		}
		if err := decodeStrict(expectedJSON, &expected); err != nil {
			return Operation{}, fmt.Errorf("%w: decode comment.add expected state: %v", ErrInvalidPlan, err)
		}
		return Operation{CommentAdd: &CommentAddOperation{Request: request, Expected: expected}}, nil
	default:
		return Operation{}, fmt.Errorf("%w: unsupported operation kind %q", ErrInvalidPlan, kind)
	}
}

func decodeStrict(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("more than one JSON value")
		}
		return err
	}
	return nil
}

func boundJSON(label string, raw []byte, maximum int) error {
	if len(raw) == 0 {
		return fmt.Errorf("%w: %s JSON is empty", ErrInvalidPlan, label)
	}
	if len(raw) > maximum {
		return fmt.Errorf("%w: %s JSON exceeds %d bytes", ErrInputTooLarge, label, maximum)
	}
	return nil
}

func insertMarker(operation Operation, planID string) {
	marker := visibleMarkerPrefix + planID
	if operation.IssueCreate != nil && operation.IssueCreate.Request.Marker == MarkerVisibleFooter {
		operation.IssueCreate.Request.Description = appendFooter(operation.IssueCreate.Request.Description, marker)
	}
	if operation.CommentAdd != nil && operation.CommentAdd.Request.Marker == MarkerVisibleFooter {
		operation.CommentAdd.Request.Text = appendFooter(operation.CommentAdd.Request.Text, marker)
	}
}

func appendFooter(value, marker string) string {
	if value == "" {
		return marker
	}
	return strings.TrimRight(value, "\n") + "\n\n" + marker
}

func normalizeOperation(operation Operation) {
	var fields []CustomFieldValue
	switch {
	case operation.IssueCreate != nil:
		fields = operation.IssueCreate.Request.CustomFields
	case operation.IssueUpdate != nil:
		fields = operation.IssueUpdate.Request.Set.CustomFields
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].FieldID < fields[j].FieldID })
}

func operationBytes(kind Kind, operation Operation) ([]byte, []byte, error) {
	var request any
	var expected any
	switch kind {
	case KindIssueCreate:
		request, expected = operation.IssueCreate.Request, operation.IssueCreate.Expected
	case KindIssueUpdate:
		request, expected = operation.IssueUpdate.Request, operation.IssueUpdate.Expected
	case KindCommentAdd:
		request, expected = operation.CommentAdd.Request, operation.CommentAdd.Expected
	default:
		return nil, nil, fmt.Errorf("%w: unsupported operation kind %q", ErrInvalidPlan, kind)
	}
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal canonical request: %w", err)
	}
	expectedBytes, err := json.Marshal(expected)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal canonical expected state: %w", err)
	}
	return requestBytes, expectedBytes, nil
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
