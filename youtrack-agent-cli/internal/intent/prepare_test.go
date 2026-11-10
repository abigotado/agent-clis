package intent

import (
	"bytes"
	"errors"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type fixedIDSource string

func (s fixedIDSource) NewPlanID() (string, error) { return string(s), nil }

func validBindings() (ProfileSnapshot, ProjectPolicy) {
	profile := ProfileSnapshot{
		Name: "work", Instance: "https://acme.youtrack.cloud", RESTBaseURL: "https://acme.youtrack.cloud/api", OAuthIssuerURL: "https://hub.example.test",
		IdentitySHA256: strings.Repeat("a", 64), CredentialGeneration: "generation-1",
		Account: AccountBinding{ID: "1-2", Login: "alice"},
	}
	policy := ProjectPolicy{
		Project: ProjectBinding{ID: "0-1", Key: "APP"}, PolicyRevision: 2,
		PolicySHA256: strings.Repeat("b", 64), SchemaSHA256: strings.Repeat("c", 64),
		ExecutorAssurance: "rest-best-effort", AuthorizedCapability: "issue-create",
		NotificationPolicy: "youtrack-default", ReconciliationStrategy: "bounded-exact-and-marker",
	}
	return profile, policy
}

func TestPrepareDeterministicAndMarkerBound(t *testing.T) {
	profile, policy := validBindings()
	requestA := []byte(`{"summary":"Created","description":"body","visibility":{"mode":"public"},"custom_fields":[{"field_id":"2-2","field_type":"enum","value_id":"3-2"},{"field_id":"2-1","field_type":"enum","value_id":"3-1"}],"marker":"visible_footer"}`)
	requestB := []byte(`{"summary":"Created","description":"body","visibility":{"mode":"public"},"custom_fields":[{"field_id":"2-1","field_type":"enum","value_id":"3-1"},{"field_id":"2-2","field_type":"enum","value_id":"3-2"}],"marker":"visible_footer"}`)
	expected := []byte(`{"project_state_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`)
	source := fixedIDSource("YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA")

	first, err := PrepareWithSource(profile, policy, KindIssueCreate, requestA, expected, source)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PrepareWithSource(profile, policy, KindIssueCreate, requestB, expected, source)
	if err != nil {
		t.Fatal(err)
	}
	if first.IntentSHA256 != second.IntentSHA256 || first.RequestSHA256 != second.RequestSHA256 {
		t.Fatalf("canonical hashes differ: %#v %#v", first, second)
	}
	if got := first.Operation.IssueCreate.Request.Description; got != "body\n\nAgent plan: "+first.PlanID {
		t.Fatalf("description = %q", got)
	}
	if err := first.Validate(); err != nil {
		t.Fatalf("prepared plan invalid: %v", err)
	}
}

func TestPrepareStrictBoundsAndKinds(t *testing.T) {
	profile, policy := validBindings()
	source := fixedIDSource("YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA")
	tests := []struct {
		name     string
		kind     Kind
		request  []byte
		expected []byte
		wantErr  error
	}{
		{"create", KindIssueCreate, []byte(`{"summary":"S","description":"","visibility":{"mode":"public"},"marker":"none"}`), []byte(`{"project_state_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`), nil},
		{"update", KindIssueUpdate, []byte(`{"issue_id":"APP-1","set":{"summary":"S"}}`), []byte(`{"issue_id":"APP-1","issue_state_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","touched_fields_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}`), nil},
		{"comment", KindCommentAdd, []byte(`{"issue_id":"APP-1","text":"hello","visibility":{"mode":"restricted","group_ids":["1-1"]},"marker":"none"}`), []byte(`{"issue_id":"APP-1","issue_state_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`), nil},
		{"unknown field", KindIssueCreate, []byte(`{"summary":"S","description":"","visibility":{"mode":"public"},"marker":"none","extra":true}`), []byte(`{"project_state_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`), ErrInvalidPlan},
		{"oversized", KindIssueCreate, []byte(strings.Repeat("x", MaxRequestBytes+1)), []byte(`{}`), ErrInputTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy.AuthorizedCapability = authorizedCapability(tt.kind)
			_, err := PrepareWithSource(profile, policy, tt.kind, tt.request, tt.expected, source)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestPrepareRejectsWhitespaceRequiredTextAndReservedMarkerSpoof(t *testing.T) {
	profile, policy := validBindings()
	source := fixedIDSource("YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA")
	digest := strings.Repeat("d", 64)
	for _, test := range []struct {
		name       string
		kind       Kind
		request    string
		expected   string
		capability string
	}{
		{
			name: "create whitespace summary", kind: KindIssueCreate, capability: "issue-create",
			request:  `{"summary":" \t\n","description":"","visibility":{"mode":"public"},"marker":"none"}`,
			expected: `{"project_state_sha256":"` + digest + `"}`,
		},
		{
			name: "update whitespace summary", kind: KindIssueUpdate, capability: "issue-update",
			request:  `{"issue_id":"APP-1","set":{"summary":"  "}}`,
			expected: `{"issue_id":"APP-1","issue_state_sha256":"` + digest + `","touched_fields_sha256":"` + strings.Repeat("e", 64) + `"}`,
		},
		{
			name: "comment whitespace text", kind: KindCommentAdd, capability: "comment-add",
			request:  `{"issue_id":"APP-1","text":" \t\n","visibility":{"mode":"public"},"marker":"none"}`,
			expected: `{"issue_id":"APP-1","issue_state_sha256":"` + digest + `"}`,
		},
		{
			name: "visible footer cannot hide whitespace raw text", kind: KindCommentAdd, capability: "comment-add",
			request:  `{"issue_id":"APP-1","text":" \t ","visibility":{"mode":"public"},"marker":"visible_footer"}`,
			expected: `{"issue_id":"APP-1","issue_state_sha256":"` + digest + `"}`,
		},
		{
			name: "create marker-none reserved prefix", kind: KindIssueCreate, capability: "issue-create",
			request:  `{"summary":"S","description":"untrusted Agent plan: YTAP-BBBBBBBBBBBBBBBBBBBBBBBBBB","visibility":{"mode":"public"},"marker":"none"}`,
			expected: `{"project_state_sha256":"` + digest + `"}`,
		},
		{
			name: "comment marker-none reserved prefix", kind: KindCommentAdd, capability: "comment-add",
			request:  `{"issue_id":"APP-1","text":"untrusted Agent plan: YTAP-BBBBBBBBBBBBBBBBBBBBBBBBBB","visibility":{"mode":"public"},"marker":"none"}`,
			expected: `{"issue_id":"APP-1","issue_state_sha256":"` + digest + `"}`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			selectedPolicy := policy
			selectedPolicy.AuthorizedCapability = test.capability
			_, err := PrepareWithSource(profile, selectedPolicy, test.kind, []byte(test.request), []byte(test.expected), source)
			if !errors.Is(err, ErrInvalidPlan) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestDurablePlanValidationRejectsRequiredTextAndMarkerSpoof(t *testing.T) {
	profile, policy := validBindings()
	source := fixedIDSource("YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA")
	digest := strings.Repeat("d", 64)

	create, err := PrepareWithSource(profile, policy, KindIssueCreate,
		[]byte(`{"summary":"S","description":"body","visibility":{"mode":"public"},"marker":"none"}`),
		[]byte(`{"project_state_sha256":"`+digest+`"}`), source)
	if err != nil {
		t.Fatal(err)
	}
	create.Operation.IssueCreate.Request.Description = "spoof Agent plan: YTAP-BBBBBBBBBBBBBBBBBBBBBBBBBB"
	if !errors.Is(create.Validate(), ErrInvalidPlan) {
		t.Fatal("durable marker-none plan accepted the reserved marker prefix")
	}

	policy.AuthorizedCapability = "issue-update"
	update, err := PrepareWithSource(profile, policy, KindIssueUpdate,
		[]byte(`{"issue_id":"APP-1","set":{"summary":"S"}}`),
		[]byte(`{"issue_id":"APP-1","issue_state_sha256":"`+digest+`","touched_fields_sha256":"`+strings.Repeat("e", 64)+`"}`), source)
	if err != nil {
		t.Fatal(err)
	}
	whitespace := " \t\n"
	update.Operation.IssueUpdate.Request.Set.Summary = &whitespace
	if !errors.Is(update.Validate(), ErrInvalidPlan) {
		t.Fatal("durable update plan accepted whitespace-only summary")
	}

	policy.AuthorizedCapability = "comment-add"
	comment, err := PrepareWithSource(profile, policy, KindCommentAdd,
		[]byte(`{"issue_id":"APP-1","text":"body","visibility":{"mode":"public"},"marker":"visible_footer"}`),
		[]byte(`{"issue_id":"APP-1","issue_state_sha256":"`+digest+`"}`), source)
	if err != nil {
		t.Fatal(err)
	}
	comment.Operation.CommentAdd.Request.Text = " \t\n\nAgent plan: " + comment.PlanID
	if !errors.Is(comment.Validate(), ErrInvalidPlan) {
		t.Fatal("durable visible-footer plan accepted whitespace-only raw comment text")
	}
}

func TestPlanTamperInvalidatesDigest(t *testing.T) {
	profile, policy := validBindings()
	policy.AuthorizedCapability = "issue-update"
	plan, err := PrepareWithSource(profile, policy, KindIssueUpdate,
		[]byte(`{"issue_id":"APP-1","set":{"summary":"S"}}`),
		[]byte(`{"issue_id":"APP-1","issue_state_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","touched_fields_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}`),
		fixedIDSource("YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA"))
	if err != nil {
		t.Fatal(err)
	}
	tampered := plan
	changed := "changed"
	tampered.Operation.IssueUpdate.Request.Set.Summary = &changed
	if !errors.Is(tampered.Validate(), ErrInvalidPlan) {
		t.Fatalf("tampered plan validated")
	}
}

func TestApprovalDisplayBytesContainEverySafetyBinding(t *testing.T) {
	profile, policy := validBindings()
	plan, err := PrepareWithSource(profile, policy, KindIssueCreate,
		[]byte(`{"summary":"S","description":"","visibility":{"mode":"public"},"marker":"none"}`),
		[]byte(`{"project_state_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`),
		fixedIDSource("YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA"))
	if err != nil {
		t.Fatal(err)
	}
	displayed, err := ApprovalDisplayBytes(plan)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalBytes(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(displayed, canonical) {
		t.Fatal("approval bytes differ from signed canonical bytes")
	}
	for _, binding := range []string{
		`"rest_base_url":"https://acme.youtrack.cloud/api"`,
		`"oauth_issuer_url":"https://hub.example.test"`,
		`"account":{"id":"1-2","login":"alice"}`,
		`"authorized_capability":"issue-create"`,
		`"notification_policy":"youtrack-default"`,
		`"reconciliation_strategy":"bounded-exact-and-marker"`,
		`"executor_assurance":"rest-best-effort"`,
	} {
		if !bytes.Contains(displayed, []byte(binding)) {
			t.Fatalf("approval bytes missing %s: %s", binding, displayed)
		}
	}
}

func TestCanonicalPlanLimitCoversEscapeHeavyMaximumKinds(t *testing.T) {
	profile, policy := escapeHeavyBindings()
	tests := []struct {
		name     string
		kind     Kind
		request  []byte
		expected []byte
	}{
		{name: "issue create", kind: KindIssueCreate, request: escapeHeavyCreateRequest(), expected: []byte(`{"project_state_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`)},
		{name: "issue update", kind: KindIssueUpdate, request: escapeHeavyUpdateRequest(), expected: []byte(`{"issue_id":"APP-1","issue_state_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","touched_fields_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}`)},
		{name: "comment add", kind: KindCommentAdd, request: []byte(`{"issue_id":"APP-1","text":"` + strings.Repeat("<", maxBodyLength) + `","visibility":{"mode":"public"},"marker":"none"}`), expected: []byte(`{"issue_id":"APP-1","issue_state_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.request) > MaxRequestBytes {
				t.Fatalf("test request is %d bytes, above input contract", len(tt.request))
			}
			policy.AuthorizedCapability = authorizedCapability(tt.kind)
			plan, err := PrepareWithSource(profile, policy, tt.kind, tt.request, tt.expected, fixedIDSource("YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA"))
			if err != nil {
				t.Fatal(err)
			}
			display, err := ApprovalDisplayBytes(plan)
			if err != nil {
				t.Fatal(err)
			}
			if len(display) <= 96<<10 {
				t.Fatalf("escape-heavy regression plan is only %d bytes; it no longer proves the former 96 KiB limit was insufficient", len(display))
			}
			if len(display) > MaxCanonicalPlanBytes {
				t.Fatalf("canonical display is %d bytes, above %d-byte invariant", len(display), MaxCanonicalPlanBytes)
			}
			if err := plan.Validate(); err != nil {
				t.Fatalf("prepared plan does not validate: %v", err)
			}
		})
	}
}

func TestBoundCanonicalPlanBoundaries(t *testing.T) {
	if _, err := boundCanonicalPlan(bytes.Repeat([]byte{'x'}, MaxCanonicalPlanBytes)); err != nil {
		t.Fatalf("exact maximum rejected: %v", err)
	}
	if _, err := boundCanonicalPlan(bytes.Repeat([]byte{'x'}, MaxCanonicalPlanBytes+1)); !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("one byte over maximum error = %v, want %v", err, ErrInputTooLarge)
	}
}

func escapeHeavyBindings() (ProfileSnapshot, ProjectPolicy) {
	profile, policy := validBindings()
	instancePrefix := "https://acme.youtrack.cloud/"
	profile.Instance = instancePrefix + strings.Repeat("a", 2048-len(instancePrefix)-len("/api"))
	profile.RESTBaseURL = profile.Instance + "/api"
	issuerPrefix := "https://hub.example.test/"
	profile.OAuthIssuerURL = issuerPrefix + strings.Repeat("a", 2048-len(issuerPrefix))
	profile.CredentialGeneration = strings.Repeat("<", maxIdentityLength)
	profile.Account.Login = strings.Repeat("<", maxLoginLength)
	return profile, policy
}

func escapeHeavyCreateRequest() []byte {
	return []byte(`{"summary":"` + strings.Repeat("<", maxSummaryLength) +
		`","description":"` + strings.Repeat("<", maxBodyLength) +
		`","visibility":{"mode":"public"},"custom_fields":` + escapeHeavyFields() + `,"marker":"none"}`)
}

func escapeHeavyUpdateRequest() []byte {
	return []byte(`{"issue_id":"APP-1","set":{"summary":"` + strings.Repeat("<", maxSummaryLength) +
		`","description":"` + strings.Repeat("<", maxBodyLength) +
		`","custom_fields":` + escapeHeavyFields() + `}}`)
}

func escapeHeavyFields() string {
	fieldType := strings.Repeat("<", maxFieldTypeLength)
	literal := strings.Repeat("<", maxLiteralValueBytes)
	return `[{"field_id":"1","field_type":"` + fieldType + `","text_value":"` + literal +
		`"},{"field_id":"2","field_type":"` + fieldType + `","text_value":"` + literal +
		`"},{"field_id":"3","field_type":"` + fieldType + `","text_value":"` + literal + `"}]`
}

func TestPreparePackageHasNoOnlineOrCredentialImports(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime caller unavailable")
	}
	packages, err := parser.ParseDir(token.NewFileSet(), filepath.Dir(filename), nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range packages["intent"].Files {
		for _, imported := range file.Imports {
			path := strings.Trim(imported.Path.Value, `"`)
			if path == "net/http" || path == "os/exec" || strings.Contains(path, "/internal/auth") {
				t.Fatalf("offline intent package imports forbidden dependency %q", path)
			}
		}
	}
}
