package application

import (
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/operatorwrite"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/profile"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/writepolicy"
)

func TestDurablePlansApplyPastTheLegacyWindowForEveryKind(t *testing.T) {
	for _, kind := range []string{"issue.update", "comment.add"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newOperatorFixture(t)
			plan := fixture.prepare(t, kind)
			fixture.service.Now = func() time.Time { return plan.Plan.CreatedAt.Add(48 * time.Hour) }
			result, err := fixture.service.ApplyOperatorWrite(t.Context(), OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: plan.IntentSHA256, Yes: true})
			if err != nil || result.State != string(operatorwrite.StateApplied) || fixture.posts.Load() != 1 {
				t.Fatalf("result=%#v error=%v posts=%d", result, err, fixture.posts.Load())
			}
		})
	}
	t.Run("issue.create", func(t *testing.T) {
		fixture := newCreateFixture(t)
		plan := fixture.prepare(createStageFields, createRequestJSON)
		fixture.service.Now = func() time.Time { return plan.Plan.CreatedAt.Add(48 * time.Hour) }
		result, err := fixture.apply(plan)
		if err != nil || result.State != string(operatorwrite.StateApplied) || fixture.posts() != 1 {
			t.Fatalf("result=%#v error=%v posts=%d", result, err, fixture.posts())
		}
	})
}

func TestCapabilitiesAdvertiseDurablePlanMetadata(t *testing.T) {
	fixture := newOperatorFixture(t)
	capabilities, err := fixture.service.Capabilities(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	wantVersions := map[string]int{
		"issue.create":   operatorwrite.PlanVersion4,
		"issue.update":   operatorwrite.PlanVersion4,
		"comment.add":    operatorwrite.PlanVersion2,
		"comment.delete": operatorwrite.PlanVersion3,
		"issue.edit":     operatorwrite.PlanVersion4,
		"attachment.add": operatorwrite.PlanVersion4,
	}
	if capabilities.PlanVersion != operatorwrite.PlanVersion4 || capabilities.PlanLifetime != operatorwrite.CurrentPlanLifetime ||
		!reflect.DeepEqual(capabilities.PlanVersions, wantVersions) {
		t.Fatalf("capabilities=%#v", capabilities)
	}
}

func TestDurablePlanStillRequiresConsentAndCurrentLocalBindingBeforeCredentials(t *testing.T) {
	for _, mode := range []string{"missing yes", "missing digest", "wrong digest", "profile", "policy", "generation"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newOperatorFixture(t)
			plan := fixture.prepare(t, "issue.update")
			fixture.service.Now = func() time.Time { return plan.Plan.CreatedAt.Add(24 * time.Hour) }
			input := OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: plan.IntentSHA256, Yes: true}
			selected, err := fixture.service.Profiles.Get(t.Context(), "work")
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "missing yes":
				input.Yes = false
			case "missing digest":
				input.ConfirmIntent = ""
			case "wrong digest":
				input.ConfirmIntent = strings.Repeat("a", 64)
			case "profile":
				input.Profile = "other"
			case "policy":
				if _, err := fixture.service.Policies.Set(t.Context(), selected, []writepolicy.Project{{ID: "0-3", Key: "APP"}}); err != nil {
					t.Fatal(err)
				}
			case "generation":
				selected.CredentialGeneration, err = profile.NewCredentialGeneration()
				if err == nil {
					err = fixture.service.Profiles.Put(t.Context(), selected)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			credentials, network := &trapCredentials{}, &trapTransport{}
			fixture.service.Credentials, fixture.service.HTTP = credentials, network
			_, err = fixture.service.ApplyOperatorWrite(t.Context(), input)
			if err == nil || credentials.calls != 0 || network.calls != 0 || fixture.posts.Load() != 0 {
				t.Fatalf("error=%v credentials=%d network=%d posts=%d", err, credentials.calls, network.calls, fixture.posts.Load())
			}
			record, getErr := fixture.service.OperatorWrites.Get(t.Context(), plan.PlanID)
			if getErr != nil || record.NonReplayable() {
				t.Fatalf("local refusal consumed plan: %#v %v", record, getErr)
			}
		})
	}
}

func TestDurablePlanRemotePreconditionsStillRefuseDispatch(t *testing.T) {
	for _, mode := range []string{"project", "archived", "updated", "schema", "account", "comment updated"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newOperatorFixture(t)
			kind := "issue.update"
			if mode == "comment updated" {
				kind = "comment.add"
			}
			plan := fixture.prepare(t, kind)
			fixture.service.Now = func() time.Time { return plan.Plan.CreatedAt.Add(72 * time.Hour) }
			fixture.mu.Lock()
			switch mode {
			case "project":
				fixture.issue = strings.Replace(fixture.issue, `"shortName":"APP"`, `"shortName":"OTHER"`, 1)
			case "archived":
				fixture.issue = strings.Replace(fixture.issue, `"archived":false`, `"archived":true`, 1)
			case "updated", "comment updated":
				fixture.issue = strings.Replace(fixture.issue, `"updated":2`, `"updated":3`, 1)
			case "schema":
				fixture.schema = strings.Replace(fixture.schema, `"canBeEmpty":true`, `"canBeEmpty":false`, 1)
			case "account":
				fixture.service.HTTP = accountMismatchTransport{base: fixture.service.HTTP}
			}
			fixture.mu.Unlock()
			_, err := fixture.service.ApplyOperatorWrite(t.Context(), OperatorApplyInput{Profile: "work", PlanID: plan.PlanID, ConfirmIntent: plan.IntentSHA256, Yes: true})
			if err == nil || fixture.posts.Load() != 0 {
				t.Fatalf("error=%v posts=%d", err, fixture.posts.Load())
			}
			record, getErr := fixture.service.OperatorWrites.Get(t.Context(), plan.PlanID)
			if getErr != nil || record.NonReplayable() {
				t.Fatalf("remote refusal consumed plan: %#v %v", record, getErr)
			}
		})
	}
}

type accountMismatchTransport struct {
	base http.RoundTripper
}

func (transport accountMismatchTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Path == "/api/users/me" {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"id":"1-9","login":"other"}`)), Request: request}, nil
	}
	return transport.base.RoundTrip(request)
}
