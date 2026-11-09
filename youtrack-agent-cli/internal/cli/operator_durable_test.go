package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/operatorwrite"
)

func TestOperatorCLIDurableApplyUsesSavedDefaultAndOmitsExpiryFromJSONAndRaw(t *testing.T) {
	service, credentials, posts := operatorCLIService(t)
	if _, err := service.ChangeProfileDefaults(t.Context(), nil, funcName("work"), false); err != nil {
		t.Fatal(err)
	}
	plan, _ := operatorCLIPlan(t, service)
	service.Now = func() time.Time { return plan.Plan.CreatedAt.Add(48 * time.Hour) }
	credentials.loads = 0
	app, _, _, _, stdout, stderr := testApp(t)
	app.service = service
	code := runApp(app, "operator-write", "apply", "--plan-id", plan.PlanID, "--confirm-intent", plan.IntentSHA256, "--yes", "-o", "json")
	if code != errx.CodeOK || credentials.loads != 1 || posts.Load() != 1 || stderr.Len() != 0 {
		t.Fatalf("code=%d loads=%d posts=%d stdout=%s stderr=%s", code, credentials.loads, posts.Load(), stdout, stderr)
	}
	data := decode(t, stdout)["data"].(map[string]any)
	if data["plan_version"] != float64(operatorwrite.PlanVersion2) || data["plan_lifetime"] != operatorwrite.CurrentPlanLifetime {
		t.Fatalf("durable json metadata=%#v", data)
	}
	if _, exists := data["expires_at"]; exists {
		t.Fatalf("durable json exposed a legacy expiry: %#v", data)
	}

	app, _, _, _, stdout, stderr = testApp(t)
	app.service = service
	code = runApp(app, "operator-write", "status", "--plan-id", plan.PlanID, "-o", "raw")
	if code != errx.CodeOK || stderr.Len() != 0 {
		t.Fatalf("raw status code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	var raw map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if raw["plan_version"] != float64(operatorwrite.PlanVersion2) || raw["plan_lifetime"] != operatorwrite.CurrentPlanLifetime {
		t.Fatalf("durable raw metadata=%#v", raw)
	}
	if _, exists := raw["expires_at"]; exists {
		t.Fatalf("durable raw exposed a legacy expiry: %#v", raw)
	}
}

func TestOperatorCLIStatusProjectsLegacyPlanLifetimeAndExpiry(t *testing.T) {
	service, _, _ := operatorCLIService(t)
	raw, err := os.ReadFile("../operatorwrite/testdata/plan-v1-comment-add.json")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := operatorwrite.DecodePlan(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.OperatorWrites.Create(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	app, _, _, _, stdout, stderr := testApp(t)
	app.service = service
	code := runApp(app, "operator-write", "status", "--plan-id", plan.ID, "-o", "raw")
	if code != errx.CodeOK || stderr.Len() != 0 {
		t.Fatalf("legacy status code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["plan_version"] != float64(operatorwrite.LegacyPlanVersion1) || result["plan_lifetime"] != operatorwrite.LegacyPlanLifetime || result["expires_at"] != plan.ExpiresAt.Format(time.RFC3339) {
		t.Fatalf("legacy status projection=%#v", result)
	}
}
