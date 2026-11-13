package cli

import (
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/operatorwrite"
)

func TestDurableStatusExplicitExpiryProjectionKeepsSelectableField(t *testing.T) {
	service, credentials, posts := operatorCLIService(t)
	plan, _ := operatorCLIPlan(t, service)
	credentials.loads = 0
	app, _, _, _, stdout, stderr := testApp(t)
	app.service = service
	code := runApp(app, "operator-write", "status", "--plan-id", plan.PlanID,
		"--fields", "plan_version,plan_lifetime,expires_at", "-o", "json")
	if code != errx.CodeOK || stderr.Len() != 0 || credentials.loads != 0 || posts.Load() != 0 {
		t.Fatalf("status code=%d loads=%d posts=%d stdout=%s stderr=%s", code, credentials.loads, posts.Load(), stdout, stderr)
	}
	data := decode(t, stdout)["data"].(map[string]any)
	if data["plan_version"] != float64(operatorwrite.PlanVersion5) ||
		data["plan_lifetime"] != operatorwrite.CurrentPlanLifetime {
		t.Fatalf("durable lifetime metadata=%#v", data)
	}
	if expiry, present := data["expires_at"]; !present || expiry != "" {
		t.Fatalf("explicit expiry projection=%#v, present=%v", expiry, present)
	}
}
