package cli

import (
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/operatorwrite"
)

func TestCapabilitiesReportsPlanVersionByKind(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"json envelope includes max version and every kind version", []string{"capabilities", "-o", "json"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			app, _, _, _, stdout, stderr := testApp(t)
			if code := runApp(app, test.args...); code != errx.CodeOK || stderr.Len() != 0 {
				t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			data := decode(t, stdout)["data"].(map[string]any)
			if data["plan_version"] != float64(operatorwrite.PlanVersion4) || data["plan_lifetime"] != operatorwrite.CurrentPlanLifetime {
				t.Fatalf("metadata=%#v", data)
			}
			versions, ok := data["plan_versions"].(map[string]any)
			if !ok || versions["issue.create"] != float64(operatorwrite.PlanVersion2) || versions["issue.update"] != float64(operatorwrite.PlanVersion4) ||
				versions["comment.add"] != float64(operatorwrite.PlanVersion2) || versions["comment.delete"] != float64(operatorwrite.PlanVersion3) || versions["issue.edit"] != float64(operatorwrite.PlanVersion4) || len(versions) != 5 {
				t.Fatalf("plan_versions=%#v", data["plan_versions"])
			}
		})
	}
}
