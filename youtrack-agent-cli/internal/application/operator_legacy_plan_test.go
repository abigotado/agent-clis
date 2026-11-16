package application

import (
	"encoding/json"
	"testing"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/operatorwrite"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/protocolvalue"
)

// storeMarkerPlan stores a plan in the shape older releases prepared: the
// visible marker appended to the request text, under an older plan version. It
// lets the marker path keep its tests now that Prepare no longer produces it.
func storeMarkerPlan(t *testing.T, service *Service, snapshot operatorwrite.Snapshot, request operatorwrite.Request, version int) OperatorWriteInfo {
	t.Helper()
	plan, err := operatorwrite.Prepare(snapshot, request, service.currentTime())
	if err != nil {
		t.Fatal(err)
	}
	switch plan.Request.Kind {
	case operatorwrite.KindIssueCreate:
		if plan.Request.Description == "" {
			plan.Request.Description = operatorwrite.Marker(plan.ID)
		} else {
			plan.Request.Description += "\n\n" + operatorwrite.Marker(plan.ID)
		}
	case operatorwrite.KindCommentAdd:
		plan.Request.CommentText += "\n\n" + operatorwrite.Marker(plan.ID)
	}
	plan.Version = version
	plan.SHA256 = ""
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	plan.SHA256 = protocolvalue.SHA256Hex(raw)
	if !plan.CarriesMarker() {
		t.Fatalf("version %d does not carry a marker", version)
	}
	record, err := service.OperatorWrites.Create(t.Context(), plan)
	if err != nil {
		t.Fatal(err)
	}
	return operatorRecordInfo(record)
}
