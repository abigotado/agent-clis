package gatecontract_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/gatecontract"
)

func TestIsolatedParsersRedactDecoderOverflow(t *testing.T) {
	parsers := []struct {
		name      string
		raw       string
		wantError string
		parse     func([]byte) error
	}{
		{"binding", loadBindings(t).Positives[0].Raw, "binding JSON is malformed", func(raw []byte) error {
			_, err := gatecontract.ParseBinding(raw)
			return err
		}},
		{"segment", loadSegmentContracts(t).Positives[0].Raw, "segment contract JSON is malformed", func(raw []byte) error {
			_, err := gatecontract.ParseSegmentContract(raw)
			return err
		}},
	}
	for _, parser := range parsers {
		for _, marker := range []string{"987654321098765432109876543210987654321", "123456789012345678901234567890123456789"} {
			t.Run(parser.name+"/"+marker, func(t *testing.T) {
				raw := []byte(strings.Replace(parser.raw, `"schema_version":1`, `"schema_version":`+marker, 1))
				if !json.Valid(raw) || len(raw) > 4096 {
					t.Fatal("redaction probe must be valid in-cap JSON")
				}
				// Control only: demonstrate that the underlying decoder leaks this
				// exact numeric marker before exercising the public codec boundary.
				var control struct {
					Version int `json:"schema_version"`
				}
				controlErr := json.Unmarshal(raw, &control)
				var typeErr *json.UnmarshalTypeError
				if !errors.As(controlErr, &typeErr) || !strings.Contains(controlErr.Error(), marker) {
					t.Fatal("control did not observe the expected marker-bearing decoder error")
				}
				err := parser.parse(raw)
				if err == nil {
					t.Fatal("overflowing schema version accepted")
				}
				if err.Error() != parser.wantError || strings.Contains(err.Error(), marker) {
					t.Fatal("public parser failed to redact decoder error")
				}
				var wrapped *json.UnmarshalTypeError
				if errors.As(err, &wrapped) {
					t.Fatal("public parser retained the sensitive decoder error in its chain")
				}
			})
		}
	}
}
