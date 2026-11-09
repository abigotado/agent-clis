package intent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestValidatePlanIDSharedCorpus(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "gate1a", "plan-id-corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Valid   []string `json:"valid"`
		Invalid []string `json:"invalid"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range corpus.Valid {
		if err := ValidatePlanID(candidate); err != nil {
			t.Errorf("valid shared plan ID %q: %v", candidate, err)
		}
	}
	for _, candidate := range corpus.Invalid {
		if err := ValidatePlanID(candidate); !errors.Is(err, ErrInvalidPlan) {
			t.Errorf("invalid shared plan ID %q error = %v", candidate, err)
		}
	}
}

func TestValidatePlanIDRequiresCanonical128BitBase32(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "zero payload", value: "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{name: "nonzero payload", value: "YTAP-AAAQEAYEAUDAOCAJBIFQYDIOB4"},
		{name: "wrong prefix", value: "YTAR-AAAQEAYEAUDAOCAJBIFQYDIOB4", wantErr: true},
		{name: "short", value: "YTAP-AAAQEAYEAUDAOCAJBIFQYDIOB", wantErr: true},
		{name: "padding", value: "YTAP-AAAQEAYEAUDAOCAJBIFQYDIOB=", wantErr: true},
		{name: "lowercase", value: "YTAP-aaaQEAYEAUDAOCAJBIFQYDIOB4", wantErr: true},
		{name: "invalid alphabet", value: "YTAP-AAAQEAYEAUDAOCAJBIFQYDIOB1", wantErr: true},
		{name: "noncanonical final bits", value: "YTAP-AAAQEAYEAUDAOCAJBIFQYDIOB5", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePlanID(tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidatePlanID(%q) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, ErrInvalidPlan) {
				t.Fatalf("error = %v, want ErrInvalidPlan", err)
			}
		})
	}
}
