package secretstore

import "testing"

func TestModeFixer(t *testing.T) {
	tests := []struct {
		name  string
		calls []Interaction
		want  []bool
	}{
		{"first call fixes the mode", []Interaction{InteractionAllowed}, []bool{true}},
		{"same mode is accepted again", []Interaction{InteractionNever, InteractionNever}, []bool{true, true}},
		{"other mode is refused", []Interaction{InteractionNever, InteractionAllowed}, []bool{true, false}},
		{"refusal does not flip the mode", []Interaction{InteractionAllowed, InteractionNever, InteractionAllowed}, []bool{true, false, true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var f modeFixer
			for i, mode := range tt.calls {
				if got := f.fix(mode); got != tt.want[i] {
					t.Fatalf("call %d (%d): got %v, want %v", i, mode, got, tt.want[i])
				}
			}
		})
	}
}

func TestOpenModeFixation(t *testing.T) {
	for _, name := range []string{"mode-conflict", "failed-first-open", "invalid-options-do-not-record"} {
		t.Run(name, func(t *testing.T) {
			runHelperProcess(t, name)
		})
	}
}
