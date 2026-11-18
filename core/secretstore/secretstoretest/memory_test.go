package secretstoretest

import (
	"context"
	"errors"
	"testing"

	"github.com/abigotado/agent-clis/core/secretstore"
)

func TestMemoryContract(t *testing.T) {
	for _, tt := range []struct {
		name string
		max  int
	}{
		{"smallest suite bound", minContractBound},
		{"typical bound", 4096},
		{"package limit", secretstore.MaxSecretBytesLimit},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := NewMemory(secretstore.Options{MaxSecretBytes: tt.max})
			// Contract cleans up when its own subtest ends, so the check
			// below runs after that.
			t.Run("suite", func(t *testing.T) { Contract(t, store, tt.max) })
			if n := len(store.items); n != 0 {
				t.Fatalf("Contract left %d items behind", n)
			}
		})
	}
}

var errInjected = errors.New("injected")

func memoryWith(t *testing.T, interaction secretstore.Interaction) (*Memory, secretstore.Key) {
	t.Helper()
	m := NewMemory(secretstore.Options{MaxSecretBytes: 64, Interaction: interaction})
	key := secretstore.Key{Service: "svc", Account: "acct"}
	if err := m.Save(t.Context(), key, []byte("v")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return m, key
}

func callOp(ctx context.Context, m *Memory, op Op, key secretstore.Key) error {
	switch op {
	case OpExists:
		_, err := m.Exists(ctx, key)
		return err
	case OpLoad:
		_, err := m.Load(ctx, key)
		return err
	case OpSave:
		return m.Save(ctx, key, []byte("new"))
	case OpDelete:
		return m.Delete(ctx, key)
	default:
		return m.RepairAccess(ctx, key)
	}
}

func TestMemoryErrorInjection(t *testing.T) {
	ops := []Op{OpExists, OpLoad, OpSave, OpDelete, OpRepair}
	for _, op := range ops {
		t.Run(op.String(), func(t *testing.T) {
			m, key := memoryWith(t, secretstore.InteractionAllowed)
			m.SetErr(op, errInjected)

			if err := callOp(t.Context(), m, op, key); !errors.Is(err, errInjected) {
				t.Fatalf("injected %v: got %v", op, err)
			}
			for _, other := range ops {
				if other == op {
					continue
				}
				if err := callOp(t.Context(), m, other, key); errors.Is(err, errInjected) {
					t.Fatalf("injection into %v leaked into %v", op, other)
				}
			}

			m.SetErr(op, nil)
			if err := callOp(t.Context(), m, op, key); errors.Is(err, errInjected) {
				t.Fatalf("SetErr(%v, nil) did not clear the error: %v", op, err)
			}
		})
	}

	t.Run("a failed save and delete change nothing", func(t *testing.T) {
		m, key := memoryWith(t, secretstore.InteractionNever)
		m.SetErr(OpSave, errInjected)
		m.SetErr(OpDelete, errInjected)
		if err := m.Save(t.Context(), key, []byte("new")); !errors.Is(err, errInjected) {
			t.Fatalf("Save: %v", err)
		}
		if err := m.Delete(t.Context(), key); !errors.Is(err, errInjected) {
			t.Fatalf("Delete: %v", err)
		}
		got, err := m.Load(t.Context(), key)
		if err != nil || string(got) != "v" {
			t.Fatalf("Load = %q, %v; want the seeded value", got, err)
		}
	})

	t.Run("checks that precede store access win over an injected error", func(t *testing.T) {
		m, key := memoryWith(t, secretstore.InteractionAllowed)
		for _, op := range ops {
			m.SetErr(op, errInjected)
		}
		canceled, cancel := context.WithCancel(t.Context())
		cancel()
		for _, op := range ops {
			if err := callOp(canceled, m, op, key); !errors.Is(err, context.Canceled) {
				t.Errorf("%v with a canceled context: %v", op, err)
			}
			if err := callOp(t.Context(), m, op, secretstore.Key{}); !errors.Is(err, secretstore.ErrInvalidArgument) {
				t.Errorf("%v with an invalid key: %v", op, err)
			}
		}
		if err := m.Save(t.Context(), key, make([]byte, 65)); !errors.Is(err, secretstore.ErrTooLarge) {
			t.Errorf("Save above the bound: %v", err)
		}
	})

	t.Run("an unknown op is ignored", func(t *testing.T) {
		m, key := memoryWith(t, secretstore.InteractionAllowed)
		m.SetErr(Op(99), errInjected)
		m.SetErr(Op(-1), errInjected)
		for _, op := range ops {
			if err := callOp(t.Context(), m, op, key); errors.Is(err, errInjected) {
				t.Fatalf("%v returned an injected error for an unknown op", op)
			}
		}
	})
}

func TestMemoryRepairAccess(t *testing.T) {
	tests := []struct {
		name        string
		interaction secretstore.Interaction
		key         secretstore.Key
		want        error
	}{
		{"refused without interaction", secretstore.InteractionNever, secretstore.Key{Service: "svc", Account: "acct"}, secretstore.ErrInteractionRequired},
		{"refused before it looks for the item", secretstore.InteractionNever, secretstore.Key{Service: "svc", Account: "missing"}, secretstore.ErrInteractionRequired},
		{"repairs an existing item", secretstore.InteractionAllowed, secretstore.Key{Service: "svc", Account: "acct"}, nil},
		{"missing item", secretstore.InteractionAllowed, secretstore.Key{Service: "svc", Account: "missing"}, secretstore.ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, _ := memoryWith(t, tt.interaction)
			var repairer secretstore.ACLRepairer = m
			err := repairer.RepairAccess(t.Context(), tt.key)
			if tt.want == nil {
				if err != nil {
					t.Fatalf("RepairAccess: %v", err)
				}
				return
			}
			var se *secretstore.Error
			if !errors.Is(err, tt.want) || !errors.As(err, &se) || se.Op != "repair" || se.Backend != "memory" {
				t.Fatalf("RepairAccess = %#v, want a repair/memory %v", err, tt.want)
			}
		})
	}

	t.Run("a refused repair leaves the item untouched", func(t *testing.T) {
		m, key := memoryWith(t, secretstore.InteractionNever)
		if err := m.RepairAccess(t.Context(), key); !errors.Is(err, secretstore.ErrInteractionRequired) {
			t.Fatalf("RepairAccess: %v", err)
		}
		if got, err := m.Load(t.Context(), key); err != nil || string(got) != "v" {
			t.Fatalf("Load = %q, %v", got, err)
		}
	})
}

func TestMemoryRejectsInvalidOptions(t *testing.T) {
	key := secretstore.Key{Service: "svc", Account: "acct"}
	for _, tt := range []struct {
		name string
		opts secretstore.Options
	}{
		{"zero bound", secretstore.Options{}},
		{"above the limit", secretstore.Options{MaxSecretBytes: secretstore.MaxSecretBytesLimit + 1}},
		{"unknown interaction", secretstore.Options{MaxSecretBytes: 10, Interaction: 7}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMemory(tt.opts)
			for _, op := range []Op{OpExists, OpLoad, OpSave, OpDelete, OpRepair} {
				if err := callOp(t.Context(), m, op, key); !errors.Is(err, secretstore.ErrInvalidArgument) {
					t.Errorf("%v: %v, want ErrInvalidArgument", op, err)
				}
			}
		})
	}
}

func TestMemoryKeysAreCaseSensitive(t *testing.T) {
	m := NewMemory(secretstore.Options{MaxSecretBytes: 16})
	lower := secretstore.Key{Service: "svc", Account: "acct"}
	upper := secretstore.Key{Service: "svc", Account: "ACCT"}
	if err := m.Save(t.Context(), lower, []byte("v")); err != nil {
		t.Fatal(err)
	}
	if ok, err := m.Exists(t.Context(), upper); err != nil || ok {
		t.Fatalf("Exists(%v) = %v, %v; want false", upper, ok, err)
	}
}

func TestZeroMemoryDoesNotPanic(t *testing.T) {
	var m Memory
	m.SetErr(OpLoad, errors.New("injected"))
	m.SetErr(OpLoad, nil)
	key := secretstore.Key{Service: "svc", Account: "acct"}
	if _, err := m.Load(t.Context(), key); !errors.Is(err, secretstore.ErrInvalidArgument) {
		t.Fatalf("Load on a zero Memory = %v, want ErrInvalidArgument", err)
	}
	if err := m.Save(t.Context(), key, []byte("x")); !errors.Is(err, secretstore.ErrInvalidArgument) {
		t.Fatalf("Save on a zero Memory = %v, want ErrInvalidArgument", err)
	}
}
