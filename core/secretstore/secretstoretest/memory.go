// Package secretstoretest provides an in-memory secretstore.Store for tests and
// Contract, a behaviour suite every secretstore.Store implementation must pass.
package secretstoretest

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/abigotado/agent-clis/core/secretstore"
	"github.com/abigotado/agent-clis/core/secretstore/internal/rules"
)

// Op names a Memory operation for SetErr.
type Op int

// The operations an error can be injected into.
const (
	OpExists Op = iota
	OpLoad
	OpSave
	OpDelete
	OpRepair
)

// String returns the operation name used in secretstore.Error.Op.
func (o Op) String() string {
	switch o {
	case OpExists:
		return "exists"
	case OpLoad:
		return "load"
	case OpSave:
		return "save"
	case OpDelete:
		return "delete"
	case OpRepair:
		return "repair"
	default:
		return fmt.Sprintf("op(%d)", int(o))
	}
}

// Memory is a goroutine-safe in-memory store. It validates keys and sizes the
// way the real stores do, copies secrets on the way in and out, compares keys
// case-sensitively, and can be made to fail per operation with SetErr. It
// implements secretstore.Store and secretstore.ACLRepairer.
//
// The zero value is usable but has no valid options: SetErr works, and every
// store operation fails with secretstore.ErrInvalidArgument, exactly like a
// Memory built by NewMemory with invalid options. Use NewMemory for a working
// store.
type Memory struct {
	max         int
	interaction secretstore.Interaction
	optionsOK   bool

	mu    sync.Mutex
	items map[secretstore.Key][]byte
	errs  map[Op]error
}

var (
	_ secretstore.Store       = (*Memory)(nil)
	_ secretstore.ACLRepairer = (*Memory)(nil)
)

// NewMemory returns an empty store. Options are checked like secretstore.Open
// checks them; with invalid options every operation fails with
// secretstore.ErrInvalidArgument instead of NewMemory panicking.
func NewMemory(opts secretstore.Options) *Memory {
	optionsOK := opts.MaxSecretBytes >= 1 && opts.MaxSecretBytes <= secretstore.MaxSecretBytesLimit &&
		(opts.Interaction == secretstore.InteractionNever || opts.Interaction == secretstore.InteractionAllowed)
	return &Memory{
		max:         opts.MaxSecretBytes,
		interaction: opts.Interaction,
		optionsOK:   optionsOK,
		items:       make(map[secretstore.Key][]byte),
	}
}

// SetErr makes op return err, after the checks that run before a real store is
// touched (context, key, size). A nil err clears it. An unknown op is ignored.
func (m *Memory) SetErr(op Op, err error) {
	if op < OpExists || op > OpRepair {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err == nil {
		delete(m.errs, op)
		return
	}
	if m.errs == nil {
		m.errs = make(map[Op]error)
	}
	m.errs[op] = err
}

func (m *Memory) fail(op Op, kind secretstore.Kind) error {
	return &secretstore.Error{Op: op.String(), Backend: "memory", Kind: kind}
}

// check runs the checks every operation performs before it touches the store.
func (m *Memory) check(ctx context.Context, op Op, key secretstore.Key) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("secretstore: %s: %w", op, err)
	}
	if !m.optionsOK || !rules.ValidService(key.Service) || !rules.ValidAccount(key.Account) {
		return m.fail(op, secretstore.KindInvalidArgument)
	}
	return nil
}

// Exists implements secretstore.Store.
func (m *Memory) Exists(ctx context.Context, key secretstore.Key) (bool, error) {
	if err := m.check(ctx, OpExists, key); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.errs[OpExists]; err != nil {
		return false, err
	}
	_, ok := m.items[key]
	return ok, nil
}

// Load implements secretstore.Store. The returned slice is a copy.
func (m *Memory) Load(ctx context.Context, key secretstore.Key) ([]byte, error) {
	if err := m.check(ctx, OpLoad, key); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.errs[OpLoad]; err != nil {
		return nil, err
	}
	secret, ok := m.items[key]
	if !ok {
		return nil, m.fail(OpLoad, secretstore.KindNotFound)
	}
	return bytes.Clone(secret), nil
}

// Save implements secretstore.Store. The store keeps a copy of secret.
func (m *Memory) Save(ctx context.Context, key secretstore.Key, secret []byte) error {
	if err := m.check(ctx, OpSave, key); err != nil {
		return err
	}
	if len(secret) == 0 {
		return m.fail(OpSave, secretstore.KindInvalidArgument)
	}
	if len(secret) > m.max {
		return m.fail(OpSave, secretstore.KindTooLarge)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.errs[OpSave]; err != nil {
		return err
	}
	if m.items == nil {
		m.items = make(map[secretstore.Key][]byte)
	}
	m.items[key] = bytes.Clone(secret)
	return nil
}

// Delete implements secretstore.Store. Deleting a missing item succeeds.
func (m *Memory) Delete(ctx context.Context, key secretstore.Key) error {
	if err := m.check(ctx, OpDelete, key); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.errs[OpDelete]; err != nil {
		return err
	}
	delete(m.items, key)
	return nil
}

// RepairAccess implements secretstore.ACLRepairer. Like the macOS store it
// refuses with ErrInteractionRequired unless the store was opened with
// InteractionAllowed, and it reports ErrNotFound for a missing item. Access
// control does not exist in memory, so a successful repair changes nothing.
func (m *Memory) RepairAccess(ctx context.Context, key secretstore.Key) error {
	if err := m.check(ctx, OpRepair, key); err != nil {
		return err
	}
	if m.interaction != secretstore.InteractionAllowed {
		return m.fail(OpRepair, secretstore.KindInteractionRequired)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.errs[OpRepair]; err != nil {
		return err
	}
	if _, ok := m.items[key]; !ok {
		return m.fail(OpRepair, secretstore.KindNotFound)
	}
	return nil
}
