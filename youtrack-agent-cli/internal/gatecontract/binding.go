// Package gatecontract implements bounded canonical syntax for Gate evidence.
// Parsing does not verify reference closure, authenticity, or authority.
package gatecontract

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/abigotado/youtrack-agent-cli/internal/protocolvalue"
)

// MaxBindingBytes bounds input before JSON decoding or field allocation.
const MaxBindingBytes = 4096

const bindingObjectType = "gate1b_isolated_binding_v1"

// Binding is an immutable, syntax-validated isolated binding. Its digest fields
// are unchecked references, not proof that the referenced objects exist or agree.
// ParseBinding is the only constructor; the zero value cannot encode or hash.
type Binding struct {
	wire bindingWire
}

type bindingWire struct {
	SchemaVersion           int    `json:"schema_version"`
	ObjectType              string `json:"object_type"`
	DescriptorSHA256        string `json:"descriptor_sha256"`
	CoverageInventorySHA256 string `json:"coverage_inventory_sha256"`
	UnitDefinitionSHA256    string `json:"unit_definition_sha256"`
	Pass                    string `json:"pass"`
	Architecture            string `json:"architecture"`
	HostInventorySHA256     string `json:"host_inventory_sha256"`
	TargetAllocationSHA256  string `json:"target_allocation_sha256"`
	GateTargetSHA256        string `json:"gate_target_sha256"`
}

// ParseBinding accepts only the exact compact canonical binding encoding.
// It performs local syntax checks only and retains no alias to raw.
func ParseBinding(raw []byte) (Binding, error) {
	if len(raw) == 0 || len(raw) > MaxBindingBytes {
		return Binding{}, errors.New("binding input is empty or exceeds the byte limit")
	}
	var wire bindingWire
	if err := json.Unmarshal(raw, &wire); err != nil {
		// Decoder errors can include attacker-controlled field names or values.
		return Binding{}, errors.New("binding JSON is malformed")
	}
	binding := Binding{wire: wire}
	canonical, err := binding.CanonicalBytes()
	if err != nil {
		return Binding{}, err
	}
	// Exact re-encoding also rejects duplicate, missing, unknown, reordered,
	// case-folded and null fields, alternate escaping, whitespace and invalid UTF-8.
	if !bytes.Equal(raw, canonical) {
		return Binding{}, errors.New("binding JSON is not canonical")
	}
	return binding, nil
}

// CanonicalBytes returns fresh canonical bytes, rejecting an unconstructed value.
func (b Binding) CanonicalBytes() ([]byte, error) {
	if !b.valid() {
		return nil, errors.New("binding fields are invalid")
	}
	raw, err := json.Marshal(b.wire)
	if err != nil {
		return nil, errors.New("binding JSON encoding failed")
	}
	return raw, nil
}

// DigestSHA256 hashes complete canonical bytes without a domain prefix.
// A digest is not a reference-closure, authenticity, or authority verdict.
func (b Binding) DigestSHA256() (string, error) {
	raw, err := b.CanonicalBytes()
	if err != nil {
		return "", err
	}
	return protocolvalue.SHA256Hex(raw), nil
}

func (b Binding) valid() bool {
	w := b.wire
	if w.SchemaVersion != 1 || w.ObjectType != bindingObjectType ||
		(w.Pass != "e1" && w.Pass != "e2") ||
		(w.Architecture != "arm64" && w.Architecture != "x86_64") {
		return false
	}
	for _, digest := range [...]string{w.DescriptorSHA256, w.CoverageInventorySHA256,
		w.UnitDefinitionSHA256, w.HostInventorySHA256, w.TargetAllocationSHA256, w.GateTargetSHA256} {
		if !protocolvalue.IsSHA256(digest) {
			return false
		}
	}
	return true
}

// SchemaVersion returns the schema version.
func (b Binding) SchemaVersion() int { return b.wire.SchemaVersion }

// ObjectType returns the object type discriminator.
func (b Binding) ObjectType() string { return b.wire.ObjectType }

// DescriptorSHA256 returns the unchecked descriptor reference.
func (b Binding) DescriptorSHA256() string { return b.wire.DescriptorSHA256 }

// CoverageInventorySHA256 returns the unchecked coverage inventory reference.
func (b Binding) CoverageInventorySHA256() string { return b.wire.CoverageInventorySHA256 }

// UnitDefinitionSHA256 returns the unchecked unit definition reference.
func (b Binding) UnitDefinitionSHA256() string { return b.wire.UnitDefinitionSHA256 }

// Pass returns the isolated pass identifier.
func (b Binding) Pass() string { return b.wire.Pass }

// Architecture returns the declared, not observed, architecture.
func (b Binding) Architecture() string { return b.wire.Architecture }

// HostInventorySHA256 returns the unchecked host inventory reference.
func (b Binding) HostInventorySHA256() string { return b.wire.HostInventorySHA256 }

// TargetAllocationSHA256 returns the unchecked target allocation reference.
func (b Binding) TargetAllocationSHA256() string { return b.wire.TargetAllocationSHA256 }

// GateTargetSHA256 returns the unchecked Gate target reference.
func (b Binding) GateTargetSHA256() string { return b.wire.GateTargetSHA256 }
