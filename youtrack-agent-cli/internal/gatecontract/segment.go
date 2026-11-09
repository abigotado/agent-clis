package gatecontract

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/abigotado/youtrack-agent-cli/internal/protocolvalue"
)

// MaxSegmentContractBytes bounds input before JSON decoding or field allocation.
const MaxSegmentContractBytes = 4096

const segmentContractObjectType = "gate1b_isolated_segment_contract_v1"

// SegmentContract is immutable canonical syntax with bounded count domains.
// Counts and digests are declarations, not verified evidence or resolved references.
// ParseSegmentContract is the only constructor; the zero value cannot encode or hash.
type SegmentContract struct {
	wire segmentContractWire
}

type segmentContractWire struct {
	SchemaVersion         int    `json:"schema_version"`
	ObjectType            string `json:"object_type"`
	SegmentOrdinal        int    `json:"segment_ordinal"`
	Mode                  string `json:"mode"`
	CommandContractSHA256 string `json:"command_contract_sha256"`
	FixtureSetSHA256      string `json:"fixture_set_sha256"`
	AssertionSetSHA256    string `json:"assertion_set_sha256"`
	TranscriptSetSHA256   string `json:"transcript_set_sha256"`
	OperationCount        int    `json:"operation_count"`
	ObservationCount      int    `json:"observation_count"`
	TranscriptCount       int    `json:"transcript_count"`
	AssertionCount        int    `json:"assertion_count"`
	FileCount             int    `json:"file_count"`
	MaximumEvidenceBytes  int    `json:"maximum_evidence_bytes"`
}

// ParseSegmentContract accepts only exact compact canonical segment syntax.
// It does not verify count relationships, compiled trees, files, or authority.
func ParseSegmentContract(raw []byte) (SegmentContract, error) {
	if len(raw) == 0 || len(raw) > MaxSegmentContractBytes {
		return SegmentContract{}, errors.New("segment contract input is empty or exceeds the byte limit")
	}
	var wire segmentContractWire
	if err := json.Unmarshal(raw, &wire); err != nil {
		// Decoder diagnostics may contain attacker-controlled field names or values.
		return SegmentContract{}, errors.New("segment contract JSON is malformed")
	}
	segment := SegmentContract{wire: wire}
	canonical, err := segment.CanonicalBytes()
	if err != nil {
		return SegmentContract{}, err
	}
	// Exact re-encoding rejects duplicate/missing/unknown/reordered/null fields,
	// alternate number or string encoding, whitespace and invalid UTF-8.
	if !bytes.Equal(raw, canonical) {
		return SegmentContract{}, errors.New("segment contract JSON is not canonical")
	}
	return segment, nil
}

// CanonicalBytes returns fresh canonical bytes, rejecting an unconstructed value.
func (s SegmentContract) CanonicalBytes() ([]byte, error) {
	if !s.valid() {
		return nil, errors.New("segment contract fields are invalid")
	}
	raw, err := json.Marshal(s.wire)
	if err != nil {
		return nil, errors.New("segment contract JSON encoding failed")
	}
	return raw, nil
}

// DigestSHA256 hashes complete canonical bytes without a domain prefix.
// It does not establish reference closure, evidence integrity, or authority.
func (s SegmentContract) DigestSHA256() (string, error) {
	raw, err := s.CanonicalBytes()
	if err != nil {
		return "", err
	}
	return protocolvalue.SHA256Hex(raw), nil
}

func (s SegmentContract) valid() bool {
	w := s.wire
	if w.SchemaVersion != 1 || w.ObjectType != segmentContractObjectType ||
		!(w.SegmentOrdinal == 1 && w.Mode == "scenario" || w.SegmentOrdinal == 2 && w.Mode == "reboot_observer") {
		return false
	}
	if w.OperationCount < 1 || w.OperationCount > 128 ||
		w.ObservationCount < 1 || w.ObservationCount > 256 ||
		w.TranscriptCount < 1 || w.TranscriptCount > 2048 ||
		w.AssertionCount < 1 || w.AssertionCount > 256 ||
		w.FileCount < 1 || w.FileCount > 4096 ||
		w.MaximumEvidenceBytes < 1 || w.MaximumEvidenceBytes > 268435456 {
		return false
	}
	for _, digest := range [...]string{w.CommandContractSHA256, w.FixtureSetSHA256,
		w.AssertionSetSHA256, w.TranscriptSetSHA256} {
		if !protocolvalue.IsSHA256(digest) {
			return false
		}
	}
	return true
}

// SchemaVersion returns the schema version.
func (s SegmentContract) SchemaVersion() int { return s.wire.SchemaVersion }

// ObjectType returns the object type discriminator.
func (s SegmentContract) ObjectType() string { return s.wire.ObjectType }

// SegmentOrdinal returns the declared segment ordinal.
func (s SegmentContract) SegmentOrdinal() int { return s.wire.SegmentOrdinal }

// Mode returns the segment mode paired with its ordinal.
func (s SegmentContract) Mode() string { return s.wire.Mode }

// CommandContractSHA256 returns the unchecked command contract reference.
func (s SegmentContract) CommandContractSHA256() string { return s.wire.CommandContractSHA256 }

// FixtureSetSHA256 returns the unchecked fixture set reference.
func (s SegmentContract) FixtureSetSHA256() string { return s.wire.FixtureSetSHA256 }

// AssertionSetSHA256 returns the unchecked assertion set reference.
func (s SegmentContract) AssertionSetSHA256() string { return s.wire.AssertionSetSHA256 }

// TranscriptSetSHA256 returns the unchecked transcript set reference.
func (s SegmentContract) TranscriptSetSHA256() string { return s.wire.TranscriptSetSHA256 }

// OperationCount returns the declared operation count.
func (s SegmentContract) OperationCount() int { return s.wire.OperationCount }

// ObservationCount returns the declared observation count.
func (s SegmentContract) ObservationCount() int { return s.wire.ObservationCount }

// TranscriptCount returns the declared transcript count.
func (s SegmentContract) TranscriptCount() int { return s.wire.TranscriptCount }

// AssertionCount returns the declared assertion count.
func (s SegmentContract) AssertionCount() int { return s.wire.AssertionCount }

// FileCount returns the declared file count.
func (s SegmentContract) FileCount() int { return s.wire.FileCount }

// MaximumEvidenceBytes returns the declared evidence byte budget.
func (s SegmentContract) MaximumEvidenceBytes() int { return s.wire.MaximumEvidenceBytes }
