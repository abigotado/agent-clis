package gatecontract_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/gatecontract"
)

type segmentPositive struct {
	Name, Raw, SHA256, Mode string
	Ordinal                 int
	Counts                  []int
}

type segmentNegative struct {
	Name, Base, SHA256 string
	Offset, Delete     int
	InsertHex          string `json:"insert_hex"`
}

type segmentCatalog struct {
	Version   int `json:"schema_version"`
	Positives []segmentPositive
	Negatives []segmentNegative
}

func loadSegmentContracts(t *testing.T) segmentCatalog {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/gate1b-isolated-segment/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var catalog segmentCatalog
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&catalog); err != nil {
		t.Fatal(err)
	}
	if catalog.Version != 1 || len(catalog.Positives) != 8 || len(catalog.Negatives) != 196 {
		t.Fatal("unexpected shared catalog shape")
	}
	return catalog
}

func segmentHash(raw []byte) string { return fmt.Sprintf("%x", sha256.Sum256(raw)) }

func TestSegmentContractSharedCanonicalVectors(t *testing.T) {
	catalog := loadSegmentContracts(t)
	seen := map[string]bool{}
	for _, vector := range catalog.Positives {
		if seen[vector.Name] {
			t.Fatal("duplicate positive name")
		}
		seen[vector.Name] = true
		t.Run(vector.Name, func(t *testing.T) {
			source := []byte(vector.Raw)
			if segmentHash(source) != vector.SHA256 {
				t.Fatal("positive fixture digest mismatch")
			}
			segment, err := gatecontract.ParseSegmentContract(source)
			if err != nil {
				t.Fatal(err)
			}
			if segment.SchemaVersion() != 1 || segment.ObjectType() != "gate1b_isolated_segment_contract_v1" || segment.Mode() != vector.Mode || segment.SegmentOrdinal() != vector.Ordinal {
				t.Fatal("header/mode/ordinal changed")
			}
			digests := []string{segment.CommandContractSHA256(), segment.FixtureSetSHA256(), segment.AssertionSetSHA256(), segment.TranscriptSetSHA256()}
			for i, digest := range digests {
				if digest != strings.Repeat(fmt.Sprint(i+1), 64) {
					t.Fatalf("digest field %d changed", i)
				}
			}
			counts := []int{segment.OperationCount(), segment.ObservationCount(), segment.TranscriptCount(), segment.AssertionCount(), segment.FileCount(), segment.MaximumEvidenceBytes()}
			if len(vector.Counts) != len(counts) {
				t.Fatal("wrong expected counter shape")
			}
			for i, count := range counts {
				if count != vector.Counts[i] {
					t.Fatalf("counter %d changed", i)
				}
			}
			source[0] = '[' // The parsed value must not retain mutable caller storage.
			encoded, err := segment.CanonicalBytes()
			if err != nil || string(encoded) != vector.Raw {
				t.Fatalf("canonical bytes mismatch: %v", err)
			}
			digest, err := segment.DigestSHA256()
			if err != nil || digest != vector.SHA256 {
				t.Fatalf("segment digest mismatch: %v", err)
			}
			encoded[0] = '[' // Returned bytes must likewise be caller-owned.
			again, err := segment.CanonicalBytes()
			if err != nil || string(again) != vector.Raw {
				t.Fatalf("mutable output escaped: %v", err)
			}
			roundTrip, err := gatecontract.ParseSegmentContract(again)
			if err != nil {
				t.Fatal(err)
			}
			roundDigest, err := roundTrip.DigestSHA256()
			if err != nil || roundDigest != vector.SHA256 {
				t.Fatal("round-trip digest changed")
			}
		})
	}
}

func TestSegmentContractSharedMalformedVectors(t *testing.T) {
	catalog := loadSegmentContracts(t)
	bases := map[string]string{}
	for _, vector := range catalog.Positives {
		bases[vector.Name] = vector.Raw
	}
	seen := map[string]bool{}
	for _, vector := range catalog.Negatives {
		if seen[vector.Name] {
			t.Fatal("duplicate negative name")
		}
		seen[vector.Name] = true
		t.Run(vector.Name, func(t *testing.T) {
			base, ok := bases[vector.Base]
			if !ok {
				t.Fatal("unknown negative base")
			}
			if vector.Offset < 0 || vector.Offset > len(base) || vector.Delete < 0 || vector.Delete > len(base)-vector.Offset {
				t.Fatal("invalid splice bounds")
			}
			insert, err := hex.DecodeString(vector.InsertHex)
			if err != nil || hex.EncodeToString(insert) != vector.InsertHex {
				t.Fatal("invalid splice hex")
			}
			raw := append([]byte(base[:vector.Offset]), insert...)
			raw = append(raw, base[vector.Offset+vector.Delete:]...)
			if segmentHash(raw) != vector.SHA256 {
				t.Fatal("expanded fixture digest mismatch")
			}
			segment, err := gatecontract.ParseSegmentContract(raw)
			if err == nil {
				t.Fatal("malformed segment accepted")
			}
			if output, err := segment.CanonicalBytes(); err == nil || len(output) != 0 {
				t.Fatal("failed parse returned usable bytes")
			}
			if digest, err := segment.DigestSHA256(); err == nil || digest != "" {
				t.Fatal("failed parse returned usable digest")
			}
		})
	}
}

func TestSegmentContractZeroValueFailsClosed(t *testing.T) {
	var segment gatecontract.SegmentContract
	if raw, err := segment.CanonicalBytes(); err == nil || len(raw) != 0 {
		t.Fatal("zero segment encoded")
	}
	if digest, err := segment.DigestSHA256(); err == nil || digest != "" {
		t.Fatal("zero segment hashed")
	}
}
