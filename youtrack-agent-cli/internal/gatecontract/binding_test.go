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

type bindingPositive struct {
	Name, Raw, SHA256, Pass, Architecture string
}

type bindingNegative struct {
	Name, Base, SHA256 string
	Offset, Delete     int
	InsertHex          string `json:"insert_hex"`
}

type bindingCatalog struct {
	Version   int `json:"schema_version"`
	Positives []bindingPositive
	Negatives []bindingNegative
}

func loadBindings(t *testing.T) bindingCatalog {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/gate1b-isolated-binding/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var catalog bindingCatalog
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&catalog); err != nil {
		t.Fatal(err)
	}
	if catalog.Version != 1 || len(catalog.Positives) != 4 || len(catalog.Negatives) != 136 {
		t.Fatal("unexpected shared catalog shape")
	}
	return catalog
}

func bindingHash(raw []byte) string { return fmt.Sprintf("%x", sha256.Sum256(raw)) }

func TestBindingSharedCanonicalVectors(t *testing.T) {
	catalog := loadBindings(t)
	seen := map[string]bool{}
	for _, vector := range catalog.Positives {
		if seen[vector.Name] {
			t.Fatal("duplicate positive name")
		}
		seen[vector.Name] = true
		t.Run(vector.Name, func(t *testing.T) {
			source := []byte(vector.Raw)
			if bindingHash(source) != vector.SHA256 {
				t.Fatal("positive fixture digest mismatch")
			}
			binding, err := gatecontract.ParseBinding(source)
			if err != nil {
				t.Fatal(err)
			}
			if binding.SchemaVersion() != 1 || binding.ObjectType() != "gate1b_isolated_binding_v1" || binding.Pass() != vector.Pass || binding.Architecture() != vector.Architecture {
				t.Fatal("header/pass/architecture changed")
			}
			got := []string{binding.DescriptorSHA256(), binding.CoverageInventorySHA256(), binding.UnitDefinitionSHA256(), binding.HostInventorySHA256(), binding.TargetAllocationSHA256(), binding.GateTargetSHA256()}
			for i, digest := range got {
				if digest != strings.Repeat(fmt.Sprint(i+1), 64) {
					t.Fatalf("digest field %d changed", i)
				}
			}
			source[0] = '[' // The parsed value must not retain mutable caller storage.
			encoded, err := binding.CanonicalBytes()
			if err != nil || string(encoded) != vector.Raw {
				t.Fatalf("canonical bytes mismatch: %v", err)
			}
			digest, err := binding.DigestSHA256()
			if err != nil || digest != vector.SHA256 {
				t.Fatalf("binding digest mismatch: %v", err)
			}
			encoded[0] = '[' // Returned bytes must likewise be caller-owned.
			again, err := binding.CanonicalBytes()
			if err != nil || string(again) != vector.Raw {
				t.Fatalf("mutable output escaped: %v", err)
			}
			roundTrip, err := gatecontract.ParseBinding(again)
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

func TestBindingSharedMalformedVectors(t *testing.T) {
	catalog := loadBindings(t)
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
			if bindingHash(raw) != vector.SHA256 {
				t.Fatal("expanded fixture digest mismatch")
			}
			binding, err := gatecontract.ParseBinding(raw)
			if err == nil {
				t.Fatal("malformed binding accepted")
			}
			if output, err := binding.CanonicalBytes(); err == nil || len(output) != 0 {
				t.Fatal("failed parse returned usable bytes")
			}
			if digest, err := binding.DigestSHA256(); err == nil || digest != "" {
				t.Fatal("failed parse returned usable digest")
			}
		})
	}
}

func TestBindingZeroValueFailsClosed(t *testing.T) {
	var binding gatecontract.Binding
	if raw, err := binding.CanonicalBytes(); err == nil || len(raw) != 0 {
		t.Fatal("zero binding encoded")
	}
	if digest, err := binding.DigestSHA256(); err == nil || digest != "" {
		t.Fatal("zero binding hashed")
	}
}
