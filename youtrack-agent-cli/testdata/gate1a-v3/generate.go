//go:build ignore

// This generator is test-only. The public fixture scalar and nonce MUST NOT be
// used for real signatures. Run from the repository root with go run
// ./testdata/gate1a-v3/generate.go; add -check to verify without writing.
package main

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/abigotado/youtrack-agent-cli/internal/approval"
)

func main() {
	check := flag.Bool("check", false, "check fixtures without writing")
	flag.Parse()
	if err := generate(*check); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func historical(name string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join("testdata", "gate1a", name))
	if err != nil {
		return nil, fmt.Errorf("read fixture %s: %w", name, err)
	}
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return nil, fmt.Errorf("fixture %s has no source-control LF", name)
	}
	return raw[:len(raw)-1], nil
}

func upgraded(name string) (approval.Receipt, error) {
	raw, err := historical(name)
	if err != nil {
		return approval.Receipt{}, err
	}
	var receipt approval.Receipt
	// This is a historical test-data conversion, not a candidate decoder. The
	// real ParseReceiptBytes must reject these schema-v2 bytes.
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return approval.Receipt{}, fmt.Errorf("decode historical fixture: %w", err)
	}
	receipt.SchemaVersion = 3
	receipt.RegistryRevision = 1
	receipt.AuthorizationContextSHA256 = strings.Repeat("a", 64)
	receipt.KeyGeneration = "YTAG-00000000000000000001"
	return receipt, nil
}

func generate(check bool) error {
	receipt, err := upgraded("receipt.json")
	if err != nil {
		return err
	}
	signing, err := approval.SigningBytes(receipt)
	if err != nil {
		return err
	}
	signed, err := approval.ReceiptBytes(receipt)
	if err != nil {
		return err
	}
	ipcReceipt, err := upgraded("ipc-success-receipt.json")
	if err != nil {
		return err
	}
	ipcSigning, err := approval.SigningBytes(ipcReceipt)
	if err != nil {
		return err
	}
	signature, err := deterministicFixtureSignature(ipcSigning)
	if err != nil {
		return err
	}
	ipcReceipt.Signature, err = approval.EncodeP256DERSignature(signature)
	if err != nil {
		return err
	}
	ipcSigned, err := approval.ReceiptBytes(ipcReceipt)
	if err != nil {
		return err
	}
	spkiHex, err := historical("public-key.spki.hex")
	if err != nil {
		return err
	}
	spki, err := hex.DecodeString(string(spkiHex))
	if err != nil {
		return fmt.Errorf("decode fixture SPKI: %w", err)
	}
	var challenge [approval.IPCChallengeSize]byte
	for i := range challenge {
		challenge[i] = byte(i)
	}
	frame, err := approval.EncodeIPCSuccess(approval.IPCSuccess{
		Challenge: challenge, SPKIDER: spki, ReceiptJSON: ipcSigned,
	})
	if err != nil {
		return err
	}
	boundaries, err := revisionBoundaries(receipt)
	if err != nil {
		return err
	}
	outputs := []struct {
		name string
		raw  []byte
	}{
		{"signing.json", signing}, {"receipt.json", signed},
		{"signing.sha256", digest(signing)}, {"receipt.sha256", digest(signed)},
		{"ipc-success-receipt.json", ipcSigned},
		{"ipc-success.hex", []byte(hex.EncodeToString(frame))},
		{"revision-boundaries.json", boundaries},
	}
	for _, output := range outputs {
		path := filepath.Join("testdata", "gate1a-v3", output.name)
		want := append(bytes.Clone(output.raw), '\n')
		if check {
			got, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read generated fixture: %w", err)
			}
			if !bytes.Equal(got, want) {
				return fmt.Errorf("fixture %s is stale", path)
			}
		} else if err := os.WriteFile(path, want, 0o644); err != nil {
			return fmt.Errorf("write fixture: %w", err)
		}
	}
	return nil
}

func revisionBoundaries(receipt approval.Receipt) ([]byte, error) {
	// Literal protocol boundaries intentionally do not follow implementation
	// constants: a unilateral ceiling bump must fail the shared corpus.
	receipt.RegistryRevision = 256
	receipt.KeyGeneration = "YTAG-00000000000000000256"
	signing, err := approval.SigningBytes(receipt)
	if err != nil {
		return nil, err
	}
	signed, err := approval.ReceiptBytes(receipt)
	if err != nil {
		return nil, err
	}
	corpus := []struct {
		Name     string `json:"name"`
		Accepted bool   `json:"accepted"`
		Signing  string `json:"signing"`
		Receipt  string `json:"receipt"`
	}{
		{"ceiling 256", true, string(signing), string(signed)},
		{"revision and generation 257", false,
			strings.ReplaceAll(strings.ReplaceAll(string(signing), `"registry_revision":256`, `"registry_revision":257`), "YTAG-00000000000000000256", "YTAG-00000000000000000257"),
			strings.ReplaceAll(strings.ReplaceAll(string(signed), `"registry_revision":256`, `"registry_revision":257`), "YTAG-00000000000000000256", "YTAG-00000000000000000257")},
		{"generation 257 at revision 256", false,
			strings.ReplaceAll(string(signing), "YTAG-00000000000000000256", "YTAG-00000000000000000257"),
			strings.ReplaceAll(string(signed), "YTAG-00000000000000000256", "YTAG-00000000000000000257")},
	}
	return json.MarshalIndent(corpus, "", "  ")
}

func digest(raw []byte) []byte {
	sum := sha256.Sum256(raw)
	return []byte(hex.EncodeToString(sum[:]))
}

func deterministicFixtureSignature(message []byte) ([]byte, error) {
	// Public test constants: d=1 (the historical fixture's generator point),
	// k=2. Deliberate nonce reuse is safe ONLY for this already public key.
	curve := elliptic.P256()
	n := curve.Params().N
	r, _ := curve.ScalarBaseMult([]byte{2})
	r.Mod(r, n)
	hash := sha256.Sum256(message)
	s := new(big.Int).SetBytes(hash[:])
	s.Add(s, r)
	s.Mul(s, new(big.Int).ModInverse(big.NewInt(2), n))
	s.Mod(s, n)
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(n), 1)) > 0 {
		s.Sub(n, s)
	}
	return asn1.Marshal(struct{ R, S *big.Int }{r, s})
}
