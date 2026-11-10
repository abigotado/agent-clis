package operatorwrite

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// These hashes pin the complete canonical wire bytes captured before the
// comment-delete schema extension. The v2 values are derived from each stored
// v1 plan by changing only its plan version, removing expiry, and recomputing
// its digest; random plan IDs are deliberately not involved.
func TestPlanWireCompatibilityGoldens(t *testing.T) {
	tests := []struct {
		name, fixture, v1BytesSHA256, v1PlanSHA256, v2BytesSHA256, v2PlanSHA256 string
		kind                                                                    Kind
	}{
		{"comment add preserves v1 and v2 canonical bytes", "plan-v1-comment-add.json", "056bfc5abaf26a061a038291c35cc513e458d034890cc418f69293ccc5ece16a", "665cc52f2dcd4a173a9842fafe5a91efca8fa42e7d51c601f8dc27235b19f518", "2d8aad47c6b0152e4cdb09bdd5487999fbcc12a9c7d00891236d2aca1c929105", "dfa2f134d5b45e21e0680e557f17420ae96964b04c8c3bd7345c13164174d705", KindCommentAdd},
		{"issue create preserves v1 and v2 canonical bytes", "plan-v1-issue-create.json", "47a126025aa54194a5bfb74c37b4130715f092a2fb656fe9baa859ea9fe9cb35", "1522e70be785de687c3a4d5e3f7fbf2383297d9a6875debbc3ee0a45b8918ec7", "eeaeb15289578274fc47d830b99478d7f6ab1b8aa6e4294624911acc95b23d30", "1a8acfb8a02b56359dd6ea27a2f849ab334fbc9296ca7c61efcbe0cbe846131c", KindIssueCreate},
		{"issue update preserves v1 and v2 canonical bytes", "plan-v1-issue-update.json", "7679d02b4215d97305dd0d3c6478f6876bf3b401be1a0828b939b654e552a8dc", "65e421c1367f17f463727b4f5a85365cd215f62f514e66a7aa8454bda1074aff", "95534cf4f811780eeb5f3ac71dfba52285e32c618f743cb8c25fc49c6ce16e75", "99f6b4dd8476a1bb1405ab369c150633caf970acec801451ac133dcffba1334d", KindIssueUpdate},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", test.fixture))
			if err != nil {
				t.Fatal(err)
			}
			if got := wireSHA256(raw); got != test.v1BytesSHA256 {
				t.Fatalf("v1 frozen bytes sha256=%s, want %s", got, test.v1BytesSHA256)
			}
			v1, err := DecodePlan(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("DecodePlan(v1): %v", err)
			}
			if v1.Version != LegacyPlanVersion1 || v1.SHA256 != test.v1PlanSHA256 || v1.Snapshot.Kind != test.kind || PlanLifetime(v1.Version) != LegacyPlanLifetime {
				t.Fatalf("v1 plan=%#v", v1)
			}
			v1Bytes, err := json.Marshal(v1)
			if err != nil {
				t.Fatal(err)
			}
			v1Canonical := bytes.TrimSuffix(raw, []byte("\n"))
			if !bytes.Equal(v1Bytes, v1Canonical) {
				t.Fatalf("v1 canonical bytes changed:\nwant %s\n got %s", v1Canonical, v1Bytes)
			}

			v2 := v1
			v2.Version, v2.ExpiresAt, v2.SHA256 = PlanVersion2, time.Time{}, ""
			v2.SHA256, err = digest(v2)
			if err != nil {
				t.Fatal(err)
			}
			if v2.SHA256 != test.v2PlanSHA256 || PlanLifetime(v2.Version) != CurrentPlanLifetime {
				t.Fatalf("v2 digest/lifetime=%q/%q, want %q/%q", v2.SHA256, PlanLifetime(v2.Version), test.v2PlanSHA256, CurrentPlanLifetime)
			}
			if err := ValidatePlan(v2); err != nil {
				t.Fatalf("ValidatePlan(v2): %v", err)
			}
			v2Bytes, err := json.Marshal(v2)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(v2Bytes, []byte(`"expires_at"`)) {
				t.Fatalf("v2 retained legacy expiry: %s", v2Bytes)
			}
			if got := wireSHA256(v2Bytes); got != test.v2BytesSHA256 {
				t.Fatalf("v2 frozen bytes sha256=%s, want %s", got, test.v2BytesSHA256)
			}
			decoded, err := DecodePlan(bytes.NewReader(v2Bytes))
			if err != nil {
				t.Fatalf("DecodePlan(v2): %v", err)
			}
			decodedBytes, err := json.Marshal(decoded)
			if err != nil || !bytes.Equal(decodedBytes, v2Bytes) {
				t.Fatalf("v2 decode bytes=%s err=%v", decodedBytes, err)
			}
		})
	}
}

func wireSHA256(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
