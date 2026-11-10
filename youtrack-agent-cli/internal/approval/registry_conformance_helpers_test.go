package approval

// This is an independent, test-only transcript oracle. It deliberately does not
// expose registry authority, storage, Keychain, or a production verifier API.
import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

type registryObject map[string]json.RawMessage

func registryFields(kind string) []string {
	var fields string
	switch kind {
	case "request":
		fields = "schema_version message_type transition_kind recovery_mode challenge expected_registry_revision previous_record_sha256 artifact_descriptor_sha256 target_generation new_generation requested_at expires_at"
	case "recovery_evidence":
		fields = "schema_version message_type request_sha256 challenge_sha256 registry_revision previous_record_sha256 artifact_descriptor_sha256 target_generation target_key_tag eligibility key_lookup_result continuity_probe_result probed_at"
	case "proposal_unsigned", "proposal":
		fields = "schema_version message_type transition_kind request_sha256 challenge_sha256 registry_revision previous_record_sha256 artifact_descriptor_sha256 recovery_evidence_sha256 target_generation target_key_id target_key_tag target_spki target_fingerprint_sha256 new_generation new_key_id new_key_tag new_spki new_fingerprint_sha256 proposed_at expires_at proposal_signer_role"
		if kind == "proposal" {
			fields += " proposal_signature"
		}
	case "acceptance":
		fields = "schema_version message_type transition_kind request_sha256 proposal_sha256 challenge_sha256 registry_revision previous_record_sha256 artifact_descriptor_sha256 recovery_evidence_sha256 target_generation new_generation accepted_at expires_at accepted"
	case "final_body", "record":
		fields = "schema_version record_type transition_kind registry_revision previous_record_sha256 request_sha256 proposal_sha256 acceptance_sha256 challenge_sha256 artifact_descriptor_sha256 recovery_evidence_sha256 requested_at accepted_at committed_at target_generation target_key_id target_key_tag target_spki target_fingerprint_sha256 target_previous_status target_new_status new_generation new_key_id new_key_tag new_spki new_fingerprint_sha256 new_status revokes_all_prior"
		if kind == "record" {
			fields += " old_signature new_signature"
		}
	}
	return strings.Fields(fields)
}

func registryObjectBytes(o registryObject, fields []string) []byte {
	var result bytes.Buffer
	result.WriteByte('{')
	for i, field := range fields {
		if i > 0 {
			result.WriteByte(',')
		}
		result.WriteString(`"` + field + `":`)
		result.Write(o[field])
	}
	result.WriteByte('}')
	return result.Bytes()
}

func registryNullable(field string) bool {
	return field == "recovery_mode" || field == "recovery_evidence_sha256" || field == "old_signature" || field == "new_signature" || field == "new_status" || strings.HasPrefix(field, "target_") || strings.HasPrefix(field, "new_")
}

// Shape and primitive validation never returns decoder text or supplied values.
// The exact ordered re-encoding rejects duplicate, extra, missing and reordered
// fields without relying on encoding/json's permissive duplicate-key behavior.
func registryParse(raw string, kind string) (registryObject, string) {
	o, reason := registryParseCanonical(raw, kind)
	if reason != "" {
		return nil, reason
	}
	return o, registryValidateGrammar(o, kind)
}

func registryCap(kind string) int {
	cap := 4096
	switch kind {
	case "request", "acceptance", "recovery_evidence":
		cap = 2048
	case "record":
		cap = 4352
	}
	return cap
}

func registryParseCanonical(raw string, kind string) (registryObject, string) {
	if len(raw) > registryCap(kind) {
		return nil, "bounds_grammar"
	}
	var o registryObject
	if json.Unmarshal([]byte(raw), &o) != nil || o == nil {
		return nil, "canonical_encoding"
	}
	fields := registryFields(kind)
	if len(fields) == 0 || len(o) != len(fields) {
		return nil, "canonical_encoding"
	}
	for _, field := range fields {
		if _, ok := o[field]; !ok {
			return nil, "canonical_encoding"
		}
	}
	if !bytes.Equal(registryObjectBytes(o, fields), []byte(raw)) {
		return nil, "canonical_encoding"
	}
	for _, field := range fields {
		value := string(o[field])
		if value == "null" {
			continue
		}
		if field == "schema_version" || field == "registry_revision" || field == "expected_registry_revision" {
			if !registryIntegerToken(value) {
				return nil, "canonical_encoding"
			}
			continue
		}
		if field == "accepted" || field == "revokes_all_prior" {
			if value != "true" && value != "false" {
				return nil, "canonical_encoding"
			}
			continue
		}
		var s string
		if json.Unmarshal(o[field], &s) != nil {
			return nil, "canonical_encoding"
		}
		if value != `"`+s+`"` {
			return nil, "canonical_encoding"
		}
		for i := range s {
			if s[i] < 0x20 || s[i] > 0x7e || s[i] == '\\' {
				return nil, "canonical_encoding"
			}
		}
	}
	return o, ""
}

// Called only after canonical validation; reuse its object without decoding again.
func registryValidateGrammar(o registryObject, kind string) string {
	for _, field := range registryFields(kind) {
		value := string(o[field])
		if value == "null" {
			if !registryNullable(field) {
				return "bounds_grammar"
			}
			continue
		}
		if field == "schema_version" || field == "registry_revision" || field == "expected_registry_revision" {
			n, err := strconv.ParseInt(value, 10, 16)
			if err != nil || n < 0 || (field == "schema_version" && n != 1) || (field != "schema_version" && (n > 256 || (field == "registry_revision" && n == 0))) {
				return "bounds_grammar"
			}
			continue
		}
		if field == "accepted" || field == "revokes_all_prior" {
			continue
		}
		s := value[1 : len(value)-1]
		if strings.HasSuffix(field, "_sha256") && !registryHex(s, 64) {
			return "bounds_grammar"
		}
		if strings.HasSuffix(field, "_key_id") && !registryHex(s, 32) {
			return "bounds_grammar"
		}
		if strings.HasSuffix(field, "_generation") && registryGeneration(s) == 0 {
			return "bounds_grammar"
		}
		if strings.HasSuffix(field, "_key_tag") && (!strings.HasPrefix(s, "io.github.abigotado.youtrack-agent.approval.signing.v1/") || !registryHex(strings.TrimPrefix(s, "io.github.abigotado.youtrack-agent.approval.signing.v1/"), 32)) {
			return "bounds_grammar"
		}
		if field == "challenge" {
			if _, ok := registryBase64(s, 32); !ok {
				return "bounds_grammar"
			}
		}
		if strings.HasSuffix(field, "_spki") {
			b, ok := registryBase64(s, 91)
			if !ok {
				return "bounds_grammar"
			}
			if _, err := P256DERSPKIToX963(b); err != nil {
				return "bounds_grammar"
			}
		}
		if strings.HasSuffix(field, "signature") {
			if _, err := DecodeP256DERSignature(s); err != nil {
				return "bounds_grammar"
			}
		}
		if strings.HasSuffix(field, "_at") {
			when, err := time.Parse("2006-01-02T15:04:05Z", s)
			if err != nil || when.Format("2006-01-02T15:04:05Z") != s {
				return "bounds_grammar"
			}
		}
	}
	if _, ok := o["message_type"]; ok && registryString(o, "message_type") != "registry_"+strings.TrimSuffix(kind, "_unsigned") {
		return "bounds_grammar"
	}
	if _, ok := o["record_type"]; ok && registryString(o, "record_type") != "approval_registry_transition" {
		return "bounds_grammar"
	}
	if transition, ok := o["transition_kind"]; ok && string(transition) != `"enroll"` && string(transition) != `"rotate"` && string(transition) != `"revoke"` && string(transition) != `"recover"` {
		return "bounds_grammar"
	}
	for _, field := range []string{"target_previous_status", "target_new_status", "new_status"} {
		if value, ok := o[field]; ok && string(value) != "null" && string(value) != `"active"` && string(value) != `"retained"` && string(value) != `"revoked"` {
			return "bounds_grammar"
		}
	}
	if value, ok := o["proposal_signer_role"]; ok && string(value) != `"old"` && string(value) != `"new"` {
		return "bounds_grammar"
	}
	if kind == "proposal_unsigned" || kind == "proposal" || kind == "final_body" || kind == "record" {
		for _, prefix := range []string{"target_", "new_"} {
			if _, reason := registryTuple(o, prefix); reason != "" {
				return reason
			}
		}
		if gen := registryString(o, "new_generation"); gen != "" && registryGeneration(gen) != registryNumber(o, "registry_revision") {
			return "bounds_grammar"
		}
	}
	return ""
}

func registryIntegerToken(raw string) bool {
	if strings.HasPrefix(raw, "-") {
		raw = raw[1:]
		if raw == "0" {
			return false
		}
	}
	if raw == "" || (len(raw) > 1 && raw[0] == '0') {
		return false
	}
	for _, c := range raw {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func registryHex(s string, size int) bool {
	if len(s) != size {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func registryGeneration(s string) int {
	if len(s) != 25 || !strings.HasPrefix(s, "YTAG-") {
		return 0
	}
	for _, c := range s[5:] {
		if c < '0' || c > '9' {
			return 0
		}
	}
	n, err := strconv.ParseUint(s[5:], 10, 16)
	if err != nil || n == 0 || n > 256 {
		return 0
	}
	return int(n)
}

func registryBase64(s string, size int) ([]byte, bool) {
	if len(s) != base64.RawURLEncoding.EncodedLen(size) {
		return nil, false
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	return b, err == nil && len(b) == size && base64.RawURLEncoding.EncodeToString(b) == s
}

func registryString(o registryObject, field string) string {
	var s string
	if json.Unmarshal(o[field], &s) != nil {
		return ""
	}
	return s
}

func registryNumber(o registryObject, field string) int {
	n, err := strconv.Atoi(string(o[field]))
	if err != nil {
		return -1
	}
	return n
}

func registryHash(domain, raw string) string {
	h := sha256.Sum256([]byte(domain + raw))
	return hex.EncodeToString(h[:])
}

func registryEqual(a registryObject, af string, b registryObject, bf string) bool {
	return bytes.Equal(a[af], b[bf])
}

func registryVerifySignature(spki, signature, domain, raw string) bool {
	b, ok := registryBase64(spki, 91)
	if !ok {
		return false
	}
	point, err := P256DERSPKIToX963(b)
	if err != nil {
		return false
	}
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return false
	}
	sig, err := DecodeP256DERSignature(signature)
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(domain + raw))
	return ecdsa.VerifyASN1(key, digest[:], sig)
}

func registryTime(o registryObject, field string) time.Time {
	v, err := time.Parse("2006-01-02T15:04:05Z", registryString(o, field))
	if err != nil {
		return time.Time{}
	}
	return v
}

func registryTuple(o registryObject, prefix string) ([5]string, string) {
	fields := []string{"generation", "key_id", "key_tag", "spki", "fingerprint_sha256"}
	var values [5]string
	nulls := 0
	for i, field := range fields {
		if string(o[prefix+field]) == "null" {
			nulls++
		}
		values[i] = registryString(o, prefix+field)
	}
	if nulls == 5 {
		return values, ""
	}
	if nulls != 0 {
		return values, "bounds_grammar"
	}
	if values[2] != "io.github.abigotado.youtrack-agent.approval.signing.v1/"+values[1] {
		return values, "bounds_grammar"
	}
	b, ok := registryBase64(values[3], 91)
	if !ok || registryHash("", string(b)) != values[4] {
		return values, "bounds_grammar"
	}
	return values, ""
}
