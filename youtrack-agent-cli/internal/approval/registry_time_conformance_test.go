package approval

// Test-only timestamp parity evidence. Historical active fixtures check supplied
// bytes and their existing intent link, not live clock freshness or authority.
import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

type registryTimestamp struct {
	ID          string `json:"id"`
	Text        string `json:"text"`
	UnixSeconds *int64 `json:"unix_seconds"`
}
type registryTimeInterval struct {
	ID      string `json:"id"`
	Start   string `json:"start"`
	End     string `json:"end"`
	Seconds int64  `json:"seconds"`
}
type registryTimeSource struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type registryTimeActive struct {
	ID          string `json:"id"`
	Base        string `json:"base"`
	IntentID    string `json:"intent_id"`
	CreatedAt   string `json:"created_at"`
	ExpiresAt   string `json:"expires_at"`
	RawHex      string `json:"raw_hex"`
	SHA256      string `json:"sha256"`
	ReasonClass string `json:"reason_class"`
}
type registryTimeCorpus struct {
	SchemaVersion int                    `json:"schema_version"`
	Scope         string                 `json:"scope"`
	Sources       []registryTimeSource   `json:"sources"`
	Timestamps    []registryTimestamp    `json:"timestamps"`
	Intervals     []registryTimeInterval `json:"intervals"`
	Active        []registryTimeActive   `json:"active"`
}

func TestSharedRegistryTimeCorpus(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/gate1a-registry-time/corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var c registryTimeCorpus
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&c); err != nil {
		t.Fatal(err)
	}
	var trailing json.RawMessage
	if decoder.Decode(&trailing) != io.EOF {
		t.Fatal("trailing timestamp corpus data")
	}
	if c.SchemaVersion != 1 || c.Scope != "registry-timestamp-interop" {
		t.Fatal("unexpected timestamp corpus schema")
	}
	sources := []registryTimeSource{
		{"testdata/gate1a-registry/corpus.json", "b0fbce184a136c8b20689d51bb9eae0a46ecf510447c78a45728f8f4d88fde61"},
		{"testdata/gate1a-registry-intent/corpus.json", "ef65c0ae8132a37a0d6a04be2ba742537fa56ac78f32d4ce537f94c363557a05"},
		{"testdata/gate1a-registry-active/corpus.json", "5fbe731e9ffa05c340586d0210d2a07ee7778e49c0d157d8d277cc029cb828c0"},
	}
	if !reflect.DeepEqual(c.Sources, sources) {
		t.Fatal("timestamp source pins differ")
	}
	for _, s := range sources {
		raw, err := os.ReadFile("../../" + s.Path)
		if err != nil {
			t.Fatal(err)
		}
		if registryHash("", string(raw)) != s.SHA256 {
			t.Fatal("timestamp source hash differs")
		}
	}
	seconds := func(n int64) *int64 { return &n }
	expected := []registryTimestamp{
		{"year-zero", "0000-01-01T00:00:00Z", seconds(-62167219200)},
		{"year-one", "0001-01-01T00:00:00Z", seconds(-62135596800)},
		{"epoch", "1970-01-01T00:00:00Z", seconds(0)},
		{"year-max", "9999-12-31T23:59:59Z", seconds(253402300799)},
		{"leap-zero", "0000-02-29T12:00:00Z", seconds(-62162078400)},
		{"leap-1600", "1600-02-29T12:00:00Z", seconds(-11670955200)},
		{"leap-2000", "2000-02-29T12:00:00Z", seconds(951825600)},
		{"cutover-oct4", "1582-10-04T00:00:00Z", seconds(-12220243200)},
		{"cutover-oct10", "1582-10-10T00:00:00Z", seconds(-12219724800)},
		{"cutover-oct15", "1582-10-15T00:00:00Z", seconds(-12219292800)},
		{"invalid-1500-leap", "1500-02-29T12:00:00Z", nil},
		{"invalid-1700-leap", "1700-02-29T12:00:00Z", nil},
		{"invalid-1900-leap", "1900-02-29T12:00:00Z", nil},
		{"invalid-zero-feb30", "0000-02-30T12:00:00Z", nil},
		{"month-zero", "2000-00-01T00:00:00Z", nil},
		{"month-overflow", "2000-13-01T00:00:00Z", nil},
		{"day-zero", "2000-01-00T00:00:00Z", nil},
		{"day-overflow", "2000-04-31T00:00:00Z", nil},
		{"hour-overflow", "2000-01-01T24:00:00Z", nil},
		{"minute-overflow", "2000-01-01T00:60:00Z", nil},
		{"second-overflow", "2000-01-01T00:00:60Z", nil},
		{"expanded-year", "10000-01-01T00:00:00Z", nil},
		{"signed-year", "-001-01-01T00:00:00Z", nil},
		{"fraction", "2000-01-01T00:00:00.0Z", nil},
		{"offset", "2000-01-01T00:00:00+00:00", nil},
		{"separator", "2000-01-01 00:00:00Z", nil},
		{"nonascii-digit", "２０００-01-01T00:00:00Z", nil},
	}
	if !reflect.DeepEqual(c.Timestamps, expected) {
		t.Fatal("timestamp pins differ")
	}
	for _, v := range c.Timestamps {
		t.Run(v.ID, func(t *testing.T) {
			parsed, err := time.Parse("2006-01-02T15:04:05Z", v.Text)
			valid := err == nil && parsed.Format("2006-01-02T15:04:05Z") == v.Text
			if v.UnixSeconds == nil {
				if valid {
					t.Fatal("accepted invalid timestamp")
				}
				return
			}
			if !valid || parsed.Unix() != *v.UnixSeconds {
				t.Fatalf("timestamp verdict or scalar differs: valid=%v unix=%d", valid, parsed.Unix())
			}
			// Exercise the shared oracle projection as well as the independent strict parse.
			quoted, err := json.Marshal(v.Text)
			if err != nil {
				t.Fatal(err)
			}
			if got := registryTime(registryObject{"time": quoted}, "time").Unix(); got != *v.UnixSeconds {
				t.Fatalf("shared timestamp scalar %d", got)
			}
		})
	}
	expectedIntervals := []registryTimeInterval{
		{"zero-leap", "0000-02-28T23:59:59Z", "0000-02-29T00:00:00Z", 1},
		{"century-nonleap", "1500-02-28T23:59:59Z", "1500-03-01T00:00:00Z", 1},
		{"cutover-1", "1582-10-04T23:59:59Z", "1582-10-05T00:00:00Z", 1},
		{"cutover-gap", "1582-10-04T23:59:59Z", "1582-10-15T00:00:00Z", 864001},
		{"ttl-300", "1582-10-10T00:00:00Z", "1582-10-10T00:05:00Z", 300},
		{"ttl-600", "1582-10-10T00:00:00Z", "1582-10-10T00:10:00Z", 600},
		{"ttl-601", "1582-10-10T00:00:00Z", "1582-10-10T00:10:01Z", 601},
		{"reverse", "1582-10-10T00:10:00Z", "1582-10-10T00:00:00Z", -600},
		{"full-range", "0000-01-01T00:00:00Z", "9999-12-31T23:59:59Z", 315569519999},
	}
	if !reflect.DeepEqual(c.Intervals, expectedIntervals) {
		t.Fatal("interval pins differ")
	}
	for _, v := range c.Intervals {
		t.Run(v.ID, func(t *testing.T) {
			start, err := time.Parse("2006-01-02T15:04:05Z", v.Start)
			if err != nil {
				t.Fatal(err)
			}
			end, err := time.Parse("2006-01-02T15:04:05Z", v.End)
			if err != nil {
				t.Fatal(err)
			}
			// time.Time.Sub saturates across the full 0000...9999 range.
			if got := end.Unix() - start.Unix(); got != v.Seconds {
				t.Fatalf("interval = %d; want %d", got, v.Seconds)
			}
		})
	}
	expectedActive := []struct{ id, created, expires, reason string }{
		{"active-zero", "0000-02-29T00:00:00Z", "0000-02-29T00:10:00Z", ""},
		{"active-gap", "1582-10-10T00:00:00Z", "1582-10-10T00:10:00Z", ""},
		{"active-century-leap", "1600-02-29T00:00:00Z", "1600-02-29T00:10:00Z", ""},
		{"active-invalid-leap", "1500-02-29T00:00:00Z", "1500-02-29T00:10:00Z", "bounds_grammar"},
		{"active-cutover", "1582-10-04T23:59:59Z", "1582-10-15T00:00:00Z", "temporal"},
		{"active-601", "1582-10-10T00:00:00Z", "1582-10-10T00:10:01Z", "temporal"},
		{"active-reverse", "1582-10-10T00:10:00Z", "1582-10-10T00:00:00Z", "temporal"},
	}
	if len(c.Active) != len(expectedActive) {
		t.Fatal("active timestamp pins incomplete")
	}
	var base registryActiveVector
	for _, v := range readRegistryActiveCorpus(t).Positives {
		if v.ID == "active-enroll1" {
			base = v
		}
	}
	baseBytes, err := hex.DecodeString(base.RawHex)
	if err != nil || len(baseBytes) == 0 {
		t.Fatal("missing active base")
	}
	intents := registryIntentPositiveMap(t)
	cores := registryPositiveMap(t, readRegistryCorpus(t))
	for i, v := range c.Active {
		t.Run(v.ID, func(t *testing.T) {
			pin := expectedActive[i]
			if v.ID != pin.id || v.Base != "active-enroll1" || v.IntentID != "intent-enroll1" || v.CreatedAt != pin.created || v.ExpiresAt != pin.expires || v.ReasonClass != pin.reason {
				t.Fatal("active timestamp metadata differs")
			}
			expectedRaw := strings.Replace(string(baseBytes), `"created_at":"2026-09-01T12:00:00Z"`, `"created_at":"`+pin.created+`"`, 1)
			expectedRaw = strings.Replace(expectedRaw, `"expires_at":"2026-09-01T12:10:00Z"`, `"expires_at":"`+pin.expires+`"`, 1)
			if v.RawHex != hex.EncodeToString([]byte(expectedRaw)) || v.SHA256 != registryHash("YTA-APPLY-COORDINATOR-ACTIVE-V1\x00", expectedRaw) {
				t.Fatal("active timestamp bytes or domain digest differs")
			}
			reason, err := registryVerifyActive(registryActiveVector{ID: v.ID, IntentID: v.IntentID, RawHex: v.RawHex, SHA256: v.SHA256}, intents, cores)
			if err != nil || reason != pin.reason {
				t.Fatalf("got %q, %v; want %q", reason, err, pin.reason)
			}
		})
	}
}
