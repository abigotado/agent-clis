//go:build ignore

// Generate test-only calendar fixtures, independently of runtime codecs.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

const outputPath = "testdata/gate1a-registry-time/corpus.json"

type timestamp struct {
	ID          string `json:"id"`
	Text        string `json:"text"`
	UnixSeconds *int64 `json:"unix_seconds"`
}
type interval struct {
	ID      string `json:"id"`
	Start   string `json:"start"`
	End     string `json:"end"`
	Seconds int64  `json:"seconds"`
}
type source struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type active struct {
	ID          string `json:"id"`
	Base        string `json:"base"`
	IntentID    string `json:"intent_id"`
	CreatedAt   string `json:"created_at"`
	ExpiresAt   string `json:"expires_at"`
	RawHex      string `json:"raw_hex"`
	SHA256      string `json:"sha256"`
	ReasonClass string `json:"reason_class"`
}
type corpus struct {
	SchemaVersion int         `json:"schema_version"`
	Scope         string      `json:"scope"`
	Sources       []source    `json:"sources"`
	Timestamps    []timestamp `json:"timestamps"`
	Intervals     []interval  `json:"intervals"`
	Active        []active    `json:"active"`
}

func seconds(n int64) *int64 { return &n }
func sum(raw []byte) string  { d := sha256.Sum256(raw); return hex.EncodeToString(d[:]) }
func generate() ([]byte, error) {
	c := corpus{SchemaVersion: 1, Scope: "registry-timestamp-interop", Timestamps: []timestamp{
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
	}, Intervals: []interval{
		{"zero-leap", "0000-02-28T23:59:59Z", "0000-02-29T00:00:00Z", 1},
		{"century-nonleap", "1500-02-28T23:59:59Z", "1500-03-01T00:00:00Z", 1},
		{"cutover-1", "1582-10-04T23:59:59Z", "1582-10-05T00:00:00Z", 1},
		{"cutover-gap", "1582-10-04T23:59:59Z", "1582-10-15T00:00:00Z", 864001},
		{"ttl-300", "1582-10-10T00:00:00Z", "1582-10-10T00:05:00Z", 300},
		{"ttl-600", "1582-10-10T00:00:00Z", "1582-10-10T00:10:00Z", 600},
		{"ttl-601", "1582-10-10T00:00:00Z", "1582-10-10T00:10:01Z", 601},
		{"reverse", "1582-10-10T00:10:00Z", "1582-10-10T00:00:00Z", -600},
		{"full-range", "0000-01-01T00:00:00Z", "9999-12-31T23:59:59Z", 315569519999},
	}}
	var baseRaw string
	for _, path := range []string{"testdata/gate1a-registry/corpus.json", "testdata/gate1a-registry-intent/corpus.json", "testdata/gate1a-registry-active/corpus.json"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read source: %w", err)
		}
		c.Sources = append(c.Sources, source{path, sum(raw)})
		if strings.Contains(path, "registry-active/") {
			var old struct {
				Positives []struct {
					ID     string `json:"id"`
					RawHex string `json:"raw_hex"`
				} `json:"positives"`
			}
			if err := json.Unmarshal(raw, &old); err != nil {
				return nil, fmt.Errorf("decode active source: %w", err)
			}
			for _, p := range old.Positives {
				if p.ID == "active-enroll1" {
					b, err := hex.DecodeString(p.RawHex)
					if err != nil {
						return nil, fmt.Errorf("decode active bytes: %w", err)
					}
					baseRaw = string(b)
				}
			}
		}
	}
	if strings.Count(baseRaw, `"created_at":"2026-09-01T12:00:00Z"`) != 1 || strings.Count(baseRaw, `"expires_at":"2026-09-01T12:10:00Z"`) != 1 {
		return nil, fmt.Errorf("unexpected active source")
	}
	for _, v := range []struct{ id, created, expires, reason string }{
		{"active-zero", "0000-02-29T00:00:00Z", "0000-02-29T00:10:00Z", ""},
		{"active-gap", "1582-10-10T00:00:00Z", "1582-10-10T00:10:00Z", ""},
		{"active-century-leap", "1600-02-29T00:00:00Z", "1600-02-29T00:10:00Z", ""},
		{"active-invalid-leap", "1500-02-29T00:00:00Z", "1500-02-29T00:10:00Z", "bounds_grammar"},
		{"active-cutover", "1582-10-04T23:59:59Z", "1582-10-15T00:00:00Z", "temporal"},
		{"active-601", "1582-10-10T00:00:00Z", "1582-10-10T00:10:01Z", "temporal"},
		{"active-reverse", "1582-10-10T00:10:00Z", "1582-10-10T00:00:00Z", "temporal"},
	} {
		raw := strings.Replace(baseRaw, `"created_at":"2026-09-01T12:00:00Z"`, `"created_at":"`+v.created+`"`, 1)
		raw = strings.Replace(raw, `"expires_at":"2026-09-01T12:10:00Z"`, `"expires_at":"`+v.expires+`"`, 1)
		c.Active = append(c.Active, active{v.id, "active-enroll1", "intent-enroll1", v.created, v.expires, hex.EncodeToString([]byte(raw)), sum([]byte("YTA-APPLY-COORDINATOR-ACTIVE-V1\x00" + raw)), v.reason})
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode corpus: %w", err)
	}
	return append(raw, '\n'), nil
}
func run() error {
	check := flag.Bool("check", false, "verify committed corpus without writing")
	flag.Parse()
	generated, err := generate()
	if err != nil {
		return err
	}
	if *check {
		current, err := os.ReadFile(outputPath)
		if err != nil {
			return fmt.Errorf("read corpus: %w", err)
		}
		if !bytes.Equal(current, generated) {
			return fmt.Errorf("timestamp corpus differs; regenerate with go run ./testdata/gate1a-registry-time/generate.go")
		}
		return nil
	}
	if err := os.WriteFile(outputPath, generated, 0644); err != nil {
		return fmt.Errorf("write corpus: %w", err)
	}
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
