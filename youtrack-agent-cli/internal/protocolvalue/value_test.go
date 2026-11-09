package protocolvalue

import "testing"

func TestValidateCanonicalBase32ID(t *testing.T) {
	for _, value := range []string{
		"YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA",
		"YTAP-AAAQEAYEAUDAOCAJBIFQYDIOB4",
	} {
		if err := ValidateCanonicalBase32ID(value, "YTAP-"); err != nil {
			t.Fatalf("valid ID %q: %v", value, err)
		}
	}
	for _, value := range []string{
		"YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAB",
		"YTAP-aaaaaaaaaaaaaaaaaaaaaaaaaa",
		"YTAP-AAAAAAAAAAAAAAAAAAAAAAAAA=",
	} {
		if err := ValidateCanonicalBase32ID(value, "YTAP-"); err == nil {
			t.Fatalf("invalid ID %q accepted", value)
		}
	}
}

func TestValidateApprovalURLCorpus(t *testing.T) {
	for _, value := range []string{
		"https://acme.youtrack.cloud",
		"https://tracker.example:8443/youtrack",
		"https://192.0.2.10/yt_A-1",
		"https://example/UPPER~ok!$&'()*+,;=:@",
	} {
		if err := ValidateApprovalURL(value); err != nil {
			t.Fatalf("valid URL %q: %v", value, err)
		}
	}
	for _, value := range []string{
		"https://tracker.example:443", "HTTPS://tracker.example", "https://Tracker.example",
		"https://192.168.001.1", "https://[2001:db8::1]", "https://example/%2e",
		"https://example/a//b", "https://example/a/", "https://example/..", "https://user@example",
	} {
		if err := ValidateApprovalURL(value); err == nil {
			t.Fatalf("invalid URL %q accepted", value)
		}
	}
}
