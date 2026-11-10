// Package protocolvalue defines language-neutral, network-free protocol
// grammars shared by intent and approval values.
package protocolvalue

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const MaxURLBytes = 2048

var ErrInvalidValue = errors.New("invalid protocol value")

// ValidateCanonicalBase32ID requires prefix followed by canonical unpadded
// uppercase RFC 4648 Base32 encoding of exactly 128 bits.
func ValidateCanonicalBase32ID(value, prefix string) error {
	const encodedBytes = 26
	if len(value) != len(prefix)+encodedBytes || !strings.HasPrefix(value, prefix) {
		return fmt.Errorf("%w: identifier has the wrong prefix or length", ErrInvalidValue)
	}
	encoded := value[len(prefix):]
	codec := base32.StdEncoding.WithPadding(base32.NoPadding)
	raw, err := codec.DecodeString(encoded)
	if err != nil || len(raw) != 16 || codec.EncodeToString(raw) != encoded {
		return fmt.Errorf("%w: identifier is not canonical 128-bit unpadded base32", ErrInvalidValue)
	}
	return nil
}

func IsIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 || !IsASCIIAlphaNumeric(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		if !IsASCIIAlphaNumeric(value[index]) && !strings.ContainsRune("._:-", rune(value[index])) {
			return false
		}
	}
	return true
}

func IsProjectKey(value string) bool {
	if len(value) == 0 || len(value) > 32 || value[0] < 'A' || value[0] > 'Z' {
		return false
	}
	for index := 1; index < len(value); index++ {
		if (value[index] < 'A' || value[index] > 'Z') && (value[index] < '0' || value[index] > '9') && value[index] != '_' {
			return false
		}
	}
	return true
}

func IsSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == sha256.Size
}

func SHA256Hex(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func IsASCIIAlphaNumeric(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

// ValidateApprovalURL enforces the canonical ASCII approval-plane URL grammar
// without parsing, resolving, or otherwise using the network.
func ValidateApprovalURL(raw string) error {
	if raw == "" || len(raw) > MaxURLBytes || !hasOnlyASCIIURLBytes(raw) || strings.Contains(raw, "%") {
		return invalid("URL is empty, oversized, or contains percent encoding, non-ASCII, control, or space bytes")
	}
	if !strings.HasPrefix(raw, "https://") {
		return invalid("URL must start with literal lowercase https://")
	}
	remainder := raw[len("https://"):]
	if remainder == "" || strings.ContainsAny(remainder, "?#\\") {
		return invalid("URL must be absolute HTTPS without query, fragment, or backslash")
	}
	authority, path := remainder, ""
	if slash := strings.IndexByte(remainder, '/'); slash >= 0 {
		authority, path = remainder[:slash], remainder[slash:]
	}
	if strings.Contains(authority, "@") {
		return invalid("URL must not contain credentials")
	}
	if err := validateCanonicalAuthority(authority); err != nil {
		return err
	}
	return validateApprovalPath(path)
}

func ValidateApprovalRESTBaseURL(instanceURL, restBaseURL string) error {
	if err := ValidateApprovalURL(instanceURL); err != nil {
		return fmt.Errorf("instance URL: %w", err)
	}
	if restBaseURL != instanceURL+"/api" {
		return invalid("REST base URL must equal instance URL + /api")
	}
	if err := ValidateApprovalURL(restBaseURL); err != nil {
		return fmt.Errorf("REST base URL: %w", err)
	}
	return nil
}

func validateCanonicalAuthority(authority string) error {
	if authority == "" || authority != strings.ToLower(authority) || strings.ContainsAny(authority, "[]") || strings.Count(authority, ":") > 1 {
		return invalid("URL host must be canonical lowercase DNS or dotted IPv4")
	}
	host, port, hasPort := authority, "", false
	if colon := strings.LastIndexByte(authority, ':'); colon >= 0 {
		host, port, hasPort = authority[:colon], authority[colon+1:], true
	}
	if looksLikeDottedIPv4(host) {
		if !validateCanonicalIPv4(host) {
			return invalid("dotted IPv4 host is not canonical")
		}
	} else if !validateCanonicalDNSName(host) {
		return invalid("URL host must be canonical lowercase DNS or dotted IPv4")
	}
	if hasPort {
		if port == "" || !isASCIIDecimal(port) || len(port) > 1 && port[0] == '0' {
			return invalid("URL port is empty or has a leading zero")
		}
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 || value == 443 {
			return invalid("URL port must be 1 through 65535 and omit the default 443")
		}
	}
	return nil
}

func validateApprovalPath(path string) error {
	if path == "" {
		return nil
	}
	if path[0] != '/' || path == "/" || strings.HasSuffix(path, "/") || strings.Contains(path, "//") {
		return invalid("URL path must be empty or contain nonempty slash-prefixed segments")
	}
	for _, segment := range strings.Split(path[1:], "/") {
		if segment == "." || segment == ".." {
			return invalid("URL path must not contain dot segments")
		}
		for index := range len(segment) {
			if !isApprovalPathByte(segment[index]) {
				return invalid("URL path contains a byte outside the canonical ASCII alphabet")
			}
		}
	}
	return nil
}

func validateCanonicalDNSName(host string) bool {
	if host == "" || len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := range len(label) {
			value := label[index]
			if value != '-' && (value < 'a' || value > 'z') && (value < '0' || value > '9') {
				return false
			}
		}
	}
	return true
}

func validateCanonicalIPv4(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 1 && part[0] == '0' || !isASCIIDecimal(part) {
			return false
		}
		value, err := strconv.Atoi(part)
		if err != nil || value > 255 {
			return false
		}
	}
	return true
}

func looksLikeDottedIPv4(host string) bool {
	if strings.Count(host, ".") != 3 {
		return false
	}
	for index := range len(host) {
		if host[index] != '.' && (host[index] < '0' || host[index] > '9') {
			return false
		}
	}
	return true
}

func isASCIIDecimal(value string) bool {
	if value == "" {
		return false
	}
	for index := range len(value) {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

func hasOnlyASCIIURLBytes(raw string) bool {
	for index := range len(raw) {
		if raw[index] < 0x21 || raw[index] > 0x7e {
			return false
		}
	}
	return true
}

func isApprovalPathByte(value byte) bool {
	return IsASCIIAlphaNumeric(value) || strings.ContainsRune("-._~!$&'()*+,;=:@", rune(value))
}

func invalid(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidValue, message)
}
