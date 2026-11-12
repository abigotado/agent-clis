// Package rules holds the key rules shared by the real stores and the in-memory
// fake, so the two cannot drift apart.
package rules

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// MaxServiceBytes is the longest Service in bytes.
	MaxServiceBytes = 64
	// MaxAccountBytes is the longest Account in bytes.
	MaxAccountBytes = 128
	// ReservedRune is the separator the module uses inside item names.
	ReservedRune = '␟'
	// ReservedByte is the byte the module uses to separate item name parts.
	ReservedByte = '#'
)

// ValidService reports whether service is 1-64 bytes matching
// ^[A-Za-z0-9][A-Za-z0-9._-]*$.
func ValidService(service string) bool {
	if service == "" || len(service) > MaxServiceBytes {
		return false
	}
	for i := 0; i < len(service); i++ {
		c := service[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if i == 0 && !alnum {
			return false
		}
		if !alnum && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// ValidAccount reports whether account is 1-128 bytes of valid UTF-8 with no
// control rune, no U+241F, and no '#'.
func ValidAccount(account string) bool {
	if account == "" || len(account) > MaxAccountBytes || !utf8.ValidString(account) {
		return false
	}
	if strings.ContainsRune(account, ReservedRune) || strings.IndexByte(account, ReservedByte) >= 0 {
		return false
	}
	for _, r := range account {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
