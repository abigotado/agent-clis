package secretstore

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateKey(t *testing.T) {
	longService := "a" + strings.Repeat("b", 63)
	valid := []struct {
		name string
		key  Key
	}{
		{"youtrack-agent-cli", Key{"youtrack-agent-cli", "work"}},
		{"confluence-cli", Key{"confluence-cli", "default"}},
		{"jira-cli", Key{"jira-cli", "default"}},
		{"slack-agent-cli", Key{"com.abigotado.slack-agent-cli", "default"}},
		{"redmine-cli", Key{"redmine-cli", "default"}},
		{"trello-cli", Key{"trello-cli", "default"}},
		{"linear-cli", Key{"com.abigotado.linear-cli", "default"}},
		{"clockify-cli", Key{"com.abigotado.clockify-cli", "default"}},
		{"account with colon", Key{"jira-cli", "account:x"}},
		{"account credentials", Key{"jira-cli", "credentials"}},
		{"mixed-case account", Key{"jira-cli", "Work-Profile"}},
		{"star account", Key{"jira-cli", "*"}},
		{"percent and question mark", Key{"jira-cli", "a%b?c"}},
		{"non-ASCII account", Key{"jira-cli", "профиль-日本語-é"}},
		{"youtrack profile name", Key{"youtrack-agent-cli", "my.profile_1-x"}},
		{"64-byte service", Key{longService, "a"}},
		{"128-byte account", Key{"jira-cli", strings.Repeat("a", 128)}},
		{"service with every allowed punctuation", Key{"a.b_c-d", "a"}},
	}
	for _, tt := range valid {
		t.Run("valid/"+tt.name, func(t *testing.T) {
			if err := validateKey("load", "memory", tt.key); err != nil {
				t.Fatalf("validateKey(%q) = %v, want nil", tt.key, err)
			}
		})
	}

	invalid := []struct {
		name string
		key  Key
	}{
		{"empty service", Key{"", "a"}},
		{"empty account", Key{"jira-cli", ""}},
		{"65-byte service", Key{"a" + strings.Repeat("b", 64), "a"}},
		{"129-byte account", Key{"jira-cli", strings.Repeat("a", 129)}},
		{"2-byte-rune account over the byte bound", Key{"jira-cli", strings.Repeat("é", 65)}},
		{"service starts with dash", Key{"-jira", "a"}},
		{"service starts with dot", Key{".jira", "a"}},
		{"service with slash", Key{"jira/cli", "a"}},
		{"service with space", Key{"jira cli", "a"}},
		{"service with hash", Key{"jira#cli", "a"}},
		{"service with colon", Key{"jira:cli", "a"}},
		{"non-ASCII service", Key{"jíra-cli", "a"}},
		{"service with control", Key{"jira\x00cli", "a"}},
		{"account NUL", Key{"jira-cli", "a\x00b"}},
		{"account newline", Key{"jira-cli", "a\nb"}},
		{"account tab", Key{"jira-cli", "a\tb"}},
		{"account DEL", Key{"jira-cli", "a\x7fb"}},
		{"account C1 control", Key{"jira-cli", "a\u0085b"}},
		{"account U+241F", Key{"jira-cli", "a␟b"}},
		{"account hash", Key{"jira-cli", "a#b"}},
		{"account stage suffix", Key{"jira-cli", "a␟stage"}},
		{"account invalid UTF-8", Key{"jira-cli", "a\xffb"}},
		{"account overlong encoding", Key{"jira-cli", "\xc0\xaf"}},
		{"account encoded surrogate", Key{"jira-cli", "\xed\xa0\x80"}},
		{"service invalid UTF-8", Key{"jira\xff", "a"}},
	}
	for _, tt := range invalid {
		t.Run("invalid/"+tt.name, func(t *testing.T) {
			err := validateKey("save", "memory", tt.key)
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("validateKey(%q) = %v, want ErrInvalidArgument", tt.key, err)
			}
			var se *Error
			if !errors.As(err, &se) || se.Op != "save" || se.Backend != "memory" || se.Kind != KindInvalidArgument {
				t.Fatalf("validateKey(%q) = %#v, want a save/memory invalid-argument *Error", tt.key, err)
			}
		})
	}

	t.Run("error text carries no key text", func(t *testing.T) {
		key := Key{Service: "svc-marker-0123/bad", Account: "acct-marker-4567#bad"}
		err := validateKey("load", "memory", key)
		if err == nil {
			t.Fatal("want an error")
		}
		for _, marker := range []string{"svc-marker", "acct-marker", "0123", "4567"} {
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("error %q contains key text %q", err, marker)
			}
		}
	})
}

func TestValidateOptions(t *testing.T) {
	tests := []struct {
		name string
		opts Options
		ok   bool
	}{
		{"minimum bound", Options{MaxSecretBytes: 1}, true},
		{"limit", Options{MaxSecretBytes: MaxSecretBytesLimit}, true},
		{"interaction allowed", Options{MaxSecretBytes: 10, Interaction: InteractionAllowed}, true},
		{"zero bound", Options{MaxSecretBytes: 0}, false},
		{"negative bound", Options{MaxSecretBytes: -1}, false},
		{"above the limit", Options{MaxSecretBytes: MaxSecretBytesLimit + 1}, false},
		{"unknown interaction", Options{MaxSecretBytes: 10, Interaction: Interaction(2)}, false},
		{"negative interaction", Options{MaxSecretBytes: 10, Interaction: Interaction(-1)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOptions(tt.opts)
			if tt.ok {
				if err != nil {
					t.Fatalf("validateOptions(%+v) = %v, want nil", tt.opts, err)
				}
				return
			}
			var se *Error
			if !errors.Is(err, ErrInvalidArgument) || !errors.As(err, &se) || se.Op != "open" {
				t.Fatalf("validateOptions(%+v) = %v, want an open ErrInvalidArgument", tt.opts, err)
			}
		})
	}

	t.Run("limit constant", func(t *testing.T) {
		if MaxSecretBytesLimit != 128*1024 {
			t.Fatalf("MaxSecretBytesLimit = %d, want 131072", MaxSecretBytesLimit)
		}
	})
}
