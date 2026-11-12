package secretstore

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestCredentialLayout pins every CREDENTIALW offset to the Win32 header, which
// a Go struct only matches by construction.
func TestCredentialLayout(t *testing.T) {
	var c credential
	const ptr = unsafe.Sizeof(uintptr(0))
	type field struct {
		name      string
		got, want uintptr
	}
	var fields []field
	if ptr == 8 {
		fields = []field{
			{"Flags", unsafe.Offsetof(c.Flags), 0},
			{"Type", unsafe.Offsetof(c.Type), 4},
			{"TargetName", unsafe.Offsetof(c.TargetName), 8},
			{"Comment", unsafe.Offsetof(c.Comment), 16},
			{"LastWritten", unsafe.Offsetof(c.LastWritten), 24},
			{"CredentialBlobSize", unsafe.Offsetof(c.CredentialBlobSize), 32},
			{"CredentialBlob", unsafe.Offsetof(c.CredentialBlob), 40},
			{"Persist", unsafe.Offsetof(c.Persist), 48},
			{"AttributeCount", unsafe.Offsetof(c.AttributeCount), 52},
			{"Attributes", unsafe.Offsetof(c.Attributes), 56},
			{"TargetAlias", unsafe.Offsetof(c.TargetAlias), 64},
			{"UserName", unsafe.Offsetof(c.UserName), 72},
			{"size", unsafe.Sizeof(c), 80},
		}
	} else {
		fields = []field{
			{"Flags", unsafe.Offsetof(c.Flags), 0},
			{"Type", unsafe.Offsetof(c.Type), 4},
			{"TargetName", unsafe.Offsetof(c.TargetName), 8},
			{"Comment", unsafe.Offsetof(c.Comment), 12},
			{"LastWritten", unsafe.Offsetof(c.LastWritten), 16},
			{"CredentialBlobSize", unsafe.Offsetof(c.CredentialBlobSize), 24},
			{"CredentialBlob", unsafe.Offsetof(c.CredentialBlob), 28},
			{"Persist", unsafe.Offsetof(c.Persist), 32},
			{"AttributeCount", unsafe.Offsetof(c.AttributeCount), 36},
			{"Attributes", unsafe.Offsetof(c.Attributes), 40},
			{"TargetAlias", unsafe.Offsetof(c.TargetAlias), 44},
			{"UserName", unsafe.Offsetof(c.UserName), 48},
			{"size", unsafe.Sizeof(c), 52},
		}
	}
	for _, f := range fields {
		if f.got != f.want {
			t.Errorf("%s = %d, want %d", f.name, f.got, f.want)
		}
	}
}

func TestWin32CodesMatchTheSystem(t *testing.T) {
	for _, tt := range []struct {
		name    string
		literal int64
		system  int64
	}{
		{"ERROR_NOT_FOUND", win32NotFound, int64(windows.ERROR_NOT_FOUND)},
		{"ERROR_NO_SUCH_LOGON_SESSION", win32NoSuchLogonSession, int64(windows.ERROR_NO_SUCH_LOGON_SESSION)},
	} {
		if tt.literal != tt.system {
			t.Errorf("%s: chunked.go says %d, x/sys/windows says %d", tt.name, tt.literal, tt.system)
		}
	}
	if credTypeGeneric != 1 || credPersistLocalHost != 2 {
		t.Errorf("CRED_TYPE_GENERIC = %d, CRED_PERSIST_LOCAL_MACHINE = %d, want 1 and 2", credTypeGeneric, credPersistLocalHost)
	}
}
