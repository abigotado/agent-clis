package secretstore

import (
	"bytes"
	"context"
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// This file is the Windows Credential Manager binding behind credAPI. It holds
// no format logic: chunked.go decides what is stored and how Win32 errors
// classify.

const (
	credTypeGeneric      = 1 // CRED_TYPE_GENERIC
	credPersistLocalHost = 2 // CRED_PERSIST_LOCAL_MACHINE

	// maxEnumerated bounds the credentials one enumeration is read from. A key
	// owns at most a few generations of 52 chunks, so this only limits what a
	// program filling the prefix with junk can make us copy; a sweep that sees
	// fewer names than exist finishes on a later Save or Delete.
	maxEnumerated = 1 << 12
)

// credential is CREDENTIALW. x/sys/windows does not define it, so the layout
// is written out and a Windows test checks every offset against the Win32
// header on each architecture.
type credential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr // PCREDENTIAL_ATTRIBUTEW; always nil here
	TargetAlias        *uint16
	UserName           *uint16
}

// credman implements credAPI over advapi32.
type credman struct {
	procRead      *windows.LazyProc
	procWrite     *windows.LazyProc
	procDelete    *windows.LazyProc
	procEnumerate *windows.LazyProc
	procFree      *windows.LazyProc
}

var _ credAPI = (*credman)(nil)

func newCredman() *credman {
	dll := windows.NewLazySystemDLL("advapi32.dll")
	return &credman{
		procRead:      dll.NewProc("CredReadW"),
		procWrite:     dll.NewProc("CredWriteW"),
		procDelete:    dll.NewProc("CredDeleteW"),
		procEnumerate: dll.NewProc("CredEnumerateW"),
		procFree:      dll.NewProc("CredFree"),
	}
}

// win32Failure turns the error LazyProc.Call reports for a zero result into the
// win32Error chunked.go classifies. Anything that is not an errno is returned
// as it is; it classifies as an unknown failure and carries no key.
func win32Failure(err error) error {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return &win32Error{code: int64(errno)}
	}
	return err
}

// free releases a buffer returned by CredReadW or CredEnumerateW.
func (c *credman) free(p unsafe.Pointer) {
	// CredFree returns nothing, so there is no result to check.
	c.procFree.Call(uintptr(p))
}

// readCredential looks the target up and calls visit while the system buffer
// is valid; the buffer is freed before it returns.
func (c *credman) readCredential(ctx context.Context, target string, visit func(*credential) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	var cred *credential
	r1, _, callErr := c.procRead.Call(uintptr(unsafe.Pointer(name)), credTypeGeneric, 0, uintptr(unsafe.Pointer(&cred)))
	if r1 == 0 {
		return win32Failure(callErr)
	}
	defer c.free(unsafe.Pointer(cred))
	return visit(cred)
}

// blobOf returns the credential's blob as a slice over the system buffer.
func blobOf(cred *credential) []byte {
	if cred.CredentialBlobSize == 0 || cred.CredentialBlob == nil {
		return nil
	}
	return unsafe.Slice(cred.CredentialBlob, int(cred.CredentialBlobSize))
}

func (c *credman) read(ctx context.Context, target string, max int) ([]byte, error) {
	var out []byte
	err := c.readCredential(ctx, target, func(cred *credential) error {
		if int64(cred.CredentialBlobSize) > int64(max) {
			return errBlobTooLarge
		}
		blob := blobOf(cred)
		out = bytes.Clone(blob)
		if out == nil {
			out = []byte{}
		}
		// The system buffer is this call's own copy; wipe it before it is freed.
		clear(blob)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *credman) write(ctx context.Context, target, userName string, blob []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(blob) > chunkSize {
		return &win32Error{code: int64(windows.ERROR_INVALID_PARAMETER)}
	}
	name, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	user, err := windows.UTF16PtrFromString(userName)
	if err != nil {
		return err
	}
	cred := credential{
		Type:               credTypeGeneric,
		TargetName:         name,
		CredentialBlobSize: uint32(len(blob)),
		Persist:            credPersistLocalHost,
		UserName:           user,
	}
	if len(blob) > 0 {
		cred.CredentialBlob = &blob[0]
	}
	r1, _, callErr := c.procWrite.Call(uintptr(unsafe.Pointer(&cred)), 0)
	if r1 == 0 {
		return win32Failure(callErr)
	}
	return nil
}

func (c *credman) delete(ctx context.Context, target string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	r1, _, callErr := c.procDelete.Call(uintptr(unsafe.Pointer(name)), credTypeGeneric, 0)
	if r1 == 0 {
		return win32Failure(callErr)
	}
	return nil
}

func (c *credman) enumerate(ctx context.Context, filter string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pattern, err := windows.UTF16PtrFromString(filter)
	if err != nil {
		return nil, err
	}
	var (
		count uint32
		creds **credential
	)
	r1, _, callErr := c.procEnumerate.Call(uintptr(unsafe.Pointer(pattern)), 0, uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&creds)))
	if r1 == 0 {
		failed := win32Failure(callErr)
		var we *win32Error
		if errors.As(failed, &we) && we.code == win32NotFound {
			return nil, nil
		}
		return nil, failed
	}
	defer c.free(unsafe.Pointer(creds))
	var names []string
	for _, cred := range unsafe.Slice(creds, min(int(count), maxEnumerated)) {
		if cred.Type != credTypeGeneric || cred.TargetName == nil {
			continue
		}
		names = append(names, windows.UTF16PtrToString(cred.TargetName))
	}
	return names, nil
}
