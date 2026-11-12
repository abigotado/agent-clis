//go:build darwin && cgo && keychainintegration

// Package kctest is the Security.framework harness of the keychain
// integration tests. It exists so the tests themselves hold no cgo: it creates
// and deletes a scratch file keychain, locks and unlocks it, records the user
// keychain configuration, switches the process-wide prompt setting, and dumps
// the access control list of an item.
//
// Nothing here touches the login keychain. A scratch keychain is created
// outside the user's search list, and every query this package builds names it
// as the only keychain to search.
package kctest

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

// kt_create creates a file keychain at path, protected by password, and turns
// off its automatic locking: neither a lock interval nor lock on sleep. A
// failed settings call deletes the keychain again, so no failure leaves a
// keychain behind.
static OSStatus kt_create(const char *path, const char *password, SecKeychainRef *keychain) {
	SecKeychainRef created = NULL;
	OSStatus status = SecKeychainCreate(path, (UInt32)strlen(password), password, false, NULL, &created);
	if (status != errSecSuccess) {
		return status;
	}
	if (created == NULL) {
		return errSecInternalComponent;
	}
	SecKeychainSettings settings = { SEC_KEYCHAIN_SETTINGS_VERS1, false, false, INT_MAX };
	status = SecKeychainSetSettings(created, &settings);
	if (status != errSecSuccess) {
		SecKeychainDelete(created);
		CFRelease(created);
		return status;
	}
	*keychain = created;
	return errSecSuccess;
}

static OSStatus kt_unlock(SecKeychainRef keychain, const char *password) {
	return SecKeychainUnlock(keychain, (UInt32)strlen(password), password, true);
}

static OSStatus kt_unlocked(SecKeychainRef keychain, int *unlocked) {
	SecKeychainStatus status = 0;
	OSStatus result = SecKeychainGetStatus(keychain, &status);
	if (result == errSecSuccess) {
		*unlocked = (status & kSecUnlockStateStatus) != 0;
	}
	return result;
}

// kt_path copies the keychain's file path, NUL terminated, into buffer.
static OSStatus kt_path(SecKeychainRef keychain, char *buffer, UInt32 capacity) {
	UInt32 length = capacity - 1;
	OSStatus status = SecKeychainGetPath(keychain, &length, buffer);
	if (status != errSecSuccess) {
		return status;
	}
	buffer[length] = '\0';
	return errSecSuccess;
}

static OSStatus kt_user_interaction(int *allowed) {
	Boolean state = false;
	OSStatus status = SecKeychainGetUserInteractionAllowed(&state);
	if (status == errSecSuccess) {
		*allowed = state != 0;
	}
	return status;
}

static OSStatus kt_search_list_path(CFArrayRef list, CFIndex index, char *buffer, UInt32 capacity) {
	return kt_path((SecKeychainRef)CFArrayGetValueAtIndex(list, index), buffer, capacity);
}

static CFStringRef kt_string(const char *value) {
	return CFStringCreateWithCString(kCFAllocatorDefault, value, kCFStringEncodingUTF8);
}

// kt_item_ref resolves the item by reference in the one keychain. It never
// decrypts, so it needs no access control list entry and shows no prompt.
static OSStatus kt_item_ref(SecKeychainRef keychain, const char *service, const char *account, SecKeychainItemRef *item) {
	CFStringRef service_string = kt_string(service);
	CFStringRef account_string = kt_string(account);
	const void *list_values[] = { keychain };
	CFArrayRef list = CFArrayCreate(kCFAllocatorDefault, list_values, 1, &kCFTypeArrayCallBacks);
	CFMutableDictionaryRef query = CFDictionaryCreateMutable(
		kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (service_string == NULL || account_string == NULL || list == NULL || query == NULL) {
		if (service_string != NULL) CFRelease(service_string);
		if (account_string != NULL) CFRelease(account_string);
		if (list != NULL) CFRelease(list);
		if (query != NULL) CFRelease(query);
		return errSecAllocate;
	}
	CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(query, kSecAttrService, service_string);
	CFDictionarySetValue(query, kSecAttrAccount, account_string);
	CFDictionarySetValue(query, kSecMatchSearchList, list);
	CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
	CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
	CFDictionarySetValue(query, kSecUseAuthenticationUI, kSecUseAuthenticationUIFail);
	CFTypeRef result = NULL;
	OSStatus status = SecItemCopyMatching(query, &result);
	CFRelease(query);
	CFRelease(list);
	CFRelease(service_string);
	CFRelease(account_string);
	if (status != errSecSuccess) {
		if (result != NULL) {
			CFRelease(result);
		}
		return status;
	}
	if (result == NULL || CFGetTypeID(result) != SecKeychainItemGetTypeID()) {
		if (result != NULL) {
			CFRelease(result);
		}
		return errSecInternalComponent;
	}
	*item = (SecKeychainItemRef)result;
	return errSecSuccess;
}

// kt_acl_open returns the item's access object and its entries. The caller
// releases both.
static OSStatus kt_acl_open(SecKeychainRef keychain, const char *service, const char *account, SecAccessRef *access, CFArrayRef *entries) {
	SecKeychainItemRef item = NULL;
	OSStatus status = kt_item_ref(keychain, service, account, &item);
	if (status != errSecSuccess) {
		return status;
	}
	SecAccessRef copied = NULL;
	status = SecKeychainItemCopyAccess(item, &copied);
	CFRelease(item);
	if (status != errSecSuccess) {
		return status;
	}
	CFArrayRef list = NULL;
	status = SecAccessCopyACLList(copied, &list);
	if (status != errSecSuccess || list == NULL) {
		CFRelease(copied);
		return status != errSecSuccess ? status : errSecInternalComponent;
	}
	*access = copied;
	*entries = list;
	return errSecSuccess;
}

// kt_auth_name names one authorization the way the Security headers do, minus
// the kSecACLAuthorization prefix. It compares against the framework's own
// constants, so it does not depend on how the strings are spelled. An
// authorization it does not know is copied out as "?<raw string>".
#define KT_KNOWN_AUTHORIZATIONS(X) \
	X(Any) X(Login) X(GenKey) X(Delete) X(ExportWrapped) X(ExportClear) X(ImportWrapped) \
	X(ImportClear) X(Sign) X(Encrypt) X(Decrypt) X(MAC) X(Derive) X(KeychainCreate) \
	X(KeychainDelete) X(KeychainItemRead) X(KeychainItemInsert) X(KeychainItemModify) \
	X(KeychainItemDelete) X(ChangeACL) X(ChangeOwner) X(PartitionID) X(Integrity)

static int kt_auth_name(CFStringRef auth, char *out, size_t capacity) {
#define KT_CHECK(name) \
	if (CFEqual(auth, kSecACLAuthorization##name)) { \
		strlcpy(out, #name, capacity); \
		return 1; \
	}
	KT_KNOWN_AUTHORIZATIONS(KT_CHECK)
#undef KT_CHECK
	out[0] = '?';
	if (!CFStringGetCString(auth, out + 1, (CFIndex)capacity - 1, kCFStringEncodingUTF8)) {
		out[1] = '\0';
	}
	return 1;
}

// kt_acl_entry describes entry index of the list: its authorizations as a
// comma separated list of names, the number of applications it trusts (-1 when
// the entry trusts any application, which is a NULL application list), how many
// of them are this binary, and the prompt selector.
static OSStatus kt_acl_entry(CFArrayRef entries, CFIndex index, SecTrustedApplicationRef self_app,
		char *authorizations, size_t capacity, long *applications, long *self_applications, unsigned int *selector) {
	SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(entries, index);
	CFArrayRef auths = SecACLCopyAuthorizations(acl);
	if (auths == NULL) {
		return errSecInternalComponent;
	}
	authorizations[0] = '\0';
	for (CFIndex i = 0; i < CFArrayGetCount(auths); i++) {
		char name[128];
		kt_auth_name((CFStringRef)CFArrayGetValueAtIndex(auths, i), name, sizeof name);
		if (strlen(authorizations) + strlen(name) + 2 > capacity) {
			CFRelease(auths);
			return errSecBufferTooSmall;
		}
		if (i > 0) {
			strlcat(authorizations, ",", capacity);
		}
		strlcat(authorizations, name, capacity);
	}
	CFRelease(auths);

	CFArrayRef apps = NULL;
	CFStringRef description = NULL;
	SecKeychainPromptSelector prompt = 0;
	OSStatus status = SecACLCopyContents(acl, &apps, &description, &prompt);
	if (status != errSecSuccess) {
		return status;
	}
	*selector = (unsigned int)prompt;
	*applications = apps == NULL ? -1 : (long)CFArrayGetCount(apps);
	*self_applications = 0;
	CFDataRef self_data = NULL;
	if (apps != NULL && CFArrayGetCount(apps) > 0) {
		status = SecTrustedApplicationCopyData(self_app, &self_data);
	}
	for (CFIndex i = 0; status == errSecSuccess && apps != NULL && i < CFArrayGetCount(apps); i++) {
		CFDataRef data = NULL;
		status = SecTrustedApplicationCopyData((SecTrustedApplicationRef)CFArrayGetValueAtIndex(apps, i), &data);
		if (status == errSecSuccess && data != NULL && self_data != NULL && CFEqual(data, self_data)) {
			(*self_applications)++;
		}
		if (data != NULL) {
			CFRelease(data);
		}
	}
	if (self_data != NULL) {
		CFRelease(self_data);
	}
	if (apps != NULL) {
		CFRelease(apps);
	}
	if (description != NULL) {
		CFRelease(description);
	}
	return status;
}
*/
import "C"

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"unsafe"
)

// Names of the authorizations a dumped ACL entry can carry. They are the
// Security header names without the kSecACLAuthorization prefix.
const (
	AuthChangeACL = "ChangeACL"
	AuthDecrypt   = "Decrypt"
	AuthEncrypt   = "Encrypt"
)

// PromptRequirePassphrase is the prompt selector bit that asks for the login
// password on every use (kSecKeychainPromptRequirePassphase).
const PromptRequirePassphrase = uint32(C.kSecKeychainPromptRequirePassphase)

// StatusError is a failed Security.framework call. It carries the call's name
// and OSStatus only.
type StatusError struct {
	Call   string
	Status int32
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("kctest: %s: OSStatus %d", e.Call, e.Status)
}

func check(call string, status C.OSStatus) error {
	if status == C.errSecSuccess {
		return nil
	}
	return &StatusError{Call: call, Status: int32(status)}
}

// pathBuffer is large enough for any path the system hands back.
const pathBuffer = 4096

// Keychain is a scratch file keychain created by Create.
type Keychain struct {
	ref      C.SecKeychainRef
	path     string
	password string
	deleted  bool
}

// Create makes a new keychain in dir with a random name and a random password.
// It is unlocked, does not lock again on its own, and is not on the user's
// search list. dir must be an absolute path to an existing directory; the
// tests pass t.TempDir().
func Create(dir string) (*Keychain, error) {
	if !filepath.IsAbs(dir) {
		return nil, errors.New("kctest: the keychain directory must be absolute")
	}
	name, err := randomHex(8)
	if err != nil {
		return nil, err
	}
	password, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "secretstore-test-"+name+".keychain-db")
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	cPassword := C.CString(password)
	defer C.free(unsafe.Pointer(cPassword))
	var ref C.SecKeychainRef
	if err := check("SecKeychainCreate", C.kt_create(cPath, cPassword, &ref)); err != nil {
		return nil, err
	}
	return &Keychain{ref: ref, path: path, password: password}, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("kctest: read random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Ref returns the SecKeychainRef as an integer, for the test to convert to the
// reference type of the package under test. The keychain keeps ownership.
func (k *Keychain) Ref() uintptr {
	return uintptr(k.ref)
}

// Path returns the path the keychain was created at.
func (k *Keychain) Path() string {
	return k.path
}

// Lock locks the keychain.
func (k *Keychain) Lock() error {
	return check("SecKeychainLock", C.SecKeychainLock(k.ref))
}

// Unlock unlocks the keychain with its password, without a prompt.
func (k *Keychain) Unlock() error {
	cPassword := C.CString(k.password)
	defer C.free(unsafe.Pointer(cPassword))
	return check("SecKeychainUnlock", C.kt_unlock(k.ref, cPassword))
}

// Unlocked reports whether the keychain is unlocked.
func (k *Keychain) Unlocked() (bool, error) {
	var unlocked C.int
	if err := check("SecKeychainGetStatus", C.kt_unlocked(k.ref, &unlocked)); err != nil {
		return false, err
	}
	return unlocked != 0, nil
}

// Delete deletes the keychain file and releases the reference. A second call
// does nothing.
func (k *Keychain) Delete() error {
	if k.deleted {
		return nil
	}
	k.deleted = true
	err := check("SecKeychainDelete", C.SecKeychainDelete(k.ref))
	C.CFRelease(C.CFTypeRef(k.ref))
	k.ref = 0
	return err
}

// Config is the user's keychain configuration as a test needs to see it
// unchanged: the search list in order, and the default keychain.
type Config struct {
	SearchList []string
	Default    string
}

// Equal reports whether the two configurations are identical.
func (c Config) Equal(other Config) bool {
	return c.Default == other.Default && slices.Equal(c.SearchList, other.SearchList)
}

// String describes the configuration for a failure message. It contains paths
// of the user's keychains and nothing else.
func (c Config) String() string {
	return fmt.Sprintf("search list [%s], default %q", strings.Join(c.SearchList, ", "), c.Default)
}

// Snapshot reads the user's search list and default keychain.
func Snapshot() (Config, error) {
	var list C.CFArrayRef
	if err := check("SecKeychainCopySearchList", C.SecKeychainCopySearchList(&list)); err != nil {
		return Config{}, err
	}
	if list == 0 {
		return Config{}, errors.New("kctest: SecKeychainCopySearchList returned no list")
	}
	defer C.CFRelease(C.CFTypeRef(list))
	var config Config
	buffer := make([]byte, pathBuffer)
	for i := C.CFIndex(0); i < C.CFArrayGetCount(list); i++ {
		if err := check("SecKeychainGetPath", C.kt_search_list_path(list, i, (*C.char)(unsafe.Pointer(&buffer[0])), pathBuffer)); err != nil {
			return Config{}, err
		}
		config.SearchList = append(config.SearchList, C.GoString((*C.char)(unsafe.Pointer(&buffer[0]))))
	}

	var def C.SecKeychainRef
	status := C.SecKeychainCopyDefault(&def)
	if status == C.errSecNoDefaultKeychain {
		// A machine without a default keychain is a valid state to compare.
		config.Default = ""
		return config, nil
	}
	if err := check("SecKeychainCopyDefault", status); err != nil {
		return Config{}, err
	}
	defer C.CFRelease(C.CFTypeRef(def))
	if err := check("SecKeychainGetPath", C.kt_path(def, (*C.char)(unsafe.Pointer(&buffer[0])), pathBuffer)); err != nil {
		return Config{}, err
	}
	config.Default = C.GoString((*C.char)(unsafe.Pointer(&buffer[0])))
	return config, nil
}

// InteractionAllowed reads the process's prompt setting.
func InteractionAllowed() (bool, error) {
	var allowed C.int
	if err := check("SecKeychainGetUserInteractionAllowed", C.kt_user_interaction(&allowed)); err != nil {
		return false, err
	}
	return allowed != 0, nil
}

// SetInteractionAllowed sets the prompt setting and reads it back, so a setting
// that did not take effect is an error.
func SetInteractionAllowed(allowed bool) error {
	flag := C.Boolean(0)
	if allowed {
		flag = 1
	}
	if err := check("SecKeychainSetUserInteractionAllowed", C.SecKeychainSetUserInteractionAllowed(flag)); err != nil {
		return err
	}
	got, err := InteractionAllowed()
	if err != nil {
		return err
	}
	if got != allowed {
		return fmt.Errorf("kctest: prompt setting is %t after setting it to %t", got, allowed)
	}
	return nil
}

// ACLEntry is one entry of an item's access control list.
type ACLEntry struct {
	// Authorizations are the names of the operations the entry covers, sorted.
	// A name outside the known set is prefixed with "?".
	Authorizations []string
	// Applications is the number of applications the entry trusts, or -1 when
	// the application list is NULL, which means any application.
	Applications int
	// SelfApplications is how many of those applications are the running
	// binary.
	SelfApplications int
	// PromptSelector is the entry's keychain prompt selector.
	PromptSelector uint32
}

// Has reports whether the entry covers the authorization.
func (e ACLEntry) Has(authorization string) bool {
	return slices.Contains(e.Authorizations, authorization)
}

// String describes the entry for a failure message.
func (e ACLEntry) String() string {
	apps := fmt.Sprintf("%d (%d this binary)", e.Applications, e.SelfApplications)
	if e.Applications < 0 {
		apps = "any"
	}
	return fmt.Sprintf("authorizations [%s] applications %s prompt 0x%x",
		strings.Join(e.Authorizations, " "), apps, e.PromptSelector)
}

// ACL dumps every access control list entry of the generic password item in
// this keychain. It looks the item up by reference, so it decrypts nothing and
// cannot show a prompt.
func (k *Keychain) ACL(service, account string) ([]ACLEntry, error) {
	cService := C.CString(service)
	defer C.free(unsafe.Pointer(cService))
	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cAccount))
	var access C.SecAccessRef
	var entries C.CFArrayRef
	if err := check("read the item's access", C.kt_acl_open(k.ref, cService, cAccount, &access, &entries)); err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(access))
	defer C.CFRelease(C.CFTypeRef(entries))

	var self C.SecTrustedApplicationRef
	if err := check("SecTrustedApplicationCreateFromPath", C.SecTrustedApplicationCreateFromPath(nil, &self)); err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(self))

	var dump []ACLEntry
	buffer := make([]byte, 2048)
	for i := C.CFIndex(0); i < C.CFArrayGetCount(entries); i++ {
		var apps, selfApps C.long
		var selector C.uint
		if err := check("read an access control entry", C.kt_acl_entry(entries, i, self,
			(*C.char)(unsafe.Pointer(&buffer[0])), C.size_t(len(buffer)), &apps, &selfApps, &selector)); err != nil {
			return nil, err
		}
		authorizations := strings.Split(C.GoString((*C.char)(unsafe.Pointer(&buffer[0]))), ",")
		slices.Sort(authorizations)
		dump = append(dump, ACLEntry{
			Authorizations:   authorizations,
			Applications:     int(apps),
			SelfApplications: int(selfApps),
			PromptSelector:   uint32(selector),
		})
	}
	return dump, nil
}
