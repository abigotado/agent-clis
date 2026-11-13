//go:build darwin && cgo && keychainintegration

// Package kctest is the Security.framework harness of the keychain
// integration tests. It exists so the tests themselves hold no cgo: it creates
// and deletes a scratch file keychain, locks and unlocks it, records the user
// keychain configuration, switches the process-wide prompt setting, and dumps
// the access control list of an item. For the cross-binary tests it also opens
// a scratch keychain in another process, imports throwaway signing identities,
// signs a file with one, and reads a file's code signature.
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
#include <stdio.h>
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
		if (list != NULL) {
			CFRelease(list);
		}
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
// kt_open opens an existing keychain file and unlocks it with its password. A
// path that is not a keychain fails the unlock, so a missing file is an error.
static OSStatus kt_open(const char *path, const char *password, SecKeychainRef *keychain) {
	SecKeychainRef opened = NULL;
	OSStatus status = SecKeychainOpen(path, &opened);
	if (status != errSecSuccess) {
		return status;
	}
	if (opened == NULL) {
		return errSecInternalComponent;
	}
	status = SecKeychainUnlock(opened, (UInt32)strlen(password), password, true);
	if (status != errSecSuccess) {
		CFRelease(opened);
		return status;
	}
	*keychain = opened;
	return errSecSuccess;
}

// kt_open_only opens a keychain file without unlocking it.
static OSStatus kt_open_only(const char *path, SecKeychainRef *keychain) {
	SecKeychainRef opened = NULL;
	OSStatus status = SecKeychainOpen(path, &opened);
	if (status != errSecSuccess) {
		return status;
	}
	if (opened == NULL) {
		return errSecInternalComponent;
	}
	*keychain = opened;
	return errSecSuccess;
}

// The code signing SPI. The Security framework exports these without a public
// header; a self-signed identity cannot be used through /usr/bin/codesign, which
// refuses an untrusted one, but the signer API accepts it.
typedef struct __SecCodeSigner *SecCodeSignerRef;
OSStatus SecCodeSignerCreate(CFDictionaryRef parameters, SecCSFlags flags, SecCodeSignerRef *signer);
OSStatus SecCodeSignerAddSignature(SecCodeSignerRef signer, SecStaticCodeRef code, SecCSFlags flags);
extern const CFStringRef kSecCodeSignerIdentity;
extern const CFStringRef kSecCodeSignerIdentifier;
extern const CFStringRef kSecCodeSignerFlags;

// The hardened runtime code signature flag (kSecCodeSignatureRuntime).
#define KT_CODE_SIGNATURE_RUNTIME 0x10000

// kt_import imports one PEM item, or with pkcs12 a PKCS#12 identity, into the
// keychain. The imported private key trusts this binary, so signing from this
// process needs no prompt. It reports how many items were imported.
static OSStatus kt_import(SecKeychainRef keychain, const UInt8 *bytes, CFIndex length, int pkcs12, const char *passphrase, long *imported) {
	SecTrustedApplicationRef self = NULL;
	OSStatus status = SecTrustedApplicationCreateFromPath(NULL, &self);
	if (status != errSecSuccess) {
		return status;
	}
	if (self == NULL) {
		return errSecInternalComponent;
	}
	const void *values[] = { self };
	CFArrayRef applications = CFArrayCreate(kCFAllocatorDefault, values, 1, &kCFTypeArrayCallBacks);
	CFRelease(self);
	if (applications == NULL) {
		return errSecAllocate;
	}
	SecAccessRef access = NULL;
	status = SecAccessCreate(CFSTR("secretstore test signing key"), applications, &access);
	CFRelease(applications);
	if (status != errSecSuccess) {
		return status;
	}
	if (access == NULL) {
		return errSecInternalComponent;
	}

	CFDataRef data = CFDataCreate(kCFAllocatorDefault, bytes, length);
	CFStringRef passphrase_string = passphrase != NULL ? kt_string(passphrase) : NULL;
	if (data == NULL || (passphrase != NULL && passphrase_string == NULL)) {
		status = errSecAllocate;
	} else {
		SecItemImportExportKeyParameters parameters;
		memset(&parameters, 0, sizeof parameters);
		parameters.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
		parameters.passphrase = passphrase_string;
		parameters.accessRef = access;
		SecExternalFormat format = pkcs12 ? kSecFormatPKCS12 : kSecFormatUnknown;
		SecExternalItemType type = pkcs12 ? kSecItemTypeAggregate : kSecItemTypeUnknown;
		CFArrayRef items = NULL;
		status = SecItemImport(data, NULL, &format, &type, 0, &parameters, keychain, &items);
		if (items != NULL) {
			*imported = (long)CFArrayGetCount(items);
			CFRelease(items);
		}
	}
	if (data != NULL) {
		CFRelease(data);
	}
	if (passphrase_string != NULL) {
		CFRelease(passphrase_string);
	}
	CFRelease(access);
	return status;
}

// kt_find_identity returns the identity in the keychain whose certificate has
// the subject summary common_name. The caller releases it.
static OSStatus kt_find_identity(SecKeychainRef keychain, const char *common_name, SecIdentityRef *identity) {
	CFStringRef wanted = kt_string(common_name);
	const void *list_values[] = { keychain };
	CFArrayRef list = CFArrayCreate(kCFAllocatorDefault, list_values, 1, &kCFTypeArrayCallBacks);
	CFMutableDictionaryRef query = CFDictionaryCreateMutable(
		kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (wanted == NULL || list == NULL || query == NULL) {
		if (wanted != NULL) CFRelease(wanted);
		if (list != NULL) CFRelease(list);
		if (query != NULL) CFRelease(query);
		return errSecAllocate;
	}
	CFDictionarySetValue(query, kSecClass, kSecClassIdentity);
	CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);
	CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
	CFDictionarySetValue(query, kSecMatchSearchList, list);
	CFTypeRef result = NULL;
	OSStatus status = SecItemCopyMatching(query, &result);
	CFRelease(query);
	CFRelease(list);
	if (status != errSecSuccess) {
		if (result != NULL) {
			CFRelease(result);
		}
		CFRelease(wanted);
		return status;
	}
	if (result == NULL || CFGetTypeID(result) != CFArrayGetTypeID()) {
		if (result != NULL) {
			CFRelease(result);
		}
		CFRelease(wanted);
		return errSecInternalComponent;
	}
	CFArrayRef identities = (CFArrayRef)result;
	status = errSecItemNotFound;
	for (CFIndex i = 0; i < CFArrayGetCount(identities); i++) {
		SecIdentityRef candidate = (SecIdentityRef)CFArrayGetValueAtIndex(identities, i);
		SecCertificateRef certificate = NULL;
		if (SecIdentityCopyCertificate(candidate, &certificate) != errSecSuccess || certificate == NULL) {
			continue;
		}
		CFStringRef summary = SecCertificateCopySubjectSummary(certificate);
		CFRelease(certificate);
		if (summary == NULL) {
			continue;
		}
		Boolean match = CFEqual(summary, wanted);
		CFRelease(summary);
		if (match) {
			*identity = (SecIdentityRef)CFRetain(candidate);
			status = errSecSuccess;
			break;
		}
	}
	CFRelease(identities);
	CFRelease(wanted);
	return status;
}

// kt_sign signs the file at path with the identity named common_name, under the
// given identifier and with the hardened runtime flag, replacing any signature
// the file has.
static OSStatus kt_sign(SecKeychainRef keychain, const char *common_name, const char *path, const char *identifier) {
	SecIdentityRef identity = NULL;
	OSStatus status = kt_find_identity(keychain, common_name, &identity);
	if (status != errSecSuccess) {
		return status;
	}
	CFStringRef identifier_string = kt_string(identifier);
	int runtime = KT_CODE_SIGNATURE_RUNTIME;
	CFNumberRef flags = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &runtime);
	CFURLRef url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, (const UInt8 *)path, (CFIndex)strlen(path), false);
	if (identifier_string == NULL || flags == NULL || url == NULL) {
		status = errSecAllocate;
	} else {
		const void *keys[] = { kSecCodeSignerIdentity, kSecCodeSignerIdentifier, kSecCodeSignerFlags };
		const void *values[] = { identity, identifier_string, flags };
		CFDictionaryRef parameters = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 3,
			&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
		if (parameters == NULL) {
			status = errSecAllocate;
		} else {
			SecCodeSignerRef signer = NULL;
			status = SecCodeSignerCreate(parameters, kSecCSDefaultFlags, &signer);
			if (status == errSecSuccess && signer == NULL) {
				status = errSecInternalComponent;
			}
			if (status == errSecSuccess) {
				SecStaticCodeRef code = NULL;
				status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
				if (status == errSecSuccess && code == NULL) {
					status = errSecInternalComponent;
				}
				if (status == errSecSuccess) {
					status = SecCodeSignerAddSignature(signer, code, kSecCSDefaultFlags);
					CFRelease(code);
				}
				CFRelease(signer);
			}
			CFRelease(parameters);
		}
	}
	if (identifier_string != NULL) CFRelease(identifier_string);
	if (flags != NULL) CFRelease(flags);
	if (url != NULL) CFRelease(url);
	CFRelease(identity);
	return status;
}

typedef struct {
	char identifier[256];
	char requirement[2048];
	char leaf[256];
	char cdhash[129];
	unsigned int flags;
	int has_certificates;
} kt_signature_info;

// kt_signature reads the code signature of the file at path: its identifier,
// flags, code directory hash, designated requirement and the leaf certificate's
// subject summary. It reads the file and nothing else.
static OSStatus kt_signature(const char *path, kt_signature_info *out) {
	memset(out, 0, sizeof *out);
	CFURLRef url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, (const UInt8 *)path, (CFIndex)strlen(path), false);
	if (url == NULL) {
		return errSecAllocate;
	}
	SecStaticCodeRef code = NULL;
	OSStatus status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
	CFRelease(url);
	if (status != errSecSuccess) {
		return status;
	}
	if (code == NULL) {
		return errSecInternalComponent;
	}
	CFDictionaryRef info = NULL;
	status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info);
	if (status == errSecSuccess && info == NULL) {
		status = errSecInternalComponent;
	}
	if (status == errSecSuccess) {
		CFStringRef identifier = (CFStringRef)CFDictionaryGetValue(info, kSecCodeInfoIdentifier);
		if (identifier != NULL) {
			CFStringGetCString(identifier, out->identifier, sizeof out->identifier, kCFStringEncodingUTF8);
		}
		CFNumberRef flags = (CFNumberRef)CFDictionaryGetValue(info, kSecCodeInfoFlags);
		if (flags != NULL) {
			SInt64 value = 0;
			CFNumberGetValue(flags, kCFNumberSInt64Type, &value);
			out->flags = (unsigned int)value;
		}
		CFDataRef unique = (CFDataRef)CFDictionaryGetValue(info, kSecCodeInfoUnique);
		if (unique != NULL) {
			CFIndex length = CFDataGetLength(unique);
			if (length > 64) {
				length = 64;
			}
			const UInt8 *bytes = CFDataGetBytePtr(unique);
			for (CFIndex i = 0; i < length; i++) {
				snprintf(out->cdhash + 2 * i, 3, "%02x", bytes[i]);
			}
		}
		CFArrayRef certificates = (CFArrayRef)CFDictionaryGetValue(info, kSecCodeInfoCertificates);
		if (certificates != NULL && CFArrayGetCount(certificates) > 0) {
			out->has_certificates = 1;
			CFStringRef summary = SecCertificateCopySubjectSummary((SecCertificateRef)CFArrayGetValueAtIndex(certificates, 0));
			if (summary != NULL) {
				CFStringGetCString(summary, out->leaf, sizeof out->leaf, kCFStringEncodingUTF8);
				CFRelease(summary);
			}
		}
		CFRelease(info);

		SecRequirementRef requirement = NULL;
		status = SecCodeCopyDesignatedRequirement(code, kSecCSDefaultFlags, &requirement);
		if (status == errSecSuccess && requirement != NULL) {
			CFStringRef text = NULL;
			status = SecRequirementCopyString(requirement, kSecCSDefaultFlags, &text);
			if (status == errSecSuccess && text != NULL) {
				CFStringGetCString(text, out->requirement, sizeof out->requirement, kCFStringEncodingUTF8);
			}
			if (text != NULL) {
				CFRelease(text);
			}
		} else if (status == errSecSuccess) {
			status = errSecInternalComponent;
		}
		if (requirement != NULL) {
			CFRelease(requirement);
		}
	}
	CFRelease(code);
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
	path := filepath.Join(dir, namePrefix+name+".keychain-db")
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

// namePrefix starts the file name of every keychain Create makes. Open refuses
// a file that does not carry it, so a helper process handed the wrong path
// cannot be pointed at a user keychain.
const namePrefix = "secretstore-test-"

// Open opens a keychain Create made, in another process, and unlocks it with
// its password. The caller releases it with Close; Delete still deletes it.
func Open(path, password string) (*Keychain, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("kctest: the keychain path must be absolute")
	}
	if name := filepath.Base(path); !strings.HasPrefix(name, namePrefix) || !strings.HasSuffix(name, ".keychain-db") {
		return nil, errors.New("kctest: refusing to open a keychain that Create did not make")
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	cPassword := C.CString(password)
	defer C.free(unsafe.Pointer(cPassword))
	var ref C.SecKeychainRef
	if err := check("open and unlock the keychain", C.kt_open(cPath, cPassword, &ref)); err != nil {
		return nil, err
	}
	return &Keychain{ref: ref, path: path, password: password}, nil
}

// OpenWithoutUnlock opens a keychain Create made, in another process, and
// neither unlocks it nor reads its status. It is for a process in a sandbox
// that refuses every keychain call, Codex's read-only one included, where
// Open fails before the call under test is reached; the process that made the
// keychain keeps it unlocked and checks that itself. SecKeychainOpen does not
// look at the file, so a wrong path only fails at the first real call.
func OpenWithoutUnlock(path string) (*Keychain, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("kctest: the keychain path must be absolute")
	}
	if name := filepath.Base(path); !strings.HasPrefix(name, namePrefix) || !strings.HasSuffix(name, ".keychain-db") {
		return nil, errors.New("kctest: refusing to open a keychain that Create did not make")
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	var ref C.SecKeychainRef
	if err := check("open the keychain", C.kt_open_only(cPath, &ref)); err != nil {
		return nil, err
	}
	return &Keychain{ref: ref, path: path}, nil
}

// Close releases the reference without deleting the keychain file. A second
// call does nothing.
func (k *Keychain) Close() {
	if k.ref == 0 {
		return
	}
	C.CFRelease(C.CFTypeRef(k.ref))
	k.ref = 0
}

// Password returns the keychain's password. A test passes it to a helper
// process on its standard input, never in an argument or the environment.
func (k *Keychain) Password() string {
	return k.password
}

// Ref returns the SecKeychainRef as an integer, for the test to convert to the
// reference type of the package under test. The keychain keeps ownership.
//
// It must not be called after Close or Delete: a NULL reference converted back
// reaches the user's default keychain. Ref panics then. That is a programming
// error, and a panic is acceptable in a test-only helper package.
func (k *Keychain) Ref() uintptr {
	if k.ref == 0 {
		panic("kctest: Ref on a closed or deleted keychain")
	}
	return uintptr(k.ref)
}

// Path returns the path the keychain was created at.
func (k *Keychain) Path() string {
	return k.path
}

// errClosed is returned by a method called on a closed or deleted keychain. A
// NULL SecKeychainRef would make the Security calls act on the user's default
// keychain, so no method reaches them without a live reference.
var errClosed = errors.New("kctest: the keychain is closed or deleted")

func (k *Keychain) live() error {
	if k.ref == 0 {
		return errClosed
	}
	return nil
}

// Lock locks the keychain.
func (k *Keychain) Lock() error {
	if err := k.live(); err != nil {
		return err
	}
	return check("SecKeychainLock", C.SecKeychainLock(k.ref))
}

// Unlock unlocks the keychain with its password, without a prompt.
func (k *Keychain) Unlock() error {
	if err := k.live(); err != nil {
		return err
	}
	cPassword := C.CString(k.password)
	defer C.free(unsafe.Pointer(cPassword))
	return check("SecKeychainUnlock", C.kt_unlock(k.ref, cPassword))
}

// Unlocked reports whether the keychain is unlocked.
func (k *Keychain) Unlocked() (bool, error) {
	if err := k.live(); err != nil {
		return false, err
	}
	var unlocked C.int
	if err := check("SecKeychainGetStatus", C.kt_unlocked(k.ref, &unlocked)); err != nil {
		return false, err
	}
	return unlocked != 0, nil
}

// Delete deletes the keychain file and releases the reference. A second call
// does nothing, and neither does a call on a keychain that was closed.
func (k *Keychain) Delete() error {
	if k.deleted || k.ref == 0 {
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
	// binary, by a path match only: it compares the application's recorded
	// path, not its code identity or signature. Never use it for a claim about
	// identity; a different binary at the same path counts.
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
	if err := k.live(); err != nil {
		return nil, err
	}
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

// markerValue is the build marker. A test builds its binary twice with a
// different -ldflags -X value for MarkerVariable, so the two builds differ in
// content and therefore in code directory hash. BuildMarker reads it, which
// shows what a binary was linked with.
var markerValue = "unset"

// MarkerVariable is the name of the variable in this package that -X sets.
const MarkerVariable = "markerValue"

// BuildMarker returns the value the binary was linked with, or "unset".
func BuildMarker() string {
	return markerValue
}

// ImportPEM imports one PEM encoded private key or certificate into the
// keychain. The format is detected, the way /usr/bin/security does. A private
// key trusts this binary. A key and a certificate that belong together form an
// identity once both are in the keychain.
func (k *Keychain) ImportPEM(data []byte) error {
	return k.importItems(data, false, "")
}

// ImportPKCS12 imports the identity in a PKCS#12 file into the keychain.
func (k *Keychain) ImportPKCS12(data []byte, passphrase string) error {
	return k.importItems(data, true, passphrase)
}

func (k *Keychain) importItems(data []byte, pkcs12 bool, passphrase string) error {
	if err := k.live(); err != nil {
		return err
	}
	if len(data) == 0 {
		return errors.New("kctest: nothing to import")
	}
	var cPassphrase *C.char
	if pkcs12 {
		cPassphrase = C.CString(passphrase)
		defer C.free(unsafe.Pointer(cPassphrase))
	}
	var imported C.long
	flag := C.int(0)
	if pkcs12 {
		flag = 1
	}
	status := C.kt_import(k.ref, (*C.UInt8)(unsafe.Pointer(&data[0])), C.CFIndex(len(data)), flag, cPassphrase, &imported)
	if err := check("SecItemImport", status); err != nil {
		return err
	}
	if imported < 1 {
		return errors.New("kctest: SecItemImport imported no item")
	}
	return nil
}

// Sign signs the file at path with the identity in the keychain whose
// certificate has the subject common name, under identifier, with the hardened
// runtime flag. It replaces any signature the file has. It goes through the
// SecCodeSigner interface, which unlike /usr/bin/codesign accepts an identity
// that is not trusted and not on the search list.
func (k *Keychain) Sign(commonName, path, identifier string) error {
	if err := k.live(); err != nil {
		return err
	}
	cName := C.CString(commonName)
	defer C.free(unsafe.Pointer(cName))
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	cIdentifier := C.CString(identifier)
	defer C.free(unsafe.Pointer(cIdentifier))
	return check("sign the binary", C.kt_sign(k.ref, cName, cPath, cIdentifier))
}

// Signature is what a signed file says about itself.
type Signature struct {
	Identifier string
	// Requirement is the designated requirement, the text the keychain access
	// check evaluates.
	Requirement string
	// LeafName is the subject summary of the leaf certificate; empty for an ad hoc
	// signature, which has none.
	LeafName string
	// CDHash is the code directory hash in hex.
	CDHash          string
	Flags           uint32
	HasCertificates bool
}

// Code signature flags the tests look at.
const (
	flagAdHoc   = 0x2
	flagRuntime = 0x10000
)

// AdHoc reports whether the signature is ad hoc.
func (s Signature) AdHoc() bool { return s.Flags&flagAdHoc != 0 }

// Runtime reports whether the hardened runtime flag is set.
func (s Signature) Runtime() bool { return s.Flags&flagRuntime != 0 }

// CodeSignature reads the code signature of the file at path.
func CodeSignature(path string) (Signature, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	var info C.kt_signature_info
	if err := check("read the code signature", C.kt_signature(cPath, &info)); err != nil {
		return Signature{}, err
	}
	return Signature{
		Identifier:      C.GoString(&info.identifier[0]),
		Requirement:     C.GoString(&info.requirement[0]),
		LeafName:        C.GoString(&info.leaf[0]),
		CDHash:          C.GoString(&info.cdhash[0]),
		Flags:           uint32(info.flags),
		HasCertificates: info.has_certificates != 0,
	}, nil
}
