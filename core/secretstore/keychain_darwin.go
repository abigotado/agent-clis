//go:build darwin && cgo

package secretstore

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

// sk_trace describes a dictionary a primitive built, for tests that must not
// reach the keychain. A primitive handed a non-NULL trace fills it in and
// returns without calling any Security.framework function that has an effect.
typedef struct {
	int use_keychain;
	int search_list;
	int ui_fail;
	int return_ref;
	int return_data;
	int value_data;
	int service_and_account;
} sk_trace;

// sk_dict builds every query and attribute dictionary the backend uses, so
// the target keychain cannot be forgotten by one primitive. A NULL target is
// the default keychain and the user's search list, which is what production
// uses; tests pass a scratch keychain.
static CFMutableDictionaryRef sk_dict(CFStringRef service, CFStringRef account, SecKeychainRef target, int for_add, int ui_fail) {
	CFMutableDictionaryRef dict = CFDictionaryCreateMutable(
		kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (dict == NULL) {
		return NULL;
	}
	CFDictionarySetValue(dict, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(dict, kSecAttrService, service);
	CFDictionarySetValue(dict, kSecAttrAccount, account);
	// SecItemAdd rejects the authentication UI key, so only lookups, reads and
	// deletes carry it.
	if (ui_fail && !for_add) {
		CFDictionarySetValue(dict, kSecUseAuthenticationUI, kSecUseAuthenticationUIFail);
	}
	if (target != NULL) {
		if (for_add) {
			CFDictionarySetValue(dict, kSecUseKeychain, target);
		} else {
			const void *values[] = { target };
			CFArrayRef list = CFArrayCreate(kCFAllocatorDefault, values, 1, &kCFTypeArrayCallBacks);
			if (list == NULL) {
				CFRelease(dict);
				return NULL;
			}
			CFDictionarySetValue(dict, kSecMatchSearchList, list);
			CFRelease(list);
		}
	}
	return dict;
}

static void sk_fill_trace(sk_trace *trace, CFDictionaryRef dict, SecKeychainRef target) {
	trace->use_keychain = target != NULL && CFDictionaryGetValue(dict, kSecUseKeychain) == (const void *)target;
	CFArrayRef list = (CFArrayRef)CFDictionaryGetValue(dict, kSecMatchSearchList);
	trace->search_list = target != NULL && list != NULL && CFArrayGetCount(list) == 1 &&
		CFArrayGetValueAtIndex(list, 0) == (const void *)target;
	trace->ui_fail = CFDictionaryGetValue(dict, kSecUseAuthenticationUI) == kSecUseAuthenticationUIFail;
	trace->return_ref = CFDictionaryGetValue(dict, kSecReturnRef) == kCFBooleanTrue;
	trace->return_data = CFDictionaryGetValue(dict, kSecReturnData) == kCFBooleanTrue;
	trace->value_data = CFDictionaryGetValue(dict, kSecValueData) != NULL;
	trace->service_and_account = CFDictionaryGetValue(dict, kSecAttrService) != NULL &&
		CFDictionaryGetValue(dict, kSecAttrAccount) != NULL;
}

// sk_lookup resolves the item by reference. It never decrypts, so it never
// needs an access control list entry. With a trace it returns not found.
static OSStatus sk_lookup(CFStringRef service, CFStringRef account, SecKeychainRef target, int ui_fail, sk_trace *trace, SecKeychainItemRef *item) {
	CFMutableDictionaryRef query = sk_dict(service, account, target, 0, ui_fail);
	if (query == NULL) {
		return errSecAllocate;
	}
	CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
	CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
	if (trace != NULL) {
		sk_fill_trace(trace, query, target);
		CFRelease(query);
		return errSecItemNotFound;
	}
	CFTypeRef result = NULL;
	OSStatus status = SecItemCopyMatching(query, &result);
	CFRelease(query);
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

static OSStatus sk_exists(CFStringRef service, CFStringRef account, SecKeychainRef target, int ui_fail, sk_trace *trace) {
	SecKeychainItemRef item = NULL;
	OSStatus status = sk_lookup(service, account, target, ui_fail, trace, &item);
	if (item != NULL) {
		CFRelease(item);
	}
	return status;
}

// The probe call a failed lock probe stopped at, reported through the stage
// out-parameter of sk_unlocked and sk_unlocked_for_add. Zero is "unknown": the
// caller initialises it, and a status from any call that did not set a stage is
// never read as the GetStatus one. Go maps these in probeStepOf.
#define SK_STAGE_LOOKUP 1
#define SK_STAGE_COPY_KEYCHAIN 2
#define SK_STAGE_COPY_DEFAULT 3
#define SK_STAGE_GET_STATUS 4

// sk_keychain_unlocked reads the unlock state of one keychain. It never
// prompts and never decrypts.
static OSStatus sk_keychain_unlocked(SecKeychainRef keychain, int *unlocked, int *stage) {
	if (keychain == NULL) {
		return errSecInternalComponent;
	}
	SecKeychainStatus keychainStatus = 0;
	*stage = SK_STAGE_GET_STATUS;
	OSStatus status = SecKeychainGetStatus(keychain, &keychainStatus);
	if (status != errSecSuccess) {
		return status;
	}
	*unlocked = (keychainStatus & kSecUnlockStateStatus) != 0;
	return errSecSuccess;
}

// sk_unlocked_for_add reports whether the keychain an add goes to is unlocked:
// the target, or the default keychain when the target is NULL. It looks at no
// item, so an existing item of the same name in another keychain cannot
// answer for the add target.
static OSStatus sk_unlocked_for_add(SecKeychainRef target, int *unlocked, int *stage) {
	SecKeychainRef keychain = NULL;
	OSStatus status = errSecSuccess;
	if (target != NULL) {
		keychain = (SecKeychainRef)CFRetain(target);
	} else {
		*stage = SK_STAGE_COPY_DEFAULT;
		status = SecKeychainCopyDefault(&keychain);
	}
	if (status != errSecSuccess) {
		return status;
	}
	status = sk_keychain_unlocked(keychain, unlocked, stage);
	if (keychain != NULL) {
		CFRelease(keychain);
	}
	return status;
}

// sk_unlocked reports whether the keychain that holds the item is unlocked.
// The lookup always carries kSecUseAuthenticationUIFail, whatever the store's
// interaction mode, so a probe never raises a dialog of its own. If the item
// is gone it falls back to the keychain an add would go to. Only a missing
// item takes that path. Any other lookup failure is returned, so a keychain
// whose lock state cannot be read never looks unlocked.
static OSStatus sk_unlocked(CFStringRef service, CFStringRef account, SecKeychainRef target, sk_trace *trace, int *unlocked, int *stage) {
	SecKeychainItemRef item = NULL;
	*stage = SK_STAGE_LOOKUP;
	OSStatus status = sk_lookup(service, account, target, 1, trace, &item);
	if (trace != NULL) {
		return status;
	}
	if (status == errSecItemNotFound) {
		return sk_unlocked_for_add(target, unlocked, stage);
	}
	if (status != errSecSuccess) {
		return status;
	}
	SecKeychainRef keychain = NULL;
	*stage = SK_STAGE_COPY_KEYCHAIN;
	status = SecKeychainItemCopyKeychain(item, &keychain);
	CFRelease(item);
	if (status != errSecSuccess) {
		return status;
	}
	status = sk_keychain_unlocked(keychain, unlocked, stage);
	if (keychain != NULL) {
		CFRelease(keychain);
	}
	return status;
}

static OSStatus sk_read(CFStringRef service, CFStringRef account, SecKeychainRef target, int ui_fail, sk_trace *trace, CFDataRef *data) {
	CFMutableDictionaryRef query = sk_dict(service, account, target, 0, ui_fail);
	if (query == NULL) {
		return errSecAllocate;
	}
	CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
	CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
	if (trace != NULL) {
		sk_fill_trace(trace, query, target);
		CFRelease(query);
		return errSecItemNotFound;
	}
	CFTypeRef result = NULL;
	OSStatus status = SecItemCopyMatching(query, &result);
	CFRelease(query);
	if (status != errSecSuccess) {
		if (result != NULL) {
			CFRelease(result);
		}
		return status;
	}
	if (result == NULL || CFGetTypeID(result) != CFDataGetTypeID()) {
		if (result != NULL) {
			CFRelease(result);
		}
		return errSecInternalComponent;
	}
	*data = (CFDataRef)result;
	return errSecSuccess;
}

// sk_delete removes the item that sk_lookup resolves. It never updates.
static OSStatus sk_delete(CFStringRef service, CFStringRef account, SecKeychainRef target, int ui_fail, sk_trace *trace) {
	SecKeychainItemRef item = NULL;
	OSStatus status = sk_lookup(service, account, target, ui_fail, trace, &item);
	if (status != errSecSuccess) {
		return status;
	}
	status = SecKeychainItemDelete(item);
	CFRelease(item);
	return status;
}

// sk_create_access builds the access object of rule 1: description = service,
// decrypt = [this binary] with the passphrase prompt cleared, and ChangeACL =
// [this binary]. SecAccessCreate puts decrypt in one entry and ChangeACL in
// another; any other shape fails closed.
static OSStatus sk_create_access(CFStringRef description, SecAccessRef *access) {
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
	SecAccessRef created = NULL;
	status = SecAccessCreate(description, applications, &created);
	if (status != errSecSuccess || created == NULL) {
		if (created != NULL) {
			CFRelease(created);
		}
		CFRelease(applications);
		return status != errSecSuccess ? status : errSecInternalComponent;
	}

	CFArrayRef decrypt = SecAccessCopyMatchingACLList(created, kSecACLAuthorizationDecrypt);
	if (decrypt == NULL || CFArrayGetCount(decrypt) != 1) {
		status = errSecInternalComponent;
	} else {
		SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(decrypt, 0);
		CFArrayRef current = NULL;
		CFStringRef current_description = NULL;
		SecKeychainPromptSelector selector = 0;
		status = SecACLCopyContents(acl, &current, &current_description, &selector);
		if (status == errSecSuccess) {
			status = SecACLSetContents(acl, applications,
				current_description != NULL ? current_description : description,
				selector & ~kSecKeychainPromptRequirePassphase);
		}
		if (current != NULL) {
			CFRelease(current);
		}
		if (current_description != NULL) {
			CFRelease(current_description);
		}
	}
	if (decrypt != NULL) {
		CFRelease(decrypt);
	}

	if (status == errSecSuccess) {
		CFArrayRef change = SecAccessCopyMatchingACLList(created, kSecACLAuthorizationChangeACL);
		if (change == NULL || CFArrayGetCount(change) < 1) {
			status = errSecInternalComponent;
		} else {
			for (CFIndex i = 0; status == errSecSuccess && i < CFArrayGetCount(change); i++) {
				status = SecACLSetContents((SecACLRef)CFArrayGetValueAtIndex(change, i), applications, description, 0);
			}
		}
		if (change != NULL) {
			CFRelease(change);
		}
	}
	CFRelease(applications);
	if (status != errSecSuccess) {
		CFRelease(created);
		return status;
	}
	*access = created;
	return errSecSuccess;
}

// sk_add creates the item with the access object attached at creation. It
// never updates an existing item: a duplicate is errSecDuplicateItem.
static OSStatus sk_add(CFStringRef service, CFStringRef account, SecKeychainRef target, int ui_fail, sk_trace *trace, CFDataRef value) {
	CFMutableDictionaryRef attributes = sk_dict(service, account, target, 1, ui_fail);
	if (attributes == NULL) {
		return errSecAllocate;
	}
	CFDictionarySetValue(attributes, kSecValueData, value);
	if (trace != NULL) {
		sk_fill_trace(trace, attributes, target);
		CFRelease(attributes);
		return errSecSuccess;
	}
	SecAccessRef access = NULL;
	OSStatus status = sk_create_access(service, &access);
	if (status != errSecSuccess) {
		CFRelease(attributes);
		return status;
	}
	CFDictionarySetValue(attributes, kSecAttrAccess, access);
	status = SecItemAdd(attributes, NULL);
	CFRelease(access);
	CFRelease(attributes);
	return status;
}

static CFTypeRef sk_placeholder(void) {
	return CFStringCreateWithCString(kCFAllocatorDefault, "placeholder keychain", kCFStringEncodingUTF8);
}
*/
import "C"

import (
	"context"
	"errors"
	"unsafe"
)

// The Security.framework values the status classification in staged.go
// hard-codes. keychain_darwin_test.go pins each pair.
const (
	cStatusItemNotFound          = int64(C.errSecItemNotFound)
	cStatusAuthFailed            = int64(C.errSecAuthFailed)
	cStatusInteractionNotAllowed = int64(C.errSecInteractionNotAllowed)
	cStatusDuplicateItem         = int64(C.errSecDuplicateItem)
	cStatusUserCanceled          = int64(C.errSecUserCanceled)
	cStatusParam                 = int64(C.errSecParam)
	cStatusWritePermission       = int64(C.errSecWrPerm)
	cStatusReadOnly              = int64(C.errSecReadOnly)
)

// keychainRef is a SecKeychainRef. The zero value is the default keychain and
// the user's search list.
type keychainRef = C.SecKeychainRef

// queryTrace is what a primitive built in dry-run mode.
type queryTrace struct {
	op string
	// useKeychain and searchList say whether the target keychain is in the
	// dictionary as kSecUseKeychain (add) or kSecMatchSearchList (lookups).
	useKeychain bool
	searchList  bool
	uiFail      bool
	returnRef   bool
	returnData  bool
	valueData   bool
	named       bool
}

// keychainItems implements itemAPI with Security.framework. It never updates
// an item. None of its calls can be interrupted, so the context is unused.
type keychainItems struct {
	// target is the keychain every dictionary names, or zero for the default
	// keychain and search list, which is what production uses.
	target keychainRef
	// uiFail sets kSecUseAuthenticationUIFail, which InteractionNever wants and
	// InteractionAllowed must not have, or an unlock prompt could never show.
	uiFail bool
	// dry, when not nil, turns every primitive into a dictionary description
	// appended here: nothing reaches the keychain. Only tests set it.
	dry *[]queryTrace
}

var _ itemAPI = (*keychainItems)(nil)

func cfString(value string) (C.CFStringRef, func(), error) {
	data := unsafe.StringData(value)
	ref := C.CFStringCreateWithBytes(C.kCFAllocatorDefault, (*C.UInt8)(unsafe.Pointer(data)),
		C.CFIndex(len(value)), C.kCFStringEncodingUTF8, C.false)
	if ref == 0 {
		return 0, func() {}, &statusError{status: int64(C.errSecAllocate)}
	}
	return ref, func() { C.CFRelease(C.CFTypeRef(ref)) }, nil
}

func (k *keychainItems) uiFailFlag() C.int {
	if k.uiFail {
		return 1
	}
	return 0
}

// trace returns the C trace to pass for op, or nil outside dry-run mode.
func (k *keychainItems) trace() *C.sk_trace {
	if k.dry == nil {
		return nil
	}
	return new(C.sk_trace)
}

func (k *keychainItems) record(op string, trace *C.sk_trace) {
	if trace == nil {
		return
	}
	*k.dry = append(*k.dry, queryTrace{
		op:          op,
		useKeychain: trace.use_keychain != 0,
		searchList:  trace.search_list != 0,
		uiFail:      trace.ui_fail != 0,
		returnRef:   trace.return_ref != 0,
		returnData:  trace.return_data != 0,
		valueData:   trace.value_data != 0,
		named:       trace.service_and_account != 0,
	})
}

func (k *keychainItems) strings(name itemName) (service, account C.CFStringRef, release func(), err error) {
	service, releaseService, err := cfString(name.service)
	if err != nil {
		return 0, 0, nil, err
	}
	account, releaseAccount, err := cfString(name.account)
	if err != nil {
		releaseService()
		return 0, 0, nil, err
	}
	return service, account, func() { releaseAccount(); releaseService() }, nil
}

func statusOf(status C.OSStatus) error {
	if status == C.errSecSuccess {
		return nil
	}
	return &statusError{status: int64(status)}
}

// probeStepOf maps the stage a lock probe reported to the step of a
// statusError. Anything it does not know, zero included, is probeStepUnknown.
func probeStepOf(stage C.int) probeStep {
	switch stage {
	case C.SK_STAGE_LOOKUP:
		return probeStepLookup
	case C.SK_STAGE_COPY_KEYCHAIN:
		return probeStepCopyKeychain
	case C.SK_STAGE_COPY_DEFAULT:
		return probeStepCopyDefault
	case C.SK_STAGE_GET_STATUS:
		return probeStepGetStatus
	default:
		return probeStepUnknown
	}
}

// probeStatusOf is statusOf for a lock probe, which also records the step.
func probeStatusOf(status C.OSStatus, stage C.int) error {
	if status == C.errSecSuccess {
		return nil
	}
	return &statusError{status: int64(status), step: probeStepOf(stage)}
}

func (k *keychainItems) exists(_ context.Context, name itemName) (bool, error) {
	service, account, release, err := k.strings(name)
	if err != nil {
		return false, err
	}
	defer release()
	trace := k.trace()
	status := C.sk_exists(service, account, k.target, k.uiFailFlag(), trace)
	k.record("exists", trace)
	switch int64(status) {
	case 0:
		return true, nil
	case cStatusItemNotFound:
		return false, nil
	default:
		return false, statusOf(status)
	}
}

func (k *keychainItems) keychainUnlocked(_ context.Context, name itemName) (bool, error) {
	service, account, release, err := k.strings(name)
	if err != nil {
		return false, err
	}
	defer release()
	trace := k.trace()
	var unlocked, stage C.int
	status := C.sk_unlocked(service, account, k.target, trace, &unlocked, &stage)
	k.record("status", trace)
	if err := probeStatusOf(status, stage); err != nil {
		return false, err
	}
	return unlocked != 0, nil
}

func (k *keychainItems) addKeychainUnlocked(_ context.Context, _ itemName) (bool, error) {
	if k.dry != nil {
		// Dry-run mode builds no dictionary for this probe and touches nothing.
		return false, nil
	}
	var unlocked, stage C.int
	// Separate statements: Go does not order reading stage against the call
	// that writes it when both sit in one expression.
	status := C.sk_unlocked_for_add(k.target, &unlocked, &stage)
	if err := probeStatusOf(status, stage); err != nil {
		return false, err
	}
	return unlocked != 0, nil
}

func (k *keychainItems) read(_ context.Context, name itemName, limit int) ([]byte, error) {
	service, account, release, err := k.strings(name)
	if err != nil {
		return nil, err
	}
	defer release()
	trace := k.trace()
	var data C.CFDataRef
	status := C.sk_read(service, account, k.target, k.uiFailFlag(), trace, &data)
	k.record("read", trace)
	if err := statusOf(status); err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(data))
	length := C.CFDataGetLength(data)
	if length < 0 || int64(length) > int64(limit) {
		return nil, errValueTooLarge
	}
	if length == 0 {
		return []byte{}, nil
	}
	bytes := C.CFDataGetBytePtr(data)
	if bytes == nil {
		return nil, &statusError{status: int64(C.errSecInternalComponent)}
	}
	return C.GoBytes(unsafe.Pointer(bytes), C.int(length)), nil
}

func (k *keychainItems) add(_ context.Context, name itemName, value []byte) error {
	service, account, release, err := k.strings(name)
	if err != nil {
		return err
	}
	defer release()
	data := C.CFDataCreate(C.kCFAllocatorDefault, (*C.UInt8)(unsafe.Pointer(unsafe.SliceData(value))), C.CFIndex(len(value)))
	if data == 0 {
		return &statusError{status: int64(C.errSecAllocate)}
	}
	defer C.CFRelease(C.CFTypeRef(data))
	trace := k.trace()
	status := C.sk_add(service, account, k.target, k.uiFailFlag(), trace, data)
	k.record("add", trace)
	return statusOf(status)
}

func (k *keychainItems) delete(_ context.Context, name itemName) error {
	service, account, release, err := k.strings(name)
	if err != nil {
		return err
	}
	defer release()
	trace := k.trace()
	status := C.sk_delete(service, account, k.target, k.uiFailFlag(), trace)
	k.record("delete", trace)
	return statusOf(status)
}

// newPlaceholderKeychainRef returns a stand-in for a keychain reference: a
// CoreFoundation object a dictionary can hold, which no Security.framework
// call is ever given.
func newPlaceholderKeychainRef() (keychainRef, func()) {
	ref := C.sk_placeholder()
	return keychainRef(ref), func() { C.CFRelease(ref) }
}

// setUserInteractionAllowed is what Open calls to turn prompts off. It is a
// variable so tests can replace it: the setting is process-wide and possibly
// session-wide, and the real function must only run in a process that means it.
var setUserInteractionAllowed = realSetUserInteractionAllowed

func realSetUserInteractionAllowed(allowed bool) error {
	flag := C.Boolean(0)
	if allowed {
		flag = 1
	}
	return statusOf(C.SecKeychainSetUserInteractionAllowed(flag))
}

// keychainStore is the macOS Store: the staged sequence over keychainItems,
// plus RepairAccess.
type keychainStore struct {
	*stagedStore
	interaction Interaction
}

var (
	_ Store       = (*keychainStore)(nil)
	_ ACLRepairer = (*keychainStore)(nil)
)

// newKeychainStore returns a store over the keychain target, or over the
// default keychain when target is zero. Production passes zero; only tests pass
// a scratch keychain. The caller keeps ownership of target.
func newKeychainStore(opts Options, target keychainRef) *keychainStore {
	items := &keychainItems{target: target, uiFail: opts.Interaction == InteractionNever}
	return newKeychainStoreOver(items, opts)
}

func newKeychainStoreOver(api itemAPI, opts Options) *keychainStore {
	return &keychainStore{
		stagedStore: newStagedStore(api, "keychain", opts.MaxSecretBytes),
		interaction: opts.Interaction,
	}
}

// openKeychain returns the store for opts. Under InteractionNever it first
// turns off every system prompt with setUI(false): kSecUseAuthenticationUIFail
// alone still let a dialog through for a legacy access list. If prompts cannot
// be turned off the store is not returned, so an agent never waits on a dialog.
func openKeychain(opts Options, setUI func(allowed bool) error) (Store, error) {
	if opts.Interaction == InteractionNever {
		if err := setUI(false); err != nil {
			var se *statusError
			open := &Error{Op: "open", Backend: "keychain", Kind: KindOther}
			if errors.As(err, &se) {
				open.Status = se.status
			}
			return nil, open
		}
	}
	return newKeychainStore(opts, 0), nil
}

// RepairAccess implements ACLRepairer: it reads the item, which may show the
// system dialog that lets this binary decrypt an item written under another
// identity, and saves it again, so the new item carries this binary's access
// list. It needs InteractionAllowed and does not touch the store otherwise.
func (s *keychainStore) RepairAccess(ctx context.Context, key Key) error {
	if err := s.begin(ctx, "repair", key); err != nil {
		return err
	}
	if s.interaction != InteractionAllowed {
		return s.fail("repair", KindInteractionRequired, 0)
	}
	value, err := s.Load(ctx, key)
	if err != nil {
		return relabel(err, "repair")
	}
	defer clear(value)
	// Load ignores a stage this identity cannot read. Saving the account value
	// over it would destroy a newer value, so refuse.
	stage := itemName{service: key.Service, account: key.Account}.stage()
	present, err := s.lookup(ctx, "repair", stage)
	if err != nil {
		return err
	}
	if present {
		staged, readable, err := s.readStage(ctx, "repair", stage)
		clear(staged)
		if err != nil {
			return relabel(err, "repair")
		}
		if !readable {
			return s.fail("repair", KindAccessDenied, 0)
		}
	}
	if err := s.Save(ctx, key, value); err != nil {
		return relabel(err, "repair")
	}
	return nil
}

// relabel reports a store failure under op.
func relabel(err error, op string) error {
	var e *Error
	if !errors.As(err, &e) {
		return err
	}
	relabeled := *e
	relabeled.Op = op
	return &relabeled
}
