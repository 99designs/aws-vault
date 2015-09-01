package osxkeychain

// See https://developer.apple.com/library/mac/documentation/Security/Reference/keychainservices/index.html for the APIs used below.
// Also see https://developer.apple.com/library/ios/documentation/Security/Conceptual/keychainServConcepts/01introduction/introduction.html .

/*
#cgo CFLAGS: -mmacosx-version-min=10.6 -D__MAC_OS_X_VERSION_MAX_ALLOWED=1060
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <stdlib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"math"
	"unicode/utf8"
	"unsafe"
)

// GenericPasswordAttributes describes the attributes for a Keychain item
// All string fields must have size that fits in 32 bits and be UTF-8
type GenericPasswordAttributes struct {

	// ServiceName is the name of the service to add the item to
	ServiceName string

	// AccountName is the name of the account to add the item to
	AccountName string

	// Password is the password for the service
	Password []byte

	// TrustedApplications is a list of additional application paths
	// that will be given trusted access to the keychain item by default.
	// The application that creates the keychain item always has access, so
	// this list is for additional apps or executables.
	TrustedApplications []string

	// Keychain contains a list of keychain files to either search or add to. If this
	// is null or empty then the user's defaults will be used
	Keychain []string
}

func check32Bit(paramName string, paramValue []byte) error {
	if uint64(len(paramValue)) > math.MaxUint32 {
		return errors.New(paramName + " has size overflowing 32 bits")
	}
	return nil
}

func check32BitUTF8(paramName, paramValue string) error {
	if uint64(len(paramValue)) > math.MaxUint32 {
		return errors.New(paramName + " has size overflowing 32 bits")
	}
	if !utf8.ValidString(paramValue) {
		return errors.New(paramName + " is not a valid UTF-8 string")
	}
	return nil
}

func (attributes *GenericPasswordAttributes) checkValidity() error {
	if err := check32BitUTF8("ServiceName", attributes.ServiceName); err != nil {
		return err
	}
	if err := check32BitUTF8("AccountName", attributes.AccountName); err != nil {
		return err
	}
	if err := check32Bit("Password", attributes.Password); err != nil {
		return err
	}
	for _, trustedApplication := range attributes.TrustedApplications {
		if err := check32BitUTF8("TrustedApplications", trustedApplication); err != nil {
			return err
		}
	}
	return nil
}

type keychainError C.OSStatus

// https://developer.apple.com/library/mac/documentation/security/Reference/keychainservices/Reference/reference.html#//apple_ref/doc/uid/TP30000898-CH5g-CJBEABHG
const (
	ErrUnimplemented     keychainError = C.errSecUnimplemented
	ErrParam             keychainError = C.errSecParam
	ErrAllocate          keychainError = C.errSecAllocate
	ErrNotAvailable      keychainError = C.errSecNotAvailable
	ErrReadOnly          keychainError = C.errSecReadOnly
	ErrAuthFailed        keychainError = C.errSecAuthFailed
	ErrNoSuchKeychain    keychainError = C.errSecNoSuchKeychain
	ErrInvalidKeychain   keychainError = C.errSecInvalidKeychain
	ErrDuplicateKeychain keychainError = C.errSecDuplicateKeychain
	ErrDuplicateCallback keychainError = C.errSecDuplicateCallback
	ErrInvalidCallback   keychainError = C.errSecInvalidCallback
	ErrDuplicateItem     keychainError = C.errSecDuplicateItem
	ErrItemNotFound      keychainError = C.errSecItemNotFound
	ErrBufferTooSmall    keychainError = C.errSecBufferTooSmall
	ErrDataTooLarge      keychainError = C.errSecDataTooLarge
	ErrNoSuchAttr        keychainError = C.errSecNoSuchAttr
	ErrInvalidItemRef    keychainError = C.errSecInvalidItemRef
	ErrInvalidSearchRef  keychainError = C.errSecInvalidSearchRef
	ErrNoSuchClass       keychainError = C.errSecNoSuchClass
	ErrNoDefaultKeychain keychainError = C.errSecNoDefaultKeychain
	ErrReadOnlyAttr      keychainError = C.errSecReadOnlyAttr
	// TODO: Fill out more of these?
)

func newKeychainError(errCode C.OSStatus) error {
	if errCode == C.noErr {
		return nil
	}
	return keychainError(errCode)
}

func (ke keychainError) Error() string {
	errorMessageCFString := C.SecCopyErrorMessageString(C.OSStatus(ke), nil)
	defer C.CFRelease(C.CFTypeRef(errorMessageCFString))

	errorMessageCString := C.CFStringGetCStringPtr(errorMessageCFString, C.kCFStringEncodingASCII)

	if errorMessageCString != nil {
		return C.GoString(errorMessageCString)
	}

	return fmt.Sprintf("keychainError with unknown error code %d", C.OSStatus(ke))
}

func openKeychains(paths []string) (result []C.SecKeychainRef, err error) {
	for _, path := range paths {
		pathName := C.CString(path)
		defer C.free(unsafe.Pointer(pathName))

		var kref C.SecKeychainRef
		if err := newKeychainError(C.SecKeychainOpen(pathName, &kref)); err != nil {
			return nil, err
		}

		result = append(result, kref)
	}
	return
}

func openKeychainsWithPool(paths []string, pool releasePool) (C.CFArrayRef, error) {
	keychains, err := openKeychains(paths)
	if err != nil {
		return nil, err
	}
	var keychainRefs []C.CFTypeRef
	for _, k := range keychains {
		pool = append(pool, C.CFTypeRef(k))
		keychainRefs = append(keychainRefs, C.CFTypeRef(k))
	}
	return pool.Array(keychainRefs), nil
}

// AddGenericPassword adds a generic password to the Keychain defined in the
// attributes Keychain property. This will raise an error if the service and account
// name already exist as an item
func AddGenericPassword(attributes *GenericPasswordAttributes) error {
	if err := attributes.checkValidity(); err != nil {
		return err
	}

	pool := releasePool{}
	defer pool.Release()

	serviceNameString, err := pool.CFStringRef(attributes.ServiceName)
	if err != nil {
		return err
	}

	accountNameString, err := pool.CFStringRef(attributes.AccountName)
	if err != nil {
		return err
	}

	dataBytes := pool.CFDataRef(attributes.Password)

	query := map[C.CFTypeRef]C.CFTypeRef{
		C.kSecClass:       C.kSecClassGenericPassword,
		C.kSecAttrService: C.CFTypeRef(serviceNameString),
		C.kSecAttrAccount: C.CFTypeRef(accountNameString),
		C.kSecValueData:   C.CFTypeRef(dataBytes),
	}

	if len(attributes.Keychain) > 1 {
		return errors.New("Can't add a password to multiple keychains")
	}

	keychains, err := openKeychains(attributes.Keychain)
	if err != nil {
		return err
	}

	if len(keychains) > 0 {
		for _, k := range keychains {
			defer C.CFRelease(C.CFTypeRef(k))
		}
		query[C.kSecUseKeychain] = C.CFTypeRef(keychains[0])
	}

	access, err := createAccess(attributes.ServiceName, attributes.TrustedApplications, pool)
	if err != nil {
		return err
	}

	if access != nil {
		defer C.CFRelease(C.CFTypeRef(access))
		query[C.kSecAttrAccess] = C.CFTypeRef(access)
	}

	return newKeychainError(C.SecItemAdd(pool.CFDictionaryRef(query), nil))
}

// FindGenericPassword searches the Keychains defined in the attributes Keychain
// property (or the default if null). It returns only the password found or an error
func FindGenericPassword(attributes *GenericPasswordAttributes) ([]byte, error) {
	if err := attributes.checkValidity(); err != nil {
		return nil, err
	}

	pool := releasePool{}
	defer pool.Release()

	serviceName := C.CString(attributes.ServiceName)
	defer C.free(unsafe.Pointer(serviceName))

	accountName := C.CString(attributes.AccountName)
	defer C.free(unsafe.Pointer(accountName))

	var passwordLength C.UInt32
	var password unsafe.Pointer
	var keychainRef C.CFTypeRef

	// search specific keychains, otherwise the defaults are used
	if len(attributes.Keychain) > 0 {
		keychains, err := openKeychainsWithPool(attributes.Keychain, pool)
		if err != nil {
			return nil, err
		}
		keychainRef = C.CFTypeRef(keychains)
	}

	errCode := C.SecKeychainFindGenericPassword(
		keychainRef,
		C.UInt32(len(attributes.ServiceName)),
		serviceName,
		C.UInt32(len(attributes.AccountName)),
		accountName,
		&passwordLength,
		&password,
		nil,
	)

	if err := newKeychainError(errCode); err != nil {
		return nil, err
	}

	defer C.SecKeychainItemFreeContent(nil, password)
	return C.GoBytes(password, C.int(passwordLength)), nil
}

// FindAndRemoveGenericPassword searches the Keychains defined in the attributes Keychain
// property (or the default if null) and removes the item if found.
func FindAndRemoveGenericPassword(attributes *GenericPasswordAttributes) error {
	itemRef, err := findGenericPasswordItem(attributes)
	if err != nil {
		return err
	}

	defer C.CFRelease(C.CFTypeRef(itemRef))

	errCode := C.SecKeychainItemDelete(itemRef)
	return newKeychainError(errCode)
}

// Apple recommends updating an item via SecKeychainItemModifyContent or SecKeychainItemModifyAttributesAndData,
// but this creates a security problem as a malicious app can delete a keychain item and re-create it with an ACL
// such that it can read it, and then wait for the app to write to it.

// See http://arxiv.org/abs/1505.06836 .
// TODO: Add a test that this function doesn't actually do update-or-add

// RemoveAndAddGenericPassword calls FindAndRemoveGenericPassword()
// with the given attributes (ignoring ErrItemNotFound) and then calls
// AddGenericPassword with the same attributes.
func RemoveAndAddGenericPassword(attributes *GenericPasswordAttributes) error {
	return removeAndAddGenericPasswordHelper(attributes, func() {})
}

// removeAndAddGenericPasswordHelper is a helper function to help test
// RemoveAndAddGenericPassword's handling of race conditions.
func removeAndAddGenericPasswordHelper(attributes *GenericPasswordAttributes, fn func()) error {
	err := FindAndRemoveGenericPassword(attributes)
	if err != nil && err != ErrItemNotFound {
		return err
	}

	fn()

	return AddGenericPassword(attributes)
}

func findGenericPasswordItem(attributes *GenericPasswordAttributes) (itemRef C.SecKeychainItemRef, err error) {
	if err = attributes.checkValidity(); err != nil {
		return
	}

	pool := releasePool{}
	defer pool.Release()

	serviceName := C.CString(attributes.ServiceName)
	defer C.free(unsafe.Pointer(serviceName))

	accountName := C.CString(attributes.AccountName)
	defer C.free(unsafe.Pointer(accountName))

	var keychainRef C.CFTypeRef

	// search specific keychains, otherwise the defaults are used
	if len(attributes.Keychain) > 0 {
		keychains, err := openKeychainsWithPool(attributes.Keychain, pool)
		if err != nil {
			return nil, err
		}
		keychainRef = C.CFTypeRef(keychains)
	}

	errCode := C.SecKeychainFindGenericPassword(
		keychainRef,
		C.UInt32(len(attributes.ServiceName)),
		serviceName,
		C.UInt32(len(attributes.AccountName)),
		accountName,
		nil,
		nil,
		&itemRef,
	)

	err = newKeychainError(errCode)
	return
}

// GetAllAccountNames returns the account names for a given service across the provided keychains. If no keychains
// are provided, the default is used
func GetAllAccountNames(serviceName string, keychains ...string) (accountNames []string, err error) {
	pool := releasePool{}
	defer pool.Release()

	var serviceNameString C.CFStringRef
	serviceNameString, err = pool.CFStringRef(serviceName)
	if err != nil {
		return
	}

	query := map[C.CFTypeRef]C.CFTypeRef{
		C.kSecClass:            C.kSecClassGenericPassword,
		C.kSecAttrService:      C.CFTypeRef(serviceNameString),
		C.kSecMatchLimit:       C.kSecMatchLimitAll,
		C.kSecReturnAttributes: C.CFTypeRef(C.kCFBooleanTrue),
	}

	// search specific keychains, otherwise the defaults are used
	if len(keychains) > 0 {
		keychains, err := openKeychainsWithPool(keychains, pool)
		if err != nil {
			return nil, err
		}
		query[C.kSecMatchSearchList] = C.CFTypeRef(keychains)
	}

	var resultsRef C.CFTypeRef
	errCode := C.SecItemCopyMatching(pool.CFDictionaryRef(query), &resultsRef)
	err = newKeychainError(errCode)
	if err == ErrItemNotFound {
		return []string{}, nil
	} else if err != nil {
		return nil, err
	}

	defer C.CFRelease(resultsRef)

	// The resultsRef should always be an array (because kSecReturnAttributes is true)
	// but it's a good sanity check and useful if want to support kSecReturnRef in the future.
	typeId := C.CFGetTypeID(resultsRef)
	if typeId != C.CFArrayGetTypeID() {
		typeDesc := C.CFCopyTypeIDDescription(typeId)
		defer C.CFRelease(C.CFTypeRef(typeDesc))
		err = fmt.Errorf("Invalid result type: %s", _CFStringToUTF8String(typeDesc))
		return
	}

	results := _CFArrayToArray(C.CFArrayRef(resultsRef))
	for _, result := range results {
		m := _CFDictionaryToMap(C.CFDictionaryRef(result))
		resultServiceName := _CFStringToUTF8String(C.CFStringRef(m[C.kSecAttrService]))
		if resultServiceName != serviceName {
			err = fmt.Errorf("Expected service name %s, got %s", serviceName, resultServiceName)
			return
		}
		accountName := _CFStringToUTF8String(C.CFStringRef(m[C.kSecAttrAccount]))
		accountNames = append(accountNames, accountName)
	}
	return
}

func createTrustedApplication(trustedApplication string, pool releasePool) (C.CFTypeRef, error) {
	var trustedApplicationCStr *C.char
	if trustedApplication != "" {
		trustedApplicationCStr = C.CString(trustedApplication)
		defer C.free(unsafe.Pointer(trustedApplicationCStr))
	}

	var trustedApplicationRef C.SecTrustedApplicationRef
	errCode := C.SecTrustedApplicationCreateFromPath(trustedApplicationCStr, &trustedApplicationRef)
	err := newKeychainError(errCode)
	if err != nil {
		return nil, err
	}
	if trustedApplicationRef != nil {
		pool = append(pool, C.CFTypeRef(trustedApplicationRef))
	}

	return C.CFTypeRef(trustedApplicationRef), nil
}

func createAccess(label string, trustedApplications []string, pool releasePool) (C.SecAccessRef, error) {
	if len(trustedApplications) == 0 {
		return nil, nil
	}

	// Always prepend with empty string which signifies that we
	// include a NULL application, which means ourselves.
	trustedApplications = append([]string{""}, trustedApplications...)

	var err error
	var labelRef C.CFStringRef
	if labelRef, err = pool.CFStringRef(label); err != nil {
		return nil, err
	}

	var trustedApplicationsRefs []C.CFTypeRef
	for _, trustedApplication := range trustedApplications {
		trustedApplicationRef, err := createTrustedApplication(trustedApplication, pool)
		if err != nil {
			return nil, err
		}
		trustedApplicationsRefs = append(trustedApplicationsRefs, trustedApplicationRef)
	}

	var access C.SecAccessRef
	errCode := C.SecAccessCreate(labelRef, pool.Array(trustedApplicationsRefs), &access)
	err = newKeychainError(errCode)
	if err != nil {
		return nil, err
	}
	if access != nil {
		pool = append(pool, C.CFTypeRef(access))
	}

	return access, nil
}

// CreateKeychain creates a Keychain from the provided password which must fit within 32-bits
// and be well-formed UTF-8
func CreateKeychain(path string, password string) error {
	if uint64(len(password)) > math.MaxUint32 {
		return errors.New("password has size overflowing 32 bits")
	}
	if !utf8.ValidString(password) {
		return errors.New("password is not a valid UTF-8 string")
	}

	passwordRef := C.CString(password)
	defer C.free(unsafe.Pointer(passwordRef))

	pathName := C.CString(path)
	defer C.free(unsafe.Pointer(pathName))

	// without passing in kref we get 'One or more parameters passed to a function were not valid.'
	var kref C.SecKeychainRef
	errCode := C.SecKeychainCreate(pathName, C.UInt32(len(password)), unsafe.Pointer(passwordRef), C.Boolean(0), nil, &kref)
	if err := newKeychainError(errCode); err != nil {
		return err
	}

	defer C.CFRelease(C.CFTypeRef(kref))
	return nil
}

// CreateKeychain creates a Keychain via a pop-up prompt to the user
func CreateKeychainViaPrompt(path string) error {
	pathName := C.CString(path)
	defer C.free(unsafe.Pointer(pathName))

	// without passing in kref we get 'One or more parameters passed to a function were not valid.'
	var kref C.SecKeychainRef
	errCode := C.SecKeychainCreate(pathName, C.UInt32(0), nil, C.Boolean(1), nil, &kref)
	if err := newKeychainError(errCode); err != nil {
		return err
	}

	defer C.CFRelease(C.CFTypeRef(kref))
	return nil
}

// DeleteKeychain deletes a Keychain
func DeleteKeychain(path string) error {
	pathName := C.CString(path)
	defer C.free(unsafe.Pointer(pathName))

	var kref C.SecKeychainRef
	if err := newKeychainError(C.SecKeychainOpen(pathName, &kref)); err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(kref))

	return newKeychainError(C.SecKeychainDelete(kref))
}
