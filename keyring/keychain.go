// +build darwin
package keyring

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
	"log"
	"os"
	"os/user"
	"unicode/utf8"
	"unsafe"
)

type OSXKeychain struct {
	path     string
	password string
	service  string
}

func (k *OSXKeychain) Get(key string) ([]byte, error) {
	if _, err := os.Stat(k.path); os.IsNotExist(err) {
		return []byte{}, ErrKeyNotFound
	}

	kref, err := openKeychain(k.path)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(kref))

	serviceRef := C.CString(k.service)
	defer C.free(unsafe.Pointer(serviceRef))

	accountRef := C.CString(key)
	defer C.free(unsafe.Pointer(accountRef))

	var passwordLength C.UInt32
	var password unsafe.Pointer

	errCode := C.SecKeychainFindGenericPassword(
		C.CFTypeRef(kref),
		C.UInt32(len(k.service)),
		serviceRef,
		C.UInt32(len(key)),
		accountRef,
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

func (k *OSXKeychain) Set(key string, secret []byte) error {
	var kref C.SecKeychainRef
	var err error

	if _, err := os.Stat(k.path); os.IsNotExist(err) {
		var prompt = true
		if k.password != "" {
			prompt = false
		}
		log.Printf("creating keychain %s (prompt %#v)", k.path, prompt)
		kref, err = createKeychain(k.path, prompt, k.password)
		if err != nil {
			return err
		}
		defer C.CFRelease(C.CFTypeRef(kref))
	} else {
		log.Printf("opening keychain %s", k.path)
		kref, err = openKeychain(k.path)
		if err != nil {
			return err
		}
		defer C.CFRelease(C.CFTypeRef(kref))
	}

	var serviceRef C.CFStringRef
	if serviceRef, err = _UTF8StringToCFString(k.service); err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(serviceRef))

	var accountRef C.CFStringRef
	if accountRef, err = _UTF8StringToCFString(key); err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(accountRef))

	var descr C.CFStringRef
	if descr, err = _UTF8StringToCFString("aws-vault credentials"); err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(descr))

	var label C.CFStringRef
	if label, err = _UTF8StringToCFString(fmt.Sprintf("%s (%s)", k.service, key)); err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(label))

	dataBytes := bytesToCFData(secret)
	defer C.CFRelease(C.CFTypeRef(dataBytes))

	access, err := createEmptyAccess(fmt.Sprintf("%s (%s)", k.service, key))
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(access))

	query := map[C.CFTypeRef]C.CFTypeRef{
		C.kSecClass:           C.kSecClassGenericPassword,
		C.kSecAttrService:     C.CFTypeRef(serviceRef),
		C.kSecAttrAccount:     C.CFTypeRef(accountRef),
		C.kSecValueData:       C.CFTypeRef(dataBytes),
		C.kSecAttrDescription: C.CFTypeRef(descr),
		C.kSecAttrLabel:       C.CFTypeRef(label),
		C.kSecUseKeychain:     C.CFTypeRef(kref),
		C.kSecAttrAccess:      C.CFTypeRef(access),
	}

	queryDict := mapToCFDictionary(query)
	defer C.CFRelease(C.CFTypeRef(queryDict))

	log.Printf("adding service=%q, account=%q to osx keychain %s", k.service, key, k.path)
	err = newKeychainError(C.SecItemAdd(queryDict, nil))

	if err == errDuplicateItem {
		if err = k.Remove(key); err != nil {
			return err
		}

		log.Printf("adding service=%q, account=%q to osx keychain %s", k.service, key, k.path)
		err = newKeychainError(C.SecItemAdd(queryDict, nil))
	}

	return err
}

func (k *OSXKeychain) Remove(key string) error {
	if _, err := os.Stat(k.path); os.IsNotExist(err) {
		return ErrKeyNotFound
	}

	kref, err := openKeychain(k.path)
	if err != nil {
		return err
	}

	item, err := findGenericPasswordItem(kref, k.service, key)
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(item))

	log.Printf("removing keychain item service=%q, account=%q from osx keychain %q", k.service, key, k.path)
	return newKeychainError(C.SecKeychainItemDelete(item))
}

func (k *OSXKeychain) Keys() ([]string, error) {
	serviceRef, err := _UTF8StringToCFString(k.service)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(serviceRef))

	query := map[C.CFTypeRef]C.CFTypeRef{
		C.kSecClass:            C.kSecClassGenericPassword,
		C.kSecAttrService:      C.CFTypeRef(serviceRef),
		C.kSecMatchLimit:       C.kSecMatchLimitAll,
		C.kSecReturnAttributes: C.CFTypeRef(C.kCFBooleanTrue),
	}
	queryDict := mapToCFDictionary(query)
	defer C.CFRelease(C.CFTypeRef(queryDict))

	var resultsRef C.CFTypeRef
	if err = newKeychainError(C.SecItemCopyMatching(queryDict, &resultsRef)); err == errItemNotFound {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	defer C.CFRelease(resultsRef)
	var accountNames = []string{}

	for _, result := range _CFArrayToArray(C.CFArrayRef(resultsRef)) {
		m := _CFDictionaryToMap(C.CFDictionaryRef(result))
		accountName := _CFStringToUTF8String(C.CFStringRef(m[C.kSecAttrAccount]))
		accountNames = append(accountNames, accountName)
	}

	return accountNames, nil
}

func init() {
	keychainFile := os.Getenv("AWS_KEYCHAIN_FILE")
	if keychainFile == "" {
		usr, err := user.Current()
		if err != nil {
			panic(err)
		}
		keychainFile = usr.HomeDir + "/Library/Keychains/aws-vault.keychain"
	}

	keyring = &OSXKeychain{path: keychainFile, service: "aws-vault"}
}

// -------------------------------------------------
// OSX Keychain API funcs
// https://developer.apple.com/library/mac/documentation/Security/Reference/keychainservices/index.html

// The returned SecAccessRef, if non-nil, must be released via CFRelease.
func createEmptyAccess(label string) (C.SecAccessRef, error) {
	var err error
	var labelRef C.CFStringRef
	if labelRef, err = _UTF8StringToCFString(label); err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(labelRef))

	var access C.SecAccessRef
	trustedApplicationsArray := arrayToCFArray([]C.CFTypeRef{})
	defer C.CFRelease(C.CFTypeRef(trustedApplicationsArray))

	if err = newKeychainError(C.SecAccessCreate(labelRef, trustedApplicationsArray, &access)); err != nil {
		return nil, err
	}

	return access, nil
}

// The returned SecKeychainRef, if non-nil, must be released via CFRelease.
func createKeychain(path string, promptUser bool, password string) (C.SecKeychainRef, error) {
	pathName := C.CString(path)
	defer C.free(unsafe.Pointer(pathName))

	var kref C.SecKeychainRef
	var errCode C.OSStatus

	if promptUser {
		errCode = C.SecKeychainCreate(pathName, C.UInt32(0), nil, C.Boolean(1), nil, &kref)
	} else {
		passwordRef := C.CString(password)
		defer C.free(unsafe.Pointer(passwordRef))
		errCode = C.SecKeychainCreate(pathName, C.UInt32(len(password)), unsafe.Pointer(passwordRef), C.Boolean(0), nil, &kref)
	}

	if err := newKeychainError(errCode); err != nil {
		return nil, err
	}

	return kref, nil
}

// The returned SecKeychainRef, if non-nil, must be released via CFRelease.
func openKeychain(path string) (C.SecKeychainRef, error) {
	pathName := C.CString(path)
	defer C.free(unsafe.Pointer(pathName))

	var kref C.SecKeychainRef
	if err := newKeychainError(C.SecKeychainOpen(pathName, &kref)); err != nil {
		return nil, err
	}

	return kref, nil
}

// The returned SecKeychainItemRef, if non-nil, must be released via CFRelease.
func findGenericPasswordItem(kref C.SecKeychainRef, service, account string) (itemRef C.SecKeychainItemRef, err error) {
	serviceRef := C.CString(service)
	defer C.free(unsafe.Pointer(serviceRef))

	accountRef := C.CString(account)
	defer C.free(unsafe.Pointer(accountRef))

	errCode := C.SecKeychainFindGenericPassword(
		C.CFTypeRef(kref),
		C.UInt32(len(service)),
		serviceRef,
		C.UInt32(len(account)),
		accountRef,
		nil,
		nil,
		&itemRef,
	)

	err = newKeychainError(errCode)
	return
}

// -------------------------------------------------
// From go-osxkeychain
// https://github.com/keybase/go-osxkeychain/blob/master/osxkeychain.go

type keychainError C.OSStatus

const (
	errUnimplemented     keychainError = C.errSecUnimplemented
	errParam             keychainError = C.errSecParam
	errAllocate          keychainError = C.errSecAllocate
	errNotAvailable      keychainError = C.errSecNotAvailable
	errReadOnly          keychainError = C.errSecReadOnly
	errAuthFailed        keychainError = C.errSecAuthFailed
	errNoSuchKeychain    keychainError = C.errSecNoSuchKeychain
	errInvalidKeychain   keychainError = C.errSecInvalidKeychain
	errDuplicateKeychain keychainError = C.errSecDuplicateKeychain
	errDuplicateCallback keychainError = C.errSecDuplicateCallback
	errInvalidCallback   keychainError = C.errSecInvalidCallback
	errDuplicateItem     keychainError = C.errSecDuplicateItem
	errItemNotFound      keychainError = C.errSecItemNotFound
	errBufferTooSmall    keychainError = C.errSecBufferTooSmall
	errDataTooLarge      keychainError = C.errSecDataTooLarge
	errNoSuchAttr        keychainError = C.errSecNoSuchAttr
	errInvalidItemRef    keychainError = C.errSecInvalidItemRef
	errInvalidSearchRef  keychainError = C.errSecInvalidSearchRef
	errNoSuchClass       keychainError = C.errSecNoSuchClass
	errNoDefaultKeychain keychainError = C.errSecNoDefaultKeychain
	errReadOnlyAttr      keychainError = C.errSecReadOnlyAttr
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

// The returned CFStringRef, if non-nil, must be released via CFRelease.
func _UTF8StringToCFString(s string) (C.CFStringRef, error) {
	if !utf8.ValidString(s) {
		return nil, errors.New("invalid UTF-8 string")
	}

	bytes := []byte(s)
	var p *C.UInt8
	if len(bytes) > 0 {
		p = (*C.UInt8)(&bytes[0])
	}
	return C.CFStringCreateWithBytes(nil, p, C.CFIndex(len(s)), C.kCFStringEncodingUTF8, C.false), nil
}

func _CFStringToUTF8String(s C.CFStringRef) string {
	p := C.CFStringGetCStringPtr(s, C.kCFStringEncodingUTF8)
	if p != nil {
		return C.GoString(p)
	}
	length := C.CFStringGetLength(s)
	if length == 0 {
		return ""
	}
	maxBufLen := C.CFStringGetMaximumSizeForEncoding(length, C.kCFStringEncodingUTF8)
	if maxBufLen == 0 {
		return ""
	}
	buf := make([]byte, maxBufLen)
	var usedBufLen C.CFIndex
	_ = C.CFStringGetBytes(s, C.CFRange{0, length}, C.kCFStringEncodingUTF8, C.UInt8(0), C.false, (*C.UInt8)(&buf[0]), maxBufLen, &usedBufLen)
	return string(buf[:usedBufLen])
}

// The returned CFDictionaryRef, if non-nil, must be released via CFRelease.
func mapToCFDictionary(m map[C.CFTypeRef]C.CFTypeRef) C.CFDictionaryRef {
	var keys, values []unsafe.Pointer
	for key, value := range m {
		keys = append(keys, unsafe.Pointer(key))
		values = append(values, unsafe.Pointer(value))
	}
	numValues := len(values)
	var keysPointer, valuesPointer *unsafe.Pointer
	if numValues > 0 {
		keysPointer = &keys[0]
		valuesPointer = &values[0]
	}
	return C.CFDictionaryCreate(nil, keysPointer, valuesPointer, C.CFIndex(numValues), &C.kCFTypeDictionaryKeyCallBacks, &C.kCFTypeDictionaryValueCallBacks)
}

func _CFDictionaryToMap(cfDict C.CFDictionaryRef) (m map[C.CFTypeRef]C.CFTypeRef) {
	count := C.CFDictionaryGetCount(cfDict)
	if count > 0 {
		keys := make([]C.CFTypeRef, count)
		values := make([]C.CFTypeRef, count)
		C.CFDictionaryGetKeysAndValues(cfDict, (*unsafe.Pointer)(&keys[0]), (*unsafe.Pointer)(&values[0]))
		m = make(map[C.CFTypeRef]C.CFTypeRef, count)
		for i := C.CFIndex(0); i < count; i++ {
			m[keys[i]] = values[i]
		}
	}
	return
}

// The returned CFArrayRef, if non-nil, must be released via CFRelease.
func arrayToCFArray(a []C.CFTypeRef) C.CFArrayRef {
	var values []unsafe.Pointer
	for _, value := range a {
		values = append(values, unsafe.Pointer(value))
	}
	numValues := len(values)
	var valuesPointer *unsafe.Pointer
	if numValues > 0 {
		valuesPointer = &values[0]
	}
	return C.CFArrayCreate(nil, valuesPointer, C.CFIndex(numValues), &C.kCFTypeArrayCallBacks)
}

func _CFArrayToArray(cfArray C.CFArrayRef) (a []C.CFTypeRef) {
	count := C.CFArrayGetCount(cfArray)
	if count > 0 {
		a = make([]C.CFTypeRef, count)
		C.CFArrayGetValues(cfArray, C.CFRange{0, count}, (*unsafe.Pointer)(&a[0]))
	}
	return
}

// The returned CFDataRef, if non-nil, must be released via CFRelease.
func bytesToCFData(b []byte) C.CFDataRef {
	var p *C.UInt8
	if len(b) > 0 {
		p = (*C.UInt8)(&b[0])
	}
	return C.CFDataCreate(nil, p, C.CFIndex(len(b)))
}
