// +build darwin

package keyring

// https://developer.apple.com/library/mac/documentation/Security/Reference/keychainservices/index.html

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
	"path/filepath"
	"unicode/utf8"
	"unsafe"

	"github.com/mitchellh/go-homedir"
)

type keychain struct {
	path       string
	service    string
	passphrase string
}

func init() {
	supportedBackends[KeychainBackend] = opener(func(name string) (Keyring, error) {
		if name == "" {
			name = "login"
		}

		home, err := homedir.Dir()
		if err != nil {
			return nil, err
		}

		return &keychain{
			path:    filepath.Join(home, "/Library/Keychains/"+name+".keychain"),
			service: name,
		}, nil
	})

	DefaultBackend = KeychainBackend
}

func (k *keychain) Get(key string) (Item, error) {
	serviceRef, err := _UTF8StringToCFString(k.service)
	if err != nil {
		return Item{}, err
	}
	defer C.CFRelease(C.CFTypeRef(serviceRef))

	accountRef, err := _UTF8StringToCFString(key)
	if err != nil {
		return Item{}, err
	}
	defer C.CFRelease(C.CFTypeRef(accountRef))

	query := map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecClass):            C.CFTypeRef(C.kSecClassGenericPassword),
		C.CFTypeRef(C.kSecAttrService):      C.CFTypeRef(serviceRef),
		C.CFTypeRef(C.kSecAttrAccount):      C.CFTypeRef(accountRef),
		C.CFTypeRef(C.kSecMatchLimit):       C.CFTypeRef(C.kSecMatchLimitOne),
		C.CFTypeRef(C.kSecReturnAttributes): C.CFTypeRef(C.kCFBooleanTrue),
		C.CFTypeRef(C.kSecReturnData):       C.CFTypeRef(C.kCFBooleanTrue),
	}

	kref, err := openKeychain(k.path)
	if err != nil {
		return Item{}, err
	}

	searchArray := arrayToCFArray([]C.CFTypeRef{C.CFTypeRef(kref)})
	defer C.CFRelease(C.CFTypeRef(searchArray))
	query[C.CFTypeRef(C.kSecMatchSearchList)] = C.CFTypeRef(searchArray)

	queryDict := mapToCFDictionary(query)
	defer C.CFRelease(C.CFTypeRef(queryDict))

	var resultsRef C.CFTypeRef

	if err = newKeychainError(C.SecItemCopyMatching(queryDict, &resultsRef)); err == errItemNotFound {
		return Item{}, ErrKeyNotFound
	} else if err != nil {
		return Item{}, err
	}

	defer C.CFRelease(resultsRef)

	m := _CFDictionaryToMap(C.CFDictionaryRef(resultsRef))

	data := C.CFDataRef(m[C.CFTypeRef(C.kSecValueData)])
	dataLen := C.int(C.CFDataGetLength(data))
	cdata := C.CFDataGetBytePtr(data)

	item := Item{
		Key:  key,
		Data: C.GoBytes(unsafe.Pointer(cdata), dataLen),
	}

	if label, exists := m[C.CFTypeRef(C.kSecAttrLabel)]; exists {
		item.Label = _CFStringToUTF8String(C.CFStringRef(label))
	}

	if descr, exists := m[C.CFTypeRef(C.kSecAttrDescription)]; exists {
		item.Description = _CFStringToUTF8String(C.CFStringRef(descr))
	}

	return item, nil
}

func (k *keychain) Set(item Item) error {
	var kref C.SecKeychainRef
	var err error

	if exists, _ := keychainExists(k.path); !exists {
		var prompt = true
		if k.passphrase != "" {
			prompt = false
		}
		log.Printf("Creating keychain %s (prompt %#v)", k.path, prompt)
		kref, err = createKeychain(k.path, prompt, k.passphrase)
		if err != nil {
			return err
		}
		defer C.CFRelease(C.CFTypeRef(kref))
	} else {
		kref, err = openKeychain(k.path)
		if err != nil {
			log.Printf("error opening %v, %v", err, k.path)
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
	if accountRef, err = _UTF8StringToCFString(item.Key); err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(accountRef))

	var descr C.CFStringRef
	if descr, err = _UTF8StringToCFString(item.Description); err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(descr))

	if item.Label == "" {
		item.Label = fmt.Sprintf("%s (%s)", k.service, item.Key)
	}

	var label C.CFStringRef
	if label, err = _UTF8StringToCFString(item.Label); err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(label))

	dataBytes := bytesToCFData(item.Data)
	defer C.CFRelease(C.CFTypeRef(dataBytes))

	query := map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecClass):           C.CFTypeRef(C.kSecClassGenericPassword),
		C.CFTypeRef(C.kSecAttrService):     C.CFTypeRef(serviceRef),
		C.CFTypeRef(C.kSecAttrAccount):     C.CFTypeRef(accountRef),
		C.CFTypeRef(C.kSecValueData):       C.CFTypeRef(dataBytes),
		C.CFTypeRef(C.kSecAttrDescription): C.CFTypeRef(descr),
		C.CFTypeRef(C.kSecAttrLabel):       C.CFTypeRef(label),
		C.CFTypeRef(C.kSecUseKeychain):     C.CFTypeRef(kref),
	}

	if !item.TrustSelf {
		access, err := createEmptyAccess(fmt.Sprintf("%s (%s)", k.service, item.Key))
		if err != nil {
			return err
		}
		defer C.CFRelease(C.CFTypeRef(access))
		query[C.CFTypeRef(C.kSecAttrAccess)] = C.CFTypeRef(access)
	}

	queryDict := mapToCFDictionary(query)
	defer C.CFRelease(C.CFTypeRef(queryDict))

	log.Printf("Adding service=%q, account=%q to osx keychain %s", k.service, item.Key, k.path)
	err = newKeychainError(C.SecItemAdd(queryDict, nil))

	if err == errDuplicateItem {
		if err = k.Remove(item.Key); err != nil {
			return err
		}
		err = newKeychainError(C.SecItemAdd(queryDict, nil))
	}

	return err
}

func (k *keychain) Remove(key string) error {
	serviceRef, err := _UTF8StringToCFString(k.service)
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(serviceRef))

	accountRef, err := _UTF8StringToCFString(key)
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(accountRef))

	query := map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecClass):       C.CFTypeRef(C.kSecClassGenericPassword),
		C.CFTypeRef(C.kSecAttrService): C.CFTypeRef(serviceRef),
		C.CFTypeRef(C.kSecAttrAccount): C.CFTypeRef(accountRef),
		C.CFTypeRef(C.kSecMatchLimit):  C.CFTypeRef(C.kSecMatchLimitOne),
	}

	kref, err := openKeychain(k.path)
	if err != nil {
		return err
	}

	searchArray := arrayToCFArray([]C.CFTypeRef{C.CFTypeRef(kref)})
	defer C.CFRelease(C.CFTypeRef(searchArray))
	query[C.CFTypeRef(C.kSecMatchSearchList)] = C.CFTypeRef(searchArray)

	queryDict := mapToCFDictionary(query)
	defer C.CFRelease(C.CFTypeRef(queryDict))

	log.Printf("Removing keychain item service=%q, account=%q from osx keychain %q", k.service, key, k.path)
	return newKeychainError(C.SecItemDelete(queryDict))
}

func (k *keychain) Keys() ([]string, error) {
	serviceRef, err := _UTF8StringToCFString(k.service)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(serviceRef))

	query := map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecClass):            C.CFTypeRef(C.kSecClassGenericPassword),
		C.CFTypeRef(C.kSecAttrService):      C.CFTypeRef(serviceRef),
		C.CFTypeRef(C.kSecMatchLimit):       C.CFTypeRef(C.kSecMatchLimitAll),
		C.CFTypeRef(C.kSecReturnAttributes): C.CFTypeRef(C.kCFBooleanTrue),
	}

	kref, err := openKeychain(k.path)
	if err != nil {
		return nil, err
	}

	searchArray := arrayToCFArray([]C.CFTypeRef{C.CFTypeRef(kref)})
	defer C.CFRelease(C.CFTypeRef(searchArray))
	query[C.CFTypeRef(C.kSecMatchSearchList)] = C.CFTypeRef(searchArray)

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
		accountName := _CFStringToUTF8String(C.CFStringRef(m[C.CFTypeRef(C.kSecAttrAccount)]))
		accountNames = append(accountNames, accountName)
	}

	return accountNames, nil
}

// -------------------------------------------------
// OSX Keychain API funcs

func keychainExists(path string) (bool, error) {
	// returns no error even if it doesn't exist
	k, err := openKeychain(path)
	if err != nil {
		log.Printf("Error opening %v", err)
		return false, err
	}
	defer C.CFRelease(C.CFTypeRef(k))

	var status C.SecKeychainStatus
	err = newKeychainError(C.SecKeychainGetStatus(k, &status))

	if err == errNoSuchKeychain {
		return false, nil
	} else if err != nil {
		return false, err
	}

	return true, nil
}

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
	log.Printf("Opening keychain %s", path)
	pathName := C.CString(path)
	defer C.free(unsafe.Pointer(pathName))

	var kref C.SecKeychainRef
	if err := newKeychainError(C.SecKeychainOpen(pathName, &kref)); err != nil {
		return nil, err
	}

	return kref, nil
}

func releaseKeychain(k C.SecKeychainRef) {
	C.CFRelease(C.CFTypeRef(k))
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
