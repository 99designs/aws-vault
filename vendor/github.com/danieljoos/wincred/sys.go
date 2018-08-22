// +build windows

package wincred

import (
	"reflect"
	"syscall"
	"unsafe"
)

var (
	modadvapi32 = syscall.NewLazyDLL("advapi32.dll")

	procCredRead      proc = modadvapi32.NewProc("CredReadW")
	procCredWrite     proc = modadvapi32.NewProc("CredWriteW")
	procCredDelete    proc = modadvapi32.NewProc("CredDeleteW")
	procCredFree      proc = modadvapi32.NewProc("CredFree")
	procCredEnumerate proc = modadvapi32.NewProc("CredEnumerateW")
)

// Interface for syscall.Proc: helps testing
type proc interface {
	Call(a ...uintptr) (r1, r2 uintptr, lastErr error)
}

// http://msdn.microsoft.com/en-us/library/windows/desktop/aa374788(v=vs.85).aspx
type sysCREDENTIAL struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        syscall.Filetime
	CredentialBlobSize uint32
	CredentialBlob     uintptr
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

// http://msdn.microsoft.com/en-us/library/windows/desktop/aa374790(v=vs.85).aspx
type sysCREDENTIAL_ATTRIBUTE struct {
	Keyword   *uint16
	Flags     uint32
	ValueSize uint32
	Value     uintptr
}

// http://msdn.microsoft.com/en-us/library/windows/desktop/aa374788(v=vs.85).aspx
type sysCRED_TYPE uint32

const (
	sysCRED_TYPE_GENERIC                 sysCRED_TYPE = 0x1
	sysCRED_TYPE_DOMAIN_PASSWORD         sysCRED_TYPE = 0x2
	sysCRED_TYPE_DOMAIN_CERTIFICATE      sysCRED_TYPE = 0x3
	sysCRED_TYPE_DOMAIN_VISIBLE_PASSWORD sysCRED_TYPE = 0x4
	sysCRED_TYPE_GENERIC_CERTIFICATE     sysCRED_TYPE = 0x5
	sysCRED_TYPE_DOMAIN_EXTENDED         sysCRED_TYPE = 0x6

	sysERROR_NOT_FOUND = "Element not found."
)

// http://msdn.microsoft.com/en-us/library/windows/desktop/aa374804(v=vs.85).aspx
func sysCredRead(targetName string, typ sysCRED_TYPE) (*Credential, error) {
	var pcred *sysCREDENTIAL
	targetNamePtr, _ := syscall.UTF16PtrFromString(targetName)
	ret, _, err := procCredRead.Call(
		uintptr(unsafe.Pointer(targetNamePtr)),
		uintptr(typ),
		0,
		uintptr(unsafe.Pointer(&pcred)),
	)
	if ret == 0 {
		return nil, err
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(pcred)))

	return sysToCredential(pcred), nil
}

// http://msdn.microsoft.com/en-us/library/windows/desktop/aa375187(v=vs.85).aspx
func sysCredWrite(cred *Credential, typ sysCRED_TYPE) error {
	ncred := sysFromCredential(cred)
	ncred.Type = uint32(typ)
	ret, _, err := procCredWrite.Call(
		uintptr(unsafe.Pointer(ncred)),
		0,
	)
	if ret == 0 {
		return err
	}

	return nil
}

// http://msdn.microsoft.com/en-us/library/windows/desktop/aa374787(v=vs.85).aspx
func sysCredDelete(cred *Credential, typ sysCRED_TYPE) error {
	targetNamePtr, _ := syscall.UTF16PtrFromString(cred.TargetName)
	ret, _, err := procCredDelete.Call(
		uintptr(unsafe.Pointer(targetNamePtr)),
		uintptr(typ),
		0,
	)
	if ret == 0 {
		return err
	}

	return nil
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa374794(v=vs.85).aspx
func sysCredEnumerate(filter string, all bool) ([]*Credential, error) {
	var count int
	var pcreds uintptr
	var filterPtr uintptr
	if !all {
		filterUtf16Ptr, _ := syscall.UTF16PtrFromString(filter)
		filterPtr = uintptr(unsafe.Pointer(filterUtf16Ptr))
	} else {
		filterPtr = 0
	}
	ret, _, err := procCredEnumerate.Call(
		filterPtr,
		0,
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&pcreds)),
	)
	if ret == 0 {
		return nil, err
	}
	defer procCredFree.Call(pcreds)
	credsSlice := *(*[]*sysCREDENTIAL)(unsafe.Pointer(&reflect.SliceHeader{
		Data: pcreds,
		Len:  count,
		Cap:  count,
	}))
	creds := make([]*Credential, count, count)
	for i, cred := range credsSlice {
		creds[i] = sysToCredential(cred)
	}

	return creds, nil
}
