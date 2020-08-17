package prompt

import (
	"errors"
	"strings"
	"syscall"
	"unsafe"
)

const (
	CREDUI_FLAGS_ALWAYS_SHOW_UI      = 0x00080
	CREDUI_FLAGS_GENERIC_CREDENTIALS = 0x40000
	CREDUI_FLAGS_KEEP_USERNAME       = 0x100000
)

type creduiInfoA struct {
	cbSize         uint32
	hwndParent     uintptr
	pszMessageText *uint16
	pszCaptionText *uint16
	hbmBanner      uintptr
}

func WinCredUiPrompt(mfaSerial string) (string, error) {
	info := &creduiInfoA{
		hwndParent:     0,
		pszCaptionText: syscall.StringToUTF16Ptr("Enter token for aws-vault"),
		pszMessageText: syscall.StringToUTF16Ptr(mfaPromptMessage(mfaSerial)),
		hbmBanner:      0,
	}
	info.cbSize = uint32(unsafe.Sizeof(*info))
	passwordBuf := make([]uint16, 64)
	save := false
	flags := CREDUI_FLAGS_ALWAYS_SHOW_UI | CREDUI_FLAGS_KEEP_USERNAME | CREDUI_FLAGS_GENERIC_CREDENTIALS
	shortSerial := strings.ReplaceAll(strings.ReplaceAll(mfaSerial, "arn:aws:iam::", ""), ":mfa", "")

	ret, _, _ := syscall.NewLazyDLL("credui.dll").NewProc("CredUIPromptForCredentialsW").Call(
		uintptr(unsafe.Pointer(info)),
		uintptr(unsafe.Pointer(syscall.StringBytePtr("aws-vault"))),
		0,
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(shortSerial))),
		uintptr(len(shortSerial)+1),
		uintptr(unsafe.Pointer(&passwordBuf[0])),
		64,
		uintptr(unsafe.Pointer(&save)),
		uintptr(flags),
	)
	if ret != 0 {
		return "", errors.New("wincredui: call to CredUIPromptForCredentialsW failed")
	}

	return strings.TrimSpace(syscall.UTF16ToString(passwordBuf)), nil
}

func init() {
	Methods["wincredui"] = WinCredUiPrompt
}
