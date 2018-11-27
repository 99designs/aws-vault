package device

import (
	"time"
)

// Reader is the interface for read only OTP devices.
type Reader interface {
	// GetOTP gets a one time password.
	GetOTP(now time.Time, name string) (string, error)

	// Name returns the name of this Reader.
	Name() string
}

// Manager is the interface to store/remove secrets from OTP devices.
type Manager interface {
	// Add adds a new TOTP secret.
	Add(name string, secret []byte) error

	// Delete removes a name TOTP secret.
	Delete(name string) error
}

// ReaderManager is the interface to both get one time passwords and manage secrets in OTP devices.
type ReaderManager interface {
	Reader
	Manager
}
