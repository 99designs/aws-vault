package vault

import (
	"os"
	"path/filepath"

	"github.com/gofrs/flock"
)

const defaultSSOLockFilename = "aws-vault.sso.lock"

// SSOTokenLock coordinates the SSO device flow across processes.
type SSOTokenLock interface {
	TryLock() (bool, error)
	Unlock() error
	Path() string
}

type fileSSOTokenLock struct {
	lock *flock.Flock
}

// NewDefaultSSOTokenLock creates a lock in the system temp directory.
// This only coordinates processes that share the same temp dir; differing TMPDIRs/users are out of scope.
func NewDefaultSSOTokenLock() SSOTokenLock {
	return NewSSOTokenLock(filepath.Join(os.TempDir(), defaultSSOLockFilename))
}

// NewSSOTokenLock creates a lock at the provided path.
func NewSSOTokenLock(path string) SSOTokenLock {
	return &fileSSOTokenLock{lock: flock.New(path)}
}

func (l *fileSSOTokenLock) TryLock() (bool, error) {
	return l.lock.TryLock()
}

func (l *fileSSOTokenLock) Unlock() error {
	return l.lock.Unlock()
}

func (l *fileSSOTokenLock) Path() string {
	return l.lock.Path()
}
