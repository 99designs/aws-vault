package vault

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gofrs/flock"
)

// ProcessLock coordinates work across processes.
type ProcessLock interface {
	TryLock() (bool, error)
	Unlock() error
	Path() string
}

type fileProcessLock struct {
	lock *flock.Flock
}

// NewFileLock creates a lock at the provided path.
func NewFileLock(path string) ProcessLock {
	return &fileProcessLock{lock: flock.New(path)}
}

func (l *fileProcessLock) TryLock() (bool, error) {
	return l.lock.TryLock()
}

func (l *fileProcessLock) Unlock() error {
	return l.lock.Unlock()
}

func (l *fileProcessLock) Path() string {
	return l.lock.Path()
}

func defaultLockPath(filename string) string {
	return filepath.Join(os.TempDir(), filename)
}

func hashedLockFilename(prefix, key string) string {
	sum := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%s.%x.lock", prefix, sum)
}
