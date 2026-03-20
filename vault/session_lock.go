package vault

const sessionLockFilenamePrefix = "aws-vault.session"

// SessionCacheLock coordinates session cache refreshes across processes.
type SessionCacheLock = ProcessLock

// NewDefaultSessionCacheLock creates a lock in the system temp directory.
// This only coordinates processes that share the same temp dir; differing TMPDIRs/users are out of scope.
func NewDefaultSessionCacheLock(lockKey string) SessionCacheLock {
	return NewSessionCacheLock(defaultLockPath(sessionLockFilename(lockKey)))
}

// NewSessionCacheLock creates a lock at the provided path.
func NewSessionCacheLock(path string) SessionCacheLock {
	return NewFileLock(path)
}

func sessionLockFilename(lockKey string) string {
	return hashedLockFilename(sessionLockFilenamePrefix, lockKey)
}
