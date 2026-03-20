package vault

const keyringLockFilenamePrefix = "aws-vault.keyring"

// KeyringLock coordinates keyring access across processes.
type KeyringLock = ProcessLock

// NewDefaultKeyringLock creates a lock in the system temp directory.
// This only coordinates processes that share the same temp dir; differing TMPDIRs/users are out of scope.
func NewDefaultKeyringLock(lockKey string) KeyringLock {
	return NewKeyringLock(defaultLockPath(keyringLockFilename(lockKey)))
}

// NewKeyringLock creates a lock at the provided path.
func NewKeyringLock(path string) KeyringLock {
	return NewFileLock(path)
}

func keyringLockFilename(lockKey string) string {
	return hashedLockFilename(keyringLockFilenamePrefix, lockKey)
}
