package vault

const ssoLockFilenamePrefix = "aws-vault.sso"

// SSOTokenLock coordinates the SSO device flow across processes.
type SSOTokenLock = ProcessLock

// NewDefaultSSOTokenLock creates a lock in the system temp directory keyed by startURL.
// Processes sharing the same StartURL serialize; different StartURLs lock independently.
// This only coordinates processes that share the same temp dir; differing TMPDIRs/users are out of scope.
func NewDefaultSSOTokenLock(startURL string) SSOTokenLock {
	return NewSSOTokenLock(defaultLockPath(ssoLockFilename(startURL)))
}

// NewSSOTokenLock creates a lock at the provided path.
func NewSSOTokenLock(path string) SSOTokenLock {
	return NewFileLock(path)
}

func ssoLockFilename(startURL string) string {
	return hashedLockFilename(ssoLockFilenamePrefix, startURL)
}
