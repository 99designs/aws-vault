package vault

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/byteness/keyring"
)

type testSessionProvider struct {
	creds      *types.Credentials
	calls      int
	onRetrieve func()
}

func (p *testSessionProvider) RetrieveStsCredentials(context.Context) (*types.Credentials, error) {
	p.calls++
	if p.onRetrieve != nil {
		p.onRetrieve()
	}
	return p.creds, nil
}

func (p *testSessionProvider) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{}, nil
}

type lockCheckingKeyring struct {
	keyring.Keyring
	setCalls int
	setLock  *testLock
}

func (k *lockCheckingKeyring) Set(item keyring.Item) error {
	k.setCalls++
	if k.setLock != nil && !k.setLock.locked {
		return fmt.Errorf("lock not held during cache set")
	}
	return k.Keyring.Set(item)
}

func newTestSessionKey() SessionMetadata {
	return SessionMetadata{
		Type:        "sso.GetRoleCredentials",
		ProfileName: "test-profile",
		MfaSerial:   "https://sso.example",
	}
}

func newTestCreds(expires time.Time) *types.Credentials {
	return &types.Credentials{
		AccessKeyId:     aws.String("AKIATEST"),
		SecretAccessKey: aws.String("secret"),
		SessionToken:    aws.String("token"),
		Expiration:      aws.Time(expires),
	}
}

func TestCachedSession_CacheHit_NoLock(t *testing.T) {
	key := newTestSessionKey()
	creds := newTestCreds(time.Now().Add(time.Hour))
	kr := keyring.NewArrayKeyring(nil)
	sk := &SessionKeyring{Keyring: kr}
	if err := sk.Set(key, creds); err != nil {
		t.Fatalf("set cache: %v", err)
	}

	lock := &testLock{}
	provider := &testSessionProvider{
		onRetrieve: func() { t.Fatal("RetrieveStsCredentials should not be called on cache hit") },
	}

	p := &CachedSessionProvider{
		SessionKey:      key,
		SessionProvider: provider,
		Keyring:         sk,
		ExpiryWindow:    0,
		UseSessionLock:  true,
		sessionLock:     lock,
	}

	got, err := p.RetrieveStsCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if aws.ToString(got.AccessKeyId) != aws.ToString(creds.AccessKeyId) {
		t.Fatalf("unexpected credentials returned")
	}
	if lock.tryCalls != 0 {
		t.Fatalf("expected no lock attempts, got %d", lock.tryCalls)
	}
	if provider.calls != 0 {
		t.Fatalf("expected no provider calls, got %d", provider.calls)
	}
}

func TestCachedSession_LockDisabled_SkipsLock(t *testing.T) {
	key := newTestSessionKey()
	creds := newTestCreds(time.Now().Add(time.Hour))
	kr := keyring.NewArrayKeyring(nil)
	sk := &SessionKeyring{Keyring: kr}
	lock := &testLock{tryResults: []bool{true}}
	provider := &testSessionProvider{creds: creds}

	p := &CachedSessionProvider{
		SessionKey:      key,
		SessionProvider: provider,
		Keyring:         sk,
		ExpiryWindow:    0,
		UseSessionLock:  false,
		sessionLock:     lock,
	}

	got, err := p.RetrieveStsCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if aws.ToString(got.AccessKeyId) != aws.ToString(creds.AccessKeyId) {
		t.Fatalf("unexpected credentials returned")
	}
	if lock.tryCalls != 0 {
		t.Fatalf("expected no lock attempts, got %d", lock.tryCalls)
	}
	if provider.calls != 1 {
		t.Fatalf("expected 1 provider call, got %d", provider.calls)
	}
	if _, err := sk.Get(key); err != nil {
		t.Fatalf("expected cached credentials, got %v", err)
	}
}

func TestCachedSession_LockMiss_ThenCacheHit_NoRefresh(t *testing.T) {
	key := newTestSessionKey()
	creds := newTestCreds(time.Now().Add(time.Hour))
	kr := keyring.NewArrayKeyring(nil)
	sk := &SessionKeyring{Keyring: kr}
	lock := &testLock{tryResults: []bool{false}}

	provider := &testSessionProvider{
		onRetrieve: func() { t.Fatal("RetrieveStsCredentials should not be called when cache fills while waiting") },
	}

	p := &CachedSessionProvider{
		SessionKey:      key,
		SessionProvider: provider,
		Keyring:         sk,
		ExpiryWindow:    0,
		UseSessionLock:  true,
		sessionLock:     lock,
		sessionLockWait: 5 * time.Second,
	}
	p.sessionSleep = func(ctx context.Context, d time.Duration) error {
		return sk.Set(key, creds)
	}

	got, err := p.RetrieveStsCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if aws.ToString(got.AccessKeyId) != aws.ToString(creds.AccessKeyId) {
		t.Fatalf("unexpected credentials returned")
	}
	if lock.tryCalls != 1 {
		t.Fatalf("expected 1 lock attempt, got %d", lock.tryCalls)
	}
	if provider.calls != 0 {
		t.Fatalf("expected no provider calls, got %d", provider.calls)
	}
}

func TestCachedSession_LockAcquired_RecheckCache(t *testing.T) {
	key := newTestSessionKey()
	creds := newTestCreds(time.Now().Add(time.Hour))
	kr := keyring.NewArrayKeyring(nil)
	sk := &SessionKeyring{Keyring: kr}
	lock := &testLock{tryResults: []bool{true}}
	lock.onTry = func(l *testLock) {
		if l.locked {
			_ = sk.Set(key, creds)
		}
	}

	provider := &testSessionProvider{
		onRetrieve: func() { t.Fatal("RetrieveStsCredentials should not be called when cache fills after lock") },
	}

	p := &CachedSessionProvider{
		SessionKey:      key,
		SessionProvider: provider,
		Keyring:         sk,
		ExpiryWindow:    0,
		UseSessionLock:  true,
		sessionLock:     lock,
	}

	got, err := p.RetrieveStsCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if aws.ToString(got.AccessKeyId) != aws.ToString(creds.AccessKeyId) {
		t.Fatalf("unexpected credentials returned")
	}
	if lock.unlockCalls != 1 {
		t.Fatalf("expected 1 unlock, got %d", lock.unlockCalls)
	}
	if provider.calls != 0 {
		t.Fatalf("expected no provider calls, got %d", provider.calls)
	}
}

func TestCachedSession_LockHeldThroughCacheSet(t *testing.T) {
	key := newTestSessionKey()
	creds := newTestCreds(time.Now().Add(time.Hour))
	lock := &testLock{tryResults: []bool{true}}
	wrappedKeyring := &lockCheckingKeyring{
		Keyring: keyring.NewArrayKeyring(nil),
		setLock: lock,
	}
	sk := &SessionKeyring{Keyring: wrappedKeyring}
	provider := &testSessionProvider{creds: creds}

	p := &CachedSessionProvider{
		SessionKey:      key,
		SessionProvider: provider,
		Keyring:         sk,
		ExpiryWindow:    0,
		UseSessionLock:  true,
		sessionLock:     lock,
	}

	_, err := p.RetrieveStsCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wrappedKeyring.setCalls != 1 {
		t.Fatalf("expected cache set once, got %d", wrappedKeyring.setCalls)
	}
	if lock.unlockCalls != 1 {
		t.Fatalf("expected 1 unlock, got %d", lock.unlockCalls)
	}
	if provider.calls != 1 {
		t.Fatalf("expected 1 provider call, got %d", provider.calls)
	}
}

func TestCachedSession_LockWaitLogs(t *testing.T) {
	lock := &testLock{tryResults: []bool{false, false, false, false}}
	kr := keyring.NewArrayKeyring(nil)
	sk := &SessionKeyring{Keyring: kr}
	key := newTestSessionKey()
	provider := &testSessionProvider{}

	ctx, cancel := context.WithCancel(context.Background())
	clock := &testClock{now: time.Unix(0, 0), cancel: cancel, cancelAfter: 4}
	var logTimes []time.Time

	p := &CachedSessionProvider{
		SessionKey:      key,
		SessionProvider: provider,
		Keyring:         sk,
		ExpiryWindow:    0,
		UseSessionLock:  true,
		sessionLock:     lock,
		sessionLockWait: 5 * time.Second,
		sessionLockLog:  15 * time.Second,
		sessionNow:      clock.Now,
	}
	p.sessionSleep = clock.Sleep
	p.sessionLogf = func(string, ...any) {
		logTimes = append(logTimes, clock.Now())
	}

	_, err := p.RetrieveStsCredentials(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	if len(logTimes) != 2 {
		t.Fatalf("expected 2 log entries, got %d", len(logTimes))
	}
	if !logTimes[0].Equal(time.Unix(0, 0)) {
		t.Fatalf("unexpected first log time: %s", logTimes[0])
	}
	if !logTimes[1].Equal(time.Unix(15, 0)) {
		t.Fatalf("unexpected second log time: %s", logTimes[1])
	}
}
