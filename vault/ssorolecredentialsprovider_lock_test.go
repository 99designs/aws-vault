package vault

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/byteness/keyring"
)

type testTokenCache struct {
	token    *ssooidc.CreateTokenOutput
	setCalls int
	setLock  *testLock
}

func (c *testTokenCache) Get(string) (*ssooidc.CreateTokenOutput, error) {
	if c.token == nil {
		return nil, keyring.ErrKeyNotFound
	}
	return c.token, nil
}

func (c *testTokenCache) Set(_ string, token *ssooidc.CreateTokenOutput) error {
	c.setCalls++
	if c.setLock != nil && !c.setLock.locked {
		return fmt.Errorf("lock not held during cache set")
	}
	c.token = token
	return nil
}

func (c *testTokenCache) Remove(string) error {
	c.token = nil
	return nil
}

func TestGetOIDCToken_CacheHit_NoLock(t *testing.T) {
	cachedToken := &ssooidc.CreateTokenOutput{AccessToken: aws.String("cached")}
	cache := &testTokenCache{token: cachedToken}
	lock := &testLock{}

	p := &SSORoleCredentialsProvider{
		OIDCTokenCache:  cache,
		StartURL:        "https://sso.example",
		ssoTokenLock:    lock,
		UseStdout:       false,
		UseSSOTokenLock: true,
	}
	p.newOIDCTokenFn = func(context.Context) (*ssooidc.CreateTokenOutput, error) {
		t.Fatal("newOIDCToken should not be called on cache hit")
		return nil, nil
	}
	p.ssoLogf = func(string, ...any) {}
	p.ssoSleep = func(context.Context, time.Duration) error { return nil }

	token, cached, err := p.getOIDCToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cached {
		t.Fatalf("expected cached token")
	}
	if token != cachedToken {
		t.Fatalf("unexpected token returned")
	}
	if lock.tryCalls != 0 {
		t.Fatalf("expected no lock attempts, got %d", lock.tryCalls)
	}
}

func TestGetOIDCToken_LockDisabled_SkipsLock(t *testing.T) {
	freshToken := &ssooidc.CreateTokenOutput{AccessToken: aws.String("fresh")}
	cache := &testTokenCache{}
	lock := &testLock{tryResults: []bool{true}}

	p := &SSORoleCredentialsProvider{
		OIDCTokenCache:  cache,
		StartURL:        "https://sso.example",
		ssoTokenLock:    lock,
		UseStdout:       false,
		UseSSOTokenLock: false,
	}
	p.newOIDCTokenFn = func(context.Context) (*ssooidc.CreateTokenOutput, error) {
		return freshToken, nil
	}
	p.ssoLogf = func(string, ...any) {}
	p.ssoSleep = func(context.Context, time.Duration) error { return nil }

	token, cached, err := p.getOIDCToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cached {
		t.Fatalf("expected non-cached token")
	}
	if token != freshToken {
		t.Fatalf("unexpected token returned")
	}
	if lock.tryCalls != 0 {
		t.Fatalf("expected no lock attempts, got %d", lock.tryCalls)
	}
	if cache.setCalls != 1 {
		t.Fatalf("expected cache set once, got %d", cache.setCalls)
	}
}

func TestGetOIDCToken_LockMiss_ThenCacheHit_NoLock(t *testing.T) {
	cachedToken := &ssooidc.CreateTokenOutput{AccessToken: aws.String("cached")}
	cache := &testTokenCache{}
	lock := &testLock{tryResults: []bool{false}}
	clock := &testClock{now: time.Unix(0, 0)}

	p := &SSORoleCredentialsProvider{
		OIDCTokenCache:  cache,
		StartURL:        "https://sso.example",
		ssoTokenLock:    lock,
		UseStdout:       false,
		UseSSOTokenLock: true,
		ssoLockWait:     5 * time.Second,
		ssoNow:          clock.Now,
	}
	p.newOIDCTokenFn = func(context.Context) (*ssooidc.CreateTokenOutput, error) {
		t.Fatal("newOIDCToken should not be called when cache fills while waiting")
		return nil, nil
	}
	p.ssoLogf = func(string, ...any) {}
	p.ssoSleep = func(ctx context.Context, d time.Duration) error {
		clock.now = clock.now.Add(d)
		cache.token = cachedToken
		return nil
	}

	token, cached, err := p.getOIDCToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cached {
		t.Fatalf("expected cached token")
	}
	if token != cachedToken {
		t.Fatalf("unexpected token returned")
	}
	if lock.tryCalls != 1 {
		t.Fatalf("expected 1 lock attempt, got %d", lock.tryCalls)
	}
	if lock.unlockCalls != 0 {
		t.Fatalf("expected no unlocks, got %d", lock.unlockCalls)
	}
}

func TestGetOIDCToken_LockAcquired_RecheckCache(t *testing.T) {
	cachedToken := &ssooidc.CreateTokenOutput{AccessToken: aws.String("cached")}
	cache := &testTokenCache{}
	lock := &testLock{tryResults: []bool{true}}
	lock.onTry = func(l *testLock) {
		if l.locked {
			cache.token = cachedToken
		}
	}

	p := &SSORoleCredentialsProvider{
		OIDCTokenCache:  cache,
		StartURL:        "https://sso.example",
		ssoTokenLock:    lock,
		UseStdout:       false,
		UseSSOTokenLock: true,
	}
	p.newOIDCTokenFn = func(context.Context) (*ssooidc.CreateTokenOutput, error) {
		t.Fatal("newOIDCToken should not be called when cache is filled after lock")
		return nil, nil
	}
	p.ssoLogf = func(string, ...any) {}
	p.ssoSleep = func(context.Context, time.Duration) error { return nil }

	token, cached, err := p.getOIDCToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cached {
		t.Fatalf("expected cached token")
	}
	if token != cachedToken {
		t.Fatalf("unexpected token returned")
	}
	if lock.unlockCalls != 1 {
		t.Fatalf("expected 1 unlock, got %d", lock.unlockCalls)
	}
}

func TestGetOIDCToken_LockHeldThroughCacheSet(t *testing.T) {
	freshToken := &ssooidc.CreateTokenOutput{AccessToken: aws.String("fresh")}
	lock := &testLock{tryResults: []bool{true}}
	cache := &testTokenCache{setLock: lock}

	p := &SSORoleCredentialsProvider{
		OIDCTokenCache:  cache,
		StartURL:        "https://sso.example",
		ssoTokenLock:    lock,
		UseStdout:       false,
		UseSSOTokenLock: true,
	}
	p.newOIDCTokenFn = func(context.Context) (*ssooidc.CreateTokenOutput, error) {
		return freshToken, nil
	}
	p.ssoLogf = func(string, ...any) {}
	p.ssoSleep = func(context.Context, time.Duration) error { return nil }

	token, cached, err := p.getOIDCToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cached {
		t.Fatalf("expected non-cached token")
	}
	if token != freshToken {
		t.Fatalf("unexpected token returned")
	}
	if cache.setCalls != 1 {
		t.Fatalf("expected cache set once, got %d", cache.setCalls)
	}
	if lock.unlockCalls != 1 {
		t.Fatalf("expected 1 unlock, got %d", lock.unlockCalls)
	}
}

func TestGetOIDCToken_UseStdout_SkipsLock(t *testing.T) {
	freshToken := &ssooidc.CreateTokenOutput{AccessToken: aws.String("fresh")}
	lock := &testLock{tryResults: []bool{true}}
	cache := &testTokenCache{}

	p := &SSORoleCredentialsProvider{
		OIDCTokenCache:  cache,
		StartURL:        "https://sso.example",
		ssoTokenLock:    lock,
		UseStdout:       true,
		UseSSOTokenLock: true,
	}
	p.newOIDCTokenFn = func(context.Context) (*ssooidc.CreateTokenOutput, error) {
		return freshToken, nil
	}
	p.ssoLogf = func(string, ...any) {}
	p.ssoSleep = func(context.Context, time.Duration) error { return nil }

	token, cached, err := p.getOIDCToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cached {
		t.Fatalf("expected non-cached token")
	}
	if token != freshToken {
		t.Fatalf("unexpected token returned")
	}
	if lock.tryCalls != 0 {
		t.Fatalf("expected no lock attempts, got %d", lock.tryCalls)
	}
}

func TestGetOIDCToken_LockWaitLogs(t *testing.T) {
	lock := &testLock{tryResults: []bool{false, false, false, false}}
	cache := &testTokenCache{}
	ctx, cancel := context.WithCancel(context.Background())
	clock := &testClock{now: time.Unix(0, 0), cancel: cancel, cancelAfter: 4}
	var logTimes []time.Time

	p := &SSORoleCredentialsProvider{
		OIDCTokenCache:  cache,
		StartURL:        "https://sso.example",
		ssoTokenLock:    lock,
		UseStdout:       false,
		UseSSOTokenLock: true,
		ssoLockWait:     5 * time.Second,
		ssoLockLog:      15 * time.Second,
		ssoNow:          clock.Now,
	}
	p.newOIDCTokenFn = func(context.Context) (*ssooidc.CreateTokenOutput, error) {
		t.Fatal("newOIDCToken should not be called when lock never acquired")
		return nil, nil
	}
	p.ssoSleep = clock.Sleep
	p.ssoLogf = func(string, ...any) {
		logTimes = append(logTimes, clock.Now())
	}

	_, _, err := p.getOIDCToken(ctx)
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
