package vault

import (
	"context"
	"time"
)

type testLock struct {
	tryResults  []bool
	tryCalls    int
	unlockCalls int
	locked      bool
	path        string
	onTry       func(*testLock)
}

func (l *testLock) TryLock() (bool, error) {
	l.tryCalls++
	locked := false
	if l.tryCalls <= len(l.tryResults) {
		locked = l.tryResults[l.tryCalls-1]
	}
	if locked {
		l.locked = true
	}
	if l.onTry != nil {
		l.onTry(l)
	}
	return locked, nil
}

func (l *testLock) Unlock() error {
	l.unlockCalls++
	l.locked = false
	return nil
}

func (l *testLock) Path() string {
	if l.path != "" {
		return l.path
	}
	return "/tmp/aws-vault.lock"
}

type testClock struct {
	now         time.Time
	sleepCalls  int
	cancelAfter int
	cancel      context.CancelFunc
}

func (c *testClock) Now() time.Time {
	return c.now
}

func (c *testClock) Sleep(ctx context.Context, d time.Duration) error {
	c.sleepCalls++
	c.now = c.now.Add(d)
	if c.cancel != nil && c.cancelAfter > 0 && c.sleepCalls >= c.cancelAfter {
		c.cancel()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}
