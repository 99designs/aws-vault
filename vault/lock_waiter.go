package vault

import (
	"context"
	"time"
)

type lockLogger func(string, ...any)

type lockWaiter struct {
	lock      ProcessLock
	waitDelay time.Duration
	logEvery  time.Duration
	warnAfter time.Duration
	now       func() time.Time
	sleep     func(context.Context, time.Duration) error
	logf      lockLogger
	warnf     lockLogger
	warnMsg   string
	logMsg    string

	lastLog   time.Time
	waitStart time.Time
	warned    bool
}

func newLockWaiter(
	lock ProcessLock,
	warnMsg string,
	logMsg string,
	waitDelay time.Duration,
	logEvery time.Duration,
	warnAfter time.Duration,
	now func() time.Time,
	sleep func(context.Context, time.Duration) error,
	logf lockLogger,
	warnf lockLogger,
) *lockWaiter {
	if now == nil {
		now = time.Now
	}
	if sleep == nil {
		sleep = func(ctx context.Context, d time.Duration) error {
			timer := time.NewTimer(d)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		}
	}
	return &lockWaiter{
		lock:      lock,
		waitDelay: waitDelay,
		logEvery:  logEvery,
		warnAfter: warnAfter,
		now:       now,
		sleep:     sleep,
		logf:      logf,
		warnf:     warnf,
		warnMsg:   warnMsg,
		logMsg:    logMsg,
	}
}

func (w *lockWaiter) sleepAfterMiss(ctx context.Context) error {
	now := w.now()
	if w.waitStart.IsZero() {
		w.waitStart = now
	}
	if !w.warned && now.Sub(w.waitStart) >= w.warnAfter {
		if w.warnf != nil {
			w.warnf(w.warnMsg, w.lock.Path())
		}
		w.warned = true
	}
	if w.logf != nil && (w.lastLog.IsZero() || now.Sub(w.lastLog) >= w.logEvery) {
		w.logf(w.logMsg, w.lock.Path())
		w.lastLog = now
	}

	return w.sleep(ctx, w.waitDelay)
}
