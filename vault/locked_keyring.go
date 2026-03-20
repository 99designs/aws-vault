package vault

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/byteness/keyring"
)

type lockedKeyring struct {
	inner keyring.Keyring
	lock  KeyringLock
	mu    sync.Mutex

	lockKey   string
	lockWait  time.Duration
	lockLog   time.Duration
	warnAfter time.Duration
	lockNow   func() time.Time
	lockSleep func(context.Context, time.Duration) error
	lockLogf  func(string, ...any)
}

const (
	defaultKeyringLockWaitDelay = 100 * time.Millisecond
	defaultKeyringLockLogEvery  = 15 * time.Second
	defaultKeyringLockWarnAfter = 5 * time.Second
	defaultKeyringLockTimeout   = 2 * time.Minute
)

// NewLockedKeyring wraps the provided keyring with a cross-process lock
// to serialize keyring operations.
func NewLockedKeyring(kr keyring.Keyring, lockKey string) keyring.Keyring {
	return &lockedKeyring{
		inner:   kr,
		lock:    NewDefaultKeyringLock(lockKey),
		lockKey: lockKey,
	}
}

func (k *lockedKeyring) ensureLockDependencies() {
	if k.lock == nil {
		lockKey := k.lockKey
		if lockKey == "" {
			lockKey = "aws-vault"
		}
		k.lock = NewDefaultKeyringLock(lockKey)
	}
	if k.lockWait == 0 {
		k.lockWait = defaultKeyringLockWaitDelay
	}
	if k.lockLog == 0 {
		k.lockLog = defaultKeyringLockLogEvery
	}
	if k.warnAfter == 0 {
		k.warnAfter = defaultKeyringLockWarnAfter
	}
	if k.lockNow == nil {
		k.lockNow = time.Now
	}
	if k.lockSleep == nil {
		k.lockSleep = func(ctx context.Context, d time.Duration) error {
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
	if k.lockLogf == nil {
		k.lockLogf = log.Printf
	}
}

func (k *lockedKeyring) withLock(fn func() error) error {
	k.ensureLockDependencies()

	k.mu.Lock()
	defer k.mu.Unlock()

	waiter := newLockWaiter(
		k.lock,
		"Waiting for keyring lock at %s\n",
		"Waiting for keyring lock at %s",
		k.lockWait,
		k.lockLog,
		k.warnAfter,
		k.lockNow,
		k.lockSleep,
		k.lockLogf,
		func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format, args...)
		},
	)

	// The keyring.Keyring interface is not context-aware, so we cannot cancel
	// in-flight keyring operations. This timeout is a safety net for the lock-wait
	// loop: if the lock holder is hung (e.g. a stuck gpg subprocess in the pass
	// backend), waiters will eventually give up rather than blocking indefinitely.
	ctx, cancel := context.WithTimeout(context.Background(), defaultKeyringLockTimeout)
	defer cancel()

	for {
		locked, err := k.lock.TryLock()
		if err != nil {
			return err
		}
		if locked {
			fnErr := fn()
			if unlockErr := k.lock.Unlock(); unlockErr != nil {
				return errors.Join(fnErr, fmt.Errorf("unlock keyring lock: %w", unlockErr))
			}
			return fnErr
		}

		if err = waiter.sleepAfterMiss(ctx); err != nil {
			return err
		}
	}
}

func (k *lockedKeyring) Get(key string) (keyring.Item, error) {
	var item keyring.Item
	if err := k.withLock(func() error {
		var err error
		item, err = k.inner.Get(key)
		return err
	}); err != nil {
		return keyring.Item{}, err
	}
	return item, nil
}

func (k *lockedKeyring) GetMetadata(key string) (keyring.Metadata, error) {
	var meta keyring.Metadata
	if err := k.withLock(func() error {
		var err error
		meta, err = k.inner.GetMetadata(key)
		return err
	}); err != nil {
		return keyring.Metadata{}, err
	}
	return meta, nil
}

func (k *lockedKeyring) Set(item keyring.Item) error {
	return k.withLock(func() error {
		return k.inner.Set(item)
	})
}

func (k *lockedKeyring) Remove(key string) error {
	return k.withLock(func() error {
		return k.inner.Remove(key)
	})
}

func (k *lockedKeyring) Keys() ([]string, error) {
	var keys []string
	if err := k.withLock(func() error {
		var err error
		keys, err = k.inner.Keys()
		return err
	}); err != nil {
		return nil, err
	}
	return keys, nil
}
