package keyring

import (
	"encoding/json"
	"errors"
)

func ForPlatform() (Keyring, error) {
	if keyring == nil {
		return nil, ErrNoAvailImpl
	}
	return keyring, nil
}

type Keyring interface {
	Get(key string) ([]byte, error)
	Set(key string, secret []byte) error
	Remove(key string) error
	Keys() ([]string, error)
}

func Marshal(k Keyring, key string, obj interface{}) error {
	bytes, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	return k.Set(key, bytes)
}

func Unmarshal(k Keyring, key string, obj interface{}) error {
	data, err := k.Get(key)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(data, obj); err != nil {
		return err
	}
	return nil
}

var keyring Keyring

var ErrNoAvailImpl = errors.New("No keyring implementation for your platform available.")
var ErrKeyNotFound = errors.New("The specified item could not be found in the keychain.")
