package keyring

import (
	"encoding/json"
	"errors"
)

type Keyring interface {
	Get(service, key string) ([]byte, error)
	Set(service, key string, secret []byte) error
	Remove(service, key string) error
	List(service string) ([]string, error)
}

func Marshal(k Keyring, service, key string, obj interface{}) error {
	bytes, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	return k.Set(service, key, bytes)
}

func Unmarshal(k Keyring, service, key string, obj interface{}) error {
	data, err := k.Get(service, key)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(data, obj); err != nil {
		return err
	}
	return nil
}

func DefaultKeyring() (Keyring, error) {
	if len(keyrings) == 0 {
		return nil, ErrNoAvailImpl
	}
	return keyrings[0], nil
}

var keyrings []Keyring

var ErrNoAvailImpl = errors.New("No keyring implementation for your platform available.")
var ErrKeyNotFound = errors.New("The specified item could not be found in the keychain.")
