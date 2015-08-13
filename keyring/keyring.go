package keyring

import "encoding/json"

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

var DefaultKeyring Keyring
