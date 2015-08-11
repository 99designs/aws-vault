package keyring

type Keyring interface {
	Get(service, key string) ([]byte, error)
	Set(service, key string, secret []byte) error
	Remove(service, key string) error
}

var DefaultKeyring Keyring
