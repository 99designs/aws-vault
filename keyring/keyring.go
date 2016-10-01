package keyring

import "errors"

const (
	KeychainBackend string = "keychain"
	SecretsBackend  string = "secrets"
	KWalletBackend  string = "kwallet"
	FileBackend     string = "file"
)

var DefaultBackend = FileBackend

var supportedBackends = map[string]opener{}

func SupportedBackends() []string {
	b := []string{}
	for k := range supportedBackends {
		b = append(b, k)
	}
	return b
}

type opener func(name string) (Keyring, error)

func Open(name string, backend string) (Keyring, error) {
	op, ok := supportedBackends[backend]
	if !ok {
		return nil, ErrNoAvailImpl
	}

	return op(name)
}

type Item struct {
	Key         string
	Data        []byte
	Label       string
	Description string
	TrustSelf   bool
}

type Keyring interface {
	Get(key string) (Item, error)
	Set(item Item) error
	Remove(key string) error
	Keys() ([]string, error)
}

var ErrNoAvailImpl = errors.New("Specified keyring backend not available")
var ErrKeyNotFound = errors.New("The specified item could not be found in the keyring.")
