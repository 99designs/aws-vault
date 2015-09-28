package keyring

import "errors"

type backend string

const (
	KeychainBackend backend = "osxkeychain"
)

var supportedBackends = map[backend]opener{}

func Open(name string, prefer ...backend) (Keyring, error) {
	if len(prefer) == 0 {
		for b := range supportedBackends {
			prefer = append(prefer, b)
		}
	}

	for _, b := range prefer {
		for supported, f := range supportedBackends {
			if b == supported {
				return f(name)
			}
		}
	}

	return nil, ErrNoAvailImpl
}

type opener func(name string) (Keyring, error)

type Item struct {
	Key         string
	Data        []byte
	Label       string
	Description string
	TrustSelf   bool
	Metadata    map[string]string
}

type Keyring interface {
	Get(key string) (Item, error)
	Set(item Item) error
	Remove(key string) error
	Keys() ([]string, error)
}

var ErrNoAvailImpl = errors.New("No keyring implementation for your platform available.")
var ErrKeyNotFound = errors.New("The specified item could not be found in the keyring.")
