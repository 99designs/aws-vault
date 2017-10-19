// Package keyring provides a uniform API over a range of desktop credential storage engines
//
// See project homepage at https://github.com/99designs/keyring for more background
package keyring

import "errors"

// All currently supported secure storage backends
const (
	SecretServiceBackend string = "secret-service"
	KeychainBackend      string = "keychain"
	KWalletBackend       string = "kwallet"
	FileBackend          string = "file"
)

// DefaultBackend is the lowest common denominator across OSes - encrypted file
var DefaultBackend = FileBackend

var supportedBackends = map[string]opener{}

// SupportedBackends provides a slice of all available backend keys on the current OS
func SupportedBackends() []string {
	b := []string{}
	for k := range supportedBackends {
		b = append(b, k)
	}
	return b
}

type opener func(name string) (Keyring, error)

// Open will ask the underlying backend to authenticate and provide access to the underlying store
func Open(name string, backend string) (Keyring, error) {
	op, ok := supportedBackends[backend]
	if !ok {
		return nil, ErrNoAvailImpl
	}

	return op(name)
}

// Item is an, uh, item that is stored on the keyring
type Item struct {
	Key         string
	Data        []byte
	Label       string
	Description string
	// macOS only, set false if you want the password prompt to appear every time
	TrustSelf bool
}

// Keyring provides the uniform interface over the underlying backends
type Keyring interface {
	// Returns an Item matching the key or ErrKeyNotFound
	Get(key string) (Item, error)
	// Stores an Item on the keyring
	Set(item Item) error
	// Removes the item with matching key
	Remove(key string) error
	// Provides a slice of all keys stored on the keyring
	Keys() ([]string, error)
}

// ErrNoAvailImpl is returned by Open when a backend cannot be found
var ErrNoAvailImpl = errors.New("Specified keyring backend not available")

// ErrKeyNotFound is returned by Keyring Get when the item is not on the keyring
var ErrKeyNotFound = errors.New("The specified item could not be found in the keyring.")
