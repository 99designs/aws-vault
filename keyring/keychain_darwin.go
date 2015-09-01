package keyring

import (
	"os"
	"os/user"

	keychain "github.com/99designs/aws-vault/Godeps/_workspace/src/github.com/99designs/go-osxkeychain"
)

var keychainFile string

type OSXKeychain struct {
	path string
}

func (k *OSXKeychain) Get(service, key string) ([]byte, error) {
	attributes := keychain.GenericPasswordAttributes{
		ServiceName: service,
		AccountName: key,
	}

	if k.path != "" {
		attributes.Keychain = []string{k.path}
	}

	if b, err := keychain.FindGenericPassword(&attributes); err == keychain.ErrItemNotFound {
		return b, ErrKeyNotFound
	} else {
		return b, err
	}
}

func (k *OSXKeychain) Set(service, key string, secret []byte) error {
	attributes := keychain.GenericPasswordAttributes{
		ServiceName: service,
		AccountName: key,
		Password:    secret,
	}

	if k.path != "" {
		if _, err := os.Stat(k.path); os.IsNotExist(err) {
			pass := os.Getenv("AWS_KEYCHAIN_PASSWORD")
			if pass != "" {
				keychain.CreateKeychain(k.path, pass)
			} else {
				keychain.CreateKeychainViaPrompt(k.path)
			}
		}
		attributes.Keychain = []string{k.path}
	}

	err := keychain.AddGenericPassword(&attributes)
	if err == keychain.ErrDuplicateItem {
		return keychain.RemoveAndAddGenericPassword(&attributes)
	}

	return err
}

func (k *OSXKeychain) Remove(service, key string) error {
	attributes := keychain.GenericPasswordAttributes{
		ServiceName: service,
		AccountName: key,
	}

	if k.path != "" {
		attributes.Keychain = []string{k.path}
	}

	if err := keychain.FindAndRemoveGenericPassword(&attributes); err == keychain.ErrItemNotFound {
		return ErrKeyNotFound
	} else {
		return err
	}
}

func (k *OSXKeychain) List(service string) ([]string, error) {
	keychains := []string{}

	if k.path != "" {
		keychains = []string{k.path}
	}

	return keychain.GetAllAccountNames(service, keychains...)
}

func init() {
	file := os.Getenv("AWS_KEYCHAIN_FILE")
	if file == "" {
		usr, err := user.Current()
		if err != nil {
			panic(err)
		}
		file = usr.HomeDir + "/Library/Keychains/aws-vault.keychain"
	}

	keyrings = append(keyrings, &OSXKeychain{file})
}
