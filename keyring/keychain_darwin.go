package keyring

import keychain "github.com/keybase/go-osxkeychain"

type OSXKeychain struct {
}

func (k *OSXKeychain) Get(service, key string) ([]byte, error) {
	attributes := keychain.GenericPasswordAttributes{
		ServiceName: service,
		AccountName: key,
	}

	return keychain.FindGenericPassword(&attributes)
}

func (k *OSXKeychain) Set(service, key string, secret []byte) error {
	attributes := keychain.GenericPasswordAttributes{
		ServiceName: service,
		AccountName: key,
		Password:    secret,
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

	return keychain.FindAndRemoveGenericPassword(&attributes)
}

func init() {
	DefaultKeyring = &OSXKeychain{}
}
