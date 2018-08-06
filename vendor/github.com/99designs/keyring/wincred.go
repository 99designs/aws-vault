// +build windows

package keyring

import (
	"strings"

	"github.com/danieljoos/wincred"
)

type windowsKeyring struct {
	name string
}

func init() {
	supportedBackends[WinCredBackend] = opener(func(cfg Config) (Keyring, error) {
		name := cfg.ServiceName
		if name == "" {
			name = "default"
		}

		return &windowsKeyring{
			name: name,
		}, nil
	})
}

func (k *windowsKeyring) Get(key string) (Item, error) {
	cred, err := wincred.GetGenericCredential(k.credentialName(key))
	if err != nil {
		if err.Error() == "Element not found." {
			return Item{}, ErrKeyNotFound
		}
		return Item{}, err
	}

	item := Item{
		Key:  key,
		Data: cred.CredentialBlob,
	}

	return item, nil
}

func (k *windowsKeyring) Set(item Item) error {
	cred := wincred.NewGenericCredential(k.credentialName(item.Key))
	cred.CredentialBlob = item.Data
	return cred.Write()
}

func (k *windowsKeyring) Remove(key string) error {
	cred, err := wincred.GetGenericCredential(k.credentialName(key))
	if err != nil {
		if err.Error() == "Element not found." {
			return ErrKeyNotFound
		}
		return err
	}
	return cred.Delete()
}

func (k *windowsKeyring) Keys() ([]string, error) {
	results := []string{}

	if creds, err := wincred.List(); err == nil {
		for _, cred := range creds {
			prefix := k.credentialName("")
			if strings.HasPrefix(cred.TargetName, prefix) {
				results = append(results, strings.TrimPrefix(cred.TargetName, prefix))
			}
		}
	}

	return results, nil
}

func (k *windowsKeyring) credentialName(key string) string {
	return "aws-vault:" + k.name + ":" + key
}
