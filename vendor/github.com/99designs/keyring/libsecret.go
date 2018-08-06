// +build linux

package keyring

import (
	"encoding/json"
	"fmt"

	"github.com/godbus/dbus"
	"github.com/gsterjov/go-libsecret"
)

func init() {
	// silently fail if dbus isn't available
	_, err := dbus.SessionBus()
	if err != nil {
		return
	}

	supportedBackends[SecretServiceBackend] = opener(func(cfg Config) (Keyring, error) {
		if cfg.ServiceName == "" {
			cfg.ServiceName = "secret-service"
		}
		if cfg.LibSecretCollectionName == "" {
			cfg.LibSecretCollectionName = cfg.ServiceName
		}

		service, err := libsecret.NewService()
		if err != nil {
			return &secretsKeyring{}, err
		}

		ring := &secretsKeyring{
			name:    cfg.LibSecretCollectionName,
			service: service,
		}

		return ring, ring.openSecrets()
	})
}

type secretsKeyring struct {
	name       string
	service    *libsecret.Service
	collection *libsecret.Collection
	session    *libsecret.Session
}

type secretsError struct {
	message string
}

func (e *secretsError) Error() string {
	return e.message
}

func (k *secretsKeyring) openSecrets() error {
	session, err := k.service.Open()
	if err != nil {
		return err
	}
	k.session = session

	// get the collection if it already exists
	collections, err := k.service.Collections()
	if err != nil {
		return err
	}

	path := libsecret.DBusPath + "/collection/" + k.name

	for _, collection := range collections {
		if string(collection.Path()) == path {
			k.collection = &collection
			return nil
		}
	}

	return nil
}

func (k *secretsKeyring) openCollection() error {
	if err := k.openSecrets(); err != nil {
		return err
	}

	if k.collection == nil {
		return &secretsError{fmt.Sprintf(
			"The collection %q does not exist. Please add a key first",
			k.name,
		)}
	}

	return nil
}

func (k *secretsKeyring) Get(key string) (Item, error) {
	if err := k.openCollection(); err != nil {
		return Item{}, err
	}

	items, err := k.collection.SearchItems(key)
	if err != nil {
		return Item{}, err
	}

	if len(items) == 0 {
		return Item{}, err
	}

	// use the first item whenever there are multiples
	// with the same profile name
	item := items[0]

	locked, err := item.Locked()
	if err != nil {
		return Item{}, err
	}

	if locked {
		if err := k.service.Unlock(item); err != nil {
			return Item{}, err
		}
	}

	secret, err := item.GetSecret(k.session)
	if err != nil {
		return Item{}, err
	}

	// pack the secret into the aws-vault item
	var ret Item
	if err = json.Unmarshal(secret.Value, &ret); err != nil {
		return Item{}, err
	}

	return ret, err
}

func (k *secretsKeyring) Set(item Item) error {
	err := k.openSecrets()
	if err != nil {
		return err
	}

	// create the collection if it doesn't already exist
	if k.collection == nil {
		collection, err := k.service.CreateCollection(k.name)
		if err != nil {
			return err
		}

		k.collection = collection
	}

	// create the new item
	data, err := json.Marshal(item)
	if err != nil {
		return err
	}

	secret := libsecret.NewSecret(k.session, []byte{}, data, "application/json")

	// unlock the collection first
	locked, err := k.collection.Locked()
	if err != nil {
		return err
	}

	if locked {
		if err := k.service.Unlock(k.collection); err != nil {
			return err
		}
	}

	if _, err := k.collection.CreateItem(item.Key, secret, true); err != nil {
		return err
	}

	return nil
}

func (k *secretsKeyring) Remove(key string) error {
	err := k.openCollection()
	if err != nil {
		return err
	}

	items, err := k.collection.SearchItems(key)
	if err != nil {
		return err
	}

	// nothing to delete
	if len(items) == 0 {
		return nil
	}

	// we dont want to delete more than one anyway
	// so just get the first item found
	item := items[0]

	locked, err := item.Locked()
	if err != nil {
		return err
	}

	if locked {
		if err := k.service.Unlock(item); err != nil {
			return err
		}
	}

	if err := item.Delete(); err != nil {
		return err
	}

	return nil
}

func (k *secretsKeyring) Keys() ([]string, error) {
	err := k.openCollection()
	if err != nil {
		return []string{}, err
	}

	items, err := k.collection.Items()
	if err != nil {
		return []string{}, err
	}

	keys := []string{}

	for _, item := range items {
		label, err := item.Label()
		if err == nil {
			keys = append(keys, label)
		}
	}

	return keys, nil
}
